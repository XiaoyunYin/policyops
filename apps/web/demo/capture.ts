import type { Page } from "@playwright/test";
import { setTimeout as delay } from "node:timers/promises";
import { MAX_VIDEO_BYTES, validateVideo } from "./guards.ts";

export const VIEWPORT = { width: 1280, height: 720 };
const FRAME_MS = 160;
const CAPTURE_TIMEOUT = 8_000;

export async function within<T>(pending: Promise<T>, label: string, ms = CAPTURE_TIMEOUT): Promise<T> {
  const timer = new AbortController();
  try {
    return await Promise.race([pending, delay(ms, undefined, { signal: timer.signal }).then(() => {
      throw new Error(`${label} timed out`);
    })]);
  } finally {
    timer.abort();
  }
}

// The locked Playwright's built-in recordVideo launches ffmpeg. Use Chromium's WebM encoder on
// an isolated, blank page instead. The canvas receives pixels from just the one walkthrough page.
export async function capture(workbench: Page, encoder: Page) {
  const firstFrame = await workbench.screenshot({ type: "jpeg", quality: 85, timeout: CAPTURE_TIMEOUT });
  const surface = await within(encoder.evaluateHandle(async ({ frame, width, height }) => {
    const canvas = document.createElement("canvas");
    canvas.width = width;
    canvas.height = height;
    document.body.append(canvas);
    const context = canvas.getContext("2d");
    if (context === null) throw new Error("Canvas capture unavailable");
    const paint = async (jpeg: string): Promise<void> => {
      const img = new Image();
      img.src = `data:image/jpeg;base64,${jpeg}`;
      await img.decode();
      context.drawImage(img, 0, 0);
    };
    await paint(frame);
    const stream = canvas.captureStream(10);
    const recorder = new MediaRecorder(stream, { mimeType: "video/webm;codecs=vp8", videoBitsPerSecond: 680_000 });
    const result = new Promise<Blob>((resolve) => {
      recorder.ondataavailable = ({ data }) => { resolve(data); };
    });
    recorder.start();
    return { paint, recorder, result, stream };
  }, { frame: firstFrame.toString("base64"), ...VIEWPORT }), "Starting WebM capture");

  const lifetime = new AbortController();
  let failure: unknown;
  const frames = (async () => {
    while (!lifetime.signal.aborted) {
      const start = performance.now();
      await within(surface.evaluate((session, jpeg) => session.paint(jpeg),
        (await workbench.screenshot({ type: "jpeg", quality: 85, timeout: CAPTURE_TIMEOUT })).toString("base64")),
      "Writing a video frame");
      await delay(Math.max(0, FRAME_MS - (performance.now() - start)));
    }
  })().catch((error: unknown) => { failure = error; });

  const check = (): void => {
    if (failure !== undefined) throw new Error("WebM frame capture failed");
  };
  return {
    check,
    cancel: () => { lifetime.abort(); }, // Closing the encoder context stops its recorder and stream.
    async finish() {
      lifetime.abort();
      await frames;
      check();
      const video = await within(surface.evaluate(async (session, maxBytes) => {
        session.recorder.stop();
        const blob = await session.result;
        session.stream.getTracks().forEach((track) => { track.stop(); });
        if (blob.size === 0 || blob.size > maxBytes) return { bytes: blob.size, seconds: 0, base64: "" };

        // Verify duration from the encoded video as decoded by Chromium, independent of the pacing timers.
        const media = document.createElement("video");
        const url = URL.createObjectURL(blob);
        try {
          await new Promise<void>((resolve, reject) => {
            media.onloadedmetadata = () => { resolve(); };
            media.onerror = () => { reject(new Error("Chromium could not decode the WebM metadata")); };
            media.src = url;
          });
          const base64 = await new Promise<string>((resolve, reject) => {
            const reader = new FileReader();
            reader.onload = () => {
              if (typeof reader.result === "string") resolve(reader.result.split(",", 2)[1] ?? "");
              else reject(new Error("Expected an encoded WebM data URL"));
            };
            reader.onerror = () => { reject(new Error("Reading encoded video failed")); };
            reader.readAsDataURL(blob);
          });
          return { bytes: blob.size, seconds: media.duration, base64 };
        } finally {
          URL.revokeObjectURL(url);
        }
      }, MAX_VIDEO_BYTES), "Finalizing WebM", 20_000);
      validateVideo(video.seconds, video.bytes);
      const data = Buffer.from(video.base64, "base64");
      if (data.length !== video.bytes) throw new Error("Encoded WebM transfer was incomplete");
      return { data, seconds: video.seconds };
    },
  };
}
