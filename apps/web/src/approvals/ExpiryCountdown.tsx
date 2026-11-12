import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { Detail } from "./api";

export function useExpiry(detail: Detail, sampledAt: number, revalidate: () => void) {
  const sample = useMemo(() => ({ server: Date.parse(detail.server_time), local: sampledAt,
    expires: Math.min(Date.parse(detail.proposal.expires_at), detail.consent === null ? Infinity : Date.parse(detail.consent.expires_at)) }), [detail, sampledAt]);
  const remaining = useCallback(() => Math.max(0, Math.ceil((sample.expires - sample.server - (performance.now() - sample.local)) / 1000)), [sample]);
  const [tick, setTick] = useState(0);
  const last = useRef(Infinity);
  const [announcement, setAnnouncement] = useState("");
  useEffect(() => {
    const timer = setInterval(() => {
      const seconds = remaining();
      setTick((v) => v + 1);
      const threshold = seconds === 0 ? 0 : seconds <= 10 ? 10 : seconds <= 60 ? 60 : Infinity;
      if (threshold < last.current) {
        last.current = threshold;
        setAnnouncement(seconds === 0 ? "Review expired. New decisions are disabled." : `Review expires within ${String(threshold)} seconds.`);
        revalidate();
      }
    }, 1000);
    return () => { clearInterval(timer); };
  }, [remaining, revalidate]);
  return { seconds: remaining(), remaining, announcement, tick };
}
export function ExpiryCountdown({ detail, seconds, announcement }: { detail: Detail; seconds: number; announcement: string }) {
  return <section className={`expiry-panel${seconds <= 60 ? " notice" : ""}`} aria-label="Review expiry">
    <p className="eyebrow">Review window · server clock</p><p className="expiry-value" aria-live="off">{seconds === 0 ? "Expired" : `${String(seconds)} seconds remaining`}</p>
    <p>Proposal expires (UTC): <time dateTime={detail.proposal.expires_at}>{detail.proposal.expires_at}</time></p>
    <p className="muted">The earlier proposal or consent expiry applies. The server rechecks before recording a decision.</p>
    <p role="status" aria-live="polite" aria-atomic="true" className="visually-hidden">{announcement}</p>
  </section>;
}
