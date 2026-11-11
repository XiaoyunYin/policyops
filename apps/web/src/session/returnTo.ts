// Local return path for sign-in. The API stores only plain absolute paths: segments of [A-Za-z0-9._~-], no "." or
// ".." segment, at most 200 characters, no query or fragment. Anything else (another origin, "//host", a backslash,
// an API route) falls back to the case list instead of being sent and refused.

export const DEFAULT_RETURN_PATH = "/cases";
const MAX_RETURN_PATH = 200;
const RETURN_PATH = /^\/([A-Za-z0-9._~-]+(\/[A-Za-z0-9._~-]+)*)?$/;

export function safeReturnTo(path: string | null | undefined): string {
  if (typeof path !== "string" || path.length > MAX_RETURN_PATH || !RETURN_PATH.test(path)) {
    return DEFAULT_RETURN_PATH;
  }
  const segments = path.split("/");
  if (segments.some((segment) => segment === "." || segment === "..") || segments[1] === "api") {
    return DEFAULT_RETURN_PATH;
  }
  return path === "/" ? DEFAULT_RETURN_PATH : path;
}
