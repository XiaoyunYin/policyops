import { useEffect } from "react";

/** Reads only; hidden tabs pause. A focus/visibility return revalidates immediately. */
export function useVisibleRefresh(refresh: () => void): void {
  useEffect(() => {
    const read = (): void => { if (document.visibilityState !== "hidden") refresh(); };
    const timer = setInterval(read, 15_000);
    window.addEventListener("focus", read);
    document.addEventListener("visibilitychange", read);
    return () => {
      clearInterval(timer); window.removeEventListener("focus", read);
      document.removeEventListener("visibilitychange", read);
    };
  }, [refresh]);
}
