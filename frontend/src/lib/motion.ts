/** Pad short async work so loading states do not flash (calmer perceived UX). Skipped when user prefers reduced motion. */
export const MIN_BOOTSTRAP_MS = 560;
export const MIN_CONTENT_LOAD_MS = 420;
export const MIN_FORM_SUBMIT_MS = 380;
export const MIN_SETUP_WIZARD_MS = 520;
/** How long vault search shows a “working” state after commit. */
export const MIN_SEARCH_FEEDBACK_MS = 640;
/** Background refresh (e.g. notification poll): no extra wait so periodic sync stays snappy. */
export const MIN_SILENT_REFRESH_MS = 0;

function prefersReducedMotion(): boolean {
  if (typeof window === 'undefined') return false;
  return window.matchMedia?.('(prefers-reduced-motion: reduce)').matches ?? false;
}

export function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export async function awaitMinElapsed(since: number, minMs: number): Promise<void> {
  if (prefersReducedMotion()) return;
  const elapsed = Date.now() - since;
  if (elapsed < minMs) await delay(minMs - elapsed);
}
