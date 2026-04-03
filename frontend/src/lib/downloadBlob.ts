/**
 * Mobile browsers often block programmatic <a download> clicks that happen after
 * async work (fetch + decrypt), because user activation is lost. Desktop Chrome
 * usually still allows it.
 */
export function prefersExplicitSaveStep(): boolean {
  if (typeof window === 'undefined') return false;
  const coarse = window.matchMedia?.('(pointer: coarse)')?.matches;
  const narrow = window.matchMedia?.('(max-width: 768px)')?.matches;
  return !!(coarse || narrow);
}

/**
 * `fetch(blob:...)` often yields a Blob with an empty or generic MIME type. Re-wrap using the
 * same type as the preview (from filename / metadata) so saves and Web Share use the correct type.
 */
export function blobFromBlobUrlFetchResponse(fetched: Blob, mimeType: string): Blob {
  return new Blob([fetched], { type: mimeType });
}

/**
 * Must run from a direct user gesture (e.g. tap on "Save") so mobile browsers accept it.
 * Tries Web Share API with a File (good on Android / many mobile Chrome), then <a download>.
 */
export async function saveBlobToDevice(blob: Blob, filename: string): Promise<void> {
  if (typeof navigator !== 'undefined' && navigator.share && navigator.canShare) {
    try {
      const file = new File([blob], filename, { type: blob.type || 'application/octet-stream' });
      const data: ShareData = { files: [file], title: filename };
      if (navigator.canShare(data)) {
        await navigator.share(data);
        return;
      }
    } catch (e) {
      if ((e as Error).name === 'AbortError') return;
      // fall through to anchor
    }
  }

  const url = URL.createObjectURL(blob);
  try {
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.rel = 'noopener';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
  } finally {
    window.setTimeout(() => URL.revokeObjectURL(url), 1500);
  }
}
