/** Lowercase file extension without dot, or empty string if none. */
export function getFileExtension(filename: string): string {
  return filename.split('.').pop()?.toLowerCase() || '';
}
