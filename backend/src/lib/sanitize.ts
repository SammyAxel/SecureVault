/**
 * Build a safe Content-Disposition header value using RFC 6266 encoding.
 * Prevents header injection from attacker-controlled filenames.
 */
export function safeContentDisposition(filename: string): string {
  const ascii = filename.replace(/[^\x20-\x7E]/g, '_').replace(/["\\]/g, '_');
  const encoded = encodeURIComponent(filename).replace(/'/g, '%27');
  return `attachment; filename="${ascii}"; filename*=UTF-8''${encoded}`;
}
