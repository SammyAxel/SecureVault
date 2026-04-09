/**
 * Browsers only expose SubtleCrypto in a "secure context" (HTTPS or http://localhost).
 * Plain http://<LAN-IP> leaves crypto.subtle undefined, which breaks E2EE flows.
 */
export function isSubtleCryptoAvailable(): boolean {
  return (
    typeof globalThis !== 'undefined' &&
    typeof globalThis.crypto !== 'undefined' &&
    typeof globalThis.crypto.subtle !== 'undefined'
  );
}

export function insecureWebCryptoMessage(): string {
  return (
    'Web Crypto is unavailable: open this app over HTTPS or at http://localhost (not http:// with an IP address). ' +
    'Browsers require a secure context for encryption.'
  );
}

export function assertSubtleCrypto(): void {
  if (!isSubtleCryptoAvailable()) {
    throw new Error(insecureWebCryptoMessage());
  }
}
