export const SAMPLE_INVOICE_TEXT =
  'INVOICE #INV-2026-0842\n' +
  'From: Aegis Cloud Security Ltd.\n' +
  'To: Meridian Financial Holdings\n' +
  'Amount Due: $48,500.00 USD\n' +
  'Settlement IBAN: DE89-3704-0044-0532-0130-00\n' +
  'Authorized By: Chief Information Security Officer\n' +
  'Terms: Net-15 Wire Transfer — Immutable Cryptographic Audit Record';

export function bytesToBase64(bytes: Uint8Array): string {
  let binary = '';
  const chunkSize = 0x8000;
  for (let i = 0; i < bytes.length; i += chunkSize) {
    const chunk = bytes.subarray(i, i + chunkSize);
    binary += String.fromCharCode(...chunk);
  }
  return btoa(binary);
}

export function utf8ToBase64(text: string): string {
  const encoder = new TextEncoder();
  return bytesToBase64(encoder.encode(text));
}

export function arrayBufferToBase64(buffer: ArrayBuffer): string {
  return bytesToBase64(new Uint8Array(buffer));
}

export function downloadTextFile(content: string, filename: string, mimeType: string): void {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  document.body.removeChild(anchor);
  URL.revokeObjectURL(url);
}

export function simulateTamperingOnText(currentText: string): string {
  if (!currentText) {
    return 'TAMPERED_PAYLOAD_1';
  }
  if (currentText.includes('$48,500.00')) {
    return currentText.replace('$48,500.00', '$98,500.00');
  }
  if (currentText.includes('$98,500.00')) {
    return currentText.replace('$98,500.00', '$48,500.00');
  }
  const lastChar = currentText.slice(-1);
  const replacement = lastChar !== 'X' ? 'X' : 'Y';
  return currentText.slice(0, -1) + replacement;
}

export function utcTimestampCompact(): string {
  return new Date().toISOString().replace('T', ' ').slice(0, 19) + ' UTC';
}
