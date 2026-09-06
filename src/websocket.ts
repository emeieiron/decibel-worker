const RESERVED_CLOSE_CODES = new Set([1004, 1005, 1006]);

export function forwardableCloseCode(code: number, fallback: number): number {
  const protocolCode = code >= 1000 && code <= 1014 && !RESERVED_CLOSE_CODES.has(code);
  const applicationCode = code >= 3000 && code <= 4999;
  return protocolCode || applicationCode ? code : fallback;
}
