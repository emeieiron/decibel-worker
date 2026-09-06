/** Read endpoints required by Kaptos for building, simulating and reconciling transactions. */
export function isAllowedAptosReadPath(path: string): boolean {
  // Ktor may percent-encode Move type separators in the balance asset identifier.
  try { path = decodeURIComponent(path); } catch { return false; }
  return path === "/" || path === "/estimate_gas_price" ||
    /^\/transactions\/by_hash\/0x[0-9a-fA-F]+$/.test(path) ||
    /^\/accounts\/0x[0-9a-fA-F]{1,64}$/.test(path) ||
    /^\/accounts\/0x[0-9a-fA-F]{1,64}\/(resources|modules)$/.test(path) ||
    /^\/accounts\/0x[0-9a-fA-F]{1,64}\/module\/[A-Za-z_][A-Za-z0-9_]*$/.test(path) ||
    /^\/accounts\/0x[0-9a-fA-F]{1,64}\/balance\/0x[0-9a-fA-F]{1,64}(?:::[A-Za-z_][A-Za-z0-9_]*::[A-Za-z_][A-Za-z0-9_]*)?$/.test(path) ||
    /^\/accounts\/0x[0-9a-fA-F]{1,64}\/resource\/.+$/.test(path);
}
