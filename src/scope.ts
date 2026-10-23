import { canonicalAddress } from "./security";

/** Account endpoints that carry the account in the path rather than in a parameter. */
const ACCOUNT_REFERRAL_PREFIXES = ["referrals/stats/", "referrals/account/"];

/** The prefix `endpoint` matches, or undefined when it is not one of them. */
export function referralAccountPrefix(endpoint: string): string | undefined {
  return ACCOUNT_REFERRAL_PREFIXES.find((prefix) => endpoint.startsWith(prefix));
}

/**
 * Whether `value` names the account this session is for. A malformed address is a mismatch rather
 * than a crash: canonicalAddress throws, which would surface as a 500 instead of a refusal.
 */
export function isSessionAccount(
  value: string | null | undefined,
  expected: string | undefined,
): boolean {
  if (!value || !expected) return false;
  try {
    return canonicalAddress(value) === expected;
  } catch {
    return false;
  }
}
