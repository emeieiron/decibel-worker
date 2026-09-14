import { canonicalAddress } from "./security";
import type { SessionClaims, SponsorshipRecord } from "./types";

type UpstreamRecord = Record<string, unknown>;

/** Accepts the current OpenAPI field and read-only aliases used by earlier Decibel deployments. */
export function subaccountRecordMatches(record: UpstreamRecord, expected: string): boolean {
  const address = stringField(
    record,
    "subaccount_address",
    "subaccount_addr",
    "subaccount",
    "address",
  );
  return address !== undefined && sameAddress(address, expected);
}

/**
 * A Flare API session is account-wide, so only an active all-perp-markets delegation is sufficient.
 * A market-scoped grant must not be promoted into authority to trade another market.
 */
export function delegationAuthorizesAllPerpMarkets(
  record: UpstreamRecord,
  signer: string,
  nowMs: number,
): boolean {
  const delegate = stringField(
    record,
    "delegated_account",
    "delegate",
    "account_to_delegate_to",
  );
  if (!delegate || !sameAddress(delegate, signer)) return false;
  if (record.is_active === false) return false;

  const permissionType = record.permission_type;
  if (record.can_trade_perps === false && permissionType !== "TradeSpotAllMarkets") return false;

  const hasAllMarketsPermission =
    permissionType === "TradePerpsAllMarkets" ||
    permissionType === "TradeSpotAllMarkets" ||
    (permissionType === undefined && (record.can_trade_perps === true || record.can_trade_spot === true));
  if (!hasAllMarketsPermission) return false;

  const rawExpiry = numberField(
    record,
    "expiration_time_s",
    "expiration_timestamp",
    "expiration",
  );
  if (rawExpiry === undefined || rawExpiry === 0) return true;
  if (!Number.isSafeInteger(rawExpiry) || rawExpiry < 0) return false;
  const expiryMs = rawExpiry < 10_000_000_000 ? rawExpiry * 1_000 : rawExpiry;
  return expiryMs > nowMs;
}

/** Recovery metadata is visible only to the authenticated identity that submitted the bytes. */
export function sponsorshipRecordMatchesSession(
  record: SponsorshipRecord,
  claims: Pick<SessionClaims, "network" | "role" | "wallet" | "subaccount">,
): boolean {
  if (claims.role === "anonymous" || !claims.wallet) return false;
  if (record.network !== claims.network || record.role !== claims.role) return false;
  if (!sameAddress(record.wallet, claims.wallet)) return false;
  if (record.subaccount === undefined || claims.subaccount === undefined) {
    return record.subaccount === claims.subaccount;
  }
  return sameAddress(record.subaccount, claims.subaccount);
}

function sameAddress(left: string, right: string): boolean {
  try {
    return canonicalAddress(left) === canonicalAddress(right);
  } catch {
    return false;
  }
}

function stringField(value: UpstreamRecord, ...names: string[]): string | undefined {
  for (const name of names) if (typeof value[name] === "string") return value[name] as string;
  return undefined;
}

function numberField(value: UpstreamRecord, ...names: string[]): number | undefined {
  for (const name of names) {
    const candidate = value[name];
    if (typeof candidate === "number") return candidate;
    if (typeof candidate === "string" && candidate.trim() !== "") return Number(candidate);
  }
  return undefined;
}
