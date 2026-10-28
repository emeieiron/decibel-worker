import type { Env, SessionClaims } from "./types";

const INTENT_TTL_MS = 7 * 24 * 60 * 60 * 1_000;
const UPSTREAM_TIMEOUT_MS = 10_000;
const CODE_PATTERN = /^[A-Za-z0-9_-]{1,128}$/;
const DEFINITIVE_REJECTIONS = new Set([400, 401, 403, 404, 422, 429]);

type ReferralStatus = "eligible" | "bound" | "ineligible" | "pending";
type IntentStatus = "pending" | "bound";

interface ReferralIntent {
  wallet: string;
  code: string;
  status: IntentStatus;
  tradingAccount?: string;
  priorAccounts: string[];
  expiresAt: number;
}

interface ReferralBinding {
  account: string;
  code: string;
  referrerAccount: string;
  isActive: boolean;
}

interface ReferralDependencies {
  authenticate(request: Request): Promise<SessionClaims>;
  rateLimit(claims: SessionClaims): Promise<void>;
  fetch?: typeof fetch;
}

export async function handleReferral(
  request: Request,
  env: Env,
  dependencies: ReferralDependencies,
): Promise<Response | null> {
  const url = new URL(request.url);
  const fetcher = dependencies.fetch ?? fetch;

  if (url.pathname === "/referrals/config" && request.method === "GET") {
    const enabled = env.REFERRALS_ENABLED === "true";
    const code = env.DEFAULT_REFERRAL_CODE?.trim();
    return noStore({
      enabled,
      ...(enabled && code ? { suggested_code: code } : {}),
    });
  }

  if (url.pathname.startsWith("/referrals/code/") && request.method === "GET") {
    let code: string;
    try {
      code = decodeURIComponent(url.pathname.slice("/referrals/code/".length));
    } catch {
      throw new ReferralError(400, "Invalid referral code");
    }
    validateCode(code);
    const claims = await dependencies.authenticate(request);
    await dependencies.rateLimit(claims);
    return noStore(await validateReferralCode(env, fetcher, code));
  }

  if (url.pathname === "/referrals/status" && request.method === "GET") {
    const claims = await dependencies.authenticate(request);
    await dependencies.rateLimit(claims);
    return noStore(await referralStatus(env, fetcher, requireOwner(claims)));
  }

  if (url.pathname === "/referrals/redeem" && request.method === "POST") {
    if (env.REFERRALS_ENABLED !== "true") {
      throw new ReferralError(503, "Referrals are disabled");
    }
    const claims = await dependencies.authenticate(request);
    await dependencies.rateLimit(claims);
    const wallet = requireOwner(claims);
    const body = await request.json().catch(() => null) as unknown;
    if (!isRecord(body) || Object.keys(body).length !== 1 || typeof body.code !== "string") {
      throw new ReferralError(400, "Expected {code:string}");
    }
    const code = body.code.trim();
    validateCode(code);
    return redeemReferral(env, fetcher, wallet, code);
  }

  return null;
}

async function referralStatus(env: Env, fetcher: typeof fetch, wallet: string): Promise<unknown> {
  const stub = referralStub(env, wallet);
  const intent = await readIntent(stub, wallet);
  if (env.REFERRALS_ENABLED !== "true" && !intent) {
    return { account: wallet, status: "ineligible" satisfies ReferralStatus };
  }
  const liveBinding = await getBinding(env, fetcher, wallet);

  if (liveBinding) {
    return {
      account: wallet,
      status: "bound" satisfies ReferralStatus,
      referral_code: liveBinding.code,
    };
  }

  if (intent?.status === "bound") {
    const accounts = await ownedAccounts(env, fetcher, wallet);
    const tradingAccount = intent.tradingAccount && accounts.includes(intent.tradingAccount)
      ? intent.tradingAccount
      : undefined;
    return {
      account: wallet,
      status: "bound" satisfies ReferralStatus,
      referral_code: intent.code,
      ...(tradingAccount ? { trading_account: tradingAccount } : {}),
    };
  }

  if (intent?.status === "pending") {
    const accounts = await ownedAccounts(env, fetcher, wallet);
    const tradingAccount = accounts.find(account => !intent.priorAccounts.includes(account));
    return {
      account: wallet,
      status: "pending" satisfies ReferralStatus,
      referral_code: intent.code,
      ...(tradingAccount ? { trading_account: tradingAccount } : {}),
    };
  }

  return {
    account: wallet,
    status: await isEligible(env, fetcher, wallet) ? "eligible" : "ineligible",
  };
}

async function redeemReferral(
  env: Env,
  fetcher: typeof fetch,
  wallet: string,
  code: string,
): Promise<Response> {
  const stub = referralStub(env, wallet);
  const existing = await readIntent(stub, wallet);
  if (existing) {
    if (existing.code !== code) {
      throw new ReferralError(409, "A different referral code is already recorded");
    }
    const live = await getBinding(env, fetcher, wallet);
    if (live) {
      if (live.code === code) {
        return noStore({ account: wallet, status: "bound", referral_code: code });
      }
      throw new ReferralError(409, `Account is already bound to referral code ${live.code}`);
    }
    const accounts = await ownedAccounts(env, fetcher, wallet);
    const tradingAccount = existing.tradingAccount && accounts.includes(existing.tradingAccount)
      ? existing.tradingAccount
      : accounts.find(account => !existing.priorAccounts.includes(account));
    return noStore({
      account: wallet,
      status: existing.status === "bound" ? "bound" : "pending",
      referral_code: code,
      ...(tradingAccount ? { trading_account: tradingAccount } : {}),
    }, existing.status === "bound" ? 200 : 202);
  }

  const liveBinding = await getBinding(env, fetcher, wallet);
  if (liveBinding) {
    if (liveBinding.code === code) {
      return noStore({ account: wallet, status: "bound", referral_code: code });
    }
    throw new ReferralError(409, `Account is already bound to referral code ${liveBinding.code}`);
  }

  const validation = await validateReferralCode(env, fetcher, code);
  if (!validation.is_valid || !validation.is_active) {
    throw new ReferralError(400, "Referral code is not active");
  }

  const priorAccounts = await ownedAccounts(env, fetcher, wallet);
  if (!await isEligible(env, fetcher, wallet, priorAccounts)) {
    throw new ReferralError(409, "Account is not eligible for referral redemption");
  }

  const intent: ReferralIntent = {
    wallet,
    code,
    status: "pending",
    priorAccounts,
    expiresAt: Date.now() + INTENT_TTL_MS,
  };
  const created = await stub.fetch("https://state/", {
    method: "POST",
    body: JSON.stringify(intent),
  });
  if (created.status === 409) {
    const raced = await readIntent(stub, wallet);
    if (raced?.code === code) {
      return noStore({ account: wallet, status: raced.status, referral_code: code }, 202);
    }
    throw new ReferralError(409, "A different referral code is already recorded");
  }
  if (created.status !== 201) {
    throw new ReferralError(503, "Unable to reserve referral redemption");
  }

  let response: Response;
  try {
    response = await upstreamFetch(fetcher, env, "referrals/redeem", {
      method: "POST",
      body: JSON.stringify({ account: wallet, referral_code: code }),
    });
  } catch {
    return noStore({ account: wallet, status: "pending", referral_code: code }, 202);
  }

  if (response.ok) {
    const result = await response.json().catch(() => null) as unknown;
    if (!isRecord(result) || result.account !== wallet || result.referral_code !== code) {
      return noStore({ account: wallet, status: "pending", referral_code: code }, 202);
    }
    intent.status = "bound";
    const accounts = await ownedAccounts(env, fetcher, wallet).catch(() => []);
    const tradingAccount = accounts.find(account => !priorAccounts.includes(account));
    intent.tradingAccount = tradingAccount;
    await writeIntent(stub, intent);
    return noStore({
      account: wallet,
      status: "bound",
      referral_code: code,
      ...(tradingAccount ? { trading_account: tradingAccount } : {}),
    });
  }

  if (response.status === 409) {
    const live = await getBinding(env, fetcher, wallet).catch(() => null);
    if (live?.code === code) {
      const accounts = await ownedAccounts(env, fetcher, wallet).catch(() => []);
      intent.status = "bound";
      intent.tradingAccount = accounts.find(account => !priorAccounts.includes(account));
      await writeIntent(stub, intent);
      return noStore({
        account: wallet,
        status: "bound",
        referral_code: code,
        ...(intent.tradingAccount ? { trading_account: intent.tradingAccount } : {}),
      });
    }
    if (live && live.code !== code) {
      await deleteIntent(stub);
      throw new ReferralError(409, `Account is already bound to referral code ${live.code}`);
    }
    return noStore({ account: wallet, status: "pending", referral_code: code }, 202);
  }

  if (DEFINITIVE_REJECTIONS.has(response.status)) {
    await deleteIntent(stub);
    throw new ReferralError(response.status, "Referral redemption was rejected");
  }
  return noStore({ account: wallet, status: "pending", referral_code: code }, 202);
}

async function validateReferralCode(
  env: Env,
  fetcher: typeof fetch,
  code: string,
): Promise<{ referral_code: string; is_valid: boolean; is_active: boolean }> {
  const response = await upstreamFetch(fetcher, env, `referrals/code/${encodeURIComponent(code)}`);
  if (!response.ok) {
    throw new ReferralError(502, "Referral service unavailable");
  }
  const body = await jsonBody(response, "Malformed referral validation response");
  if (!isRecord(body) || typeof body.referral_code !== "string" ||
      typeof body.is_valid !== "boolean" || typeof body.is_active !== "boolean" ||
      body.referral_code !== code) {
    throw new ReferralError(502, "Malformed referral validation response");
  }
  return {
    referral_code: body.referral_code,
    is_valid: body.is_valid,
    is_active: body.is_active,
  };
}

async function isEligible(
  env: Env,
  fetcher: typeof fetch,
  wallet: string,
  knownAccounts?: string[],
): Promise<boolean> {
  const accounts = knownAccounts ?? await ownedAccounts(env, fetcher, wallet);
  for (let index = 0; index < accounts.length; index += 8) {
    const batch = accounts.slice(index, index + 8);
    const results = await Promise.all(batch.flatMap(account => [
      "account_fund_history",
      "trade_history",
    ].map(async endpoint => {
      const url = upstreamUrl(env, endpoint);
      url.searchParams.set("account", account);
      url.searchParams.set("limit", "1");
      const response = await upstreamFetch(fetcher, env, url);
      if (!response.ok) throw new ReferralError(503, "Unable to verify referral eligibility");
      const rows = extractRows(await jsonBody(response, "Malformed eligibility history response"));
      if (!rows) throw new ReferralError(503, "Malformed eligibility history response");
      return rows.length > 0;
    })));
    if (results.some(Boolean)) return false;
  }
  return true;
}

async function ownedAccounts(env: Env, fetcher: typeof fetch, wallet: string): Promise<string[]> {
  const url = upstreamUrl(env, "subaccounts");
  url.searchParams.set("owner", wallet);
  const response = await upstreamFetch(fetcher, env, url);
  if (!response.ok) throw new ReferralError(503, "Unable to verify owned accounts");
  const rows = extractRows(await jsonBody(response, "Malformed owned account response"));
  if (!rows) throw new ReferralError(503, "Malformed owned account response");

  return [...new Set(rows.map(row => {
    const address = row.subaccount_address;
    const owner = row.primary_account_address;
    if (typeof address !== "string" || typeof owner !== "string") {
      throw new ReferralError(503, "Malformed owned account data");
    }
    const canonicalAddress = normalizeAddress(address);
    if (normalizeAddress(owner) !== wallet) {
      throw new ReferralError(503, "Owned account owner mismatch");
    }
    return canonicalAddress;
  }))];
}

async function getBinding(
  env: Env,
  fetcher: typeof fetch,
  wallet: string,
): Promise<ReferralBinding | null> {
  const response = await upstreamFetch(fetcher, env, `referrals/account/${wallet}`);
  if (response.status === 404) return null;
  if (!response.ok) throw new ReferralError(503, "Unable to read referral binding");
  const body = await jsonBody(response, "Malformed referral binding response");
  if (!isRecord(body) || typeof body.account !== "string" ||
      typeof body.referral_code !== "string" || typeof body.referrer_account !== "string" ||
      typeof body.is_active !== "boolean") {
    throw new ReferralError(503, "Malformed referral binding response");
  }
  const account = normalizeAddress(body.account);
  const referrerAccount = normalizeAddress(body.referrer_account);
  if (account !== wallet || !CODE_PATTERN.test(body.referral_code)) {
    throw new ReferralError(503, "Referral binding scope mismatch");
  }
  return {
    account,
    code: body.referral_code,
    referrerAccount,
    isActive: body.is_active,
  };
}

async function readIntent(stub: DurableObjectStub, wallet: string): Promise<ReferralIntent | undefined> {
  const response = await stub.fetch("https://state/");
  if (response.status === 404) return undefined;
  if (!response.ok) throw new ReferralError(503, "Referral state unavailable");
  const body = await jsonBody(response, "Corrupt referral state");
  if (!isRecord(body) || body.wallet !== wallet || typeof body.code !== "string" ||
      !CODE_PATTERN.test(body.code) || (body.status !== "pending" && body.status !== "bound") ||
      !Array.isArray(body.priorAccounts) || !body.priorAccounts.every(isAddress) ||
      typeof body.expiresAt !== "number" || !Number.isSafeInteger(body.expiresAt) || body.expiresAt <= Date.now() ||
      (body.tradingAccount !== undefined && !isAddress(body.tradingAccount))) {
    throw new ReferralError(503, "Corrupt referral state");
  }
  const priorAccounts = body.priorAccounts.map(normalizeAddress);
  const tradingAccount = body.tradingAccount === undefined ? undefined : normalizeAddress(body.tradingAccount);
  return {
    wallet,
    code: body.code,
    status: body.status,
    priorAccounts,
    expiresAt: body.expiresAt,
    ...(tradingAccount ? { tradingAccount } : {}),
  };
}

async function writeIntent(stub: DurableObjectStub, intent: ReferralIntent): Promise<void> {
  const response = await stub.fetch("https://state/", {
    method: "PUT",
    body: JSON.stringify(intent),
  });
  if (response.status !== 204) throw new ReferralError(503, "Unable to update referral state");
}

async function deleteIntent(stub: DurableObjectStub): Promise<void> {
  const response = await stub.fetch("https://state/", { method: "DELETE" });
  if (!response.ok) throw new ReferralError(503, "Unable to clear referral state");
}

function referralStub(env: Env, wallet: string): DurableObjectStub {
  const key = `referral:${wallet}`;
  return env.SPONSORSHIPS.get(env.SPONSORSHIPS.idFromName(key));
}

function requireOwner(claims: SessionClaims): string {
  if (claims.role !== "owner" || !claims.wallet) {
    throw new ReferralError(403, "Owner session required");
  }
  return normalizeAddress(claims.wallet);
}

function validateCode(code: string): void {
  if (!CODE_PATTERN.test(code)) throw new ReferralError(400, "Invalid referral code");
}

function upstreamUrl(env: Env, endpoint: string): URL {
  return new URL(`${env.DECIBEL_REST_ORIGIN.replace(/\/$/, "")}/api/v1/${endpoint}`);
}

function upstreamFetch(
  fetcher: typeof fetch,
  env: Env,
  target: string | URL,
  options: { method?: string; body?: string } = {},
): Promise<Response> {
  const url = target instanceof URL
    ? target
    : /^https?:\/\//.test(target)
      ? new URL(target)
      : upstreamUrl(env, target);
  return fetcher(url, {
    method: options.method ?? "GET",
    headers: headers(env),
    ...(options.body ? { body: options.body } : {}),
    redirect: "manual",
    signal: AbortSignal.timeout(UPSTREAM_TIMEOUT_MS),
  });
}

function headers(env: Env): HeadersInit {
  return {
    Authorization: `Bearer ${env.DECIBEL_NODE_API_KEY}`,
    Origin: env.DECIBEL_ORIGIN,
  };
}

async function jsonBody(response: Response, message: string): Promise<unknown> {
  try {
    return await response.json();
  } catch {
    throw new ReferralError(503, message);
  }
}

function extractRows(value: unknown): Record<string, unknown>[] | null {
  if (Array.isArray(value)) return value.every(isRecord) ? value : null;
  if (!isRecord(value)) return null;
  const rows = value.subaccounts ?? value.items ?? value.data ?? value.history;
  return Array.isArray(rows) && rows.every(isRecord) ? rows : null;
}

function normalizeAddress(value: string): string {
  if (!isAddress(value)) throw new ReferralError(503, "Malformed account address");
  return `0x${value.slice(2).toLowerCase().padStart(64, "0")}`;
}

function isAddress(value: unknown): value is string {
  return typeof value === "string" && /^0x[0-9a-fA-F]{1,64}$/.test(value);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function noStore(body: unknown, status = 200): Response {
  return Response.json(body, { status, headers: { "Cache-Control": "no-store" } });
}

export class ReferralError extends Error {
  constructor(readonly status: number, message: string) {
    super(message);
  }
}
