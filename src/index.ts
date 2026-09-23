import { isAllowedAptosReadPath } from "./routes";
import {
  aptosAddressFromEd25519,
  buildChallenge,
  canonicalAddress,
  CHALLENGE_TTL_MS,
  issueSessionToken,
  parseChallenge,
  randomHex,
  SESSION_TTL_SECONDS,
  verifyEd25519,
  verifySessionToken,
} from "./security";
import { FlareState } from "./state";
import {
  authorizeGasStationRequest,
  externalFeePayerFingerprint,
  validateGasStationRequest,
} from "./gasStation";
import { validateTopic } from "./topics";
import { forwardableCloseCode } from "./websocket";
import {
  delegationAuthorizesAllPerpMarkets,
  sponsorshipRecordMatchesSession,
  subaccountRecordMatches,
} from "./authorization";
import type {
  ChallengeRecord,
  Env,
  SessionClaims,
  SessionRole,
  SponsorshipRecord,
} from "./types";

export { FlareState };

const PUBLIC_DECIBEL_ENDPOINTS = new Set([
  "asset_contexts",
  "candlesticks",
  "contract_specs",
  "contracts",
  "dex",
  "markets",
  "orderbook",
  "prices",
  "spot/asset_contexts",
  "subaccounts",
  "trades",
  "vaults",
]);

const ACCOUNT_DECIBEL_ENDPOINTS = new Set([
  "account_fund_history",
  "account_overviews",
  "account_positions",
  "account_vault_performance",
  "account_owned_vaults",
  "active_twaps",
  "twap_history",
  "portfolio_chart",
  "delegations",
  "funding_rate_history",
  "open_orders",
  "order_history",
  "trade_history",
  "user_fee_rates",
  "withdraw_queue",
  "points/amps",
  "points/amps/daily",
]);

const SPONSORSHIP_RECORD_TTL_MS = 7 * 24 * 60 * 60 * 1_000;
const TRANSACTION_HASH_PATTERN = /^0x[0-9a-fA-F]{64}$/;
const FINGERPRINT_PATTERN = /^0x[0-9a-fA-F]{64}$/;
const DEFINITIVE_GAS_STATION_REJECTIONS = new Set([400, 401, 403, 404, 422, 429]);

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    try {
      if (request.method === "OPTIONS") return corsResponse(env, null, 204);
      enforceOrigin(request, env);
      await enforceIpBackstop(request, env);

      const url = new URL(request.url);
      if (request.method === "POST" && url.pathname === "/v1/session/anonymous") {
        return corsResponse(env, await createAnonymousSession(request, env));
      }
      if (request.method === "POST" && url.pathname === "/v1/auth/challenge") {
        return corsResponse(env, await createChallenge(request, env));
      }
      if (request.method === "POST" && url.pathname === "/v1/auth/session") {
        return corsResponse(env, await createAuthenticatedSession(request, env));
      }
      if (request.method === "POST" && url.pathname === "/v1/session/revoke") {
        return corsResponse(env, await revokeSession(request, env));
      }
      if (url.pathname === "/decibel/ws") return await proxyWebSocket(request, env);
      if (url.pathname.startsWith("/decibel/api/v1/")) {
        return corsResponse(env, await proxyDecibelRest(request, env));
      }
      if (url.pathname === "/aptos/v1" || url.pathname.startsWith("/aptos/v1/")) {
        return corsResponse(env, await proxyAptos(request, env));
      }
      if (url.pathname === "/gas/sponsor/owner" || url.pathname === "/gas/sponsor/trading") {
        return corsResponse(env, await proxyGasStation(request, env));
      }
      if (request.method === "GET" && url.pathname.startsWith("/gas/sponsor/status/")) {
        return corsResponse(env, await sponsorshipStatus(request, env));
      }
      return corsResponse(env, jsonError("Route not found", 404));
    } catch (error) {
      return corsResponse(env, errorResponse(error));
    }
  },
} satisfies ExportedHandler<Env>;

async function createAnonymousSession(request: Request, env: Env): Promise<Response> {
  const body = await readJson<{ installationId?: string }>(request);
  const installationId = body.installationId ?? randomHex(16);
  if (!/^[A-Za-z0-9_-]{16,128}$/.test(installationId)) {
    throw new HttpError(400, "Invalid installation identifier");
  }
  const limited = await env.ANONYMOUS_RATE_LIMITER.limit({ key: `session:${installationId}` });
  if (!limited.success) throw new HttpError(429, "Rate limit exceeded");
  return issueAndStoreSession(env, "anonymous", { jti: randomHex(16) });
}

async function createChallenge(request: Request, env: Env): Promise<Response> {
  const body = await readJson<{
    network?: string;
    origin?: string;
    walletAddress?: string;
    subaccount?: string;
  }>(request);
  if (body.network !== env.NETWORK || body.origin !== env.APP_ORIGIN || !body.walletAddress) {
    throw new HttpError(400, "Challenge scope does not match this deployment");
  }
  const issuedAt = Date.now();
  const fields = {
    network: env.NETWORK,
    origin: env.APP_ORIGIN,
    walletAddress: canonicalAddress(body.walletAddress),
    subaccount: body.subaccount ? canonicalAddress(body.subaccount) : undefined,
    nonce: randomHex(32),
    issuedAt,
    expiresAt: issuedAt + CHALLENGE_TTL_MS,
  };
  const challenge = buildChallenge(fields);
  const record: ChallengeRecord = { challenge, expiresAt: fields.expiresAt };
  const stored = await stateStub(env.NONCES, fields.nonce).fetch("https://state/", {
    method: "POST",
    body: JSON.stringify(record),
  });
  if (!stored.ok) throw new HttpError(503, "Unable to allocate authentication challenge");
  return Response.json({ challenge, expiresAt: fields.expiresAt });
}

async function createAuthenticatedSession(request: Request, env: Env): Promise<Response> {
  const body = await readJson<{ challenge?: string; publicKey?: string; signature?: string }>(request);
  if (!body.challenge || !body.publicKey || !body.signature) {
    throw new HttpError(400, "Challenge, public key, and signature are required");
  }
  const fields = parseChallenge(body.challenge);
  if (fields.network !== env.NETWORK || fields.origin !== env.APP_ORIGIN) {
    throw new HttpError(401, "Challenge scope mismatch");
  }
  if (fields.expiresAt <= Date.now() || fields.issuedAt > Date.now() + 30_000) {
    throw new HttpError(401, "Challenge expired");
  }

  const nonceStub = stateStub(env.NONCES, fields.nonce);
  const storedResponse = await nonceStub.fetch("https://state/");
  if (!storedResponse.ok) throw new HttpError(401, "Challenge is unavailable");
  const stored = await storedResponse.json<ChallengeRecord>();
  if (stored.challenge !== body.challenge || stored.expiresAt !== fields.expiresAt) {
    throw new HttpError(401, "Challenge mismatch");
  }

  const signer = aptosAddressFromEd25519(body.publicKey);
  if (signer !== fields.walletAddress || !verifyEd25519(body.challenge, body.publicKey, body.signature)) {
    throw new HttpError(401, "Signature or wallet address is invalid");
  }

  const consumed = await nonceStub.fetch("https://state/", { method: "DELETE" });
  if (!consumed.ok) throw new HttpError(401, "Challenge was already consumed");
  const consumedRecord = await consumed.json<ChallengeRecord>();
  if (consumedRecord.challenge !== body.challenge || consumedRecord.expiresAt !== fields.expiresAt) {
    throw new HttpError(401, "Challenge mismatch");
  }
  const role = await resolveRole(env, signer, fields.subaccount);
  return issueAndStoreSession(env, role, {
    jti: randomHex(16),
    wallet: signer,
    subaccount: fields.subaccount,
  });
}

async function issueAndStoreSession(
  env: Env,
  role: SessionRole,
  identity: Pick<SessionClaims, "jti" | "wallet" | "subaccount">,
): Promise<Response> {
  const now = Math.floor(Date.now() / 1_000);
  const claims: SessionClaims = {
    iat: now,
    exp: now + SESSION_TTL_SECONDS,
    jti: identity.jti,
    network: env.NETWORK,
    role,
    wallet: identity.wallet,
    subaccount: identity.subaccount,
  };
  const stored = await stateStub(env.SESSIONS, claims.jti).fetch("https://state/", {
    method: "POST",
    body: JSON.stringify(claims),
  });
  if (!stored.ok) throw new HttpError(503, "Unable to allocate session");
  const token = await issueSessionToken(claims, env.SESSION_SIGNING_KEY);
  return Response.json({
    token,
    expiresAt: claims.exp * 1_000,
    role,
    walletAddress: claims.wallet,
    subaccount: claims.subaccount,
  });
}

async function revokeSession(request: Request, env: Env): Promise<Response> {
  const claims = await authenticate(request, env);
  await enforceSessionRateLimit(claims, env);
  const deleted = await stateStub(env.SESSIONS, claims.jti).fetch("https://state/", {
    method: "DELETE",
  });
  if (!deleted.ok) throw new HttpError(401, "Session is no longer active");
  return new Response(null, { status: 204, headers: { "Cache-Control": "no-store" } });
}

async function resolveRole(
  env: Env,
  signer: string,
  subaccount?: string,
): Promise<Exclude<SessionRole, "anonymous">> {
  if (!subaccount) return "owner";

  const subaccounts = await decibelJson(env, "subaccounts", { owner: signer });
  if (itemsFrom(subaccounts, "subaccounts").some((item) =>
    subaccountRecordMatches(item, subaccount))) {
    return "owner";
  }

  const delegations = await decibelJson(env, "delegations", { subaccount });
  const now = Date.now();
  const active = itemsFrom(delegations, "delegations").some((item) =>
    delegationAuthorizesAllPerpMarkets(item, signer, now));
  if (!active) throw new HttpError(403, "Wallet is not authorized for this subaccount");
  return "api";
}

async function proxyDecibelRest(request: Request, env: Env): Promise<Response> {
  if (request.method !== "GET") throw new HttpError(405, "Only GET is allowed for Decibel REST");
  const url = new URL(request.url);
  const endpoint = url.pathname.slice("/decibel/api/v1/".length);
  const isPublicReferral = endpoint.startsWith("referrals/code/");
  const isAllowed =
    PUBLIC_DECIBEL_ENDPOINTS.has(endpoint) ||
    ACCOUNT_DECIBEL_ENDPOINTS.has(endpoint) ||
    isPublicReferral;
  if (!endpoint || !isAllowed) {
    throw new HttpError(404, "Decibel route is not allowlisted");
  }
  const claims = await authenticate(request, env);
  await enforceSessionRateLimit(claims, env);

  if (PUBLIC_DECIBEL_ENDPOINTS.has(endpoint) || isPublicReferral) {
    // Public market data is available to every valid Flare session.
  } else if (ACCOUNT_DECIBEL_ENDPOINTS.has(endpoint)) {
    if (claims.role === "anonymous") throw new HttpError(403, "Wallet session required");
    enforceAccountScope(endpoint, url.searchParams, claims);
  } else {
    throw new HttpError(404, "Decibel route is not allowlisted");
  }

  const upstream = new URL(`${env.DECIBEL_REST_ORIGIN.replace(/\/$/, "")}/api/v1/${endpoint}`);
  upstream.search = url.search;
  return upstreamFetch(
    request,
    upstream,
    {
      Authorization: `Bearer ${env.DECIBEL_NODE_API_KEY}`,
      Origin: env.DECIBEL_ORIGIN,
    },
    PUBLIC_DECIBEL_ENDPOINTS.has(endpoint) || isPublicReferral ? "public" : "private",
  );
}

async function proxyAptos(request: Request, env: Env): Promise<Response> {
  const claims = await authenticate(request, env);
  await enforceSessionRateLimit(claims, env);
  const url = new URL(request.url);
  const suffix = url.pathname.slice("/aptos/v1".length) || "/";
  const readAllowed = request.method === "GET" && isAllowedAptosReadPath(suffix);
  const publicView = request.method === "POST" && suffix === "/view";
  const accountWrite = request.method === "POST" && [
    "/transactions",
    "/transactions/encode_submission",
    "/transactions/simulate",
  ].includes(suffix);
  if (!(readAllowed || publicView || accountWrite)) throw new HttpError(404, "Aptos route is not allowlisted");
  if (accountWrite && claims.role === "anonymous") throw new HttpError(403, "Wallet session required");

  const upstream = new URL(`${env.APTOS_FULLNODE_ORIGIN.replace(/\/$/, "")}${suffix}`);
  upstream.search = url.search;
  const headers: Record<string, string> = {};
  if (env.DECIBEL_NODE_API_KEY) {
    headers.Authorization = `Bearer ${env.DECIBEL_NODE_API_KEY}`;
  }
  return upstreamFetch(request, upstream, headers, readAllowed || publicView ? "public" : "private");
}

async function proxyGasStation(request: Request, env: Env): Promise<Response> {
  if (request.method !== "POST") throw new HttpError(405, "Gas sponsorship requires POST");
  const claims = await authenticate(request, env);
  await enforceSessionRateLimit(claims, env);
  if (claims.role === "anonymous") throw new HttpError(403, "Wallet session required");
  if (!claims.wallet) throw new HttpError(401, "Authenticated session has no wallet identity");
  const ownerOnly = new URL(request.url).pathname.endsWith("/owner");
  if (ownerOnly && claims.role !== "owner") throw new HttpError(403, "Owner authorization required");
  let body;
  try {
    body = validateGasStationRequest(await readJson<unknown>(request));
  } catch (error) {
    throw new HttpError(400, safeMessage(error));
  }
  let submissionBody;
  try {
    submissionBody = authorizeGasStationRequest(body, {
      walletAddress: claims.wallet ?? "",
      subaccount: claims.subaccount,
      network: claims.network,
      ownerOnly,
      decibelPackageAddress: env.DECIBEL_PACKAGE_ADDRESS,
      usdcMetadataAddress: env.USDC_METADATA_ADDRESS,
    });
  } catch (error) {
    throw new HttpError(403, safeMessage(error));
  }
  const fingerprint = externalFeePayerFingerprint(body);
  const sponsorship = stateStub(env.SPONSORSHIPS, fingerprint);
  const expiresAt = Date.now() + SPONSORSHIP_RECORD_TTL_MS;
  const pending: SponsorshipRecord = {
    fingerprint,
    network: env.NETWORK,
    role: claims.role,
    subaccount: claims.subaccount,
    status: "pending",
    expiresAt,
    wallet: claims.wallet,
  };
  const reserved = await sponsorship.fetch("https://state/", {
    method: "POST",
    body: JSON.stringify(pending),
  });
  if (!reserved.ok) {
    const existing = await sponsorship.fetch("https://state/");
    if (existing.ok) {
      const record = await existing.json<SponsorshipRecord>();
      if (
        record.fingerprint !== fingerprint ||
        !sponsorshipRecordMatchesSession(record, claims)
      ) {
        throw new HttpError(409, "Sponsorship correlation conflict");
      }
      if (record.status === "submitted" && record.transactionHash) {
        return Response.json(
          { transactionHash: record.transactionHash },
          { headers: { "Cache-Control": "no-store" } },
        );
      }
    }
    throw new HttpError(409, "Sponsorship request is already being processed");
  }
  const gasStationApiKey = env.GAS_STATION_API_KEY?.trim();
  if (!gasStationApiKey) {
    await sponsorship.fetch("https://state/", { method: "DELETE" });
    return sponsorshipUnavailable("gas_station_not_configured");
  }
  const upstream = new URL(
    `${env.GAS_STATION_ORIGIN.replace(/\/$/, "")}/api/transaction/signAndSubmit`,
  );
  let response: Response;
  try {
    response = await fetch(upstream, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${gasStationApiKey}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(submissionBody),
      redirect: "manual",
    });
  } catch {
    throw new HttpError(502, "Gas Station request outcome is unknown");
  }
  const responseBody = await response.text();
  if (!response.ok) {
    console.error("Gas Station error:", response.status, responseBody);
    if (DEFINITIVE_GAS_STATION_REJECTIONS.has(response.status)) {
      await sponsorship.fetch("https://state/", { method: "DELETE" });
    }
    if (response.status === 401) {
      return sponsorshipUnavailable("gas_station_credentials_rejected");
    }
    return new Response(responseBody, {
      status: response.status,
      headers: {
        "Cache-Control": "no-store",
        "Content-Type": response.headers.get("Content-Type") ?? "application/json",
      },
    });
  }
  let transactionHash: string;
  try {
    const payload = JSON.parse(responseBody) as { transactionHash?: unknown };
    if (typeof payload.transactionHash !== "string" || !TRANSACTION_HASH_PATTERN.test(payload.transactionHash)) {
      throw new Error("Invalid Gas Station transaction hash");
    }
    transactionHash = payload.transactionHash;
  } catch {
    throw new HttpError(502, "Gas Station returned an invalid response");
  }
  const submitted: SponsorshipRecord = {
    ...pending,
    status: "submitted",
    transactionHash,
  };
  const stored = await sponsorship.fetch("https://state/", {
    method: "PUT",
    body: JSON.stringify(submitted),
  });
  if (!stored.ok) throw new HttpError(503, "Unable to journal sponsored transaction");
  return Response.json(
    { transactionHash },
    { headers: { "Cache-Control": "no-store" } },
  );
}

function sponsorshipUnavailable(
  code: "gas_station_not_configured" | "gas_station_credentials_rejected",
): Response {
  return Response.json(
    { error: "Gas sponsorship is unavailable. You can choose to pay gas with APT.", code },
    { status: 503, headers: { "Cache-Control": "no-store" } },
  );
}

async function sponsorshipStatus(request: Request, env: Env): Promise<Response> {
  const claims = await authenticate(request, env);
  await enforceSessionRateLimit(claims, env);
  const fingerprint = new URL(request.url).pathname.slice("/gas/sponsor/status/".length);
  if (!FINGERPRINT_PATTERN.test(fingerprint)) throw new HttpError(400, "Invalid sponsorship fingerprint");
  const response = await stateStub(env.SPONSORSHIPS, fingerprint).fetch("https://state/");
  if (!response.ok) throw new HttpError(404, "Sponsorship record not found");
  const record = await response.json<SponsorshipRecord>();
  if (
    record.fingerprint !== fingerprint ||
    !sponsorshipRecordMatchesSession(record, claims)
  ) {
    throw new HttpError(404, "Sponsorship record not found");
  }
  if (record.status !== "submitted" || !record.transactionHash) {
    return Response.json(
      { status: "pending" },
      { status: 202, headers: { "Cache-Control": "no-store" } },
    );
  }
  return Response.json(
    { status: "submitted", transactionHash: record.transactionHash },
    { headers: { "Cache-Control": "no-store" } },
  );
}


async function proxyWebSocket(request: Request, env: Env): Promise<Response> {
  if (request.headers.get("Upgrade")?.toLowerCase() !== "websocket") {
    throw new HttpError(426, "WebSocket upgrade required");
  }
  const token = webSocketToken(request.headers.get("Sec-WebSocket-Protocol"));
  const claims = await authenticateToken(token, env);
  await enforceSessionRateLimit(claims, env);

  const pair = new WebSocketPair();
  const client = pair[0];
  const server = pair[1];
  // Proxying needs control over both close handshakes. With the current Workers
  // compatibility date, the default automatic reply can close the downstream side
  // before the upstream close has been coordinated.
  server.accept({ allowHalfOpen: true });
  const upstream = new WebSocket(env.DECIBEL_WS_ORIGIN, ["decibel", env.DECIBEL_NODE_API_KEY]);
  const pending: string[] = [];
  const activeTopics = new Set<string>();
  let downstreamClosed = false;
  const maximumTopics = claims.role === "anonymous" ? 25 : 150;
  const closeForExpiry = setTimeout(() => {
    if (server.readyState === WebSocket.OPEN) server.close(4001, "Session expired");
    if (upstream.readyState === WebSocket.OPEN) upstream.close(1000, "Flare session expired");
  }, Math.max(0, claims.exp * 1_000 - Date.now()));

  server.addEventListener("message", (event) => {
    try {
      if (typeof event.data !== "string") throw new Error("Subscription messages must be JSON text");
      if (event.data.length > 1_024) throw new Error("Subscription message is too large");
      const message = JSON.parse(event.data) as { method?: string; topic?: string };
      if ((message.method !== "subscribe" && message.method !== "unsubscribe") || !message.topic) {
        throw new Error("Only subscribe and unsubscribe messages are allowed");
      }
      validateTopic(message.topic, claims);
      let changed = false;
      if (message.method === "subscribe") {
        if (!activeTopics.has(message.topic) && activeTopics.size >= maximumTopics) {
          throw new Error(`Maximum topic count is ${maximumTopics}`);
        }
        if (!activeTopics.has(message.topic)) {
          activeTopics.add(message.topic);
          changed = true;
        }
      } else {
        changed = activeTopics.delete(message.topic);
      }
      if (!changed) {
        if (!downstreamClosed && server.readyState === WebSocket.OPEN) {
          try {
            server.send(JSON.stringify({ success: true, method: message.method, topic: message.topic }));
          } catch {}
        }
        return;
      }
      if (upstream.readyState === WebSocket.OPEN) upstream.send(event.data);
      else {
        if (pending.length >= maximumTopics * 2) {
          throw new Error("Too many subscription changes while the upstream is connecting");
        }
        pending.push(event.data);
      }
    } catch (error) {
      if (!downstreamClosed && server.readyState === WebSocket.OPEN) {
        try {
          server.send(JSON.stringify({ success: false, error: safeMessage(error) }));
        } catch {}
      }
    }
  });
  upstream.addEventListener("open", () => {
    if (downstreamClosed || server.readyState !== WebSocket.OPEN) {
      pending.length = 0;
      upstream.close(1001, "Client closed");
      return;
    }
    for (const message of pending.splice(0)) upstream.send(message);
  });
  upstream.addEventListener("message", (event) => {
    if (!downstreamClosed && server.readyState === WebSocket.OPEN) {
      try {
        server.send(event.data);
      } catch {}
    }
  });
  upstream.addEventListener("close", (event) => {
    clearTimeout(closeForExpiry);
    const closeCode = forwardableCloseCode(event.code, 1011);
    const reason = closeCode === event.code ? "Upstream closed" : "Upstream closed unexpectedly";
    closeWebSocket(server, closeCode, reason);
  });
  upstream.addEventListener("error", (event) => {
    event.preventDefault();
    clearTimeout(closeForExpiry);
    closeWebSocket(server, 1011, "Upstream unavailable");
  });
  server.addEventListener("close", (event) => {
    downstreamClosed = true;
    pending.length = 0;
    clearTimeout(closeForExpiry);
    const closeCode = forwardableCloseCode(event.code, 1001);
    if (upstream.readyState === WebSocket.OPEN) {
      upstream.close(closeCode, "Client closed");
    }
    closeWebSocket(server, closeCode, "Client closed");
  });
  server.addEventListener("error", (event) => {
    event.preventDefault();
    downstreamClosed = true;
    pending.length = 0;
    clearTimeout(closeForExpiry);
    if (upstream.readyState === WebSocket.OPEN) upstream.close(1001, "Client unavailable");
    closeWebSocket(server, 1011, "Client unavailable");
  });

  return new Response(null, {
    status: 101,
    headers: { "Sec-WebSocket-Protocol": "decibel" },
    webSocket: client,
  });
}

function closeWebSocket(socket: WebSocket, code: number, reason: string): void {
  if (socket.readyState === WebSocket.OPEN || socket.readyState === WebSocket.CLOSING) {
    socket.close(code, reason);
  }
}

async function authenticate(request: Request, env: Env): Promise<SessionClaims> {
  const value = request.headers.get("Authorization");
  if (!value?.startsWith("Bearer ")) throw new HttpError(401, "Session token required");
  return authenticateToken(value.slice(7), env);
}

async function authenticateToken(token: string, env: Env): Promise<SessionClaims> {
  let claims: SessionClaims;
  try {
    claims = await verifySessionToken(token, env.SESSION_SIGNING_KEY);
  } catch {
    throw new HttpError(401, "Invalid or expired session");
  }
  if (claims.network !== env.NETWORK) throw new HttpError(401, "Session network mismatch");
  const stored = await stateStub(env.SESSIONS, claims.jti).fetch("https://state/");
  if (!stored.ok) throw new HttpError(401, "Session is no longer active");
  const state = await stored.json<SessionClaims>();
  if (state.exp !== claims.exp || state.role !== claims.role || state.wallet !== claims.wallet ||
    state.subaccount !== claims.subaccount) {
    throw new HttpError(401, "Session state mismatch");
  }
  return claims;
}

function enforceAccountScope(endpoint: string, parameters: URLSearchParams, claims: SessionClaims): void {
  const expectedAccount = claims.subaccount ?? claims.wallet;
  if (endpoint === "delegations") {
    const requested = parameters.get("subaccount");
    if (!claims.subaccount || !requested || canonicalAddress(requested) !== claims.subaccount) {
      throw new HttpError(403, "Subaccount scope mismatch");
    }
    return;
  }
  if (endpoint === "points/amps" || endpoint === "points/amps/daily") {
    const owner = parameters.get("owner");
    if (!claims.wallet || !owner || canonicalAddress(owner) !== claims.wallet) {
      throw new HttpError(403, "Owner scope mismatch");
    }
    return;
  }
  const account = parameters.get("account");
  if (!expectedAccount || !account || canonicalAddress(account) !== expectedAccount) {
    throw new HttpError(403, "Account scope mismatch");
  }
}

async function enforceSessionRateLimit(claims: SessionClaims, env: Env): Promise<void> {
  if (env.NETWORK === "testnet") return;
  const limiter = claims.role === "anonymous" ? env.ANONYMOUS_RATE_LIMITER : env.AUTHENTICATED_RATE_LIMITER;
  const key = claims.role === "anonymous" ? claims.jti : `${claims.wallet}:${claims.subaccount ?? "primary"}`;
  const result = await limiter.limit({ key });
  if (!result.success) throw new HttpError(429, "Rate limit exceeded");
}

async function enforceIpBackstop(request: Request, env: Env): Promise<void> {
  const ip = request.headers.get("CF-Connecting-IP");
  if (!ip || ip === "127.0.0.1" || ip === "localhost") return;
  const result = await env.IP_BACKSTOP_RATE_LIMITER.limit({ key: ip });
  if (!result.success) throw new HttpError(429, "Rate limit exceeded");
}

function enforceOrigin(request: Request, env: Env): void {
  const origin = request.headers.get("Origin");
  if (origin && origin !== env.APP_ORIGIN) throw new HttpError(403, "Origin is not allowed");
}

async function decibelJson(
  env: Env,
  endpoint: string,
  parameters: Record<string, string>,
): Promise<unknown> {
  const url = new URL(`${env.DECIBEL_REST_ORIGIN.replace(/\/$/, "")}/api/v1/${endpoint}`);
  Object.entries(parameters).forEach(([key, value]) => url.searchParams.set(key, value));
  const response = await fetch(url, {
    headers: {
      Authorization: `Bearer ${env.DECIBEL_NODE_API_KEY}`,
      Origin: env.DECIBEL_ORIGIN,
    },
  });
  if (!response.ok) throw new HttpError(502, "Unable to verify Decibel account authorization");
  return response.json();
}

async function upstreamFetch(
  request: Request,
  url: URL,
  injectedHeaders: Record<string, string>,
  cacheScope: "public" | "private",
): Promise<Response> {
  const headers = new Headers();
  const contentType = request.headers.get("Content-Type");
  if (contentType) headers.set("Content-Type", contentType);
  Object.entries(injectedHeaders).forEach(([key, value]) => headers.set(key, value));
  const response = await fetch(url, {
    method: request.method,
    headers,
    body: request.method === "GET" || request.method === "HEAD" ? undefined : request.body,
    redirect: "manual",
  });
  const responseHeaders = new Headers();
  for (const [name, value] of response.headers.entries()) {
    const lower = name.toLowerCase();
    if (
      lower === "content-type" ||
      lower === "etag" ||
      lower === "last-modified" ||
      lower.startsWith("x-aptos-")
    ) {
      responseHeaders.set(name, value);
    }
  }
  responseHeaders.set("Cache-Control", cacheScope === "public" ? "public, max-age=5" : "no-store");
  return new Response(response.body, { status: response.status, headers: responseHeaders });
}


function stateStub(namespace: DurableObjectNamespace, name: string): DurableObjectStub {
  return namespace.get(namespace.idFromName(name));
}

function webSocketToken(protocolHeader: string | null): string {
  const protocols = protocolHeader?.split(",").map((value) => value.trim()).filter(Boolean) ?? [];
  if (protocols[0] !== "decibel" || !protocols[1]) throw new HttpError(401, "WebSocket session required");
  return protocols[1];
}

function itemsFrom(value: unknown, envelopeKey: string): Array<Record<string, unknown>> {
  if (Array.isArray(value)) return value.filter(isRecord);
  if (isRecord(value)) {
    const nested = value[envelopeKey] ?? value.items;
    if (Array.isArray(nested)) return nested.filter(isRecord);
  }
  return [];
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

async function readJson<T>(request: Request): Promise<T> {
  if (!request.headers.get("Content-Type")?.toLowerCase().startsWith("application/json")) {
    throw new HttpError(415, "Content-Type must be application/json");
  }
  try {
    return await request.json<T>();
  } catch {
    throw new HttpError(400, "Invalid JSON body");
  }
}

function corsResponse(env: Env, response: Response | null, status?: number): Response {
  const target = response ?? new Response(null, { status: status ?? 204 });
  const headers = new Headers(target.headers);
  headers.set("Access-Control-Allow-Origin", env.APP_ORIGIN);
  headers.set("Access-Control-Allow-Headers", "Authorization, Content-Type");
  headers.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  headers.set("Vary", "Origin");
  return new Response(target.body, { status: target.status, statusText: target.statusText, headers });
}

function errorResponse(error: unknown): Response {
  if (error instanceof HttpError) return jsonError(error.message, error.status);
  console.error("Internal request failure:", error);
  return jsonError("Internal request failure", 500);
}

function jsonError(message: string, status: number): Response {
  return Response.json({ error: message }, { status, headers: { "Cache-Control": "no-store" } });
}

function safeMessage(error: unknown): string {
  return error instanceof Error ? error.message : "Invalid request";
}

class HttpError extends Error {
  constructor(readonly status: number, message: string) {
    super(message);
  }
}
