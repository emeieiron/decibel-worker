import { afterEach, describe, expect, it, vi } from "vitest";
vi.mock("../src/state", () => ({ FlareState: class {} }));
import worker from "../src/index";
import { issueSessionToken } from "../src/security";
import type { Env } from "../src/types";
import { Account, AccountAddress, AccountAuthenticatorEd25519, ChainId, FeePayerRawTransaction, generateSigningMessage, RawTransaction } from "@aptos-labs/ts-sdk";
import fixture from "./fixtures/panora.json";
import exactInputFixture from "./fixtures/panora-exact-input.json";
import { authorizeGasStationRequest } from "../src/gasStation";
import { issueSwapAuthorization, limitedQuoteText, PANORA_ROUTER, parseSwapRequest, panoraUrl, SwapProviderHealth, validatePanoraQuote, verifySwapAuthorization, type SwapAuthorization } from "../src/swaps";
import { canonicalAddress } from "../src/security";

afterEach(() => vi.unstubAllGlobals());

const owner = canonicalAddress("0x1");
const request = parseSwapRequest({ owner, kind: "EXACT_OUTPUT", amount: "10000000", slippageBps: 50 }, owner);
// Tests use an ephemeral HMAC key, never a deployment credential.
const secret = crypto.randomUUID() + crypto.randomUUID();
const copy = () => structuredClone(fixture);

describe("Panora quote policy", () => {
  it("encodes exact-input quotes without increasing the input budget", () => {
    const quote = validatePanoraQuote(exactInputFixture, { ...request, kind: "EXACT_INPUT", amount: "100000000" });
    expect(quote.payloadHash).toBe("0x07417876b9b078fff00d1f421d707ebfa3093d2500b8be0c38d4f292d43935d0");
  });
  it("bounds provider response sizes and backs off after repeated transport failures", async () => {
    await expect(limitedQuoteText(new Response("x".repeat(131073)))).rejects.toThrow();
    const health = new SwapProviderHealth();
    health.failed(0); health.failed(0);
    expect(health.available(0)).toBe(true);
    health.failed(0);
    expect(health.available(29999)).toBe(false);
    expect(health.available(30000)).toBe(true);
    health.failed(30000); health.succeeded();
    expect(health.available(30000)).toBe(true);
  });
  it("encodes the captured mainnet payload with the Aptos SDK", () => {
    const quote = validatePanoraQuote(copy(), request);
    expect(quote.payloadHash).toBe("0x4c24cc8066461391f206e5cbbb186a89def796dab3dda73d6993452a02d63c98");
    expect(quote.response).not.toHaveProperty("rawTransaction");
    const url = panoraUrl(request);
    expect(url.searchParams.get("toTokenAmount")).toBe("10.000000");
    expect(url.searchParams.get("slippagePercentage")).toBe("0.50");
    expect(url.searchParams.get("integratorFeePercentage")).toBe("0");
    expect(url.searchParams.get("onlyDirectRoutes")).toBe("true");
  });

  it("rejects changed recipients, withdrawal assets, protections and fees", () => {
    const cases: ((value: ReturnType<typeof copy>) => void)[] = [
      q => { q.quotes[0].txData.function = PANORA_ROUTER.replace("router_entry", "router"); },
      q => { q.quotes[0].txData.arguments[1] = "0x2"; },
      q => { q.quotes[0].txData.arguments[15] = "0xa"; },
      q => { q.quotes[0].txData.arguments[16] = ["1"]; },
      q => { q.quotes[0].txData.arguments[17] = 1; },
      q => { q.quotes[0].txData.arguments[18] = "9999999999999999"; },
      q => { q.quotes[0].txData.arguments[8] = [[3]]; },
      q => { q.quotes[0].feeTokenAmount = "0.01"; },
      q => { q.toToken.address = "0x2"; },
      q => { q.quotes[0].slippagePercentage = "5"; },
      q => { q.quotes[0].maxFromTokenAmount = "100"; },
      q => { q.quotes[0].txData.type_arguments[0] = "0x1::aptos_coin::AptosCoin"; },
    ];
    for (const mutate of cases) { const value = copy(); mutate(value); expect(() => validatePanoraQuote(value, request)).toThrow(); }
  });

  it("keeps amount strings exact and rejects invalid request limits", () => {
    expect(panoraUrl({ ...request, amount: "18446744073709551615" }).searchParams.get("toTokenAmount"))
      .toBe("18446744073709.551615");
    for (const amount of ["0", "01", "1e6", "1.1", "18446744073709551616"]) {
      expect(() => parseSwapRequest({ ...request, amount }, owner)).toThrow();
    }
    expect(() => parseSwapRequest({ ...request, owner: "0x2" }, owner)).toThrow();
    expect(() => parseSwapRequest({ ...request, slippageBps: 101 }, owner)).toThrow();
  });
});

describe("swap sponsorship authorization", () => {
  it("binds authorization to wallet, expiry and a separate token purpose", async () => {
    const now = Date.now();
    const claims: SwapAuthorization = { purpose: "flare.swap.v1", id: crypto.randomUUID(), wallet: owner,
      expiresAtMs: now + 30000, payloadHash: validatePanoraQuote(copy(), request).payloadHash };
    const token = await issueSwapAuthorization(claims, secret);
    expect(await verifySwapAuthorization(token, secret, owner, now)).toEqual(claims);
    await expect(verifySwapAuthorization(token, secret, "0x2", now)).rejects.toThrow();
    await expect(verifySwapAuthorization(token, secret, owner, now + 30000)).rejects.toThrow();
    await expect(verifySwapAuthorization(token + "x", secret, owner, now)).rejects.toThrow();
    await expect(verifySwapAuthorization(token, "another-secret-with-at-least-32-bytes", owner, now)).rejects.toThrow();
  });

  it("sponsors only the quoted payload on the owner route", () => {
    const account = Account.generate();
    const wallet = canonicalAddress(account.accountAddress.toStringLong());
    const quote = copy(); quote.quotes[0].txData.arguments[1] = wallet;
    const validated = validatePanoraQuote(quote, { ...request, owner: wallet });
    const expiresAtMs = Date.now() + 30000;
    const raw = new RawTransaction(account.accountAddress, 0n, validated.payload, 50000n, 100n,
      BigInt(Math.floor(expiresAtMs / 1000)), new ChainId(1));
    const bytes = new FeePayerRawTransaction(raw, [], AccountAddress.ZERO).bcsToBytes();
    const auth = new AccountAuthenticatorEd25519(account.publicKey, account.sign(generateSigningMessage(bytes, "APTOS::RawTransactionWithData")));
    const body = { transactionBytes: [...bytes], senderAuth: [...auth.bcsToBytes()] };
    const policy = { walletAddress: wallet, ownerOnly: true, decibelPackageAddress: "0x2", usdcMetadataAddress: "0x3",
      swapAuthorization: { purpose: "flare.swap.v1" as const, id: crypto.randomUUID(), wallet, expiresAtMs, payloadHash: validated.payloadHash } };
    expect(() => authorizeGasStationRequest(body, policy)).not.toThrow();
    expect(() => authorizeGasStationRequest(body, { ...policy, ownerOnly: false })).toThrow();
    expect(() => authorizeGasStationRequest(body, { ...policy, swapAuthorization: undefined })).toThrow();
    expect(() => authorizeGasStationRequest(body, { ...policy, swapAuthorization: { ...policy.swapAuthorization, payloadHash: "0x" + "00".repeat(32) } })).toThrow();
    expect(() => authorizeGasStationRequest(body, { ...policy, swapAuthorization: { ...policy.swapAuthorization, expiresAtMs: Date.now() - 1 } })).toThrow();
  });
});


describe("swap quotes without sponsorship", () => {
  it("returns an authorized quote without a Gas Station key", async () => {
    const now = Math.floor(Date.now() / 1000);
    const claims = { iat: now, exp: now + 3600, jti: "22".repeat(16), network: "mainnet" as const,
      role: "owner" as const, wallet: owner };
    const token = await issueSessionToken(claims, secret);
    const limiter = { limit: async () => ({ success: true }) };
    const env = {
      NETWORK: "mainnet", APP_ORIGIN: "flare://mobile", SESSION_SIGNING_KEY: secret,
      SWAPS_ENABLED: "true", PANORA_API_KEY: "test-panora-key",
      SESSIONS: { idFromName: (name: string) => name, get: () => ({ fetch: async () => Response.json(claims) }) },
      AUTHENTICATED_RATE_LIMITER: limiter, IP_BACKSTOP_RATE_LIMITER: limiter,
      SESSION_CREATION_RATE_LIMITER: limiter,
    } as unknown as Env;
    const upstream = vi.fn(async (url: URL, init: RequestInit) => {
      expect(url.origin).toBe("https://api.panora.exchange");
      expect(init.method).toBe("POST");
      expect(new Headers(init.headers).get("x-api-key")).toBe("test-panora-key");
      return Response.json(copy());
    });
    vi.stubGlobal("fetch", upstream);
    const response = await worker.fetch(new Request("https://worker/swap/quote", {
      method: "POST", headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify(request),
    }), env);
    expect(response.status).toBe(200);
    const body = await response.json<{ authorization: string; payloadHash: string }>();
    expect(body.payloadHash).toBe(validatePanoraQuote(copy(), request).payloadHash);
    expect(await verifySwapAuthorization(body.authorization, secret, owner)).toMatchObject({ payloadHash: body.payloadHash });
    expect(upstream).toHaveBeenCalledOnce();
  });
});
