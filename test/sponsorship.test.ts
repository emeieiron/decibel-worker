import { Deserializer, SimpleTransaction } from "@aptos-labs/ts-sdk";
import { afterEach, describe, expect, it, vi } from "vitest";
vi.mock("../src/state", () => ({ FlareState: class {} }));
import worker from "../src/index";
import { issueSessionToken } from "../src/security";
import type { Env } from "../src/types";
import { sponsoredFixture, DECIBEL_PACKAGE, USDC_METADATA } from "./sponsorshipFixture";

afterEach(() => vi.unstubAllGlobals());

async function fixture(key?: string) {
  const signed = sponsoredFixture({ functionName: "create_new_subaccount", arguments: [] });
  const now = Math.floor(Date.now() / 1000);
  const claims = { iat: now, exp: now + 3600, jti: "11".repeat(16), network: "testnet" as const,
    role: "owner" as const, wallet: signed.walletAddress };
  const signingKey = "test-session-key-with-more-than-thirty-two-bytes";
  const token = await issueSessionToken(claims, signingKey);
  let record: unknown;
  const stateFetch = vi.fn(async (_url: unknown, init?: RequestInit) => {
    if (init?.method === "POST") {
      if (record) return new Response(null, { status: 409 });
      record = JSON.parse(init.body as string); return new Response(null, { status: 201 });
    }
    if (init?.method === "PUT") {
      record = JSON.parse(init.body as string); return new Response(null);
    }
    if (init?.method === "DELETE") { record = undefined; return new Response(null); }
    return record ? Response.json(record) : new Response(null, { status: 404 });
  });
  const namespace = (fetch: unknown) => ({ idFromName: (name: string) => name, get: () => ({ fetch }) });
  const limiter = { limit: async () => ({ success: true }) };
  const env = {
    NETWORK: "testnet", APP_ORIGIN: "flare://mobile", SESSION_SIGNING_KEY: signingKey,
    DECIBEL_PACKAGE_ADDRESS: DECIBEL_PACKAGE, USDC_METADATA_ADDRESS: USDC_METADATA,
    GAS_STATION_ORIGIN: "https://api.testnet.aptoslabs.com/gs/v1", GAS_STATION_API_KEY: key,
    SESSIONS: namespace(async () => Response.json(claims)), SPONSORSHIPS: namespace(stateFetch),
    AUTHENTICATED_RATE_LIMITER: limiter, IP_BACKSTOP_RATE_LIMITER: limiter,
  } as unknown as Env;
  const send = () => worker.fetch(new Request("https://worker/gas/sponsor/owner", {
    method: "POST", headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    body: JSON.stringify(signed.request),
  }), env);
  return { send, stateFetch, env };
}

describe("sponsorship submission outcomes", () => {
  it.each([undefined, "", "  "])("rejects an absent key without submitting (%s)", async key => {
    const upstream = vi.fn(); vi.stubGlobal("fetch", upstream);
    const f = await fixture(key); const response = await f.send();
    expect(response.status).toBe(503);
    expect(await response.json()).toMatchObject({ code: "gas_station_not_configured" });
    expect(f.stateFetch.mock.calls.map(c => c[1]?.method)).toEqual(["POST", "DELETE"]); expect(upstream).not.toHaveBeenCalled();
  });
  it("distinguishes rejected sponsor credentials from wallet-session authentication", async () => {
    const upstream = vi.fn(async () => new Response("private upstream diagnostic", { status: 401 }));
    vi.stubGlobal("fetch", upstream);
    const f = await fixture("test-only-key"); const response = await f.send();
    expect(response.status).toBe(503);
    const body = await response.text(); expect(body).toContain("gas_station_credentials_rejected");
    expect(body).not.toContain("private upstream diagnostic");
    expect(f.stateFetch.mock.calls.map(c => c[1]?.method)).toEqual(["POST", "DELETE"]);
    expect(upstream).toHaveBeenCalledOnce();
  });
  it("keeps an uncertain upstream failure reserved and refuses to resubmit", async () => {
    const upstream = vi.fn(async () => { throw new Error("connection lost"); }); vi.stubGlobal("fetch", upstream);
    const f = await fixture("test-only-key");
    expect((await f.send()).status).toBe(502);
    expect((await f.send()).status).toBe(409);
    expect(upstream).toHaveBeenCalledOnce();
    expect(f.stateFetch.mock.calls.some(c => c[1]?.method === "DELETE")).toBe(false);
  });
  it("journals successful sponsorship and returns the same hash without resubmitting", async () => {
    const hash = "0x" + "22".repeat(32);
    const upstream = vi.fn(async (url: URL, init: RequestInit) => {
      expect(url.toString()).toBe("https://api.testnet.aptoslabs.com/gs/v1/api/transaction/signAndSubmit");
      expect(new Headers(init.headers).get("Authorization")).toBe("Bearer test-only-key");
      const body = JSON.parse(init.body as string);
      const transaction = SimpleTransaction.deserialize(new Deserializer(Uint8Array.from(body.transactionBytes)));
      expect(transaction.feePayerAddress?.toStringLong()).toBe("0x" + "00".repeat(32));
      expect(transaction.rawTransaction.payload).toBeDefined();
      expect(Array.from(transaction.bcsToBytes())).toEqual(body.transactionBytes);
      return Response.json({ transactionHash: hash });
    }); vi.stubGlobal("fetch", upstream);
    const f = await fixture("test-only-key");
    expect(await (await f.send()).json()).toEqual({ transactionHash: hash });
    // Removing credentials cannot turn an already submitted request into a safe retry.
    f.env.GAS_STATION_API_KEY = undefined;
    expect(await (await f.send()).json()).toEqual({ transactionHash: hash });
    expect(upstream).toHaveBeenCalledOnce();
  });
});
