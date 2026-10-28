import { afterEach, describe, expect, it, vi } from "vitest";
vi.mock("../src/state", () => ({ FlareState: class {} }));
import worker from "../src/index";
import { issueSessionToken } from "../src/security";
import type { Env, SessionRole } from "../src/types";

afterEach(() => vi.unstubAllGlobals());

describe("unsigned swap sponsorship availability", () => {
  it.each([
    { enabled: undefined, key: "test", available: false },
    { enabled: "false", key: "test", available: false },
    { enabled: "true", key: " ", available: false },
    { enabled: "true", key: "test", available: true },
  ])("checks deployment policy without contacting a submitter: $available", async ({ enabled, key, available }) => {
    const { env, token } = await fixture("owner");
    env.SWAP_SPONSORSHIP_ENABLED = enabled;
    env.GAS_STATION_API_KEY = key;
    const upstream = vi.fn();
    vi.stubGlobal("fetch", upstream);
    const response = await worker.fetch(new Request("https://worker/gas/sponsor/swap-availability", {
      headers: { Authorization: `Bearer ${token}` },
    }), env);
    expect(response.status).toBe(200);
    expect(response.headers.get("Cache-Control")).toBe("no-store");
    expect(await response.json()).toEqual({ available });
    expect(upstream).not.toHaveBeenCalled();
  });

  it.each(["anonymous", "api"] as const)("rejects %s sessions", async role => {
    const { env, token } = await fixture(role);
    const response = await worker.fetch(new Request("https://worker/gas/sponsor/swap-availability", {
      headers: { Authorization: `Bearer ${token}` },
    }), env);
    expect(response.status).toBe(403);
  });
});

async function fixture(role: SessionRole) {
  const now = Math.floor(Date.now() / 1000);
  const secret = crypto.randomUUID() + crypto.randomUUID();
  const claims = { iat: now, exp: now + 3600, jti: "22".repeat(16), network: "mainnet" as const,
    role, wallet: "0x" + "01".repeat(32), subaccount: "0x" + "02".repeat(32) };
  const token = await issueSessionToken(claims, secret);
  const limiter = { limit: async () => ({ success: true }) };
  const env = {
    NETWORK: "mainnet", APP_ORIGIN: "flare://mobile", SESSION_SIGNING_KEY: secret,
    SWAPS_ENABLED: "true",
    SESSIONS: { idFromName: (name: string) => name, get: () => ({ fetch: async () => Response.json(claims) }) },
    AUTHENTICATED_RATE_LIMITER: limiter, ANONYMOUS_RATE_LIMITER: limiter, IP_BACKSTOP_RATE_LIMITER: limiter,
  } as unknown as Env;
  return { env, token };
}
