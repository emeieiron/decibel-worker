import { afterEach, describe, expect, it, vi } from "vitest";
vi.mock("../src/state", () => ({ FlareState: class {} }));
import worker from "../src/index";
import { issueSessionToken } from "../src/security";
import type { Env, SessionRole } from "../src/types";

afterEach(() => vi.unstubAllGlobals());
const endpoint = "https://worker/gas/sponsor/trading-availability";

async function fixture(role: SessionRole = "anonymous") {
  const now = Math.floor(Date.now() / 1000);
  const secret = crypto.randomUUID() + crypto.randomUUID();
  const claims = { iat: now, exp: now + 3600, jti: "22".repeat(16), network: "mainnet" as const,
    role, ...(role === "anonymous" ? {} : { wallet: "0x" + "01".repeat(32), subaccount: "0x" + "02".repeat(32) }) };
  const token = await issueSessionToken(claims, secret);
  const limiter = { limit: vi.fn(async () => ({ success: true })) };
  const env = {
    NETWORK: "mainnet", APP_ORIGIN: "flare://mobile", SESSION_SIGNING_KEY: secret,
    TRADING_SPONSORSHIP_ENABLED: "true", GAS_STATION_API_KEY: "test-only-key",
    SESSIONS: { idFromName: (name: string) => name, get: () => ({ fetch: async () => Response.json(claims) }) },
    AUTHENTICATED_RATE_LIMITER: limiter, ANONYMOUS_RATE_LIMITER: limiter, IP_BACKSTOP_RATE_LIMITER: limiter,
  } as unknown as Env;
  const send = (method = "GET", authenticated = true) => worker.fetch(new Request(endpoint, {
    method, headers: authenticated ? { Authorization: `Bearer ${token}` } : {},
  }), env);
  return { env, send, limiter, claims };
}

describe("unsigned trading sponsorship availability", () => {
  it.each(["anonymous", "owner", "api"] as const)("allows and meters a valid %s session without upstream access", async role => {
    const f = await fixture(role);
    const upstream = vi.fn(); vi.stubGlobal("fetch", upstream);
    const response = await f.send();
    expect(response.status).toBe(200);
    expect(response.headers.get("Cache-Control")).toBe("no-store");
    expect(await response.json()).toEqual({ available: true });
    expect(f.limiter.limit).toHaveBeenCalledWith({ key: role === "anonymous" ? f.claims.jti : `${f.claims.wallet}:${f.claims.subaccount}` });
    expect(upstream).not.toHaveBeenCalled();
  });

  it.each([
    { enabled: undefined, key: "test", available: false },
    { enabled: "false", key: "test", available: false },
    { enabled: "TRUE", key: "test", available: false },
    { enabled: "true", key: undefined, available: false },
    { enabled: "true", key: " ", available: false },
    { enabled: "true", key: "test", available: true },
  ])("checks explicit policy and configured key: $enabled / $available", async ({ enabled, key, available }) => {
    const f = await fixture();
    f.env.TRADING_SPONSORSHIP_ENABLED = enabled;
    f.env.GAS_STATION_API_KEY = key;
    expect(await (await f.send()).json()).toEqual({ available });
  });

  it.each(["POST", "PUT", "DELETE", "HEAD"])("rejects %s without changing state", async method => {
    const f = await fixture();
    expect((await f.send(method)).status).toBe(405);
    expect(f.limiter.limit).not.toHaveBeenCalled();
  });

  it("requires authentication", async () => {
    const f = await fixture();
    expect((await f.send("GET", false)).status).toBe(401);
  });

  it("rejects a session over its rate limit", async () => {
    const f = await fixture("api");
    f.limiter.limit.mockResolvedValue({ success: false });
    expect((await f.send()).status).toBe(429);
  });
});
