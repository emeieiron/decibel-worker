import { afterEach, describe, expect, it, vi } from "vitest";
import { handleReferral } from "../src/referrals";
import type { Env, SessionClaims } from "../src/types";

afterEach(() => vi.unstubAllGlobals());

const wallet = `0x${"0".repeat(60)}1234`;
const subaccount = `0x${"0".repeat(60)}5678`;
const otherSubaccount = `0x${"0".repeat(60)}9876`;
const code = "OC9E6E";
const owner: SessionClaims = {
  role: "owner",
  wallet,
  jti: "owner",
  exp: 9999999999,
  iat: 1,
  network: "mainnet",
};

function account(address: string, primary = wallet) {
  return {
    subaccount_address: address,
    primary_account_address: primary,
    is_primary: address === primary,
    is_active: true,
  };
}

function binding(referralCode = code, accountAddress = wallet) {
  return {
    account: accountAddress,
    referral_code: referralCode,
    referrer_account: otherSubaccount,
    is_active: true,
  };
}

function setup(options: {
  enabled?: string;
  suggestedCode?: string;
  claims?: SessionClaims;
  accounts?: unknown;
  validation?: unknown;
  binding?: unknown;
  histories?: unknown;
  redeem?: (input: RequestInfo | URL, init?: RequestInit) => Response | Promise<Response>;
} = {}) {
  let record: unknown;
  const state = vi.fn(async (_url: unknown, init?: RequestInit) => {
    if (init?.method === "POST") {
      if (record) return new Response(null, { status: 409 });
      record = JSON.parse(init.body as string);
      return new Response(null, { status: 201 });
    }
    if (init?.method === "PUT") {
      record = JSON.parse(init.body as string);
      return new Response(null, { status: 204 });
    }
    if (init?.method === "DELETE") {
      record = undefined;
      return Response.json({});
    }
    return record ? Response.json(record) : new Response(null, { status: 404 });
  });
  const namespace = {
    idFromName: (id: string) => id,
    get: () => ({ fetch: state }),
  } as unknown as DurableObjectNamespace;
  const env = {
    REFERRALS_ENABLED: options.enabled ?? "true",
    DEFAULT_REFERRAL_CODE: options.suggestedCode ?? code,
    DECIBEL_REST_ORIGIN: "https://decibel.test",
    DECIBEL_NODE_API_KEY: "secret",
    DECIBEL_ORIGIN: "flare://mobile",
    SPONSORSHIPS: namespace,
  } as unknown as Env;

  const upstream = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(String(input));
    if (init?.signal === undefined || init.redirect !== "manual") {
      throw new Error("upstream request missing bounded redirect-safe options");
    }
    if (url.pathname.endsWith(`/referrals/account/${wallet}`)) {
      return options.binding === undefined
        ? new Response(null, { status: 404 })
        : Response.json(options.binding);
    }
    if (url.pathname.endsWith(`/referrals/code/${code}`)) {
      return Response.json(options.validation ?? {
        referral_code: code,
        is_valid: true,
        is_active: true,
      });
    }
    if (url.pathname.endsWith("/subaccounts")) {
      return Response.json(options.accounts ?? [account(subaccount)]);
    }
    if (url.pathname.endsWith("/account_fund_history") || url.pathname.endsWith("/trade_history")) {
      return Response.json(options.histories ?? []);
    }
    if (url.pathname.endsWith("/referrals/redeem")) {
      if (options.redeem) return options.redeem(input, init);
      return Response.json({ account: wallet, referral_code: code });
    }
    return new Response(null, { status: 404 });
  });
  const authenticate = vi.fn(async () => options.claims ?? owner);
  const rateLimit = vi.fn(async () => {});
  const run = (path: string, method = "GET", body?: unknown) => handleReferral(
    new Request(`https://worker${path}`, {
      method,
      headers: body ? { "Content-Type": "application/json" } : {},
      body: body ? JSON.stringify(body) : undefined,
    }),
    env,
    { authenticate, rateLimit, fetch: upstream },
  );
  return { run, env, upstream, authenticate, rateLimit, state };
}

describe("referral routes", () => {
  it("uses configuration for the suggested code and hides it when disabled", async () => {
    const enabled = setup({ suggestedCode: "NEWCODE" });
    expect(await (await enabled.run("/referrals/config"))!.json()).toEqual({
      enabled: true,
      suggested_code: "NEWCODE",
    });
    const disabled = setup({ enabled: "false", suggestedCode: "NEWCODE" });
    expect(await (await disabled.run("/referrals/config"))!.json()).toEqual({ enabled: false });
    await expect(disabled.run("/referrals/redeem", "POST", { code })).rejects.toThrow("Referrals are disabled");
    expect(disabled.upstream).not.toHaveBeenCalled();
  });

  it("returns disabled status without upstream reads when no local intent exists", async () => {
    const fixture = setup({ enabled: "false" });
    const response = await fixture.run("/referrals/status") as Response;
    expect(await response.json()).toEqual({ account: wallet, status: "ineligible" });
    expect(fixture.upstream).not.toHaveBeenCalled();
  });

  it("requires a valid Flare session before public code validation", async () => {
    const fixture = setup();
    fixture.authenticate.mockRejectedValue(new Error("unauthenticated"));
    await expect(fixture.run(`/referrals/code/${code}`)).rejects.toThrow("unauthenticated");
    expect(fixture.upstream).not.toHaveBeenCalled();
  });

  it("normalizes only the documented code validation DTO", async () => {
    const fixture = setup({
      validation: { referral_code: code, is_valid: false, is_active: false, extra: "discard" },
    });
    const response = await fixture.run(`/referrals/code/${code}`) as Response;
    expect(await response.json()).toEqual({ referral_code: code, is_valid: false, is_active: false });
    expect(response.headers.get("Cache-Control")).toBe("no-store");
  });

  it("distinguishes unavailable and malformed validation responses from invalid codes", async () => {
    const unavailable = setup();
    unavailable.upstream.mockImplementation(async input => {
      if (new URL(String(input)).pathname.endsWith(`/referrals/code/${code}`)) {
        return new Response("upstream down", { status: 503 });
      }
      return new Response(null, { status: 404 });
    });
    await expect(unavailable.run(`/referrals/code/${code}`)).rejects.toThrow("Referral service unavailable");

    const malformed = setup({ validation: { referral_code: code, is_valid: "false", is_active: true } });
    await expect(malformed.run(`/referrals/code/${code}`)).rejects.toThrow("Malformed referral validation response");
  });

  it("rejects non-owner sessions and caller-selected account fields", async () => {
    const api: SessionClaims = { ...owner, role: "api" };
    const fixture = setup({ claims: api });
    await expect(fixture.run("/referrals/redeem", "POST", { code, account: otherSubaccount }))
      .rejects.toThrow("Owner session required");
    expect(fixture.upstream).not.toHaveBeenCalled();
  });

  it("uses official subaccount fields and omits history reads for no accounts", async () => {
    const fixture = setup({ accounts: { subaccounts: [] } });
    const response = await fixture.run("/referrals/redeem", "POST", { code: ` ${code} ` }) as Response;
    expect(response.status).toBe(200);
    const post = fixture.upstream.mock.calls.find(call => new URL(String(call[0])).pathname.endsWith("/referrals/redeem"));
    expect(JSON.parse(post![1]!.body as string)).toEqual({ account: wallet, referral_code: code });
    expect(fixture.upstream.mock.calls.some(call => /account_fund_history|trade_history/.test(String(call[0])))).toBe(false);
  });

  it("fails closed on an official subaccount whose primary account does not match", async () => {
    const fixture = setup({ accounts: [account(subaccount, otherSubaccount)] });
    await expect(fixture.run("/referrals/redeem", "POST", { code })).rejects.toThrow("Owned account owner mismatch");
    expect(fixture.upstream.mock.calls.some(call => new URL(String(call[0])).pathname.endsWith("/referrals/redeem"))).toBe(false);
  });

  it("journals before submission and sends only account plus referral_code", async () => {
    const fixture = setup();
    const response = await fixture.run("/referrals/redeem", "POST", { code }) as Response;
    expect(response.status).toBe(200);
    const post = fixture.upstream.mock.calls.find(call => new URL(String(call[0])).pathname.endsWith("/referrals/redeem"));
    expect(JSON.parse(post![1]!.body as string)).toEqual({ account: wallet, referral_code: code });
    expect(fixture.state.mock.calls.some(call => call[1]?.method === "POST")).toBe(true);
  });

  it("keeps 408 submission outcomes pending and does not retry them", async () => {
    const fixture = setup({ redeem: () => new Response("timeout", { status: 408 }) });
    const first = await fixture.run("/referrals/redeem", "POST", { code }) as Response;
    const second = await fixture.run("/referrals/redeem", "POST", { code }) as Response;
    expect(first.status).toBe(202);
    expect(second.status).toBe(202);
    expect(fixture.upstream.mock.calls.filter(call => new URL(String(call[0])).pathname.endsWith("/referrals/redeem"))).toHaveLength(1);
  });

  it("keeps a pending intent pending when an unrelated new subaccount appears", async () => {
    const fixture = setup({ redeem: () => new Response("unknown", { status: 502 }) });
    const first = await fixture.run("/referrals/redeem", "POST", { code }) as Response;
    expect(first.status).toBe(202);
    fixture.upstream.mockImplementation(async (input, init) => {
      const url = new URL(String(input));
      if (init?.signal === undefined || init.redirect !== "manual") throw new Error("missing fetch policy");
      if (url.pathname.endsWith(`/referrals/account/${wallet}`)) return new Response(null, { status: 404 });
      if (url.pathname.endsWith("/subaccounts")) {
        return Response.json({ items: [account(subaccount), account(otherSubaccount)] });
      }
      if (url.pathname.endsWith("/account_fund_history") || url.pathname.endsWith("/trade_history")) return Response.json([]);
      return new Response(null, { status: 404 });
    });
    const status = await fixture.run("/referrals/status") as Response;
    expect(await status.json()).toMatchObject({ account: wallet, status: "pending", referral_code: code, trading_account: otherSubaccount });
  });

  it("confirms attribution only from a matching live binding and verifies cached trading accounts", async () => {
    const fixture = setup({ binding: binding() });
    const response = await fixture.run("/referrals/status") as Response;
    expect(await response.json()).toEqual({ account: wallet, status: "bound", referral_code: code });

    const invalidCachedAccount = setup();
    const stored = invalidCachedAccount.state;
    stored.mockImplementationOnce(async () => Response.json({
      wallet,
      code,
      status: "bound",
      tradingAccount: otherSubaccount,
      priorAccounts: [subaccount],
      expiresAt: Date.now() + 60_000,
    }));
    const cached = await invalidCachedAccount.run("/referrals/status") as Response;
    const cachedBody = await cached.json();
    expect(cachedBody).toMatchObject({ status: "bound", referral_code: code });
    expect(cachedBody).not.toHaveProperty("trading_account");
  });

  it("prefers a different live binding over stale local attribution", async () => {
    const fixture = setup({ binding: binding("OTHER") });
    const localRecord = fixture.state;
    localRecord.mockImplementationOnce(async () => Response.json({
      wallet,
      code,
      status: "bound",
      priorAccounts: [subaccount],
      expiresAt: Date.now() + 60_000,
    }));
    const response = await fixture.run("/referrals/status") as Response;
    expect(await response.json()).toEqual({ account: wallet, status: "bound", referral_code: "OTHER" });
  });

  it("accepts matching binding on a redemption conflict", async () => {
    const fixture = setup({ redeem: () => new Response(null, { status: 409 }) });
    let bindingReads = 0;
    fixture.upstream.mockImplementation(async (input, init) => {
      const url = new URL(String(input));
      if (init?.signal === undefined || init.redirect !== "manual") throw new Error("missing fetch policy");
      if (url.pathname.endsWith(`/referrals/account/${wallet}`)) {
        bindingReads++;
        return bindingReads === 1 ? new Response(null, { status: 404 }) : Response.json(binding());
      }
      if (url.pathname.endsWith(`/referrals/code/${code}`)) {
        return Response.json({ referral_code: code, is_valid: true, is_active: true });
      }
      if (url.pathname.endsWith("/subaccounts")) return Response.json([account(subaccount)]);
      if (url.pathname.endsWith("/account_fund_history") || url.pathname.endsWith("/trade_history")) return Response.json([]);
      if (url.pathname.endsWith("/referrals/redeem")) return new Response(null, { status: 409 });
      return new Response(null, { status: 404 });
    });
    const response = await fixture.run("/referrals/redeem", "POST", { code }) as Response;
    expect(response.status).toBe(200);
    expect(await response.json()).toMatchObject({ status: "bound", referral_code: code });
  });

  it("makes only one upstream redemption for concurrent same-owner requests", async () => {
    const fixture = setup();
    await Promise.all([
      fixture.run("/referrals/redeem", "POST", { code }),
      fixture.run("/referrals/redeem", "POST", { code }),
    ]);
    expect(fixture.upstream.mock.calls.filter(call => new URL(String(call[0])).pathname.endsWith("/referrals/redeem"))).toHaveLength(1);
  });
});
