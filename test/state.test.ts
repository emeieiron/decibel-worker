import { describe, expect, it, vi } from "vitest";

vi.mock("cloudflare:workers", () => ({
  DurableObject: class {
    constructor(readonly ctx: unknown, readonly env: unknown) {}
  },
}));
import { FlareState } from "../src/state";
import type { Env } from "../src/types";

function fixture() {
  const records = new Map<string, unknown>();
  const storage = {
    get: vi.fn(async (key: string) => records.get(key)),
    put: vi.fn(async (key: string, value: unknown) => { records.set(key, value); }),
    delete: vi.fn(async (key: string) => records.delete(key)),
    deleteAll: vi.fn(async () => { records.clear(); }),
    setAlarm: vi.fn(async (_time: number) => {}),
    deleteAlarm: vi.fn(async () => {}),
    transaction: async (callback: (storage: unknown) => unknown) => callback(storage),
  };
  const state = new FlareState({ storage } as unknown as DurableObjectState, {} as Env);
  const write = (body: unknown, method = "POST") => state.fetch(new Request("https://state/", { method, body: JSON.stringify(body) }));
  return { state, storage, write };
}
const referral = { kind: "referral-intent", wallet: "0x1", code: "OC9E6E", status: "pending", priorAccounts: [] };

describe("referral journal retention", () => {
  it("retains explicitly scoped referral records when an old alarm executes", async () => {
    const f = fixture();
    expect((await f.write(referral)).status).toBe(201);
    await f.state.alarm();
    expect(f.storage.deleteAll).not.toHaveBeenCalled();
    expect(await (await f.state.fetch(new Request("https://state/"))).json()).toEqual(referral);
  });

  it("upgrading a legacy record cancels its alarm and survives an already queued alarm", async () => {
    const f = fixture();
    const expiresAt = Date.now() + 60_000;
    expect((await f.write({ wallet: "0x1", code: "OC9E6E", status: "pending", priorAccounts: [], expiresAt })).status).toBe(201);
    expect(f.storage.setAlarm).toHaveBeenCalledWith(expiresAt);
    expect((await f.write(referral, "PUT")).status).toBe(204);
    expect(f.storage.deleteAlarm).toHaveBeenCalled();
    await f.state.alarm();
    expect(f.storage.deleteAll).not.toHaveBeenCalled();
  });

  it("preserves confirmation when a delayed pending migration arrives after it", async () => {
    const f = fixture();
    expect((await f.write(referral)).status).toBe(201);
    const bound = { ...referral, status: "bound", tradingAccount: "0x2" };
    expect((await f.write(bound, "PUT")).status).toBe(204);
    expect((await f.write(referral, "PUT")).status).toBe(204);
    expect(await (await f.state.fetch(new Request("https://state/"))).json()).toEqual(bound);
    expect((await f.write({ ...referral, code: "DIFFERENT" }, "PUT")).status).toBe(409);
    expect((await f.write({ ...referral, wallet: "0x3" }, "PUT")).status).toBe(409);
    expect(await (await f.state.fetch(new Request("https://state/"))).json()).toEqual(bound);
  });

  it("still requires expiration for ordinary records and invalid referral markers", async () => {
    for (const record of [{ status: "pending" }, { ...referral, wallet: "invalid" }, { kind: "referral-intent" }]) {
      expect((await fixture().write(record)).status).toBe(400);
    }
    const f = fixture();
    expect((await f.write({ exp: Math.floor(Date.now() / 1000) + 60 })).status).toBe(201);
    await f.state.alarm();
    expect(f.storage.deleteAll).toHaveBeenCalledOnce();
  });
});
