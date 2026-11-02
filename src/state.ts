import { DurableObject } from "cloudflare:workers";
import type { Env } from "./types";

const RECORD_KEY = "record";

// Only referral recovery records may outlive an expiry. Nonces, sessions and gas
// sponsorships retain their existing mandatory expiration.
function persistentReferral(record: unknown): record is { wallet: string; code: string; status: "pending" | "bound" } {
  if (typeof record !== "object" || record === null) return false;
  const value = record as Record<string, unknown>;
  const address = (item: unknown) => typeof item === "string" && /^0x[0-9a-fA-F]{1,64}$/.test(item);
  return value.kind === "referral-intent" && address(value.wallet) &&
    typeof value.code === "string" && /^[A-Za-z0-9_-]{1,128}$/.test(value.code) &&
    (value.status === "pending" || value.status === "bound") &&
    Array.isArray(value.priorAccounts) && value.priorAccounts.every(address) &&
    (value.tradingAccount === undefined || address(value.tradingAccount));
}

/** One-record state: expiring credentials/sponsorships and persistent referral recovery. */
export class FlareState extends DurableObject<Env> {
  async fetch(request: Request): Promise<Response> {
    if (request.method === "GET") {
      const record = await this.ctx.storage.get(RECORD_KEY);
      return record === undefined ? new Response(null, { status: 404 }) : Response.json(record);
    }

    if (request.method === "POST") {
      const record = (await request.json()) as { expiresAt?: number; exp?: number };
      const expiresAt = record.expiresAt ?? (record.exp ? record.exp * 1_000 : undefined);
      const persistent = persistentReferral(record);
      if (!persistent && (!expiresAt || expiresAt <= Date.now())) return new Response(null, { status: 400 });
      const created = await this.ctx.storage.transaction(async (transaction) => {
        const current = await transaction.get(RECORD_KEY);
        if (current !== undefined) return false;
        await transaction.put(RECORD_KEY, record);
        return true;
      });
      if (!created) return new Response(null, { status: 409 });
      if (persistent) await this.ctx.storage.deleteAlarm();
      else await this.ctx.storage.setAlarm(expiresAt!);
      return new Response(null, { status: 201 });
    }

    if (request.method === "PUT") {
      const record = (await request.json()) as { expiresAt?: number; exp?: number };
      const expiresAt = record.expiresAt ?? (record.exp ? record.exp * 1_000 : undefined);
      const persistent = persistentReferral(record);
      if (!persistent && (!expiresAt || expiresAt <= Date.now())) return new Response(null, { status: 400 });
      if (persistentReferral(record)) {
        const { wallet, code, status } = record;
        const updated = await this.ctx.storage.transaction(async (transaction) => {
          const current = await transaction.get(RECORD_KEY);
          if (persistentReferral(current)) {
            if (current.wallet !== wallet || current.code !== code) return false;
            // A delayed legacy upgrade must not overwrite a concurrent confirmation.
            if (current.status === "bound" && status === "pending") return true;
          }
          await transaction.put(RECORD_KEY, record);
          return true;
        });
        if (!updated) return new Response(null, { status: 409 });
      } else {
        await this.ctx.storage.put(RECORD_KEY, record);
      }
      if (persistent) await this.ctx.storage.deleteAlarm();
      else await this.ctx.storage.setAlarm(expiresAt!);
      return new Response(null, { status: 204 });
    }

    if (request.method === "DELETE") {
      const record = await this.ctx.storage.transaction(async (transaction) => {
        const value = await transaction.get(RECORD_KEY);
        if (value !== undefined) await transaction.delete(RECORD_KEY);
        return value;
      });
      return record === undefined ? new Response(null, { status: 404 }) : Response.json(record);
    }

    return new Response(null, { status: 405 });
  }

  async alarm(): Promise<void> {
    // An already queued legacy alarm can still run after deleteAlarm().
    if (persistentReferral(await this.ctx.storage.get(RECORD_KEY))) return;
    await this.ctx.storage.deleteAll();
  }
}
