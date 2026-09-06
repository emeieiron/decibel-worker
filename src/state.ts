import { DurableObject } from "cloudflare:workers";
import type { Env } from "./types";

const RECORD_KEY = "record";

/** A one-record, expiring object used for nonce, session, and sponsorship state. */
export class FlareState extends DurableObject<Env> {
  async fetch(request: Request): Promise<Response> {
    if (request.method === "GET") {
      const record = await this.ctx.storage.get(RECORD_KEY);
      return record === undefined ? new Response(null, { status: 404 }) : Response.json(record);
    }

    if (request.method === "POST") {
      const record = (await request.json()) as { expiresAt?: number; exp?: number };
      const expiresAt = record.expiresAt ?? (record.exp ? record.exp * 1_000 : undefined);
      if (!expiresAt || expiresAt <= Date.now()) return new Response(null, { status: 400 });
      const created = await this.ctx.storage.transaction(async (transaction) => {
        const current = await transaction.get(RECORD_KEY);
        if (current !== undefined) return false;
        await transaction.put(RECORD_KEY, record);
        return true;
      });
      if (!created) return new Response(null, { status: 409 });
      await this.ctx.storage.setAlarm(expiresAt);
      return new Response(null, { status: 201 });
    }

    if (request.method === "PUT") {
      const record = (await request.json()) as { expiresAt?: number; exp?: number };
      const expiresAt = record.expiresAt ?? (record.exp ? record.exp * 1_000 : undefined);
      if (!expiresAt || expiresAt <= Date.now()) return new Response(null, { status: 400 });
      await this.ctx.storage.put(RECORD_KEY, record);
      await this.ctx.storage.setAlarm(expiresAt);
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
    await this.ctx.storage.deleteAll();
  }
}
