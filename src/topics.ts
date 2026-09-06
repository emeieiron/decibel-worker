import { canonicalAddress } from "./security";
import type { SessionClaims } from "./types";

const PUBLIC_TOPICS = new Set(["all_market_prices", "all_spot_mids"]);
const ACCOUNT_TOPIC_NAMES = new Set([
  "account_open_orders",
  "account_overview",
  "account_positions",
  "bulk_order_fills",
  "bulk_orders",
  "notifications",
  "order_updates",
  "protected_trial_update",
  "user_active_twaps",
  "user_trades",
  "withdraw_queue",
]);
const DEPTH_LEVELS = new Set(["1", "2", "5", "10", "100", "1000"]);
const CANDLE_INTERVALS = new Set([
  "1m",
  "5m",
  "15m",
  "30m",
  "1h",
  "2h",
  "4h",
  "1d",
  "1w",
  "1mo",
]);

export function validateTopic(topic: string, claims: SessionClaims): void {
  if (PUBLIC_TOPICS.has(topic)) return;
  const parts = topic.split(":");
  const name = parts[0];

  if (name === "depth") {
    if (parts.length < 2 || parts.length > 3) throw new Error("Invalid market topic");
    canonicalAddress(parts[1]);
    if (parts[2] && !DEPTH_LEVELS.has(parts[2])) {
      throw new Error("Invalid depth aggregation level");
    }
    return;
  }
  if (name === "market_candlestick") {
    if (parts.length !== 3) throw new Error("Invalid candlestick topic");
    canonicalAddress(parts[1]);
    if (!CANDLE_INTERVALS.has(parts[2])) throw new Error("Invalid candlestick interval");
    return;
  }
  if (name === "market_price" || name === "trades") {
    if (parts.length !== 2) throw new Error("Invalid market topic");
    canonicalAddress(parts[1]);
    return;
  }

  if (!ACCOUNT_TOPIC_NAMES.has(name) || parts.length !== 2) {
    throw new Error("Topic is not allowlisted");
  }
  if (claims.role === "anonymous") throw new Error("Wallet session required for account topics");
  const address = canonicalAddress(parts[1]);
  const expected = claims.subaccount ?? claims.wallet;
  if (!expected || address !== expected) throw new Error("Account topic is outside the session scope");
}
