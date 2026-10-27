import { AccountAddress, EntryFunction, EntryFunctionBytes, Deserializer, parseTypeTag, TransactionPayloadEntryFunction } from "@aptos-labs/ts-sdk";
import { sha3_256 } from "@noble/hashes/sha3.js";
import { canonicalAddress } from "./security";

export const PANORA_ROUTER = "0x1c3206329806286fd2223647c9f9b130e66baeb6d7224a18c1f642ffe48f3b4c::panora_swap::router_entry";
export const NATIVE_USDC = "0xbae207659db88bea0cbead6da0ed00aac12edcdda169e591cd41c94180b46f3b";
const APT = canonicalAddress("0xa");
const U64_MAX = (1n << 64n) - 1n;
const STRING_TAG = "0x1::string::String";
const TYPES = ["o:signer", "address", "u64", "u8", "v:u8", "v:v:v:u8", "v:v:v:u64", "v:v:v:bool", "v:v:u8", "v:v:v:address", "v:v:address", "v:v:address", "o:v:v:v:v:v:u8", "v:v:v:u64", "o:v:v:v:u8", "address", "v:u64", "u64", "u64", "address"];

export type SwapRequest = { owner: string; kind: "EXACT_INPUT" | "EXACT_OUTPUT"; amount: string; slippageBps: number };
export type SwapAuthorization = { purpose: "flare.swap.v1"; id: string; wallet: string; payloadHash: string; expiresAtMs: number };
export type ValidatedQuote = { response: Record<string, unknown>; payloadHash: string; payload: TransactionPayloadEntryFunction };

/** Per-isolate backoff limits repeated transport failures; owner/IP limits apply independently. */
export class SwapProviderHealth {
  private failures = 0;
  private blockedUntil = 0;
  available(now = Date.now()): boolean {
    if (now < this.blockedUntil) return false;
    if (this.blockedUntil) { this.blockedUntil = 0; this.failures = 0; }
    return true;
  }
  succeeded(): void { this.failures = 0; this.blockedUntil = 0; }
  failed(now = Date.now()): void { if (++this.failures >= 3) this.blockedUntil = now + 30000; }
}

export async function limitedQuoteText(response: Response): Promise<string> {
  if (!response.body) throw new Error("Missing quote response");
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let size = 0, result = "";
  try {
    while (true) {
      const chunk = await reader.read();
      if (chunk.done) return result + decoder.decode();
      size += chunk.value.byteLength;
      if (size > 131072) { await reader.cancel(); throw new Error("Swap quote too large"); }
      result += decoder.decode(chunk.value, { stream: true });
    }
  } finally { reader.releaseLock(); }
}

export function parseSwapRequest(value: unknown, owner: string): SwapRequest {
  const body = record(value);
  const wallet = canonicalAddress(text(body.owner));
  if (wallet !== canonicalAddress(owner)) throw new Error("Swap owner does not match the session");
  if (body.kind !== "EXACT_INPUT" && body.kind !== "EXACT_OUTPUT") throw new Error("Unsupported swap kind");
  const amount = text(body.amount);
  if (integer(amount) === 0n) throw new Error("Swap amount must be positive");
  const slippageBps = body.slippageBps;
  if (typeof slippageBps !== "number" || !Number.isInteger(slippageBps) || slippageBps < 1 || slippageBps > 100) {
    throw new Error("Slippage must be between 1 and 100 basis points");
  }
  return { owner: wallet, kind: body.kind, amount, slippageBps };
}

export function panoraUrl(request: SwapRequest): URL {
  const url = new URL("https://api.panora.exchange/swap");
  const exactOut = request.kind === "EXACT_OUTPUT";
  url.search = new URLSearchParams({
    chainId: "1", fromTokenAddress: "0xa", toTokenAddress: NATIVE_USDC,
    [exactOut ? "toTokenAmount" : "fromTokenAmount"]: decimal(BigInt(request.amount), exactOut ? 6 : 8),
    toWalletAddress: request.owner,
    slippagePercentage: decimal(BigInt(request.slippageBps), 2),
    integratorFeePercentage: "0", onlyDirectRoutes: "true", disableSplits: "true",
  }).toString();
  return url;
}

/** Normalizes only the supported APT/native-USDC FA route and computes its canonical BCS hash. */
export function validatePanoraQuote(value: unknown, request: SwapRequest): ValidatedQuote {
  const response = record(value);
  const from = record(response.fromToken), to = record(response.toToken), feeToken = record(response.feeToken);
  if (canonicalAddress(text(from.address)) !== APT || from.decimals !== 8 ||
    canonicalAddress(text(to.address)) !== canonicalAddress(NATIVE_USDC) || to.decimals !== 6 ||
    canonicalAddress(text(feeToken.address)) !== canonicalAddress(NATIVE_USDC)) throw new Error("Unexpected swap assets");
  const quote = record(array(response.quotes)[0]);
  const exactOut = request.kind === "EXACT_OUTPUT";
  const input = units(exactOut ? quote.fromTokenAmount : response.fromTokenAmount, 8);
  const output = units(exactOut ? response.toTokenAmount : quote.toTokenAmount, 6);
  const maxInput = exactOut ? units(quote.maxFromTokenAmount, 8) : input;
  const minOutput = exactOut ? output : units(quote.minToTokenAmount, 6);
  if (input === 0n || output === 0n || maxInput < input || minOutput === 0n || minOutput > output ||
    (exactOut ? output : input) !== BigInt(request.amount)) throw new Error("Unexpected swap quantities");
  const bps = BigInt(request.slippageBps);
  if (maxInput > (input * (10000n + bps) + 9999n) / 10000n ||
    minOutput < output * (10000n - bps) / 10000n || units(quote.slippagePercentage, 2) !== bps) {
    throw new Error("Swap limits exceed requested slippage");
  }
  if (units(quote.feeTokenAmount, 6) !== 0n) throw new Error("Fee-bearing routes are not supported yet");
  const tx = record(quote.txData);
  if (tx.function !== PANORA_ROUTER) throw new Error("Unknown swap router");
  const tags = array(tx.type_arguments);
  if (tags.length !== 32 || tags.some(tag => parseTypeTag(text(tag)).toString() !== parseTypeTag(STRING_TAG).toString())) {
    throw new Error("Only fungible-asset routes are supported");
  }
  const args = array(tx.arguments);
  if (args.length !== TYPES.length || args[0] !== null || canonicalAddress(text(args[1])) !== request.owner ||
    integer(args[2]) !== (exactOut ? 2n : 1n) || integer(args[3]) !== 1n) throw new Error("Invalid swap recipient or mode");
  if (JSON.stringify(args[8]) !== "[[1]]") throw new Error("Unsupported withdrawal mode");
  const sources = array(args[10]);
  if (!sources.length || array(sources[0]).length !== 1 || canonicalAddress(text(array(sources[0])[0])) !== APT) {
    throw new Error("Wrong input asset");
  }
  for (const index of [10, 11]) for (const row of array(args[index])) for (const asset of array(row)) {
    const address = canonicalAddress(text(asset));
    if (address !== APT && address !== canonicalAddress(NATIVE_USDC)) throw new Error("Unsupported intermediate asset");
  }
  if (canonicalAddress(text(args[15])) !== canonicalAddress(NATIVE_USDC) ||
    array(args[16]).length !== 1 || integer(array(args[16])[0]) !== maxInput || integer(args[17]) !== minOutput ||
    String(args[18]) !== "10000000000000000") {
    throw new Error("Router limits do not match the quote");
  }
  let nodes = 0;
  function encode(type: string, value: unknown): number[] {
    if (++nodes > 8192) throw new Error("Swap route too large");
    if (type.startsWith("o:")) return value === null ? [0] : [1, ...encode(type.slice(2), value)];
    if (type.startsWith("v:")) {
      const values = array(value);
      if (values.length > 256) throw new Error("Swap vector too large");
      return [...uleb(values.length), ...values.flatMap(item => encode(type.slice(2), item))];
    }
    if (type === "address") return [...AccountAddress.fromString(text(value)).toUint8Array()];
    if (type === "bool") { if (typeof value !== "boolean") throw new Error("Invalid boolean"); return [value ? 1 : 0]; }
    const number = integer(value);
    if (type === "u8") { if (number > 255n) throw new Error("Invalid u8"); return [Number(number)]; }
    if (type === "u64") return Array.from({ length: 8 }, (_, index) => Number(number >> BigInt(index * 8) & 255n));
    throw new Error("Unsupported route type");
  }
  const encoded = TYPES.map((type, index) => Uint8Array.from(encode(type, args[index])));
  const [address, module, name] = PANORA_ROUTER.split("::");
  const payload = new TransactionPayloadEntryFunction(EntryFunction.build(
    `${address}::${module}`, name, tags.map(tag => parseTypeTag(text(tag))),
    encoded.map(bytes => EntryFunctionBytes.deserialize(new Deserializer(bytes), bytes.length)),
  ));
  const payloadHash = `0x${Buffer.from(sha3_256(payload.bcsToBytes())).toString("hex")}`;
  // Discard provider transaction envelopes, signing messages and extra route candidates.
  return { response: { fromToken: from, toToken: to, feeToken, ...(exactOut ?
    { toTokenAmount: response.toTokenAmount } : { fromTokenAmount: response.fromTokenAmount }), quotes: [quote] }, payloadHash, payload };
}

export async function issueSwapAuthorization(claims: SwapAuthorization, secret: string): Promise<string> {
  const payload = Buffer.from(JSON.stringify(claims)).toString("base64url");
  const signature = await crypto.subtle.sign("HMAC", await hmacKey(secret), new TextEncoder().encode(`flare.swap.v1.${payload}`));
  return `${payload}.${Buffer.from(signature).toString("base64url")}`;
}

export async function verifySwapAuthorization(token: string, secret: string, wallet: string, now = Date.now()): Promise<SwapAuthorization> {
  if (token.length > 2048) throw new Error("Swap authorization too large");
  const [payload, signature, extra] = token.split(".");
  if (!payload || !signature || extra !== undefined) throw new Error("Invalid swap authorization");
  const valid = await crypto.subtle.verify("HMAC", await hmacKey(secret),
    new Uint8Array(Buffer.from(signature, "base64url")), new TextEncoder().encode(`flare.swap.v1.${payload}`));
  if (!valid) throw new Error("Invalid swap authorization signature");
  const claims = JSON.parse(Buffer.from(payload, "base64url").toString("utf8")) as SwapAuthorization;
  if (claims.purpose !== "flare.swap.v1" || canonicalAddress(claims.wallet) !== canonicalAddress(wallet) ||
    !Number.isSafeInteger(claims.expiresAtMs) || claims.expiresAtMs <= now || claims.expiresAtMs > now + 30000 ||
    !/^[0-9a-f-]{36}$/.test(claims.id) || !/^0x[0-9a-f]{64}$/.test(claims.payloadHash)) {
    throw new Error("Expired or mismatched swap authorization");
  }
  return claims;
}

async function hmacKey(secret: string): Promise<CryptoKey> {
  if (new TextEncoder().encode(secret).length < 32) throw new Error("Signing key too short");
  return crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
}
function integer(value: unknown): bigint {
  // Panora emits the zero-fee multiplier as the exactly representable numeric constant 10^16.
  if (typeof value === "number" && !Number.isSafeInteger(value) && value !== 10_000_000_000_000_000) throw new Error("Unsafe JSON integer");
  if ((typeof value !== "string" && typeof value !== "number") || !/^(0|[1-9][0-9]*)$/.test(String(value))) throw new Error("Invalid unsigned integer");
  const number = BigInt(value);
  if (number > U64_MAX) throw new Error("Integer exceeds u64");
  return number;
}
function units(value: unknown, decimals: number): bigint {
  if (typeof value !== "string" || !/^[0-9]+(?:\.[0-9]+)?$/.test(value)) throw new Error("Invalid decimal amount");
  const [whole, fraction = ""] = value.split(".");
  if (fraction.length > decimals && /[1-9]/.test(fraction.slice(decimals))) throw new Error("Excess precision");
  return integer((whole + fraction.slice(0, decimals).padEnd(decimals, "0")).replace(/^0+(?=\d)/, ""));
}
function decimal(value: bigint, decimals: number): string {
  const padded = value.toString().padStart(decimals + 1, "0");
  return `${padded.slice(0, -decimals)}.${padded.slice(-decimals)}`;
}
function uleb(value: number): number[] {
  const bytes = [];
  do { const byte = value & 127; value >>>= 7; bytes.push(byte | (value ? 128 : 0)); } while (value);
  return bytes;
}
function text(value: unknown): string { if (typeof value !== "string") throw new Error("Expected text"); return value; }
function array(value: unknown): unknown[] { if (!Array.isArray(value)) throw new Error("Expected array"); return value; }
function record(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("Expected object");
  return value as Record<string, unknown>;
}
