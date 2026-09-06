import { createHash, createPublicKey, verify as verifyNodeSignature } from "node:crypto";
import type { SessionClaims } from "./types";

const encoder = new TextEncoder();
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

export const AUTH_DOMAIN = "FLARE_AUTH_V1";
export const CHALLENGE_TTL_MS = 5 * 60 * 1_000;
export const SESSION_TTL_SECONDS = 55 * 60;

export interface ChallengeFields {
  network: "testnet" | "mainnet";
  origin: string;
  walletAddress: string;
  subaccount?: string;
  nonce: string;
  issuedAt: number;
  expiresAt: number;
}

export function canonicalAddress(value: string): string {
  const hex = value.toLowerCase().replace(/^0x/, "");
  if (!/^[0-9a-f]{1,64}$/.test(hex)) throw new Error("Invalid Aptos address");
  return `0x${hex.padStart(64, "0")}`;
}

export function randomHex(byteLength: number): string {
  const bytes = new Uint8Array(byteLength);
  crypto.getRandomValues(bytes);
  return Buffer.from(bytes).toString("hex");
}

export function buildChallenge(fields: ChallengeFields): string {
  if (!/^[0-9a-f]{64}$/.test(fields.nonce)) throw new Error("Nonce must contain 32 bytes");
  if (!Number.isSafeInteger(fields.issuedAt) || !Number.isSafeInteger(fields.expiresAt)) {
    throw new Error("Challenge timestamps are invalid");
  }
  if (fields.expiresAt <= fields.issuedAt) throw new Error("Challenge expiry is invalid");
  if (/\r|\n|=/.test(fields.origin)) throw new Error("Origin is invalid");

  return [
    AUTH_DOMAIN,
    `network=${fields.network}`,
    `origin=${fields.origin}`,
    `wallet_address=${canonicalAddress(fields.walletAddress)}`,
    `subaccount=${fields.subaccount ? canonicalAddress(fields.subaccount) : ""}`,
    `nonce=${fields.nonce}`,
    `issued_at=${fields.issuedAt}`,
    `expires_at=${fields.expiresAt}`,
  ].join("\n");
}

export function parseChallenge(challenge: string): ChallengeFields {
  const lines = challenge.split("\n");
  if (lines.length !== 8 || lines[0] !== AUTH_DOMAIN) throw new Error("Invalid challenge domain");

  const values = new Map<string, string>();
  for (const line of lines.slice(1)) {
    const separator = line.indexOf("=");
    if (separator < 1) throw new Error("Invalid challenge field");
    const key = line.slice(0, separator);
    if (values.has(key)) throw new Error("Duplicate challenge field");
    values.set(key, line.slice(separator + 1));
  }

  const network = values.get("network");
  if (network !== "testnet" && network !== "mainnet") throw new Error("Invalid network");
  const issuedAt = Number(values.get("issued_at"));
  const expiresAt = Number(values.get("expires_at"));
  const parsed: ChallengeFields = {
    network,
    origin: required(values, "origin"),
    walletAddress: canonicalAddress(required(values, "wallet_address")),
    subaccount: values.get("subaccount")
      ? canonicalAddress(required(values, "subaccount"))
      : undefined,
    nonce: required(values, "nonce"),
    issuedAt,
    expiresAt,
  };
  if (buildChallenge(parsed) !== challenge) throw new Error("Challenge is not canonical");
  return parsed;
}

export function aptosAddressFromEd25519(publicKeyHex: string): string {
  const publicKey = decodeHex(publicKeyHex, 32, "public key");
  return aptosAddressFromEd25519Bytes(publicKey);
}

export function aptosAddressFromEd25519Bytes(publicKey: Uint8Array): string {
  if (publicKey.byteLength !== 32) throw new Error("Invalid public key");
  const authenticationKey = createHash("sha3-256").update(publicKey).update(Uint8Array.of(0)).digest("hex");
  return canonicalAddress(authenticationKey);
}

export function verifyEd25519(
  challenge: string,
  publicKeyHex: string,
  signatureHex: string,
): boolean {
  const publicKey = decodeHex(publicKeyHex, 32, "public key");
  const signature = decodeHex(signatureHex, 64, "signature");
  return verifyEd25519Bytes(Buffer.from(challenge, "utf8"), publicKey, signature);
}

export function verifyEd25519Bytes(
  message: Uint8Array,
  publicKey: Uint8Array,
  signature: Uint8Array,
): boolean {
  if (publicKey.byteLength !== 32 || signature.byteLength !== 64) return false;
  const key = createPublicKey({
    key: Buffer.concat([ED25519_SPKI_PREFIX, publicKey]),
    format: "der",
    type: "spki",
  });
  return verifyNodeSignature(null, message, key, signature);
}

export async function issueSessionToken(
  claims: SessionClaims,
  signingKey: string,
): Promise<string> {
  assertSigningKey(signingKey);
  const header = encodeBase64Url(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const payload = encodeBase64Url(JSON.stringify(claims));
  const input = `${header}.${payload}`;
  const key = await importHmacKey(signingKey);
  const signature = await crypto.subtle.sign("HMAC", key, encoder.encode(input));
  return `${input}.${encodeBase64Url(signature)}`;
}

export async function verifySessionToken(
  token: string,
  signingKey: string,
  nowSeconds = Math.floor(Date.now() / 1_000),
): Promise<SessionClaims> {
  assertSigningKey(signingKey);
  const parts = token.split(".");
  if (parts.length !== 3) throw new Error("Invalid session token");
  const [header, payload, signature] = parts;
  const decodedHeader = JSON.parse(decodeBase64UrlText(header)) as { alg?: string; typ?: string };
  if (decodedHeader.alg !== "HS256" || decodedHeader.typ !== "JWT") {
    throw new Error("Invalid session token header");
  }

  const key = await importHmacKey(signingKey);
  const valid = await crypto.subtle.verify(
    "HMAC",
    key,
    decodeBase64Url(signature),
    encoder.encode(`${header}.${payload}`),
  );
  if (!valid) throw new Error("Invalid session signature");

  const claims = JSON.parse(decodeBase64UrlText(payload)) as SessionClaims;
  if (!Number.isSafeInteger(claims.iat) || !Number.isSafeInteger(claims.exp)) {
    throw new Error("Invalid session timestamps");
  }
  if (claims.exp <= nowSeconds || claims.iat > nowSeconds + 30) throw new Error("Session expired");
  if (!/^[0-9a-f]{32}$/.test(claims.jti)) throw new Error("Invalid session identifier");
  if (!(["anonymous", "owner", "api"] as const).includes(claims.role)) {
    throw new Error("Invalid session role");
  }
  if (claims.wallet) claims.wallet = canonicalAddress(claims.wallet);
  if (claims.subaccount) claims.subaccount = canonicalAddress(claims.subaccount);
  return claims;
}

function required(values: Map<string, string>, key: string): string {
  const value = values.get(key);
  if (!value) throw new Error(`Missing challenge field: ${key}`);
  return value;
}

function decodeHex(value: string, expectedBytes: number, label: string): Buffer {
  const normalized = value.replace(/^0x/, "");
  if (!new RegExp(`^[0-9a-fA-F]{${expectedBytes * 2}}$`).test(normalized)) {
    throw new Error(`Invalid ${label}`);
  }
  return Buffer.from(normalized, "hex");
}

function assertSigningKey(signingKey: string): void {
  if (encoder.encode(signingKey).byteLength < 32) {
    throw new Error("SESSION_SIGNING_KEY must contain at least 32 bytes");
  }
}

async function importHmacKey(signingKey: string): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "raw",
    encoder.encode(signingKey),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"],
  );
}

function encodeBase64Url(value: string | ArrayBuffer): string {
  const bytes = typeof value === "string" ? encoder.encode(value) : new Uint8Array(value);
  return Buffer.from(bytes).toString("base64url");
}

function decodeBase64Url(value: string): Uint8Array<ArrayBuffer> {
  return new Uint8Array(Buffer.from(value, "base64url"));
}

function decodeBase64UrlText(value: string): string {
  return Buffer.from(value, "base64url").toString("utf8");
}
