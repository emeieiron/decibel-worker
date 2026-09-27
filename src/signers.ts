import {
  AccountAuthenticator,
  AccountAuthenticatorEd25519,
  AccountAuthenticatorSingleKey,
  AnyPublicKey,
  Deserializer,
  Ed25519PublicKey,
  Ed25519Signature,
  Secp256k1PublicKey,
  Secp256k1Signature,
} from "@aptos-labs/ts-sdk";

import { canonicalAddress } from "./security";

/**
 * The owner keys Flare accepts: legacy Ed25519 accounts, and SingleKey accounts holding a
 * Secp256k1 key (what Aptos wallets create for `secp256k1-priv-0x…` keys). Key handling, address
 * derivation and signature checks all come from the Aptos TypeScript SDK.
 */
export type OwnerKey =
  | { scheme: "ed25519"; publicKey: Ed25519PublicKey }
  | { scheme: "secp256k1"; publicKey: Secp256k1PublicKey };

export type OwnerSignature = { key: OwnerKey; signature: Ed25519Signature | Secp256k1Signature };

/** An owner key from its public key bytes: 32 are Ed25519, 65 (uncompressed) are Secp256k1. */
export function ownerKey(publicKey: Uint8Array): OwnerKey {
  if (publicKey.byteLength === Ed25519PublicKey.LENGTH) {
    return { scheme: "ed25519", publicKey: new Ed25519PublicKey(publicKey) };
  }
  if (publicKey.byteLength === Secp256k1PublicKey.LENGTH) {
    return { scheme: "secp256k1", publicKey: new Secp256k1PublicKey(publicKey) };
  }
  throw new Error("Unsupported public key");
}

/** The signature an owner key makes, from its bytes. */
export function ownerSignature(key: OwnerKey, signature: Uint8Array): OwnerSignature {
  return {
    key,
    signature: key.scheme === "ed25519" ? new Ed25519Signature(signature) : new Secp256k1Signature(signature),
  };
}

/** The account address a key authenticates: legacy Ed25519, or SingleKey for Secp256k1. */
export function ownerAddress(key: OwnerKey): string {
  const authKey = key.scheme === "ed25519" ? key.publicKey.authKey() : new AnyPublicKey(key.publicKey).authKey();
  return canonicalAddress(authKey.derivedAddress().toStringLong());
}

/** Verifies an owner's signature over `message` (bytes, never reinterpreted as hex). */
export function verifyOwnerSignature({ key, signature }: OwnerSignature, message: Uint8Array): boolean {
  try {
    return key.scheme === "ed25519"
      ? key.publicKey.verifySignature({ message, signature: signature as Ed25519Signature })
      : key.publicKey.verifySignature({ message, signature: signature as Secp256k1Signature });
  } catch {
    return false;
  }
}

/**
 * A transaction sender's AccountAuthenticator, accepted only when it is legacy Ed25519, or
 * SingleKey with a Secp256k1 key and signature. Anything else, or trailing bytes, is rejected.
 */
export function parseSenderAuthenticator(bytes: Uint8Array): OwnerSignature {
  const deserializer = new Deserializer(bytes);
  const authenticator = AccountAuthenticator.deserialize(deserializer);
  deserializer.assertFinished();
  if (authenticator instanceof AccountAuthenticatorEd25519) {
    return { key: { scheme: "ed25519", publicKey: authenticator.public_key }, signature: authenticator.signature };
  }
  if (
    authenticator instanceof AccountAuthenticatorSingleKey &&
    authenticator.public_key.publicKey instanceof Secp256k1PublicKey &&
    authenticator.signature.signature instanceof Secp256k1Signature
  ) {
    return {
      key: { scheme: "secp256k1", publicKey: authenticator.public_key.publicKey },
      signature: authenticator.signature.signature,
    };
  }
  throw new Error("Only Ed25519 and Secp256k1 sender authenticators are supported");
}

/** Hex (with or without 0x) to bytes, or null when it isn't whole-byte hex. */
export function hexBytes(value: string): Uint8Array | null {
  const normalized = value.replace(/^0x/, "");
  if (normalized.length === 0 || normalized.length % 2 !== 0 || !/^[0-9a-fA-F]+$/.test(normalized)) return null;
  return Uint8Array.from(Buffer.from(normalized, "hex"));
}
