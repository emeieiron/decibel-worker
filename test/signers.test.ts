import {
  Account,
  Ed25519PrivateKey,
  Secp256k1PrivateKey,
  SigningSchemeInput,
} from "@aptos-labs/ts-sdk";
import { describe, expect, it } from "vitest";

import { authorizeGasStationRequest } from "../src/gasStation";
import { canonicalAddress } from "../src/security";
import { ownerAddress, ownerKey, ownerSignature, verifyOwnerSignature } from "../src/signers";
import { addressBytes, DECIBEL_PACKAGE, sponsoredFixture, USDC_METADATA } from "./sponsorshipFixture";

const CHALLENGE = new TextEncoder().encode("FLARE_AUTH_V1\nnetwork=testnet\nnonce=abc");
const SECP256K1_ORDER = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;

/** The two account kinds Flare supports, built by the Aptos SDK. */
const accounts = {
  ed25519: () => Account.generate(),
  secp256k1: () => Account.generate({ scheme: SigningSchemeInput.Secp256k1Ecdsa }),
};

function publicKeyBytes(account: Account): Uint8Array {
  // Ed25519 accounts expose the key directly; SingleKey accounts wrap it in AnyPublicKey.
  const key = account.publicKey as { publicKey?: { toUint8Array(): Uint8Array }; toUint8Array(): Uint8Array };
  return (key.publicKey ?? key).toUint8Array();
}

function signatureBytes(account: Account, message: Uint8Array): Uint8Array {
  const signature = account.sign(message) as { signature?: { toUint8Array(): Uint8Array }; toUint8Array(): Uint8Array };
  return (signature.signature ?? signature).toUint8Array();
}

describe.each(Object.entries(accounts))("%s owners", (_, generate) => {
  it("derive the same address as the Aptos SDK account", () => {
    const account = generate();
    expect(ownerAddress(ownerKey(publicKeyBytes(account)))).toBe(
      canonicalAddress(account.accountAddress.toStringLong()),
    );
  });

  it("verify an SDK signature over the challenge, and nothing else", () => {
    const account = generate();
    const key = ownerKey(publicKeyBytes(account));
    const signature = signatureBytes(account, CHALLENGE);
    expect(verifyOwnerSignature(ownerSignature(key, signature), CHALLENGE)).toBe(true);

    const tampered = Uint8Array.from(CHALLENGE);
    tampered[tampered.length - 1] ^= 1;
    expect(verifyOwnerSignature(ownerSignature(key, signature), tampered)).toBe(false);

    const other = signatureBytes(generate(), CHALLENGE);
    expect(verifyOwnerSignature(ownerSignature(key, other), CHALLENGE)).toBe(false);
  });
});

describe("Secp256k1 owner keys", () => {
  it("reject a high-S signature, which Aptos treats as malleable", () => {
    const account = accounts.secp256k1();
    const key = ownerKey(publicKeyBytes(account));
    const signature = signatureBytes(account, CHALLENGE);
    const s = BigInt(`0x${Buffer.from(signature.slice(32)).toString("hex")}`);
    const highS = Buffer.from((SECP256K1_ORDER - s).toString(16).padStart(64, "0"), "hex");
    const malleated = Uint8Array.from([...signature.slice(0, 32), ...highS]);
    expect(verifyOwnerSignature(ownerSignature(key, malleated), CHALLENGE)).toBe(false);
  });

  it("reject keys that are neither Ed25519 nor uncompressed Secp256k1", () => {
    const compressed = Secp256k1PrivateKey.generate().publicKey().toUint8Array().slice(0, 33);
    expect(() => ownerKey(compressed)).toThrow("Unsupported public key");
    expect(() => ownerKey(new Uint8Array(64))).toThrow("Unsupported public key");
    expect(Ed25519PrivateKey.generate().publicKey().toUint8Array()).toHaveLength(32);
  });
});

describe("sponsorship senders", () => {
  const authorization = (walletAddress: string) => ({
    walletAddress,
    subaccount: "0x22",
    network: "testnet" as const,
    ownerOnly: false,
    decibelPackageAddress: DECIBEL_PACKAGE,
    usdcMetadataAddress: USDC_METADATA,
  });
  const call = {
    functionName: "configure_user_settings_for_market",
    arguments: [addressBytes("0x22"), addressBytes("0x33"), [1], [5]],
  };

  it("accept a transaction signed by a Secp256k1 SingleKey account", () => {
    const fixture = sponsoredFixture({ ...call, signer: "secp256k1" });
    expect(() => authorizeGasStationRequest(fixture.request, authorization(fixture.walletAddress))).not.toThrow();
  });

  it("reject a Secp256k1 transaction claimed for another wallet", () => {
    const fixture = sponsoredFixture({ ...call, signer: "secp256k1" });
    expect(() => authorizeGasStationRequest(fixture.request, authorization("0x999"))).toThrow();
  });

  it("reject a Secp256k1 signature over a different transaction", () => {
    const fixture = sponsoredFixture({ ...call, signer: "secp256k1" });
    const other = sponsoredFixture({ ...call, signer: "secp256k1" });
    const request = { ...fixture.request, senderAuth: other.request.senderAuth };
    expect(() => authorizeGasStationRequest(request, authorization(fixture.walletAddress))).toThrow();
  });

  it("reject a SingleKey sender holding Ed25519, which Flare does not use", () => {
    const fixture = sponsoredFixture({ ...call, signer: "ed25519-singlekey" });
    expect(() => authorizeGasStationRequest(fixture.request, authorization(fixture.walletAddress))).toThrow(
      "Only Ed25519 and Secp256k1 sender authenticators are supported",
    );
  });
});
