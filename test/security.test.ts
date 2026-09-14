import { Deserializer, SimpleTransaction, generateSigningMessageForTransaction } from "@aptos-labs/ts-sdk";
import { sha3_256 } from "@noble/hashes/sha3.js";
import { generateKeyPairSync, sign } from "node:crypto";
import { sponsoredFixture, addressBytes, u64, DECIBEL_PACKAGE, USDC_METADATA } from "./sponsorshipFixture";
import { describe, expect, it } from "vitest";
import {
  aptosAddressFromEd25519,
  buildChallenge,
  canonicalAddress,
  issueSessionToken,
  parseChallenge,
  verifyEd25519,
  verifySessionToken,
} from "../src/security";
import {
  authorizeGasStationRequest,
  externalFeePayerFingerprint,
  validateGasStationRequest,
} from "../src/gasStation";
import { validateTopic } from "../src/topics";
import { forwardableCloseCode } from "../src/websocket";
import {
  delegationAuthorizesAllPerpMarkets,
  sponsorshipRecordMatchesSession,
  subaccountRecordMatches,
} from "../src/authorization";

const SIGNING_KEY = "test-session-key-with-more-than-thirty-two-bytes";

describe("FLARE_AUTH_V1", () => {
  it("round-trips a canonical challenge", () => {
    const challenge = buildChallenge({
      network: "testnet",
      origin: "flare://mobile",
      walletAddress: "0x1",
      subaccount: "0x2",
      nonce: "ab".repeat(32),
      issuedAt: 1_000,
      expiresAt: 301_000,
    });

    expect(parseChallenge(challenge)).toEqual({
      network: "testnet",
      origin: "flare://mobile",
      walletAddress: canonicalAddress("0x1"),
      subaccount: canonicalAddress("0x2"),
      nonce: "ab".repeat(32),
      issuedAt: 1_000,
      expiresAt: 301_000,
    });
  });

  it("verifies Ed25519 signatures and derives the Aptos authentication key", () => {
    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    const publicDer = publicKey.export({ format: "der", type: "spki" }) as Buffer;
    const rawPublicKey = toHex(publicDer.subarray(publicDer.length - 32));
    const challenge = buildChallenge({
      network: "testnet",
      origin: "flare://mobile",
      walletAddress: aptosAddressFromEd25519(rawPublicKey),
      nonce: "cd".repeat(32),
      issuedAt: 1_000,
      expiresAt: 301_000,
    });
    const signature = toHex(sign(null, Buffer.from(challenge), privateKey));

    expect(verifyEd25519(challenge, rawPublicKey, signature)).toBe(true);
    expect(verifyEd25519(`${challenge}x`, rawPublicKey, signature)).toBe(false);
  });
});

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

describe("session tokens", () => {
  it("accepts an active token and rejects tampering", async () => {
    const claims = {
      iat: 1_000,
      exp: 4_300,
      jti: "01".repeat(16),
      network: "testnet" as const,
      role: "owner" as const,
      wallet: canonicalAddress("0x1"),
    };
    const token = await issueSessionToken(claims, SIGNING_KEY);

    await expect(verifySessionToken(token, SIGNING_KEY, 1_001)).resolves.toEqual(claims);
    await expect(verifySessionToken(`${token.slice(0, -1)}x`, SIGNING_KEY, 1_001)).rejects.toThrow();
  });

  it("rejects expired tokens", async () => {
    const token = await issueSessionToken({
      iat: 1_000,
      exp: 1_001,
      jti: "02".repeat(16),
      network: "testnet",
      role: "anonymous",
    }, SIGNING_KEY);

    await expect(verifySessionToken(token, SIGNING_KEY, 1_001)).rejects.toThrow("Session expired");
  });
});

describe("Decibel account authorization records", () => {
  it("recognizes the current subaccount OpenAPI field", () => {
    expect(subaccountRecordMatches(
      { subaccount_address: "0x22", primary_account_address: "0x11" },
      canonicalAddress("0x22"),
    )).toBe(true);
  });

  it("accepts only active account-wide perp delegation", () => {
    const signer = canonicalAddress("0x33");
    expect(delegationAuthorizesAllPerpMarkets({
      delegated_account: signer,
      permission_type: "TradePerpsAllMarkets",
      expiration_time_s: 1_001,
    }, signer, 1_000_000)).toBe(true);
    expect(delegationAuthorizesAllPerpMarkets({
      delegated_account: signer,
      permission_type: "TradePerpsAllMarkets",
      expiration_time_s: 999,
    }, signer, 1_000_000)).toBe(false);
    expect(delegationAuthorizesAllPerpMarkets({
      delegated_account: signer,
      permission_type: "TradePerpsOnMarket",
      permission_market: canonicalAddress("0x44"),
    }, signer, 1_000_000)).toBe(false);
  });

  it("requires an explicit permission signal for legacy records", () => {
    const signer = canonicalAddress("0x33");
    expect(delegationAuthorizesAllPerpMarkets({
      delegate: signer,
      can_trade_perps: true,
    }, signer, 1_000_000)).toBe(true);
    expect(delegationAuthorizesAllPerpMarkets({ delegate: signer }, signer, 1_000_000))
      .toBe(false);
  });
});

describe("WebSocket topic allowlist", () => {
  const anonymous = {
    iat: 1_000,
    exp: 4_300,
    jti: "03".repeat(16),
    network: "testnet" as const,
    role: "anonymous" as const,
  };
  const account = canonicalAddress("0x22");
  const authenticated = {
    ...anonymous,
    role: "api" as const,
    wallet: canonicalAddress("0x11"),
    subaccount: account,
  };

  it("accepts canonical public market topics", () => {
    expect(() => validateTopic("all_market_prices", anonymous)).not.toThrow();
    expect(() => validateTopic(`depth:${account}:10`, anonymous)).not.toThrow();
    expect(() => validateTopic(`trades:${account}`, anonymous)).not.toThrow();
    expect(() => validateTopic(`market_candlestick:${account}:4h`, anonymous)).not.toThrow();
  });

  it("rejects extra market topic segments", () => {
    expect(() => validateTopic(`market_price:${account}:1`, anonymous))
      .toThrow("Invalid market topic");
    expect(() => validateTopic(`trades:${account}:1`, anonymous))
      .toThrow("Invalid market topic");
  });

  it("binds account topics to an authenticated session", () => {
    expect(() => validateTopic(`account_positions:${account}`, anonymous))
      .toThrow("Wallet session required");
    expect(() => validateTopic(`account_positions:${account}`, authenticated)).not.toThrow();
    expect(() => validateTopic(`account_positions:${canonicalAddress("0x33")}`, authenticated))
      .toThrow("outside the session scope");
  });
});

describe("WebSocket close forwarding", () => {
  it("preserves sendable protocol and application codes", () => {
    expect(forwardableCloseCode(1000, 1011)).toBe(1000);
    expect(forwardableCloseCode(1011, 1001)).toBe(1011);
    expect(forwardableCloseCode(4001, 1011)).toBe(4001);
  });

  it("normalizes reserved or missing close codes", () => {
    expect(forwardableCloseCode(1006, 1011)).toBe(1011);
    expect(forwardableCloseCode(1015, 1011)).toBe(1011);
    expect(forwardableCloseCode(0, 1001)).toBe(1001);
  });
});

describe("Gas Station request allowlist", () => {
  it("binds sponsorship recovery to the submitting session identity", () => {
    const record = {
      fingerprint: `0x${"ab".repeat(32)}`,
      network: "testnet" as const,
      role: "api" as const,
      subaccount: canonicalAddress("0x22"),
      status: "pending" as const,
      expiresAt: 2_000,
      wallet: canonicalAddress("0x11"),
    };
    const session = {
      network: "testnet" as const,
      role: "api" as const,
      subaccount: canonicalAddress("0x22"),
      wallet: canonicalAddress("0x11"),
    };

    expect(sponsorshipRecordMatchesSession(record, session)).toBe(true);
    expect(sponsorshipRecordMatchesSession(record, { ...session, role: "owner" })).toBe(false);
    expect(sponsorshipRecordMatchesSession(record, {
      ...session,
      wallet: canonicalAddress("0x33"),
    })).toBe(false);
    expect(sponsorshipRecordMatchesSession(record, {
      ...session,
      subaccount: canonicalAddress("0x44"),
    })).toBe(false);
    expect(sponsorshipRecordMatchesSession(record, {
      network: "testnet",
      role: "anonymous",
    })).toBe(false);
  });

  it("uses a stable domain-separated fingerprint for recovery", () => {
    const request = {
      transactionBytes: [1, 2, 3],
      senderAuth: [4, 5],
      additionalSignersAuth: [[6]],
    };

    const fingerprint = externalFeePayerFingerprint(request);

    expect(fingerprint).toBe(
      "0x7a517cc968f0461294ead057f06331b6177770d148278817822d4841ed712dd1",
    );
    expect(externalFeePayerFingerprint(request)).toBe(fingerprint);
    expect(externalFeePayerFingerprint({ ...request, transactionBytes: [1, 2, 4] }))
      .not.toBe(fingerprint);
  });

  it("retains only the documented BCS fields", () => {
    expect(validateGasStationRequest({
      transactionBytes: [0, 1, 255],
      senderAuth: [2, 3],
      additionalSignersAuth: [[4, 5]],
      arbitraryUpstreamField: "discarded",
    })).toEqual({
      transactionBytes: [0, 1, 255],
      senderAuth: [2, 3],
      additionalSignersAuth: [[4, 5]],
    });
  });

  it("rejects malformed byte arrays", () => {
    expect(() => validateGasStationRequest({
      transactionBytes: [256],
      senderAuth: [1],
    })).toThrow("Invalid transactionBytes");
  });

  it("authorizes a signed Decibel transaction bound to the API-wallet session", () => {
    const fixture = sponsoredFixture({
      functionName: "configure_user_settings_for_market",
      arguments: [addressBytes("0x22"), addressBytes("0x33"), [1], [5]],
    });

    expect(() => authorizeGasStationRequest(fixture.request, {
      walletAddress: fixture.walletAddress,
      subaccount: "0x22",
      network: "testnet",
      ownerOnly: false,
      decibelPackageAddress: DECIBEL_PACKAGE,
      usdcMetadataAddress: USDC_METADATA,
    })).not.toThrow();
  });

  it("accepts the pinned order ABI only when builder fields are empty", () => {
    const baseArguments = [
      addressBytes("0x22"),
      addressBytes("0x33"),
      u64(10n),
      u64(2n),
      [1],
      [2],
      [0],
      [0],
      [0],
      [0],
      [0],
      [0],
      [0],
      [0],
      [0],
    ];
    const accepted = sponsoredFixture({
      functionName: "place_order_to_subaccount",
      arguments: baseArguments,
    });
    const authorization = {
      walletAddress: accepted.walletAddress,
      subaccount: "0x22",
      network: "testnet" as const,
      ownerOnly: false,
      decibelPackageAddress: DECIBEL_PACKAGE,
      usdcMetadataAddress: USDC_METADATA,
    };

    expect(() => authorizeGasStationRequest(accepted.request, authorization)).not.toThrow();

    const withBuilderFee = sponsoredFixture({
      functionName: "place_order_to_subaccount",
      arguments: [
        ...baseArguments.slice(0, 13),
        [1, ...addressBytes("0x99")],
        [1, ...u64(1n)],
      ],
    });
    expect(() => authorizeGasStationRequest(withBuilderFee.request, {
      ...authorization,
      walletAddress: withBuilderFee.walletAddress,
    })).toThrow("builder address is not supported");
  });

  it("rejects shifted TP/SL option slots", () => {
    const fixture = sponsoredFixture({
      functionName: "place_tp_sl_order_for_position",
      arguments: [
        addressBytes("0x22"),
        addressBytes("0x33"),
        [0],
        [0],
        [1, ...u64(10n)],
        [1, ...u64(11n)],
        [0],
        [0],
        [0],
        [0],
      ],
    });

    expect(() => authorizeGasStationRequest(fixture.request, {
      walletAddress: fixture.walletAddress,
      subaccount: "0x22",
      network: "testnet",
      ownerOnly: false,
      decibelPackageAddress: DECIBEL_PACKAGE,
      usdcMetadataAddress: USDC_METADATA,
    })).toThrow("take-profit limit or size requires a trigger");
  });

  it("authorizes perpetual-only delegation exclusively on the owner route", () => {
    const fixture = sponsoredFixture({
      functionName: "delegate_perp_trading_to_for_subaccount",
      arguments: [addressBytes("0x22"), addressBytes("0x44"), [0]],
    });
    const authorization = {
      walletAddress: fixture.walletAddress,
      subaccount: "0x22",
      network: "testnet" as const,
      ownerOnly: true,
      decibelPackageAddress: DECIBEL_PACKAGE,
      usdcMetadataAddress: USDC_METADATA,
    };
    expect(() => authorizeGasStationRequest(fixture.request, authorization)).not.toThrow();
    expect(() => authorizeGasStationRequest(fixture.request, {
      ...authorization, ownerOnly: false,
    })).toThrow();
  });

  it("authorizes the dedicated TP/SL cancellation ABI", () => {
    const fixture = sponsoredFixture({
      functionName: "cancel_tp_sl_order_for_position",
      arguments: [addressBytes("0x22"), addressBytes("0x33"), new Array(16).fill(0xff)],
    });

    expect(() => authorizeGasStationRequest(fixture.request, {
      walletAddress: fixture.walletAddress,
      subaccount: "0x22",
      network: "testnet",
      ownerOnly: false,
      decibelPackageAddress: DECIBEL_PACKAGE,
      usdcMetadataAddress: USDC_METADATA,
    })).not.toThrow();
  });

  it("authorizes spot order placement and cancellation on dex_accounts_spot_entry", () => {
    const baseArguments = [
      addressBytes("0x22"),
      addressBytes("0x33"),
      u64(10n),
      u64(2n),
      [1],
      [2],
      [0],
      [0],
    ];
    const acceptedPlace = sponsoredFixture({
      module: "dex_accounts_spot_entry",
      functionName: "place_spot_order_to_subaccount",
      arguments: baseArguments,
    });
    const authorization = {
      walletAddress: acceptedPlace.walletAddress,
      subaccount: "0x22",
      network: "testnet" as const,
      ownerOnly: false,
      decibelPackageAddress: DECIBEL_PACKAGE,
      usdcMetadataAddress: USDC_METADATA,
    };

    expect(() => authorizeGasStationRequest(acceptedPlace.request, authorization)).not.toThrow();

    const wrongModule = sponsoredFixture({
      module: "dex_accounts_entry",
      functionName: "place_spot_order_to_subaccount",
      arguments: baseArguments,
    });
    expect(() => authorizeGasStationRequest(wrongModule.request, {
      ...authorization,
      walletAddress: wrongModule.walletAddress,
    })).toThrow("Transaction is outside the Decibel package allowlist");

    const acceptedCancel = sponsoredFixture({
      module: "dex_accounts_spot_entry",
      functionName: "cancel_spot_order_to_subaccount",
      arguments: [addressBytes("0x22"), addressBytes("0x33"), new Array(16).fill(0xff)],
    });
    expect(() => authorizeGasStationRequest(acceptedCancel.request, {
      ...authorization,
      walletAddress: acceptedCancel.walletAddress,
    })).not.toThrow();
  });

  it("rejects leverage outside the documented range", () => {
    const fixture = sponsoredFixture({
      functionName: "configure_user_settings_for_market",
      arguments: [addressBytes("0x22"), addressBytes("0x33"), [1], [101]],
    });

    expect(() => authorizeGasStationRequest(fixture.request, {
      walletAddress: fixture.walletAddress,
      subaccount: "0x22",
      network: "testnet",
      ownerOnly: false,
      decibelPackageAddress: DECIBEL_PACKAGE,
      usdcMetadataAddress: USDC_METADATA,
    })).toThrow("Leverage is outside the supported range");
  });

  it("rejects a valid signature when the transaction is outside its subaccount scope", () => {
    const fixture = sponsoredFixture({
      functionName: "configure_user_settings_for_market",
      arguments: [addressBytes("0x44"), addressBytes("0x33"), [1], [5]],
    });

    expect(() => authorizeGasStationRequest(fixture.request, {
      walletAddress: fixture.walletAddress,
      subaccount: "0x22",
      network: "testnet",
      ownerOnly: false,
      decibelPackageAddress: DECIBEL_PACKAGE,
      usdcMetadataAddress: USDC_METADATA,
    })).toThrow("Transaction subaccount does not match the session scope");
  });

  it("rejects owner funding with a non-USDC asset", () => {
    const fixture = sponsoredFixture({
      functionName: "deposit_to_subaccount_at",
      arguments: [addressBytes("0x22"), addressBytes("0x99"), u64(1_000_000n)],
    });

    expect(() => authorizeGasStationRequest(fixture.request, {
      walletAddress: fixture.walletAddress,
      subaccount: "0x22",
      network: "testnet",
      ownerOnly: true,
      decibelPackageAddress: DECIBEL_PACKAGE,
      usdcMetadataAddress: USDC_METADATA,
    })).toThrow("Only the configured Aptos USDC asset can be sponsored");
  });

  it("rejects a sender signature after transaction bytes are changed", () => {
    const fixture = sponsoredFixture({ functionName: "create_new_subaccount", arguments: [] });
    fixture.request.transactionBytes[33] = 1;

    expect(() => authorizeGasStationRequest(fixture.request, {
      walletAddress: fixture.walletAddress,
      network: "testnet",
      ownerOnly: true,
      decibelPackageAddress: DECIBEL_PACKAGE,
      usdcMetadataAddress: USDC_METADATA,
    })).toThrow("Sender transaction signature is invalid");
  });
});

describe("Geomi transaction envelope compatibility", () => {
  it("preserves the signed message while encoding the official SDK SimpleTransaction wire format", () => {
    const fixture = sponsoredFixture({ functionName: "create_new_subaccount", arguments: [] });
    const submission = authorizeGasStationRequest(fixture.request, {
      walletAddress: fixture.walletAddress, network: "testnet", ownerOnly: true,
      decibelPackageAddress: DECIBEL_PACKAGE, usdcMetadataAddress: USDC_METADATA,
    });
    const transaction = SimpleTransaction.deserialize(new Deserializer(Uint8Array.from(submission.transactionBytes)));
    expect(transaction.rawTransaction.sender.toStringLong()).toBe(fixture.walletAddress);
    expect(transaction.feePayerAddress?.toStringLong()).toBe("0x" + "00".repeat(32));
    expect(Array.from(transaction.bcsToBytes())).toEqual(submission.transactionBytes);
    const originalMessage = Buffer.concat([
      sha3_256(Buffer.from("APTOS::RawTransactionWithData")),
      Buffer.from(fixture.request.transactionBytes),
    ]);
    expect(Buffer.from(generateSigningMessageForTransaction(transaction))).toEqual(originalMessage);
    expect(submission.senderAuth).toEqual(fixture.request.senderAuth);
    expect(submission.transactionBytes).not.toEqual(fixture.request.transactionBytes);
  });
});
