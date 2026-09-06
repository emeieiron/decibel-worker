import { sha3_256 } from "@noble/hashes/sha3.js";
import {
  aptosAddressFromEd25519Bytes,
  canonicalAddress,
  verifyEd25519Bytes,
} from "./security";

export type GasStationRequest = {
  transactionBytes: number[];
  senderAuth: number[];
  additionalSignersAuth?: number[][];
};

export type GasStationAuthorization = {
  walletAddress: string;
  subaccount?: string;
  network: "testnet" | "mainnet";
  ownerOnly: boolean;
  decibelPackageAddress: string;
  usdcMetadataAddress: string;
};

const RAW_TRANSACTION_WITH_DATA_SALT = "APTOS::RawTransactionWithData";
const DECIBEL_MODULE = "dex_accounts_entry";
const OWNER_FUNCTIONS = new Set([
  "create_new_subaccount",
  "deposit_to_subaccount_at",
  "withdraw_from_cross_collateral",
  "delegate_perp_trading_to_for_subaccount",
  "revoke_delegation",
]);
const TRADING_FUNCTIONS = new Set([
  "configure_user_settings_for_market",
  "place_order_to_subaccount",
  "cancel_order_to_subaccount",
  "cancel_tp_sl_order_for_position",
  "place_tp_sl_order_for_position",
]);
const FUNDING_FUNCTIONS = new Set([
  "deposit_to_subaccount_at",
  "withdraw_from_cross_collateral",
]);
const EXPECTED_ARGUMENT_COUNTS = new Map<string, number>([
  ["create_new_subaccount", 0],
  ["deposit_to_subaccount_at", 3],
  ["withdraw_from_cross_collateral", 3],
  ["delegate_perp_trading_to_for_subaccount", 3],
  ["revoke_delegation", 2],
  ["configure_user_settings_for_market", 4],
  ["place_order_to_subaccount", 15],
  ["cancel_order_to_subaccount", 3],
  ["cancel_tp_sl_order_for_position", 3],
  ["place_tp_sl_order_for_position", 10],
]);

/** Strictly narrows the public route to the Aptos Gas Station sign-and-submit operation. */
export function validateGasStationRequest(value: unknown): GasStationRequest {
  if (!isRecord(value)) throw new Error("Invalid Gas Station request");
  const transactionBytes = byteArray(value.transactionBytes, "transactionBytes", 128 * 1024);
  const senderAuth = byteArray(value.senderAuth, "senderAuth", 16 * 1024);
  const additional = value.additionalSignersAuth;
  let additionalSignersAuth: number[][] | undefined;
  if (additional !== undefined) {
    if (!Array.isArray(additional) || additional.length > 32) {
      throw new Error("Invalid additionalSignersAuth");
    }
    additionalSignersAuth = additional.map((item, index) =>
      byteArray(item, `additionalSignersAuth[${index}]`, 16 * 1024));
  }
  return {
    transactionBytes,
    senderAuth,
    ...(additionalSignersAuth?.length ? { additionalSignersAuth } : {}),
  };
}

/** Matches Kaptos' domain-separated correlation fingerprint for an external fee-payer request. */
export function externalFeePayerFingerprint(request: GasStationRequest): string {
  const correlation = Buffer.concat([
    bcsBytes(request.transactionBytes),
    bcsBytes(request.senderAuth),
    bcsUleb128(request.additionalSignersAuth?.length ?? 0),
    ...(request.additionalSignersAuth ?? []).map(bcsBytes),
  ]);
  const prefix = sha3_256.create()
    .update(Buffer.from("APTOS::ExternalFeePayerRequest", "utf8"))
    .digest();
  return `0x${Buffer.from(sha3_256.create().update(prefix).update(correlation).digest()).toString("hex")}`;
}

/**
 * Independently verifies the Kaptos-produced BCS request before a server credential is attached.
 * Flare v1 intentionally accepts only legacy Ed25519, direct entry-function transactions with no
 * secondary signers. Supporting another authenticator or payload requires an explicit parser and
 * policy update rather than weakening this check.
 */
export function authorizeGasStationRequest(
  request: GasStationRequest,
  authorization: GasStationAuthorization,
): void {
  if (request.additionalSignersAuth?.length) {
    throw new Error("Secondary signers are not supported by Flare sponsorship");
  }

  const transactionBytes = Uint8Array.from(request.transactionBytes);
  const sender = parseSponsoredTransaction(transactionBytes);
  const authenticator = parseEd25519Authenticator(Uint8Array.from(request.senderAuth));
  const walletAddress = canonicalAddress(authorization.walletAddress);

  if (addressHex(sender.sender) !== walletAddress) {
    throw new Error("Transaction sender does not match the authenticated wallet");
  }
  if (aptosAddressFromEd25519Bytes(authenticator.publicKey) !== walletAddress) {
    throw new Error("Sender authenticator does not match the authenticated wallet");
  }

  const signingSalt = sha3_256.create()
    .update(Buffer.from(RAW_TRANSACTION_WITH_DATA_SALT, "utf8"))
    .digest();
  const signingMessage = Buffer.concat([signingSalt, transactionBytes]);
  if (!verifyEd25519Bytes(signingMessage, authenticator.publicKey, authenticator.signature)) {
    throw new Error("Sender transaction signature is invalid");
  }

  const expectedChainId = authorization.network === "mainnet" ? 1 : 2;
  if (sender.chainId !== expectedChainId) throw new Error("Transaction network mismatch");
  if (addressHex(sender.packageAddress) !== canonicalAddress(authorization.decibelPackageAddress) ||
    sender.module !== DECIBEL_MODULE) {
    throw new Error("Transaction is outside the Decibel package allowlist");
  }

  const allowedFunctions = authorization.ownerOnly ? OWNER_FUNCTIONS : TRADING_FUNCTIONS;
  if (!allowedFunctions.has(sender.function)) {
    throw new Error("Entry function is outside the sponsorship route allowlist");
  }
  if (sender.arguments.length !== EXPECTED_ARGUMENT_COUNTS.get(sender.function)) {
    throw new Error("Entry-function argument count does not match the Flare contract");
  }

  if (sender.function !== "create_new_subaccount") {
    if (!authorization.subaccount) throw new Error("A subaccount-bound session is required");
    const argument = sender.arguments[0];
    if (!argument || argument.byteLength !== 32 ||
      addressHex(argument) !== canonicalAddress(authorization.subaccount)) {
      throw new Error("Transaction subaccount does not match the session scope");
    }
  }

  if (FUNDING_FUNCTIONS.has(sender.function)) {
    const asset = sender.arguments[1];
    if (!asset || asset.byteLength !== 32 ||
      addressHex(asset) !== canonicalAddress(authorization.usdcMetadataAddress)) {
      throw new Error("Only the configured Aptos USDC asset can be sponsored");
    }
  }

  validateFunctionArguments(sender.function, sender.arguments);
}

function validateFunctionArguments(functionName: string, args: Uint8Array[]): void {
  switch (functionName) {
    case "create_new_subaccount":
      return;
    case "deposit_to_subaccount_at":
    case "withdraw_from_cross_collateral":
      aptosAddress(args[0], "subaccount");
      aptosAddress(args[1], "asset metadata");
      unsignedInteger(args[2], 8, "collateral amount", true);
      return;
    case "delegate_perp_trading_to_for_subaccount":
      aptosAddress(args[0], "subaccount");
      aptosAddress(args[1], "delegate");
      optionFixed(args[2], 8, "delegation expiry", true);
      return;
    case "revoke_delegation":
      aptosAddress(args[0], "subaccount");
      aptosAddress(args[1], "delegate");
      return;
    case "configure_user_settings_for_market": {
      aptosAddress(args[0], "subaccount");
      aptosAddress(args[1], "market");
      booleanArgument(args[2], "margin mode");
      const leverage = singleByte(args[3], "leverage");
      if (leverage < 1 || leverage > 100) throw new Error("Leverage is outside the supported range");
      return;
    }
    case "place_order_to_subaccount":
      aptosAddress(args[0], "subaccount");
      aptosAddress(args[1], "market");
      unsignedInteger(args[2], 8, "order price", true);
      unsignedInteger(args[3], 8, "order size", true);
      booleanArgument(args[4], "order side");
      if (singleByte(args[5], "time in force") > 2) {
        throw new Error("Time in force is outside the supported range");
      }
      booleanArgument(args[6], "reduce-only flag");
      optionString(args[7], "client order ID");
      optionFixed(args[8], 8, "stop price", true);
      const hasTakeProfitTrigger = optionFixed(args[9], 8, "take-profit trigger", true);
      const hasTakeProfitLimit = optionFixed(args[10], 8, "take-profit limit", true);
      const hasStopLossTrigger = optionFixed(args[11], 8, "stop-loss trigger", true);
      const hasStopLossLimit = optionFixed(args[12], 8, "stop-loss limit", true);
      if (hasTakeProfitLimit && !hasTakeProfitTrigger) {
        throw new Error("A take-profit limit requires a trigger");
      }
      if (hasStopLossLimit && !hasStopLossTrigger) {
        throw new Error("A stop-loss limit requires a trigger");
      }
      emptyOption(args[13], "builder address");
      emptyOption(args[14], "builder fee");
      return;
    case "cancel_order_to_subaccount":
      aptosAddress(args[0], "subaccount");
      unsignedInteger(args[1], 16, "order ID", true);
      aptosAddress(args[2], "market");
      return;
    case "cancel_tp_sl_order_for_position":
      aptosAddress(args[0], "subaccount");
      aptosAddress(args[1], "market");
      unsignedInteger(args[2], 16, "TP/SL order ID", true);
      return;
    case "place_tp_sl_order_for_position": {
      aptosAddress(args[0], "subaccount");
      aptosAddress(args[1], "market");
      const hasTakeProfit = optionFixed(args[2], 8, "take-profit trigger", true);
      const hasTakeProfitLimit = optionFixed(args[3], 8, "take-profit limit", true);
      const hasTakeProfitSize = optionFixed(args[4], 8, "take-profit size", true);
      const hasStopLoss = optionFixed(args[5], 8, "stop-loss trigger", true);
      const hasStopLossLimit = optionFixed(args[6], 8, "stop-loss limit", true);
      const hasStopLossSize = optionFixed(args[7], 8, "stop-loss size", true);
      if (!hasTakeProfit && !hasStopLoss) throw new Error("A TP/SL trigger is required");
      if ((hasTakeProfitLimit || hasTakeProfitSize) && !hasTakeProfit) {
        throw new Error("A take-profit limit or size requires a trigger");
      }
      if ((hasStopLossLimit || hasStopLossSize) && !hasStopLoss) {
        throw new Error("A stop-loss limit or size requires a trigger");
      }
      emptyOption(args[8], "builder address");
      emptyOption(args[9], "builder fee");
      return;
    }
    default:
      throw new Error("Entry function has no argument policy");
  }
}

function aptosAddress(value: Uint8Array | undefined, name: string): void {
  if (!value || value.byteLength !== 32) throw new Error(`Invalid ${name}`);
}

function booleanArgument(value: Uint8Array | undefined, name: string): void {
  const byte = singleByte(value, name);
  if (byte !== 0 && byte !== 1) throw new Error(`Invalid ${name}`);
}

function singleByte(value: Uint8Array | undefined, name: string): number {
  if (!value || value.byteLength !== 1) throw new Error(`Invalid ${name}`);
  return value[0];
}

function unsignedInteger(
  value: Uint8Array | undefined,
  byteLength: number,
  name: string,
  requirePositive: boolean,
): void {
  if (!value || value.byteLength !== byteLength) throw new Error(`Invalid ${name}`);
  if (requirePositive && value.every((byte) => byte === 0)) {
    throw new Error(`${name} must be positive`);
  }
}

function optionFixed(
  value: Uint8Array | undefined,
  byteLength: number,
  name: string,
  requirePositive: boolean,
): boolean {
  if (!value || value.byteLength === 0) throw new Error(`Invalid ${name}`);
  if (value[0] === 0 && value.byteLength === 1) return false;
  if (value[0] !== 1 || value.byteLength !== byteLength + 1) throw new Error(`Invalid ${name}`);
  unsignedInteger(value.slice(1), byteLength, name, requirePositive);
  return true;
}

function optionString(value: Uint8Array | undefined, name: string): boolean {
  if (!value || value.byteLength === 0) throw new Error(`Invalid ${name}`);
  if (value[0] === 0 && value.byteLength === 1) return false;
  if (value[0] !== 1) throw new Error(`Invalid ${name}`);
  const reader = new BcsReader(value.slice(1));
  const bytes = reader.bytes(128);
  reader.finished();
  if (bytes.byteLength === 0) throw new Error(`${name} cannot be empty`);
  new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(bytes);
  return true;
}

function emptyOption(value: Uint8Array | undefined, name: string): void {
  if (!value || value.byteLength !== 1 || value[0] !== 0) {
    throw new Error(`${name} is not supported by Flare`);
  }
}

type ParsedSponsoredTransaction = {
  sender: Uint8Array;
  packageAddress: Uint8Array;
  module: string;
  function: string;
  arguments: Uint8Array[];
  chainId: number;
};

function parseSponsoredTransaction(bytes: Uint8Array): ParsedSponsoredTransaction {
  const reader = new BcsReader(bytes);
  if (reader.uleb128() !== 1) throw new Error("Expected a fee-payer transaction");
  const sender = reader.fixed(32);
  reader.fixed(8); // sequence number
  if (reader.uleb128() !== 2) throw new Error("Only direct entry-function payloads are supported");
  const packageAddress = reader.fixed(32);
  const module = reader.identifier();
  const functionName = reader.identifier();
  const typeArgumentCount = reader.uleb128();
  if (typeArgumentCount > 64) throw new Error("Too many transaction type arguments");
  for (let index = 0; index < typeArgumentCount; index += 1) reader.typeTag(0);
  const argumentCount = reader.uleb128();
  if (argumentCount > 64) throw new Error("Too many transaction arguments");
  const args = Array.from({ length: argumentCount }, () => reader.bytes(64 * 1024));
  reader.fixed(8); // maximum gas amount
  reader.fixed(8); // gas unit price
  reader.fixed(8); // expiration timestamp
  const chainId = reader.u8();
  if (reader.uleb128() !== 0) throw new Error("Secondary signers are not supported");
  const feePayer = reader.fixed(32);
  if (feePayer.some((byte) => byte !== 0)) {
    throw new Error("External fee-payer address must use the zero placeholder");
  }
  reader.finished();
  return {
    sender,
    packageAddress,
    module,
    function: functionName,
    arguments: args,
    chainId,
  };
}

function parseEd25519Authenticator(bytes: Uint8Array): {
  publicKey: Uint8Array;
  signature: Uint8Array;
} {
  const reader = new BcsReader(bytes);
  if (reader.uleb128() !== 0) throw new Error("Only Ed25519 sender authenticators are supported");
  const publicKey = reader.bytes(32);
  const signature = reader.bytes(64);
  if (publicKey.byteLength !== 32 || signature.byteLength !== 64) {
    throw new Error("Invalid Ed25519 sender authenticator");
  }
  reader.finished();
  return { publicKey, signature };
}

class BcsReader {
  private offset = 0;

  constructor(private readonly input: Uint8Array) {}

  u8(): number {
    if (this.offset >= this.input.byteLength) throw new Error("Truncated BCS value");
    return this.input[this.offset++];
  }

  fixed(length: number): Uint8Array {
    if (!Number.isSafeInteger(length) || length < 0 || this.offset + length > this.input.byteLength) {
      throw new Error("Truncated BCS value");
    }
    const value = this.input.slice(this.offset, this.offset + length);
    this.offset += length;
    return value;
  }

  uleb128(): number {
    let result = 0;
    let shift = 0;
    for (let index = 0; index < 5; index += 1) {
      const byte = this.u8();
      const digit = byte & 0x7f;
      if (shift === 28 && digit > 0x0f) throw new Error("BCS ULEB128 value exceeds u32");
      result += digit * 2 ** shift;
      if ((byte & 0x80) === 0) {
        if (index > 0 && digit === 0) throw new Error("Non-canonical BCS ULEB128 value");
        return result;
      }
      shift += 7;
    }
    throw new Error("BCS ULEB128 value exceeds u32");
  }

  bytes(maximumLength: number): Uint8Array {
    const length = this.uleb128();
    if (length > maximumLength) throw new Error("BCS byte sequence exceeds the route limit");
    return this.fixed(length);
  }

  identifier(): string {
    const value = new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(this.bytes(128));
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(value)) throw new Error("Invalid Move identifier");
    return value;
  }

  typeTag(depth: number): void {
    if (depth > 16) throw new Error("Type tag nesting is too deep");
    const variant = this.uleb128();
    if (variant === 6) {
      this.typeTag(depth + 1);
      return;
    }
    if (variant === 7) {
      this.fixed(32);
      this.identifier();
      this.identifier();
      const length = this.uleb128();
      if (length > 64) throw new Error("Too many struct type arguments");
      for (let index = 0; index < length; index += 1) this.typeTag(depth + 1);
      return;
    }
    if (variant > 16) throw new Error("Unsupported transaction type tag");
  }

  finished(): void {
    if (this.offset !== this.input.byteLength) throw new Error("Trailing bytes in BCS value");
  }
}

function addressHex(bytes: Uint8Array): string {
  if (bytes.byteLength !== 32) throw new Error("Invalid Aptos address bytes");
  return canonicalAddress(Buffer.from(bytes).toString("hex"));
}

function bcsBytes(value: number[]): Buffer {
  return Buffer.concat([bcsUleb128(value.length), Buffer.from(value)]);
}

function bcsUleb128(value: number): Buffer {
  if (!Number.isSafeInteger(value) || value < 0 || value > 0xffff_ffff) {
    throw new Error("BCS length exceeds u32");
  }
  const bytes: number[] = [];
  let remaining = value;
  do {
    let byte = remaining & 0x7f;
    remaining = Math.floor(remaining / 128);
    if (remaining !== 0) byte |= 0x80;
    bytes.push(byte);
  } while (remaining !== 0);
  return Buffer.from(bytes);
}

function byteArray(value: unknown, name: string, maximumLength: number): number[] {
  if (!Array.isArray(value) || value.length === 0 || value.length > maximumLength ||
    value.some((item) => !Number.isInteger(item) || item < 0 || item > 255)) {
    throw new Error(`Invalid ${name}`);
  }
  return value as number[];
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
