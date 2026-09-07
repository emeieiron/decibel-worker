import { generateKeyPairSync, sign } from "node:crypto";
import { sha3_256 } from "@noble/hashes/sha3.js";
import { aptosAddressFromEd25519, canonicalAddress } from "../src/security";
function toHex(bytes: Uint8Array): string { return Buffer.from(bytes).toString("hex"); }
export const DECIBEL_PACKAGE = "0xe7da2794b1d8af76532ed95f38bfdf1136abfd8ea3a240189971988a83101b7f";
export const USDC_METADATA = "0x5428acf5c112826d0c74ae1cd2de9030f53d1d01235e6c2621d967bf914ee1c8";

export function sponsoredFixture(input: { functionName: string; arguments: number[][] }): {
  request: { transactionBytes: number[]; senderAuth: number[] };
  walletAddress: string;
} {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const publicDer = publicKey.export({ format: "der", type: "spki" }) as Buffer;
  const rawPublicKey = publicDer.subarray(publicDer.length - 32);
  const walletAddress = aptosAddressFromEd25519(toHex(rawPublicKey));
  const transactionBytes = Uint8Array.from([
    1,
    ...addressBytes(walletAddress),
    ...u64(0n),
    2,
    ...addressBytes(DECIBEL_PACKAGE),
    ...bcsString("dex_accounts_entry"),
    ...bcsString(input.functionName),
    0,
    input.arguments.length,
    ...input.arguments.flatMap((argument) => [argument.length, ...argument]),
    ...u64(200_000n),
    ...u64(100n),
    ...u64(2_000_000_000n),
    2,
    0,
    ...new Array(32).fill(0),
  ]);
  const salt = sha3_256.create()
    .update(Buffer.from("APTOS::RawTransactionWithData", "utf8"))
    .digest();
  const signature = sign(null, Buffer.concat([salt, transactionBytes]), privateKey);
  return {
    walletAddress,
    request: {
      transactionBytes: Array.from(transactionBytes),
      senderAuth: [0, 32, ...rawPublicKey, 64, ...signature],
    },
  };
}

export function addressBytes(value: string): number[] {
  return Array.from(Buffer.from(canonicalAddress(value).slice(2), "hex"));
}

function bcsString(value: string): number[] {
  const bytes: number[] = Array.from(Buffer.from(value, "utf8") as Uint8Array);
  return [bytes.length, ...bytes];
}

export function u64(value: bigint): number[] {
  const bytes: number[] = [];
  let remaining = value;
  for (let index = 0; index < 8; index += 1) {
    bytes.push(Number(remaining & 0xffn));
    remaining >>= 8n;
  }
  return bytes;
}
