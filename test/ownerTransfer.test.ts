import { describe, expect, it } from "vitest";
import { authorizeGasStationRequest } from "../src/gasStation";
import { sponsoredFixture, addressBytes, bcsString, u64, DECIBEL_PACKAGE, USDC_METADATA } from "./sponsorshipFixture";

const metadataType = [7, ...addressBytes("0x1"), ...bcsString("fungible_asset"), ...bcsString("Metadata"), 0];
function transfer(input: { metadata?: string; amount?: bigint; typeArguments?: number[][]; destination?: number[] } = {}) {
  const signed = sponsoredFixture({
    packageAddress: "0x1", module: "primary_fungible_store", functionName: "transfer",
    typeArguments: input.typeArguments ?? [metadataType],
    arguments: [addressBytes(input.metadata ?? USDC_METADATA), input.destination ?? addressBytes("0x789"), u64(input.amount ?? 1_000_000n)],
  });
  const authorization = {
    walletAddress: signed.walletAddress, subaccount: "0x123", network: "testnet" as const,
    ownerOnly: true, decibelPackageAddress: DECIBEL_PACKAGE, usdcMetadataAddress: USDC_METADATA,
  };
  return { ...signed, authorization };
}

describe("owner USDC destination transfers", () => {
  it("accepts a signed owner transfer of configured USDC", () => {
    const f = transfer();
    expect(() => authorizeGasStationRequest(f.request, f.authorization)).not.toThrow();
  });
  it("rejects trading authorization and unbound owners", () => {
    const f = transfer();
    expect(() => authorizeGasStationRequest(f.request, { ...f.authorization, ownerOnly: false })).toThrow();
    expect(() => authorizeGasStationRequest(f.request, { ...f.authorization, subaccount: undefined })).toThrow();
  });
  it.each([
    { metadata: "0x456" }, { amount: 0n }, { typeArguments: [] },
    { typeArguments: [[4]] }, { typeArguments: [metadataType, metadataType] }, { destination: [1] },
  ])("rejects an invalid asset, amount, type, or destination (case %#)", input => {
    const f = transfer(input);
    expect(() => authorizeGasStationRequest(f.request, f.authorization)).toThrow();
  });
  it("rejects a transfer signed by another wallet", () => {
    const f = transfer();
    expect(() => authorizeGasStationRequest(f.request, { ...f.authorization, walletAddress: "0x999" })).toThrow();
  });
});
