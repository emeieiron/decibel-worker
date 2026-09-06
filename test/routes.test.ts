import { describe, expect, it } from "vitest";
import { isAllowedAptosReadPath } from "../src/routes";

describe("Kaptos transaction prerequisite routes", () => {
  it.each([
    "/estimate_gas_price",
    "/accounts/0x123/module/dex_accounts_entry",
    "/accounts/0x123/balance/0x1::aptos_coin::AptosCoin",
    "/accounts/0x123/balance/0x1%3A%3Aaptos_coin%3A%3AAptosCoin",
    "/accounts/0x123/balance/0x456",
  ])("allows %s", (path) => expect(isAllowedAptosReadPath(path)).toBe(true));

  it.each([
    "/transactions", "/accounts/0x1/transactions", "/estimate_gas_price/extra",
    "/accounts/invalid/module/coin", "/accounts/0x1/module/coin/extra",
    "/accounts/0x1/balance/0x2/extra", "/accounts/0x1/module/%2e%2e%2fsecret",
    "/accounts/0x1/balance/%ZZ",
  ])("rejects %s", (path) => expect(isAllowedAptosReadPath(path)).toBe(false));
});
