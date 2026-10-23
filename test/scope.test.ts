import { describe, expect, it } from "vitest";
import { isSessionAccount, referralAccountPrefix } from "../src/scope";

const WALLET = `0x${"a".repeat(64)}`;
const OTHER = `0x${"c".repeat(64)}`;

describe("referral account paths", () => {
  it.each([
    `referrals/stats/${WALLET}`,
    `referrals/account/${WALLET}`,
  ])("recognises %s", (endpoint) => expect(referralAccountPrefix(endpoint)).toBeDefined());

  it.each([
    "referrals/code/ABC",
    "referrals/users",
    "points/amps",
    "referrals",
  ])("leaves %s alone", (endpoint) => expect(referralAccountPrefix(endpoint)).toBeUndefined());

  it("hands back only the account, so a further segment cannot match", () => {
    const prefix = referralAccountPrefix(`referrals/stats/${WALLET}/extra`)!;
    const rest = `referrals/stats/${WALLET}/extra`.slice(prefix.length);
    expect(isSessionAccount(rest, WALLET)).toBe(false);
  });
});

describe("session account comparison", () => {
  it("accepts the session's own account, however it is written", () => {
    expect(isSessionAccount(WALLET, WALLET)).toBe(true);
    expect(isSessionAccount(WALLET.toUpperCase().replace("0X", "0x"), WALLET)).toBe(true);
    // Short form canonicalises to the same padded address.
    expect(isSessionAccount("0x1", `0x${"0".repeat(63)}1`)).toBe(true);
  });

  it("refuses another account", () => {
    expect(isSessionAccount(OTHER, WALLET)).toBe(false);
  });

  it("treats a malformed address as a mismatch, not a crash", () => {
    // canonicalAddress throws on each of these; a refusal must come back, never a 500.
    for (const bad of ["", "nonsense", "0x", "0xzz", "../../etc", `0x${"a".repeat(65)}`,
                       `${WALLET}/extra`, `${WALLET}%2f..%2fsecret`]) {
      expect(() => isSessionAccount(bad, WALLET)).not.toThrow();
      expect(isSessionAccount(bad, WALLET)).toBe(false);
    }
  });

  it("refuses when the session names no account", () => {
    expect(isSessionAccount(WALLET, undefined)).toBe(false);
    expect(isSessionAccount(null, WALLET)).toBe(false);
  });
});
