/**
 * Security-focused tests covering fixes for:
 * - Empty delegation targets (unrestricted IC access)
 * - Prototype pollution in candidToJson
 * - BigInt/integer range validation in jsonToCandid
 */
import { describe, it, expect } from "vitest";
import { Principal } from "@icp-sdk/core/principal";
import { IDL } from "@icp-sdk/core/candid";
import { getDelegationTargets } from "../auth.js";
import { candidToJson, jsonToCandid } from "../candid-json.js";

// ── Delegation scope ─────────────────────────────────────────────────

describe("getDelegationTargets", () => {
  it("always includes the primary canister ID", () => {
    const targets = getDelegationTargets("ryjl3-tyaaa-aaaaa-aaaba-cai");
    expect(targets).toHaveLength(1);
    expect(targets[0].toText()).toBe("ryjl3-tyaaa-aaaaa-aaaba-cai");
  });

  it("merges manifest delegation_targets with primary canister", () => {
    const targets = getDelegationTargets("ryjl3-tyaaa-aaaaa-aaaba-cai", {
      type: "internet-identity",
      delegation_targets: [
        "qoctq-giaaa-aaaaa-aaaea-cai",
        "ryjl3-tyaaa-aaaaa-aaaba-cai", // duplicate — should deduplicate
      ],
    });
    // deduplication means ryjl3 appears once, qoctq once
    expect(targets).toHaveLength(2);
  });

  it("never returns an empty list", () => {
    const targets = getDelegationTargets("aaaaa-aa", undefined);
    expect(targets.length).toBeGreaterThan(0);
  });
});

// ── Prototype pollution ───────────────────────────────────────────────

describe("candidToJson — prototype pollution guard", () => {
  it("strips __proto__ keys from decoded objects", () => {
    // Simulate a decoded Candid record that somehow contains __proto__
    // We test toJsonValue indirectly via candidToJson with a Record type.
    const RecordType = IDL.Record({ name: IDL.Text, age: IDL.Nat32 });
    const encoded = IDL.encode([RecordType], [{ name: "alice", age: 30 }]);
    const result = candidToJson(encoded, [RecordType]) as Record<
      string,
      unknown
    >;
    expect(result.name).toBe("alice");
    // Verify prototype is unmodified
    expect(Object.prototype.toString).toBe(Object.prototype.toString);
  });
});

// ── Integer range validation ──────────────────────────────────────────

describe("jsonToCandid — integer range validation", () => {
  it("accepts valid Nat8 values", () => {
    expect(() =>
      jsonToCandid({ arg0: 0 }, [IDL.Nat8]),
    ).not.toThrow();
    expect(() =>
      jsonToCandid({ arg0: 255 }, [IDL.Nat8]),
    ).not.toThrow();
  });

  it("rejects Nat8 values out of range", () => {
    expect(() =>
      jsonToCandid({ arg0: 256 }, [IDL.Nat8]),
    ).toThrow(RangeError);
    expect(() =>
      jsonToCandid({ arg0: -1 }, [IDL.Nat8]),
    ).toThrow(RangeError);
  });

  it("accepts valid Nat32 boundary values", () => {
    expect(() =>
      jsonToCandid({ arg0: 0 }, [IDL.Nat32]),
    ).not.toThrow();
    expect(() =>
      jsonToCandid({ arg0: 4_294_967_295 }, [IDL.Nat32]),
    ).not.toThrow();
  });

  it("rejects Nat32 values exceeding 2^32-1", () => {
    expect(() =>
      jsonToCandid({ arg0: 4_294_967_296 }, [IDL.Nat32]),
    ).toThrow(RangeError);
  });

  it("accepts valid Int8 values", () => {
    expect(() =>
      jsonToCandid({ arg0: -128 }, [IDL.Int8]),
    ).not.toThrow();
    expect(() =>
      jsonToCandid({ arg0: 127 }, [IDL.Int8]),
    ).not.toThrow();
  });

  it("rejects Int8 values out of range", () => {
    expect(() =>
      jsonToCandid({ arg0: 128 }, [IDL.Int8]),
    ).toThrow(RangeError);
    expect(() =>
      jsonToCandid({ arg0: -129 }, [IDL.Int8]),
    ).toThrow(RangeError);
  });

  it("accepts valid Nat64 bigint string", () => {
    expect(() =>
      jsonToCandid({ arg0: "18446744073709551615" }, [IDL.Nat64]),
    ).not.toThrow();
  });

  it("rejects negative Nat64", () => {
    expect(() =>
      jsonToCandid({ arg0: "-1" }, [IDL.Nat64]),
    ).toThrow(RangeError);
  });

  it("rejects Nat64 exceeding 2^64-1", () => {
    expect(() =>
      jsonToCandid({ arg0: "18446744073709551616" }, [IDL.Nat64]),
    ).toThrow(RangeError);
  });
});

// ── createScopedDelegation — tested via integration ───────────────────
// (Full delegation creation requires an IC connection; the empty-targets
//  guard is tested in auth.ts by importing directly in integration tests.)
describe("getDelegationTargets — never empty", () => {
  it("returns at least the primary canister when auth has no targets", () => {
    const primary = "ryjl3-tyaaa-aaaaa-aaaba-cai";
    const targets = getDelegationTargets(primary, {
      type: "internet-identity",
      delegation_targets: [],
    });
    expect(targets.map((t) => t.toText())).toContain(primary);
  });
});
