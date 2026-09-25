import { describe, it, expect } from "vitest";
import { IDL } from "@icp-sdk/core/candid";
import { Principal } from "@icp-sdk/core/principal";
import { jsonToCandid, candidToJson } from "../candid-json.js";

// ── Helpers ─────────────────────────────────────────────────────────

function roundtrip(value: unknown, type: IDL.Type): unknown {
  const encoded = jsonToCandid(
    value as Record<string, unknown>,
    [type],
  );
  return candidToJson(encoded, [type]);
}

function encodeArg(params: Record<string, unknown>, types: IDL.Type[]): ArrayBuffer {
  return jsonToCandid(params, types);
}

// ── Primitive types ─────────────────────────────────────────────────

describe("jsonToCandid / candidToJson — primitives", () => {
  it("roundtrips text", () => {
    const encoded = encodeArg({ arg0: "hello world" }, [IDL.Text]);
    expect(candidToJson(encoded, [IDL.Text])).toBe("hello world");
  });

  it("roundtrips bool true/false", () => {
    const t = encodeArg({ arg0: true }, [IDL.Bool]);
    expect(candidToJson(t, [IDL.Bool])).toBe(true);
    const f = encodeArg({ arg0: false }, [IDL.Bool]);
    expect(candidToJson(f, [IDL.Bool])).toBe(false);
  });

  it("roundtrips nat as string", () => {
    const encoded = encodeArg({ arg0: "12345678901234567890" }, [IDL.Nat]);
    expect(candidToJson(encoded, [IDL.Nat])).toBe("12345678901234567890");
  });

  it("roundtrips int as string", () => {
    const encoded = encodeArg({ arg0: "-42" }, [IDL.Int]);
    expect(candidToJson(encoded, [IDL.Int])).toBe("-42");
  });

  it("roundtrips nat8", () => {
    const encoded = encodeArg({ arg0: 255 }, [IDL.Nat8]);
    expect(candidToJson(encoded, [IDL.Nat8])).toBe(255);
  });

  it("roundtrips nat64 as string", () => {
    const encoded = encodeArg({ arg0: "18446744073709551615" }, [IDL.Nat64]);
    expect(candidToJson(encoded, [IDL.Nat64])).toBe("18446744073709551615");
  });

  it("roundtrips float64", () => {
    const encoded = encodeArg({ arg0: 3.14 }, [IDL.Float64]);
    expect(candidToJson(encoded, [IDL.Float64])).toBeCloseTo(3.14);
  });

  it("roundtrips null", () => {
    const encoded = encodeArg({ arg0: null }, [IDL.Null]);
    expect(candidToJson(encoded, [IDL.Null])).toBeNull();
  });

  it("roundtrips principal", () => {
    const p = "ryjl3-tyaaa-aaaaa-aaaba-cai";
    const encoded = encodeArg({ arg0: p }, [IDL.Principal]);
    expect(candidToJson(encoded, [IDL.Principal])).toBe(p);
  });
});

// ── Composite types ─────────────────────────────────────────────────

describe("jsonToCandid / candidToJson — composite types", () => {
  it("roundtrips opt (some)", () => {
    const encoded = encodeArg({ arg0: "hello" }, [IDL.Opt(IDL.Text)]);
    expect(candidToJson(encoded, [IDL.Opt(IDL.Text)])).toBe("hello");
  });

  it("roundtrips opt (none)", () => {
    const encoded = encodeArg({ arg0: null }, [IDL.Opt(IDL.Text)]);
    expect(candidToJson(encoded, [IDL.Opt(IDL.Text)])).toBeNull();
  });

  it("roundtrips vec text", () => {
    const encoded = encodeArg({ arg0: ["a", "b", "c"] }, [IDL.Vec(IDL.Text)]);
    expect(candidToJson(encoded, [IDL.Vec(IDL.Text)])).toEqual(["a", "b", "c"]);
  });

  it("roundtrips blob as base64", () => {
    // Encode a blob via IDL directly, then decode to base64
    const bytes = new Uint8Array([0x48, 0x65, 0x6c, 0x6c, 0x6f]); // "Hello"
    const encoded = IDL.encode([IDL.Vec(IDL.Nat8)], [bytes]);
    const result = candidToJson(encoded, [IDL.Vec(IDL.Nat8)]);
    expect(typeof result).toBe("string");
    expect(atob(result as string)).toBe("Hello");
  });

  it("roundtrips record", () => {
    const AccountType = IDL.Record({
      owner: IDL.Principal,
      amount: IDL.Nat64,
    });
    const encoded = encodeArg(
      { owner: "ryjl3-tyaaa-aaaaa-aaaba-cai", amount: "1000000" },
      [AccountType],
    );
    const result = candidToJson(encoded, [AccountType]) as Record<string, unknown>;
    expect(result.owner).toBe("ryjl3-tyaaa-aaaaa-aaaba-cai");
    expect(result.amount).toBe("1000000");
  });

  it("roundtrips variant (unit)", () => {
    const Status = IDL.Variant({ Ok: IDL.Null, Err: IDL.Text });
    const encoded = IDL.encode([Status], [{ Ok: null }]);
    // Unit variants (Null payload) are represented as plain strings
    expect(candidToJson(encoded, [Status])).toBe("Ok");
  });

  it("roundtrips variant (with payload)", () => {
    const Status = IDL.Variant({ Ok: IDL.Nat, Err: IDL.Text });
    const encoded = IDL.encode([Status], [{ Err: "something failed" }]);
    const result = candidToJson(encoded, [Status]) as Record<string, unknown>;
    expect(result.Err).toBe("something failed");
  });

  it("handles multiple positional args", () => {
    const encoded = encodeArg(
      { arg0: "alice", arg1: 42 },
      [IDL.Text, IDL.Nat32],
    );
    const decoded = IDL.decode([IDL.Text, IDL.Nat32], encoded);
    expect(decoded[0]).toBe("alice");
    expect(decoded[1]).toBe(42);
  });

  it("handles empty arg list", () => {
    const encoded = jsonToCandid({}, []);
    expect(encoded.byteLength).toBeGreaterThan(0); // DIDL header
  });
});

// ── toJsonValue edge cases ──────────────────────────────────────────

describe("candidToJson — value conversion", () => {
  it("converts bigint to string", () => {
    const encoded = IDL.encode([IDL.Nat], [BigInt("999999999999999999")]);
    expect(candidToJson(encoded, [IDL.Nat])).toBe("999999999999999999");
  });

  it("converts Principal to text", () => {
    const p = Principal.fromText("aaaaa-aa");
    const encoded = IDL.encode([IDL.Principal], [p]);
    expect(candidToJson(encoded, [IDL.Principal])).toBe("aaaaa-aa");
  });

  it("returns null for empty return type list", () => {
    const encoded = IDL.encode([], []);
    expect(candidToJson(encoded, [])).toBeNull();
  });

  it("returns array for multiple return values", () => {
    const encoded = IDL.encode([IDL.Text, IDL.Nat32], ["hello", 7]);
    const result = candidToJson(encoded, [IDL.Text, IDL.Nat32]);
    expect(Array.isArray(result)).toBe(true);
    expect((result as unknown[])[0]).toBe("hello");
    expect((result as unknown[])[1]).toBe(7);
  });
});
