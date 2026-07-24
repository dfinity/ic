import { IDL } from "@icp-sdk/core/candid";
import { Principal } from "@icp-sdk/core/principal";

/**
 * Encode JSON parameters into Candid binary format.
 *
 * This function takes a JSON object (as received from a WebMCP tool call)
 * and the Candid IDL types for the method arguments, then produces the
 * binary Candid encoding suitable for an agent call.
 *
 * For methods with a single record argument, the JSON params map directly
 * to the record fields. For methods with multiple positional arguments,
 * params are expected as { arg0: ..., arg1: ..., ... }.
 */
export function jsonToCandid(
  params: Record<string, unknown>,
  argTypes: IDL.Type[],
): Uint8Array {
  if (argTypes.length === 0) {
    return IDL.encode([], []);
  }

  // Single record argument: params ARE the record fields
  if (argTypes.length === 1 && argTypes[0] instanceof IDL.RecordClass) {
    const converted = convertValue(params, argTypes[0]);
    return IDL.encode(argTypes, [converted]);
  }

  // Multiple positional arguments
  const args = argTypes.map((type, i) => {
    const key = `arg${i}`;
    const value = params[key];
    if (value === undefined) {
      throw new Error(`Missing argument ${key}`);
    }
    return convertValue(value, type);
  });
  return IDL.encode(argTypes, args);
}

/**
 * Decode a Candid binary response into a JSON-friendly value.
 */
export function candidToJson(
  data: Uint8Array | ArrayBuffer,
  retTypes: IDL.Type[],
): unknown {
  const bytes = data instanceof Uint8Array ? data : new Uint8Array(data);
  const decoded = IDL.decode(retTypes, bytes);
  if (decoded.length === 0) return null;
  if (decoded.length === 1) return toJsonValueTyped(decoded[0], retTypes[0]);
  return decoded.map((v, i) => toJsonValueTyped(v, retTypes[i]));
}

/**
 * Convert a JSON value into the shape expected by @icp-sdk/core/candid IDL encoding.
 */
function convertValue(value: unknown, type: IDL.Type): unknown {
  if (type instanceof IDL.BoolClass) {
    return Boolean(value);
  }
  if (type instanceof IDL.TextClass) {
    return String(value);
  }
  if (type instanceof IDL.NatClass || type instanceof IDL.IntClass) {
    return BigInt(value as string | number);
  }
  // Fixed-width nat types (Nat8, Nat16, Nat32, Nat64)
  if (type instanceof IDL.FixedNatClass) {
    const bits = (type as IDL.FixedNatClass & { _bits: number })._bits;
    if (bits >= 64) {
      const n = BigInt(value as string | number);
      const max = (1n << BigInt(bits)) - 1n;
      if (n < 0n || n > max)
        throw new RangeError(`Nat${bits} value ${n} is out of range [0, ${max}]`);
      return n;
    }
    const n = Number(value);
    const max = 2 ** bits - 1;
    if (!Number.isInteger(n) || n < 0 || n > max)
      throw new RangeError(`Nat${bits} value ${n} is out of range [0, ${max}]`);
    return n;
  }
  // Fixed-width int types (Int8, Int16, Int32, Int64)
  if (type instanceof IDL.FixedIntClass) {
    const bits = (type as IDL.FixedIntClass & { _bits: number })._bits;
    if (bits >= 64) {
      const n = BigInt(value as string | number);
      const min = -(1n << BigInt(bits - 1));
      const max = (1n << BigInt(bits - 1)) - 1n;
      if (n < min || n > max)
        throw new RangeError(`Int${bits} value ${n} is out of range [${min}, ${max}]`);
      return n;
    }
    const n = Number(value);
    const min = -(2 ** (bits - 1));
    const max = 2 ** (bits - 1) - 1;
    if (!Number.isInteger(n) || n < min || n > max)
      throw new RangeError(`Int${bits} value ${n} is out of range [${min}, ${max}]`);
    return n;
  }
  if (type instanceof IDL.FloatClass) {
    return Number(value);
  }
  if (type instanceof IDL.PrincipalClass) {
    return Principal.fromText(value as string);
  }
  if (type instanceof IDL.VecClass) {
    // blob (vec nat8) encoded as base64
    const innerType = (type as IDL.VecClass<IDL.Type> & { _type: IDL.Type })
      ._type;
    if (innerType instanceof IDL.FixedNatClass && typeof value === "string") {
      const bits = (innerType as IDL.FixedNatClass & { _bits: number })._bits;
      if (bits === 8) {
        return base64ToUint8Array(value);
      }
    }
    if (!Array.isArray(value)) {
      throw new Error(`Expected array for vec type, got ${typeof value}`);
    }
    return value.map((item) => convertValue(item, innerType));
  }
  if (type instanceof IDL.OptClass) {
    if (value === null || value === undefined) {
      return [];
    }
    const innerType = (type as IDL.OptClass<IDL.Type> & { _type: IDL.Type })
      ._type;
    return [convertValue(value, innerType)];
  }
  if (type instanceof IDL.RecordClass) {
    const obj = value as Record<string, unknown>;
    const fields = (
      type as IDL.RecordClass & { _fields: [string, IDL.Type][] }
    )._fields;
    const result: Record<string, unknown> = {};
    for (const [fieldName, fieldType] of fields) {
      if (fieldName in obj) {
        result[fieldName] = convertValue(obj[fieldName], fieldType);
      }
    }
    return result;
  }
  if (type instanceof IDL.VariantClass) {
    // Variant: either a string (unit variant) or { Tag: payload }
    if (typeof value === "string") {
      return { [value]: null };
    }
    const obj = value as Record<string, unknown>;
    const tag = Object.keys(obj)[0];
    // Access _fields via bracket notation to bypass private access check
    const fields = (type as unknown as { _fields: [string, IDL.Type][] })
      ._fields;
    const fieldType = fields.find(
      ([name]: [string, IDL.Type]) => name === tag,
    );
    if (!fieldType) {
      throw new Error(`Unknown variant tag: ${tag}`);
    }
    return { [tag]: convertValue(obj[tag], fieldType[1]) };
  }
  if (type instanceof IDL.NullClass) {
    return null;
  }

  // Fallback: pass through
  return value;
}

/**
 * Type-aware converter: uses IDL type to correctly unwrap Opt, Vec, Record, etc.
 */
function toJsonValueTyped(value: unknown, type: IDL.Type): unknown {
  // Opt is decoded as [] (none) or [value] (some)
  if (type instanceof IDL.OptClass) {
    if (!Array.isArray(value) || value.length === 0) return null;
    const innerType = (type as IDL.OptClass<IDL.Type> & { _type: IDL.Type })._type;
    return toJsonValueTyped(value[0], innerType);
  }
  // blob (vec nat8) → base64
  if (type instanceof IDL.VecClass) {
    const innerType = (type as IDL.VecClass<IDL.Type> & { _type: IDL.Type })._type;
    if (innerType instanceof IDL.FixedNatClass) {
      const bits = (innerType as IDL.FixedNatClass & { _bits: number })._bits;
      if (bits === 8 && value instanceof Uint8Array) return uint8ArrayToBase64(value);
    }
    if (Array.isArray(value)) return value.map((v) => toJsonValueTyped(v, innerType));
  }
  // Record: recurse per-field
  if (type instanceof IDL.RecordClass) {
    const fields = (type as IDL.RecordClass & { _fields: [string, IDL.Type][] })._fields;
    const obj = value as Record<string, unknown>;
    const result: Record<string, unknown> = {};
    for (const [name, fieldType] of fields) {
      result[name] = toJsonValueTyped(obj[name], fieldType);
    }
    return result;
  }
  // Variant: unwrap the single key
  if (type instanceof IDL.VariantClass) {
    const fields = (type as unknown as { _fields: [string, IDL.Type][] })._fields;
    const obj = value as Record<string, unknown>;
    const tag = Object.keys(obj)[0];
    const fieldType = fields.find(([n]) => n === tag);
    if (fieldType) {
      const inner = toJsonValueTyped(obj[tag], fieldType[1]);
      return inner === null ? tag : { [tag]: inner };
    }
  }
  // Fallback to untyped
  return toJsonValue(value);
}

/**
 * Convert a decoded Candid value into a JSON-safe representation (untyped fallback).
 */
function toJsonValue(value: unknown): unknown {
  if (value === null || value === undefined) return null;
  if (typeof value === "bigint") return value.toString();
  if (value instanceof Principal) return value.toText();
  if (value instanceof Uint8Array) return uint8ArrayToBase64(value);
  if (Array.isArray(value)) return value.map(toJsonValue);
  if (typeof value === "object") {
    const result: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      // Guard against prototype pollution: skip keys that would mutate
      // Object.prototype or Function.prototype via property assignment.
      if (k === "__proto__" || k === "constructor" || k === "prototype") {
        continue;
      }
      result[k] = toJsonValue(v);
    }
    return result;
  }
  return value;
}

function base64ToUint8Array(base64: string): Uint8Array {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function uint8ArrayToBase64(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}
