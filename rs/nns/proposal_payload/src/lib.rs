//! # IC NNS Proposal Payload
//!

use candid::{CandidType, Deserialize, IDLArgs, IDLValue, Int, Nat};
use candid_parser::{check_prog, IDLProg, TypeEnv};
use ic_crypto_sha2::Sha256;
use serde::Serialize;
use serde_json::Value as JsonValue;
use std::{collections::BTreeMap, str::FromStr};

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum GenericValue {
    Blob(Vec<u8>),
    Text(String),
    Nat(Nat),
    Int(Int),
    Array(Vec<GenericValue>),
    Map(BTreeMap<String, GenericValue>),
}

pub fn candid_to_json(
    candid_source: &str,
    method_name: &str,
    args: &[u8],
) -> Result<JsonValue, String> {
    let arg = candid_to_idl(candid_source, method_name, args)?;
    Ok(idl2json(arg))
}

pub fn candid_to_generic(
    candid_source: &str,
    method_name: &str,
    args: &[u8],
) -> Result<GenericValue, String> {
    let arg = candid_to_idl(candid_source, method_name, args)?;
    Ok(idl2generic(arg))
}

fn candid_to_idl(candid_source: &str, method_name: &str, args: &[u8]) -> Result<IDLValue, String> {
    // Parse the Candid source
    let candid_prog = IDLProg::from_str(candid_source)
        .map_err(|e| format!("Failed to parse candid source: {:?}", e))?;

    let mut type_env = TypeEnv::new();
    let service = check_prog(&mut type_env, &candid_prog)
        .map_err(|e| format!("Failed to check candid program: {:?}", e))?
        .ok_or_else(|| "Failed to parse candid: no service found".to_string())?;

    // Get the method signature
    let method = type_env
        .get_method(&service, method_name)
        .map_err(|e| format!("Failed to get method '{}': {:?}", method_name, e))?;

    // Parse the arguments using the method signature
    let idl_args = IDLArgs::from_bytes_with_types(args, &type_env, &method.args)
        .map_err(|e| format!("Failed to parse args: {:?}", e))?;

    // Check if we have exactly one argument (as expected for NNS functions)
    if idl_args.args.len() != 1 {
        return Err(format!(
            "Expected exactly one argument, got {}",
            idl_args.args.len()
        ));
    }

    let arg = idl_args.args.into_iter().next().unwrap();
    Ok(arg)
}

pub fn idl2generic(idl: IDLValue) -> GenericValue {
    match idl {
        IDLValue::Blob(bytes) => GenericValue::Text(convert_bytes(bytes)),
        IDLValue::Bool(bool) => {
            GenericValue::Nat(if bool { Nat::from(1u8) } else { Nat::from(0u8) })
        }
        IDLValue::Null => GenericValue::Array(vec![]),
        IDLValue::Text(s) => GenericValue::Text(s),
        IDLValue::Number(s) => GenericValue::Text(s),
        IDLValue::Opt(value) => GenericValue::Array(vec![idl2generic(*value)]),
        IDLValue::Vec(value) => convert_array_to_generic(value),
        IDLValue::Record(value) => GenericValue::Map(
            value
                .into_iter()
                .map(|field| (format!("{}", field.id), idl2generic(field.val)))
                .collect(),
        ),
        IDLValue::Variant(field) => GenericValue::Map(
            vec![(format!("{}", field.0.id), idl2generic(field.0.val))]
                .into_iter()
                .collect(),
        ),
        IDLValue::Principal(p) => GenericValue::Text(format!("{}", p)),
        IDLValue::None => GenericValue::Array(vec![]),
        IDLValue::Int(i) => GenericValue::Int(i),
        IDLValue::Nat(i) => GenericValue::Nat(i),
        IDLValue::Nat8(i) => GenericValue::Nat(Nat::from(i)),
        IDLValue::Nat16(i) => GenericValue::Nat(Nat::from(i)),
        IDLValue::Nat32(i) => GenericValue::Nat(Nat::from(i)),
        IDLValue::Nat64(i) => GenericValue::Nat(Nat::from(i)),
        IDLValue::Int8(i) => GenericValue::Int(Int::from(i)),
        IDLValue::Int16(i) => GenericValue::Int(Int::from(i)),
        IDLValue::Int32(i) => GenericValue::Int(Int::from(i)),
        IDLValue::Int64(i) => GenericValue::Int(Int::from(i)),
        IDLValue::Float32(f) => GenericValue::Text(format!("{}", f)),
        IDLValue::Float64(f) => GenericValue::Text(format!("{}", f)),
        IDLValue::Reserved => GenericValue::Text(idl.to_string()),
        IDLValue::Service(_) | IDLValue::Func(..) => panic!("Unexpected IDLValue: {:?}", idl),
    }
}

pub fn idl2json(idl: IDLValue) -> JsonValue {
    match idl {
        IDLValue::Blob(bytes) => JsonValue::String(convert_bytes(bytes)),
        IDLValue::Bool(bool) => JsonValue::Bool(bool),
        IDLValue::Null => JsonValue::Null,
        IDLValue::Text(s) => JsonValue::String(s.clone()),
        IDLValue::Number(s) => JsonValue::String(s.clone()),
        IDLValue::Opt(value) => JsonValue::Array(vec![idl2json(*value)]),
        IDLValue::Vec(value) => convert_array_to_json(value),
        IDLValue::Record(value) => JsonValue::Object(
            value
                .into_iter()
                .map(|field| (format!("{}", field.id), idl2json(field.val)))
                .collect(),
        ),
        IDLValue::Variant(field) => JsonValue::Object(
            vec![(format!("{}", field.0.id), idl2json(field.0.val))]
                .into_iter()
                .collect(),
        ),
        IDLValue::Principal(p) => JsonValue::String(format!("{}", p)),
        IDLValue::None => JsonValue::Array(vec![]),
        IDLValue::Int(i) => JsonValue::String(format!("{}", i)),
        IDLValue::Nat(i) => JsonValue::String(format!("{}", i)),
        IDLValue::Nat8(i) => JsonValue::Number(serde_json::Number::from(i)),
        IDLValue::Nat16(i) => JsonValue::Number(serde_json::Number::from(i)),
        IDLValue::Nat32(i) => JsonValue::Number(serde_json::Number::from(i)),
        IDLValue::Nat64(i) => JsonValue::Number(serde_json::Number::from(i)),
        IDLValue::Int8(i) => JsonValue::Number(serde_json::Number::from(i)),
        IDLValue::Int16(i) => JsonValue::Number(serde_json::Number::from(i)),
        IDLValue::Int32(i) => JsonValue::Number(serde_json::Number::from(i)),
        IDLValue::Int64(i) => JsonValue::Number(serde_json::Number::from(i)),
        IDLValue::Float32(f) => serde_json::Number::from_f64(f as f64)
            .map(JsonValue::Number)
            .unwrap_or_else(|| JsonValue::String("NaN".to_string())),
        IDLValue::Float64(f) => serde_json::Number::from_f64(f)
            .map(JsonValue::Number)
            .unwrap_or_else(|| JsonValue::String("NaN".to_string())),
        IDLValue::Reserved => JsonValue::String(idl.to_string()),
        IDLValue::Service(_) | IDLValue::Func(..) => panic!("Unexpected IDLValue: {:?}", idl),
    }
}

fn convert_array_to_json(value: Vec<IDLValue>) -> JsonValue {
    match try_extract_bytes(value) {
        Ok(bytes) => JsonValue::String(convert_bytes(bytes)),
        Err(value) => JsonValue::Array(value.into_iter().map(idl2json).collect()),
    }
}

fn convert_array_to_generic(value: Vec<IDLValue>) -> GenericValue {
    match try_extract_bytes(value) {
        Ok(bytes) => GenericValue::Text(convert_bytes(bytes)),
        Err(value) => GenericValue::Array(value.into_iter().map(idl2generic).collect()),
    }
}

fn try_extract_bytes(value: Vec<IDLValue>) -> Result<Vec<u8>, Vec<IDLValue>> {
    let mut bytes = Vec::new();
    let mut is_bytes = true;
    for value in value.iter() {
        if let IDLValue::Nat8(byte) = value {
            bytes.push(*byte);
        } else {
            is_bytes = false;
        }
    }
    if is_bytes {
        Ok(bytes)
    } else {
        Err(value)
    }
}

fn convert_bytes(bytes: Vec<u8>) -> String {
    if bytes.len() > 100 {
        let first_4_hex = hex::encode(&bytes[..4]);
        let last_4_hex = hex::encode(&bytes[bytes.len() - 4..]);
        format!(
            "[{}...{}](len:{};sha256:{})",
            first_4_hex,
            last_4_hex,
            bytes.len(),
            sha256_hex(&bytes)
        )
    } else {
        hex::encode(&bytes)
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.write(bytes);
    hex::encode(hasher.finish())
}
