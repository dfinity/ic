use crate::pb::v1::{SelfDescribingValue, SelfDescribingValueArray, SelfDescribingValueMap};

use candid::{IDLValue, Int, Nat, types::value::{IDLField, VariantValue}};
use candid_parser::{IDLArgs, IDLProg, TypeEnv, check_prog};
use std::{collections::HashMap, str::FromStr};

/// Converts candid arguments to a self-describing value using the candid source schema.
pub(crate) fn candid_to_self_describing(
    candid_source: &str,
    method_name: &str,
    args: &[u8],
) -> Result<SelfDescribingValue, String> {
    let arg = candid_to_idl(candid_source, method_name, args)?;
    Ok(idl_to_self_describing(arg))
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

    if idl_args.args.is_empty() {
        return Ok(IDLValue::Null);
    }

    // Check if we have exactly one argument (as expected for NNS functions)
    if idl_args.args.len() > 1 {
        return Err(format!(
            "Expected at most one argument, got {}",
            idl_args.args.len()
        ));
    }

    let arg = idl_args.args.into_iter().next().unwrap();
    Ok(arg)
}

fn idl_to_self_describing(idl: IDLValue) -> SelfDescribingValue {
    use crate::pb::v1::self_describing_value::Value::{
        Array, Blob, Int as IntVariant, Map, Nat as NatVariant, Text,
    };

    let value = match idl {
        IDLValue::Blob(bytes) => Blob(bytes),
        IDLValue::Bool(bool) => NatVariant(encode_nat(if bool {
            Nat::from(1u8)
        } else {
            Nat::from(0u8)
        })),
        IDLValue::Null => Array(SelfDescribingValueArray { values: vec![] }),
        IDLValue::Text(s) => Text(s),
        IDLValue::Number(s) => Text(s),
        IDLValue::Opt(value) => Array(SelfDescribingValueArray {
            values: vec![idl_to_self_describing(*value)],
        }),
        IDLValue::Vec(value) => convert_array_to_self_describing(value),
        IDLValue::Record(value) => Map(SelfDescribingValueMap {
            values: value
                .into_iter()
                .map(|field| (format!("{}", field.id), idl_to_self_describing(field.val)))
                .collect(),
        }),
        IDLValue::Variant(value) => convert_variant_to_self_describing(value),
        IDLValue::Principal(p) => Text(format!("{}", p)),
        IDLValue::None => Array(SelfDescribingValueArray { values: vec![] }),
        IDLValue::Int(i) => IntVariant(encode_int(i)),
        IDLValue::Nat(i) => NatVariant(encode_nat(i)),
        IDLValue::Nat8(i) => NatVariant(encode_nat(Nat::from(i))),
        IDLValue::Nat16(i) => NatVariant(encode_nat(Nat::from(i))),
        IDLValue::Nat32(i) => NatVariant(encode_nat(Nat::from(i))),
        IDLValue::Nat64(i) => NatVariant(encode_nat(Nat::from(i))),
        IDLValue::Int8(i) => IntVariant(encode_int(Int::from(i))),
        IDLValue::Int16(i) => IntVariant(encode_int(Int::from(i))),
        IDLValue::Int32(i) => IntVariant(encode_int(Int::from(i))),
        IDLValue::Int64(i) => IntVariant(encode_int(Int::from(i))),
        IDLValue::Float32(f) => Text(format!("{}", f)),
        IDLValue::Float64(f) => Text(format!("{}", f)),
        IDLValue::Reserved => Text(idl.to_string()),
        IDLValue::Service(_) | IDLValue::Func(..) => panic!("Unexpected IDLValue: {:?}", idl),
    };

    SelfDescribingValue { value: Some(value) }
}

fn convert_array_to_self_describing(
    value: Vec<IDLValue>,
) -> crate::pb::v1::self_describing_value::Value {
    use crate::pb::v1::self_describing_value::Value::{Array, Blob};

    match try_extract_bytes(value) {
        Ok(bytes) => Blob(bytes),
        Err(value) => Array(SelfDescribingValueArray {
            values: value.into_iter().map(idl_to_self_describing).collect(),
        }),
    }
}

fn convert_variant_to_self_describing(
    variant_value: VariantValue,
) -> crate::pb::v1::self_describing_value::Value {
    use crate::pb::v1::self_describing_value::Value::{Array, Map, Text};

    let IDLField { id, val } = *variant_value.0;
    let label = format!("{}", id);
    let generic_val = idl_to_self_describing(val);

    // Check if the value is an empty array (represents a unit variant)
    let is_empty_array = matches!(&generic_val.value, Some(Array(arr)) if arr.values.is_empty());

    if is_empty_array {
        Text(label)
    } else {
        let mut map = HashMap::new();
        map.insert(label, generic_val);
        Map(SelfDescribingValueMap { values: map })
    }
}

fn try_extract_bytes(value: Vec<IDLValue>) -> Result<Vec<u8>, Vec<IDLValue>> {
    // Sometimes a blob is represented as `vec nat8`, and in those cases we try to interpret it as a
    // blob first, but if any one of the values is not a nat8, we return the original value. In
    // practice, each value should have the same type, but we don't make such assumption here as
    // the `IDLValue` type does not make such assumption.
    let mut bytes = Vec::new();
    let mut is_bytes = true;
    for value in value.iter() {
        if let IDLValue::Nat8(byte) = value {
            bytes.push(*byte);
        } else {
            is_bytes = false;
        }
    }
    if is_bytes { Ok(bytes) } else { Err(value) }
}

fn encode_nat(n: Nat) -> Vec<u8> {
    let mut bytes = Vec::new();
    n.encode(&mut bytes).expect("Failed to encode Nat");
    bytes
}

fn encode_int(i: Int) -> Vec<u8> {
    let mut bytes = Vec::new();
    i.encode(&mut bytes).expect("Failed to encode Int");
    bytes
}

#[path = "candid_to_self_describing_tests.rs"]
#[cfg(test)]
pub mod tests;

