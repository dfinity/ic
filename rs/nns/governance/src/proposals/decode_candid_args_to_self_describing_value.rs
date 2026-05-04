use crate::{
    pb::v1::{
        Empty, SelfDescribingValue, SelfDescribingValueArray, SelfDescribingValueMap,
        self_describing_value::Value,
    },
    proposals::self_describing::{to_self_describing_int, to_self_describing_nat},
};

use candid::{
    IDLValue,
    types::value::{IDLField, VariantValue},
};
use candid_parser::{IDLArgs, IDLProg, TypeEnv, check_prog};
use std::{collections::HashMap, str::FromStr};

/// Converts encoded candid method arguments to a self-describing value, per the schema/interface
/// definition.
#[allow(dead_code)]
pub(crate) fn decode_candid_args_to_self_describing_value(
    schema: &str,
    method_name: &str,
    encoded_args: &[u8],
) -> Result<SelfDescribingValue, String> {
    let arg = convert_encoded_candid_args_to_idl(schema, method_name, encoded_args)?;
    Ok(SelfDescribingValue {
        value: Some(candid_value_to_self_describing(arg)),
    })
}

fn convert_encoded_candid_args_to_idl(
    schema: &str,
    method_name: &str,
    encoded_args: &[u8],
) -> Result<IDLValue, String> {
    // Parse the Candid source
    let schema =
        IDLProg::from_str(schema).map_err(|e| format!("Failed to parse candid source: {:?}", e))?;

    let mut type_env = TypeEnv::new();
    let service = check_prog(&mut type_env, &schema)
        .map_err(|e| format!("Failed to check candid program: {:?}", e))?
        .ok_or_else(|| "Failed to parse candid: no service found".to_string())?;

    // Get the method signature
    let method = type_env
        .get_method(&service, method_name)
        .map_err(|e| format!("Failed to get method '{}': {:?}", method_name, e))?;

    // Parse the arguments using the method signature
    let decoded_args = IDLArgs::from_bytes_with_types(encoded_args, &type_env, &method.args)
        .map_err(|e| format!("Failed to parse args: {:?}", e))?;

    if decoded_args.args.is_empty() {
        return Ok(IDLValue::Null);
    }

    // Check if we have exactly one argument (as expected for NNS functions)
    if decoded_args.args.len() > 1 {
        return Err(format!(
            "Expected at most one argument, got {}",
            decoded_args.args.len()
        ));
    }

    let decoded_arg = decoded_args.args.into_iter().next().unwrap();
    Ok(decoded_arg)
}

fn candid_value_to_self_describing(candid_value: IDLValue) -> Value {
    match candid_value {
        // Boolean types are converted to Nat.
        IDLValue::Bool(bool) => Value::Bool(bool),

        // Unsigned integer types are converted to Nat.
        IDLValue::Nat(i) => to_self_describing_nat(i),
        IDLValue::Nat8(n) => to_self_describing_nat(n),
        IDLValue::Nat16(n) => to_self_describing_nat(n),
        IDLValue::Nat32(n) => to_self_describing_nat(n),
        IDLValue::Nat64(n) => to_self_describing_nat(n),

        // Signed integer types are converted to Int.
        IDLValue::Int(i) => to_self_describing_int(i),
        IDLValue::Int8(i) => to_self_describing_int(i),
        IDLValue::Int16(i) => to_self_describing_int(i),
        IDLValue::Int32(i) => to_self_describing_int(i),
        IDLValue::Int64(i) => to_self_describing_int(i),

        // Floating point types are converted to Text.
        IDLValue::Float32(f) => Value::Text(format!("{}", f)),
        IDLValue::Float64(f) => Value::Text(format!("{}", f)),

        // This should be unreacheable as no type in candid is represented as this `Number` type,
        // but we convert it anyway. Also, the content of the `Number` type is already a string,
        IDLValue::Number(s) => Value::Text(s),

        IDLValue::Blob(bytes) => Value::Blob(bytes),
        IDLValue::Text(s) => Value::Text(s),
        IDLValue::Principal(p) => Value::Text(format!("{}", p)),

        IDLValue::Opt(value) => candid_value_to_self_describing(*value),
        IDLValue::Null | IDLValue::None | IDLValue::Reserved => Value::Null(Empty {}),

        IDLValue::Vec(value) => Value::Array(SelfDescribingValueArray {
            values: value
                .into_iter()
                .map(|idl_value| SelfDescribingValue {
                    value: Some(candid_value_to_self_describing(idl_value)),
                })
                .collect(),
        }),
        IDLValue::Record(value) => Value::Map(SelfDescribingValueMap {
            values: value
                .into_iter()
                .map(|field| {
                    (
                        format!("{}", field.id),
                        SelfDescribingValue {
                            value: Some(candid_value_to_self_describing(field.val)),
                        },
                    )
                })
                .collect(),
        }),
        IDLValue::Variant(value) => convert_variant_to_self_describing(value),

        IDLValue::Service(_) | IDLValue::Func(..) => {
            panic!("Unexpected IDLValue: {:?}", candid_value)
        }
    }
}

fn convert_variant_to_self_describing(
    variant_value: VariantValue,
) -> crate::pb::v1::self_describing_value::Value {
    use crate::pb::v1::self_describing_value::Value::{Map, Null, Text};

    let IDLField { id, val } = *variant_value.0;
    let label = format!("{}", id);
    let generic_val = candid_value_to_self_describing(val);

    // Check if the value is a unit variant (null)
    let is_null = matches!(&generic_val, Null(_));

    if is_null {
        Text(label)
    } else {
        let mut map = HashMap::new();
        map.insert(
            label,
            SelfDescribingValue {
                value: Some(generic_val),
            },
        );
        Map(SelfDescribingValueMap { values: map })
    }
}

#[path = "decode_candid_args_to_self_describing_value_tests.rs"]
#[cfg(test)]
pub mod tests;
