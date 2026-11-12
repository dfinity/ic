use crate::{
    governance::PROPOSAL_EXECUTE_NNS_FUNCTION_PAYLOAD_BYTES_MAX,
    pb::v1::{
        Empty, SelfDescribingValue, SelfDescribingValueArray, SelfDescribingValueMap,
        self_describing_value::Value,
    },
    proposals::self_describing::{to_self_describing_int, to_self_describing_nat},
};

use candid::{
    DecoderConfig, IDLValue,
    types::value::{IDLField, VariantValue},
};
use candid_parser::{IDLArgs, IDLProg, TypeEnv, check_prog};
use std::{collections::HashMap, str::FromStr};

/// When the `encoded_len` of the `SelfDescribingProposalAction.value` field
/// exceeds this, then, that field is not populated. This only applies to
/// `ExecuteNnsFunction` proposals.
///
/// (Wasm modules do NOT cause this limit to be exceeded, because Wasm modules
/// get replaced with their hashes. Ditto for install args.)
///
/// ## Value Justification
///
/// Based on past proposals, this is very generous. As of late 2026, the largest
/// proposals were on the order of 10 KiB.
///
/// ## Motivation
///
/// As you would expect, this is to avoid using too much space. More
/// specifically, our goals are as follows:
///
/// 1. To avoid proposals taking up excessive memory.
/// 2. So that "many" proposals can fit in responses.
///
/// ## Interesting Related Facts
///
/// We figured the ratio between the amount of main memory allocated vs.
/// `encoded_len` was as follows:
///
/// * typical cases: about 10:1
/// * worst case: about 30:1
///
/// This was measured using a custom counting memory allocator.
pub(crate) const MAX_SELF_DESCRIBING_VALUE_ENCODED_LEN_BYTES: usize =
    PROPOSAL_EXECUTE_NNS_FUNCTION_PAYLOAD_BYTES_MAX; // 70_000 as of Nov, 2026.

/// Conversion factor between
///
/// - Candid's decoding cost units, and
/// - `encoded_len` of the resulting `SelfDescribingValue`.
///
/// ## How This is Used
///
/// Determines Candid's budget when decoding the `payload` of an
/// `ExecuteNnsFunction` proposal. The budget avoids wasting resources when the
/// resulting `SelfDescribingValue` would exceed
/// `MAX_SELF_DESCRIBING_VALUE_ENCODED_LEN_BYTES`.
///
/// ## Value Justification
///
/// In the worst case measured, the conversion factor was 4. A larger value is
/// used here so that all "good" proposals still receive a
/// `SelfDescribingProposalAction.value`, more or less. (Here, "good" means that
/// `MAX_SELF_DESCRIBING_VALUE_ENCODED_LEN_BYTES` is not exceeded.) At the same
/// time, we do not want to be overly generous, since that would lead to waste.
///
/// The measured value was determined as you would expect: a bunch of blobs were
/// Candid decoded. Then, cost of decoding was compared to the `encoded_len` of
/// the resulting `SelfDescribingValue`.
const PAYLOAD_DECODING_COST_PER_SELF_DESCRIBING_VALUE_BYTE: usize = 8;

/// When decoding to IDLValue (as opposed to a Rust type), Candid multiplies the decoding cost by
/// this factor (but not the skipping cost). See `add_cost` in candid's de.rs.
const CANDID_UNTYPED_DECODING_COST_MULTIPLIER: usize = 50;

/// Returns a `DecoderConfig` that puts a budget on the "effort" Candid should
/// expend when decoding the `payload` of an `ExecuteNnsFunction` proposal.
///
/// The goal here is to avoid wasting effort on decoding `payload`s when the
/// result is going to be thrown away later anyway due to exceeding
/// `MAX_SELF_DESCRIBING_VALUE_ENCODED_LEN_BYTES`.
///
/// To achieve that, the following formula is used:
///
/// ```text
///     payload_len
///         +
///     PAYLOAD_DECODING_COST_PER_SELF_DESCRIBING_VALUE_BYTE
///         *
///     MAX_SELF_DESCRIBING_VALUE_ENCODED_LEN_BYTES
/// ```
///
/// The first term is needed so that `payload`s that contain a Wasm module get
/// accepted. That term takes into account the fact that Wasm modules (which are
/// large blobs) are replaced with their hashes, which results in a much smaller
/// `SelfDescribingValue`.
fn new_decoder_config(payload_len: usize) -> DecoderConfig {
    let cost_limit = PAYLOAD_DECODING_COST_PER_SELF_DESCRIBING_VALUE_BYTE
        .saturating_mul(MAX_SELF_DESCRIBING_VALUE_ENCODED_LEN_BYTES)
        .saturating_add(payload_len);

    let mut config = DecoderConfig::new();

    // We want this to avoid Candid copying the entire `payload` into the error
    // message, which is something you don't want happening when the input is
    // untrusted, as is the case here (anyone can submit a proposal for not much
    // money).
    config.set_full_error_message(false);

    // Why we set both budgets: `payload` is decoded to IDLValue, which means
    // that Candid counts everything as "skipped". Skipped cost has a 50x
    // penalty on decoding cost (not sure why). If Candid never changes how it
    // does cost accounting, setting both of these is overkill, but we want to
    // defend against such changes, because the 50x penalty is not a documented
    // behavior, and is therefore highly subject to change.
    config.set_decoding_quota(cost_limit.saturating_mul(CANDID_UNTYPED_DECODING_COST_MULTIPLIER));
    config.set_skipping_quota(cost_limit);

    config
}

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

    // Parse the arguments using the method signature. The decoder config limits how much work
    // decoding may do, because encoded_args comes from whoever made the proposal.
    let decoder_config = new_decoder_config(encoded_args.len());
    let decoded_args = IDLArgs::from_bytes_with_types_with_config(
        encoded_args,
        &type_env,
        &method.args,
        &decoder_config,
    )
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
