use candid::types::{subtype::subtype, Type};
use candid_parser::{
    parse_idl_args,
    utils::{instantiate_candid, CandidSource},
};

/// Checks whether `upgrade_args` is a valid argument sequence for `candid_service`.
///
/// Returns the byte encoding of `upgrade_args` in the successful case.
pub fn validate_upgrade_args(
    candid_service: String,
    upgrade_args: String,
) -> Result<Vec<u8>, String> {
    let upgrade_args = parse_idl_args(&upgrade_args).map_err(|err| format!("{err:?}"))?;
    let args_types = upgrade_args.get_types();

    let (expected_args_types, (env, _)) = instantiate_candid(CandidSource::Text(&candid_service))
        .map_err(|err| format!("{err:?}"))?;

    fn fmt_type_vec(types: &Vec<Type>) -> String {
        let tab = " ".repeat(4);
        let types_str = if types.is_empty() {
            "// <empty>".to_string()
        } else {
            types
                .iter()
                .map(|typ| typ.to_string())
                .collect::<Vec<_>>()
                .join(&format!(",\n{tab}"))
        };
        format!("```candid\n(\n{tab}{types_str}\n)\n```\n")
    }

    if args_types.len() != expected_args_types.len() {
        return Err(format!(
            "Number of specified upgrade arguments ({}) does not match expected number \
             of arguments for the target canister ({}).",
            args_types.len(),
            expected_args_types.len(),
        ));
    }

    let mut gamma = std::collections::HashSet::new();

    let subtyping_subresults = args_types
        .iter()
        .zip(expected_args_types.iter())
        .map(|(observed_type, expected_type)| {
            subtype(&mut gamma, &env, &observed_type, &expected_type)
                .map_err(|err| format!("{err:?}"))
        })
        .collect::<Vec<_>>();

    if subtyping_subresults != vec![Ok(()); subtyping_subresults.len()] {
        return Err(format!(
            "Specified upgrade arguments have types:\n{}\
             that are not subtypes of the Candid service arguments' types:\n{}\n\
             {subtyping_subresults:#?}",
            fmt_type_vec(&args_types),
            fmt_type_vec(&expected_args_types),
        ));
    }

    let upgrade_args = upgrade_args.to_bytes().map_err(|err| format!("{err:?}"))?;

    Ok(upgrade_args)
}

#[cfg(test)]
mod tests;
