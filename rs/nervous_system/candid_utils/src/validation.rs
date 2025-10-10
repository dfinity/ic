use candid::types::{
    Type,
    subtype::{OptReport, subtype_with_config},
};
use candid_parser::{
    parse_idl_args,
    utils::{CandidSource, instantiate_candid},
};

fn fmt_type_vec(types: &[Type]) -> String {
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

#[derive(Debug)]
pub enum CandidServiceArgValidationError {
    BadService(String),
    ArgsParseError(String),
    WrongArgumentCount(String),
    SubtypingErrors(String),
    ArgsSerializationError(String),
}

impl PartialEq for CandidServiceArgValidationError {
    fn eq(&self, other: &Self) -> bool {
        matches!(
            (self, other),
            (Self::BadService(_), Self::BadService(_))
                | (Self::ArgsParseError(_), Self::ArgsParseError(_))
                | (Self::WrongArgumentCount(_), Self::WrongArgumentCount(_))
                | (Self::SubtypingErrors(_), Self::SubtypingErrors(_))
                | (
                    Self::ArgsSerializationError(_),
                    Self::ArgsSerializationError(_)
                )
        )
    }
}

impl CandidServiceArgValidationError {
    fn deconstruct(&self) -> (String, String) {
        match self {
            Self::BadService(err) => ("BadService".to_string(), err.clone()),
            Self::ArgsParseError(err) => ("ArgsParseError".to_string(), err.clone()),
            Self::WrongArgumentCount(err) => ("WrongArgumentCount".to_string(), err.clone()),
            Self::SubtypingErrors(err) => ("SubtypingErrors".to_string(), err.clone()),
            Self::ArgsSerializationError(err) => {
                ("ArgsSerializationError".to_string(), err.clone())
            }
        }
    }

    pub fn message(&self) -> String {
        let (_, msg) = self.deconstruct();
        msg
    }

    pub fn kind(&self) -> String {
        let (kind, _) = self.deconstruct();
        kind
    }
}

impl std::fmt::Display for CandidServiceArgValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (kind, message) = self.deconstruct();
        write!(f, "CandidServiceArgValidationError::{kind}: {message}")
    }
}

/// Checks whether `upgrade_args` is a valid argument sequence for `candid_service`.
///
/// If `upgrade_args` is None, checks that `candid_service` does not require any arguments.
///
/// Example `upgrade_args` with two arguments: "((42 : nat32), opt record { foo = opt bar; })".
///
/// Returns the byte encoding of `upgrade_args` (if any; otherwise None) in the successful case.
pub fn encode_upgrade_args(
    candid_service: String,
    upgrade_args: Option<String>,
) -> Result<Option<Vec<u8>>, CandidServiceArgValidationError> {
    let (expected_args_types, (env, _)) =
        instantiate_candid(CandidSource::Text(&candid_service))
            .map_err(|err| CandidServiceArgValidationError::BadService(format!("{err:?}")))?;

    let (upgrade_args, args_types) = if let Some(upgrade_args) = upgrade_args {
        let upgrade_args = parse_idl_args(&upgrade_args)
            .map_err(|err| CandidServiceArgValidationError::ArgsParseError(format!("{err:?}")))?;

        let types = upgrade_args.get_types();

        (Some(upgrade_args), types)
    } else {
        (None, vec![])
    };

    if args_types.len() != expected_args_types.len() {
        return Err(CandidServiceArgValidationError::WrongArgumentCount(
            format!(
                "Number of specified upgrade arguments ({}) does not match expected number \
                 of arguments for the target canister ({}).",
                args_types.len(),
                expected_args_types.len(),
            ),
        ));
    }

    let Some(upgrade_args) = upgrade_args else {
        return Ok(None);
    };

    let mut gamma = std::collections::HashSet::new();

    let subtyping_subresults = args_types
        .iter()
        .zip(expected_args_types.iter())
        .map(|(observed_type, expected_type)| {
            subtype_with_config(
                OptReport::Error,
                &mut gamma,
                &env,
                observed_type,
                expected_type,
            )
            .map_err(|err| format!("{err:?}"))
        })
        .collect::<Vec<_>>();

    if subtyping_subresults != vec![Ok(()); subtyping_subresults.len()] {
        return Err(CandidServiceArgValidationError::SubtypingErrors(format!(
            "Specified upgrade arguments have types:\n{}\
             that are not subtypes of the Candid service arguments' types:\n{}\n\
             {subtyping_subresults:#?}",
            fmt_type_vec(&args_types),
            fmt_type_vec(&expected_args_types),
        )));
    }

    let upgrade_args = upgrade_args.to_bytes().map_err(|err| {
        CandidServiceArgValidationError::ArgsSerializationError(format!("{err:?}"))
    })?;

    Ok(Some(upgrade_args))
}

/// Returns the byte encoding of `upgrade_args` in the Ok result.
///
/// WARNING. Please use the [encode_upgrade_args] function instead. This function is only
/// suitable for best-effort upgrades in which the Candid service is not available.
pub fn encode_upgrade_args_without_service(
    upgrade_args: String,
) -> Result<Vec<u8>, CandidServiceArgValidationError> {
    let upgrade_args = parse_idl_args(&upgrade_args)
        .map_err(|err| CandidServiceArgValidationError::ArgsParseError(format!("{err:?}")))?;

    let upgrade_args = upgrade_args.to_bytes().map_err(|err| {
        CandidServiceArgValidationError::ArgsSerializationError(format!("{err:?}"))
    })?;

    Ok(upgrade_args)
}

#[cfg(test)]
mod tests;
