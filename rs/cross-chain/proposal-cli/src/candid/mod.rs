#[cfg(test)]
mod tests;

use crate::canister::TargetCanister;
use crate::git::ArgsHash;
use candid::TypeEnv;
use candid::types::{Type, TypeInner};
use std::path::Path;

const EMPTY_UPGRADE_ARGS: &str = "()";

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct UpgradeArgs {
    constructor_types: Vec<Type>,
    upgrade_args: String,
    encoded_upgrade_args: Vec<u8>,
    args_sha256: ArgsHash,
    candid_file_path: String,
}

impl UpgradeArgs {
    pub fn upgrade_args_bin(&self) -> &[u8] {
        &self.encoded_upgrade_args
    }

    pub fn args_sha256_hex(&self) -> String {
        self.args_sha256.to_string()
    }

    pub fn didc_encode_cmd(&self) -> String {
        if self.upgrade_args != EMPTY_UPGRADE_ARGS {
            format!(
                "didc encode -d {} -t '{}' '{}'",
                self.candid_file_path,
                format_types(&self.constructor_types),
                self.upgrade_args
            )
        } else {
            format!("didc encode '{EMPTY_UPGRADE_ARGS}'")
        }
    }
}

pub fn encode_upgrade_args<F: Into<String>>(
    canister: &TargetCanister,
    candid_file: &Path,
    upgrade_args: F,
) -> UpgradeArgs {
    let upgrade_args: String = upgrade_args.into();
    let (env, upgrade_types) = if upgrade_args != EMPTY_UPGRADE_ARGS {
        parse_constructor_args(candid_file)
    } else {
        (TypeEnv::new(), vec![])
    };
    let encoded_upgrade_args = candid_parser::parse_idl_args(&upgrade_args)
        .expect("fail to parse upgrade args")
        .to_bytes_with_types(&env, &upgrade_types)
        .expect("failed to encode");
    let args_sha256 = ArgsHash::sha256(&encoded_upgrade_args);
    let repo_candid_file = canister.candid_file().to_string_lossy().to_string();
    UpgradeArgs {
        constructor_types: upgrade_types,
        upgrade_args,
        encoded_upgrade_args,
        args_sha256,
        candid_file_path: repo_candid_file,
    }
}

fn parse_constructor_args(candid_file: &Path) -> (TypeEnv, Vec<Type>) {
    let (env, class_type) =
        candid_parser::check_file(candid_file).expect("fail to parse candid file");
    let class_type = class_type.expect("missing class type");
    let constructor_types = match class_type.as_ref() {
        TypeInner::Class(constructor_types, _service_type) => constructor_types,
        type_inner => panic!("unexpected {type_inner:?}"),
    };
    (env, constructor_types.clone())
}

fn format_types(types: &[Type]) -> String {
    let types: Vec<_> = types.iter().map(Type::to_string).collect();
    format!("({})", types.join(", "))
}
