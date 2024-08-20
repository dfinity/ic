#[cfg(test)]
mod tests;

use candid::types::{Type, TypeInner};
use candid::TypeEnv;
use std::path::Path;

const EMPTY_UPGRADE_ARGS: &str = "()";

#[derive(Debug, Eq, PartialEq, Clone)]
pub struct UpgradeArgs {
    constructor_types: Vec<Type>,
    upgrade_args: String,
    encoded_upgrade_args: Vec<u8>,
    candid_file_name: String,
}

impl UpgradeArgs {
    pub fn upgrade_args_bin(&self) -> &[u8] {
        &self.encoded_upgrade_args
    }

    pub fn upgrade_args_hex(&self) -> String {
        hex::encode(&self.encoded_upgrade_args)
    }

    pub fn didc_encode_cmd(&self) -> String {
        if self.upgrade_args != EMPTY_UPGRADE_ARGS {
            format!(
                "didc encode -d {} -t '{}' '{}'",
                self.candid_file_name,
                format_types(&self.constructor_types),
                self.upgrade_args
            )
        } else {
            format!("didc encode '{}'", EMPTY_UPGRADE_ARGS)
        }
    }
}

pub fn encode_upgrade_args<F: Into<String>>(candid_file: &Path, upgrade_args: F) -> UpgradeArgs {
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
    let candid_file_name = candid_file
        .file_name()
        .expect("missing file name")
        .to_string_lossy()
        .to_string();
    UpgradeArgs {
        constructor_types: upgrade_types,
        upgrade_args,
        encoded_upgrade_args,
        candid_file_name,
    }
}

fn parse_constructor_args(candid_file: &Path) -> (TypeEnv, Vec<Type>) {
    let (env, class_type) =
        candid_parser::check_file(candid_file).expect("fail to parse candid file");
    let class_type = class_type.expect("missing class type");
    let constructor_types = match class_type.as_ref() {
        TypeInner::Class(constructor_types, _service_type) => constructor_types,
        type_inner => panic!("unexpected {:?}", type_inner),
    };
    (env, constructor_types.clone())
}

fn format_types(types: &[Type]) -> String {
    let types: Vec<_> = types.iter().map(Type::to_string).collect();
    format!("({})", types.join(", "))
}
