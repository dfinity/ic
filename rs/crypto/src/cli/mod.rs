//! Command line interface for the crypto component.
//!
//! The CLI is for demo/testing purposes and not for use in production.
//!
//! Subcommands are used to direct work to subcomponents.
use crate::common::utils::csp_at_root;
use ic_crypto_internal_csp::secret_key_store::proto_store::ProtoSecretKeyStore;
use ic_crypto_internal_csp::Csp;
use rand_core::OsRng;
use std::str::FromStr;
use strum::IntoEnumIterator;
use strum_macros::{Display, EnumIter, EnumString};

mod clib;
pub mod csp;

#[derive(EnumString, EnumIter, Display)]
#[strum(serialize_all = "snake_case")]
enum Command {
    Lib,
    Csp,
    Idkm,
}

fn help_str() -> String {
    Command::iter().fold("Subcommands:\n".to_string(), |accumulator, next| {
        format!("{}{}\n", accumulator, next.to_string())
    })
}

/// Processes a command from the command line.
pub fn main(args: &[String]) -> Result<(), (String, i32)> {
    match args {
        [] => Err((help_str(), 1)),
        _ => {
            let command = Command::from_str(&args[0]).map_err(|_| {
                (
                    format!("Unsupported subcommand '{}'.\n{}", args[0], help_str()),
                    1,
                )
            })?;
            let args = &args[1..];
            match command {
                Command::Lib => clib::main(args),
                Command::Csp => csp::main(args),
                _ => unimplemented!(),
            }
        }
    }
}

/// Creates a Crypto Service Provider (CSP) in the current working directory.
/// This is used for the command line interface (CLI).
pub fn csp() -> Csp<OsRng, ProtoSecretKeyStore, ProtoSecretKeyStore> {
    let path = std::env::current_dir()
        .expect("Cannot get current working directory")
        .join(".secret_key_store");
    csp_at_root(&path)
}
