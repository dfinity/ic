//! Command line for crypto lib.
//! Subcommands are used to direct work to subcomponents.
use std::str::FromStr;
use strum::IntoEnumIterator;
use strum_macros::{EnumIter, EnumString, ToString};

mod basic_sig;
mod hash;
mod multi_sig;
mod threshold_sig;

#[derive(EnumString, EnumIter, ToString)]
#[strum(serialize_all = "snake_case")]
enum Command {
    Hash,
    BasicSig,
    MultiSig,
    ThresholdSig,
}

fn help_str() -> String {
    Command::iter().fold("Subcommands:\n".to_string(), |accumulator, next| {
        format!("{}{}\n", accumulator, next.to_string())
    })
}

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
                Command::Hash => hash::main(args),
                Command::BasicSig => basic_sig::main(args),
                Command::MultiSig => multi_sig::main(args),
                Command::ThresholdSig => threshold_sig::main(args),
            }
        }
    }
}
