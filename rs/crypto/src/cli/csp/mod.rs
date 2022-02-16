//! Command line interface for the crypto service provider (CSP) layer.
//!
//! Subcommands are used to direct work to subcomponents.
use std::str::FromStr;
use std::string::ToString;
use strum::IntoEnumIterator;
use strum_macros::{Display, EnumIter, EnumString};

mod multi;

#[derive(EnumString, EnumIter, Display)]
#[strum(serialize_all = "snake_case")]
enum Command {
    Sign,
    Multi,
    Threshold,
}

fn help_str() -> String {
    Command::iter().fold("Subcommands:\n".to_string(), |accumulator, next| {
        format!("{}{}\n", accumulator, next)
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
                Command::Multi => multi::main(args),
                _ => unimplemented!(),
            }
        }
    }
}
