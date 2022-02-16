//! Command line for basic signatures
use std::str::FromStr;
use strum::IntoEnumIterator;
use strum_macros::{Display, EnumIter, EnumString};

mod bench;
mod keygen;
mod sign;
mod verify;

#[derive(EnumString, EnumIter, Display)]
#[strum(serialize_all = "snake_case")]
enum Command {
    Keygen,
    Sign,
    Verify,
    Bench,
}

fn help_str() -> String {
    Command::iter().fold("Subcommands:\n".to_string(), |accumulator, next| {
        format!("{}{}\n", accumulator, next)
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
                Command::Keygen => keygen::main(args),
                Command::Sign => sign::main(args),
                Command::Verify => verify::main(args),
                Command::Bench => bench::main(args),
            }
        }
    }
}
