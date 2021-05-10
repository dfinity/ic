//! Command line interface for threshold signatures
use std::str::FromStr;
use strum::IntoEnumIterator;
use strum_macros::{EnumIter, EnumString, ToString};

mod bench;
mod combine_signatures;
mod combined_public_key;
mod individual_public_key;
mod keygen;
mod sign;
mod verify_combined;
mod verify_individual;

#[derive(EnumString, EnumIter, ToString)]
#[strum(serialize_all = "snake_case")]
enum Command {
    Keygen,
    IndividualPublicKey,
    CombinedPublicKey,
    CombineSignatures,
    VerifyIndividual,
    VerifyCombined,
    Bench,
    Sign,
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
                Command::Keygen => keygen::main(args),
                Command::IndividualPublicKey => individual_public_key::main(args),
                Command::CombinedPublicKey => combined_public_key::main(args),
                Command::Sign => sign::main(args),
                Command::CombineSignatures => combine_signatures::main(args),
                Command::VerifyIndividual => verify_individual::main(args),
                Command::VerifyCombined => verify_combined::main(args),
                Command::Bench => bench::main(args),
            }
        }
    }
}
