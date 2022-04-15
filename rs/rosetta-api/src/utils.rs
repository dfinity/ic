use clap::Parser;
use ic_types::PrincipalId;
use ledger_canister::AccountIdentifier;
use std::convert::TryFrom;
use std::str::FromStr;

/// Some utils for tasks we have to do a lot

fn main() {
    let opt = Opt::parse();
    for s in opt.convert.into_iter() {
        match PrincipalId::from_str(&s)
            .map_err(|e| e.to_string())
            .or_else(|_| {
                PrincipalId::try_from(hex::decode(s.clone()).map_err(|e| e.to_string())?)
                    .map_err(|e| e.to_string())
            }) {
            Ok(pid) => {
                let aid: AccountIdentifier = pid.into();
                println!("{} → {}", s, aid)
            }
            Err(err) => println!("Failed to decode {}, {}", s, err),
        }
    }
}

#[derive(Debug, Parser)]
#[clap(version)]
struct Opt {
    #[clap(short = 'c', long = "convert_address", multiple_values(true))]
    convert: Vec<String>,
}
