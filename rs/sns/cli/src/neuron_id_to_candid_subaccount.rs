use anyhow::{Result, bail};
use candid_utils::printing;
use clap::Parser;
use ic_sns_governance_api::pb::v1::NeuronId;
use std::str::FromStr;

#[derive(Clone, Debug)]
pub struct ParsedSnsNeuron(pub NeuronId);

impl FromStr for ParsedSnsNeuron {
    type Err = hex::FromHexError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(NeuronId {
            id: hex::decode(s)?,
        }))
    }
}

#[derive(Debug, Parser)]
pub struct NeuronIdToCandidSubaccountArgs {
    /// The SNS neuron ID to be converted to a candid subaccount blob.
    pub neuron_id: ParsedSnsNeuron,

    /// If true, print an escaped version of the candid, useful for pasting into
    /// bash for example. Default is false.
    #[clap(long)]
    pub escaped: bool,
}

pub fn neuron_id_to_subaccount(args: NeuronIdToCandidSubaccountArgs) -> Result<String> {
    let subaccount = args.neuron_id.0.id.to_vec();

    // Subaccounts are arbitrary 32-byte values.
    if subaccount.len() != 32 {
        bail!(format!(
            "Invalid subaccount, expected 32 bytes, got {} bytes.",
            subaccount.len()
        ));
    }

    // We'll convert it to a candid string.
    let idl = printing::pretty(&subaccount).unwrap();

    if args.escaped {
        Ok(idl.replace('\\', "\\\\").replace('\"', "\\\""))
    } else {
        Ok(idl)
    }
}

pub fn exec(args: NeuronIdToCandidSubaccountArgs) -> Result<()> {
    println!("{}", neuron_id_to_subaccount(args)?);
    Ok(())
}

#[test]
fn test_neuron_id_to_subaccount() {
    let neuron_id = ParsedSnsNeuron::from_str(
        "9f5f9fda77a03e7177126d0be8c99e931a5381731d00da53ede363140e1be5d6",
    )
    .unwrap()
    .0;
    let expected_candid = r#"blob "\9f\5f\9f\da\77\a0\3e\71\77\12\6d\0b\e8\c9\9e\93\1a\53\81\73\1d\00\da\53\ed\e3\63\14\0e\1b\e5\d6""#;

    let args = NeuronIdToCandidSubaccountArgs {
        neuron_id: ParsedSnsNeuron(neuron_id),
        escaped: false,
    };
    let observed_subaccount = neuron_id_to_subaccount(args).unwrap();

    assert_eq!(observed_subaccount, expected_candid);
}

#[test]
fn test_neuron_id_to_subaccount_escaped() {
    let neuron_id = ParsedSnsNeuron::from_str(
        "9f5f9fda77a03e7177126d0be8c99e931a5381731d00da53ede363140e1be5d6",
    )
    .unwrap()
    .0;
    let expected_candid = r#"blob \"\\9f\\5f\\9f\\da\\77\\a0\\3e\\71\\77\\12\\6d\\0b\\e8\\c9\\9e\\93\\1a\\53\\81\\73\\1d\\00\\da\\53\\ed\\e3\\63\\14\\0e\\1b\\e5\\d6\""#;

    let args = NeuronIdToCandidSubaccountArgs {
        neuron_id: ParsedSnsNeuron(neuron_id),
        escaped: true,
    };
    let observed_subaccount = neuron_id_to_subaccount(args).unwrap();

    assert_eq!(observed_subaccount, expected_candid);
}

#[test]
fn test_neuron_id_to_subaccount_fail() {
    let neuron_id = ParsedSnsNeuron::from_str(
        "9f5f9fda77a03e7177126d0be8c99e931a5381731d00da53ede363140e1be5", // one character too short
    )
    .unwrap()
    .0;

    let args = NeuronIdToCandidSubaccountArgs {
        neuron_id: ParsedSnsNeuron(neuron_id),
        escaped: false,
    };
    let error = neuron_id_to_subaccount(args).unwrap_err().to_string();

    assert_eq!(
        error,
        "Invalid subaccount, expected 32 bytes, got 31 bytes."
    );
}
