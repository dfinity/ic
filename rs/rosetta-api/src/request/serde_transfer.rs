use ledger_canister::{AccountIdentifier, Operation, Tokens};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::convert::TryFrom;

/// A helper for serializing `TransactionResults`
pub fn deserialize<'d, D: Deserializer<'d>>(d: D) -> Result<Operation, D::Error> {
    Send::deserialize(d)
        .map(Operation::from)
        .map_err(D::Error::from)
}

pub fn serialize<S: Serializer>(t: &Operation, s: S) -> Result<S::Ok, S::Error> {
    Send::try_from(t)
        .map_err(serde::ser::Error::custom)
        .and_then(|t| t.serialize(s))
}

#[derive(Copy, Clone, Deserialize, Serialize)]
struct Send {
    from: AccountIdentifier,
    to: AccountIdentifier,
    amount: Tokens,
    fee: Tokens,
}

impl TryFrom<&Operation> for Send {
    type Error = String;

    fn try_from(transfer: &Operation) -> Result<Self, String> {
        match *transfer {
            Operation::Transfer {
                from,
                to,
                amount,
                fee,
            } => Ok(Send {
                from,
                to,
                amount,
                fee,
            }),
            Operation::Burn { .. } => {
                Err("Burn operations are not supported through rosetta".to_owned())
            }
            Operation::Mint { .. } => {
                Err("Mint operations are not supported through rosetta".to_owned())
            }
        }
    }
}

impl From<Send> for Operation {
    fn from(s: Send) -> Self {
        let Send {
            from,
            to,
            amount,
            fee,
        } = s;
        Operation::Transfer {
            from,
            to,
            amount,
            fee,
        }
    }
}
