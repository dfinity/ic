use std::{convert::TryFrom, str::FromStr};

use ic_types::{
    messages::{HttpRequestEnvelope, HttpSubmitContent},
    PrincipalId,
};
use ledger_canister::{HashOf, SendArgs, Transaction};
use serde::{Deserialize, Serialize};

use crate::{convert, errors::ApiError, request_types::RequestType};

pub const NEURON_MANAGEMEN_PSEUDO_HASH: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

/// Neuron management commands have no transaction identifier.
/// Since Rosetta requires a transaction identifier,
/// `None` is serialized to a transaction identifier with the hash
/// "Neuron management commands have no transaction identifier".
///
/// The transaction_identifier uniquely identifies a transaction in a particular
/// network and block or in the mempool.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "conversion", derive(LabelledGeneric))]
pub struct TransactionIdentifier {
    /// Any transactions that are attributable only to a block (ex: a block
    /// event) should use the hash of the block as the identifier.
    pub hash: String,
}

impl TransactionIdentifier {
    pub fn is_transfer(&self) -> bool {
        self.hash != NEURON_MANAGEMEN_PSEUDO_HASH
    }

    /// This could be `TryFrom<&HttpRequestEnvelope<HttpSubmitContent>>`,
    /// but double checking `RequestType` instead of using the canister method
    /// string is nice.
    pub fn try_from_envelope(
        request_type: RequestType,
        signed_transaction: &HttpRequestEnvelope<HttpSubmitContent>,
    ) -> Result<TransactionIdentifier, ApiError> {
        match request_type {
            RequestType::Send => {
                let HttpSubmitContent::Call { update } = &signed_transaction.content;
                let from = PrincipalId::try_from(update.sender.clone().0)
                    .map_err(|e| ApiError::internal_error(e.to_string()))?;
                let SendArgs {
                    memo,
                    amount,
                    fee,
                    from_subaccount,
                    to,
                    created_at_time,
                } = convert::from_arg(update.arg.clone().0)?;
                let created_at_time = created_at_time.ok_or_else(|| ApiError::internal_error(
                    "A transaction ID cannot be generated from a constructed transaction without an explicit 'created_at_time'"
            ))?;

                let from = ledger_canister::AccountIdentifier::new(from, from_subaccount);

                let hash = Transaction::new(from, to, amount, fee, memo, created_at_time).hash();

                Ok(TransactionIdentifier::from(&hash))
            }
            RequestType::Stake { .. }
            | RequestType::StartDissolve { .. }
            | RequestType::StopDissolve { .. }
            | RequestType::SetDissolveTimestamp { .. }
            | RequestType::Disburse { .. }
            | RequestType::AddHotKey { .. }
            | RequestType::Spawn { .. } => {
                // Unfortunately, staking operations don't really have a transaction ID
                Ok(TransactionIdentifier {
                    hash: NEURON_MANAGEMEN_PSEUDO_HASH.to_string(),
                })
            }
        }
    }
}

impl From<&Transaction> for TransactionIdentifier {
    fn from(tx: &Transaction) -> Self {
        TransactionIdentifier::from(&tx.hash())
    }
}

impl From<&HashOf<Transaction>> for TransactionIdentifier {
    fn from(hash: &HashOf<Transaction>) -> Self {
        TransactionIdentifier {
            hash: (format!("{}", hash)),
        }
    }
}

impl TryFrom<&TransactionIdentifier> for HashOf<Transaction> {
    type Error = String;

    fn try_from(tid: &TransactionIdentifier) -> Result<Self, Self::Error> {
        HashOf::from_str(&tid.hash)
    }
}
