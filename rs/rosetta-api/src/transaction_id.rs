use std::{convert::TryFrom, str::FromStr};

use crate::{convert, errors::ApiError, request_types::RequestType};
use ic_ledger_canister_core::ledger::LedgerTransaction;
use ic_ledger_hash_of::HashOf;
use ic_types::{
    messages::{HttpCallContent, HttpRequestEnvelope},
    PrincipalId,
};
use icp_ledger::{SendArgs, Transaction};
use serde::{Deserialize, Serialize};

pub const NEURON_MANAGEMENT_PSEUDO_HASH: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransactionIdentifier(pub crate::models::TransactionIdentifier);

impl TransactionIdentifier {
    pub fn is_transfer(&self) -> bool {
        self.0.hash != NEURON_MANAGEMENT_PSEUDO_HASH
    }

    /// This could be `TryFrom<&HttpRequestEnvelope<HttpCallContent>>`,
    /// but double checking `RequestType` instead of using the canister method
    /// string is nice.
    pub fn try_from_envelope(
        request_type: RequestType,
        signed_transaction: &HttpRequestEnvelope<HttpCallContent>,
    ) -> Result<TransactionIdentifier, ApiError> {
        match request_type {
            RequestType::Send => {
                let HttpCallContent::Call { update } = &signed_transaction.content;
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

                let from = icp_ledger::AccountIdentifier::new(from, from_subaccount);

                let hash =
                    Transaction::new(from, to, None, amount, fee, memo, created_at_time).hash();

                Ok(TransactionIdentifier::from(&hash))
            }
            RequestType::Stake { .. }
            | RequestType::StartDissolve { .. }
            | RequestType::StopDissolve { .. }
            | RequestType::SetDissolveTimestamp { .. }
            | RequestType::ChangeAutoStakeMaturity { .. }
            | RequestType::Disburse { .. }
            | RequestType::AddHotKey { .. }
            | RequestType::RemoveHotKey { .. }
            | RequestType::Spawn { .. }
            | RequestType::RegisterVote { .. }
            | RequestType::MergeMaturity { .. }
            | RequestType::StakeMaturity { .. }
            | RequestType::NeuronInfo { .. }
            | RequestType::ListNeurons { .. }
            | RequestType::Follow { .. } => {
                // Unfortunately, staking operations don't really have a transaction ID
                Ok(TransactionIdentifier::from(
                    NEURON_MANAGEMENT_PSEUDO_HASH.to_string(),
                ))
            }
        }
    }
}

impl From<&Transaction> for TransactionIdentifier {
    fn from(tx: &Transaction) -> Self {
        TransactionIdentifier::from(&tx.hash())
    }
}

impl From<String> for TransactionIdentifier {
    fn from(hash: String) -> Self {
        TransactionIdentifier(crate::models::TransactionIdentifier { hash })
    }
}

impl From<&HashOf<Transaction>> for TransactionIdentifier {
    fn from(hash: &HashOf<Transaction>) -> Self {
        TransactionIdentifier(crate::models::TransactionIdentifier {
            hash: (format!("{}", hash)),
        })
    }
}

impl From<TransactionIdentifier> for crate::models::TransactionIdentifier {
    fn from(value: TransactionIdentifier) -> Self {
        value.0
    }
}

impl From<crate::models::TransactionIdentifier> for TransactionIdentifier {
    fn from(value: crate::models::TransactionIdentifier) -> Self {
        TransactionIdentifier(value)
    }
}

impl TryFrom<&TransactionIdentifier> for HashOf<Transaction> {
    type Error = String;

    fn try_from(tid: &TransactionIdentifier) -> Result<Self, Self::Error> {
        HashOf::from_str(&tid.0.hash)
    }
}
