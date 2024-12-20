#[cfg(test)]
use ic_exhaustive_derive::ExhaustiveSet;
use ic_protobuf::{proxy::ProxyDecodeError, types::v1 as pb};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::hash::Hash;

use crate::messages::CallbackId;

/// For completed VetKeys, we differentiate between those
/// that have already been reported and those that have not. This is
/// to prevent keys from being reported more than once.
#[derive(Clone, Eq, PartialEq, Hash, Debug, Deserialize, Serialize)]
#[cfg_attr(test, derive(ExhaustiveSet))]
pub enum CompletedVetKey {
    ReportedToExecution,
    Unreported(crate::batch::ConsensusResponse),
}

#[derive(Clone, Eq, PartialEq, Hash, Debug, Deserialize, Serialize)]
#[cfg_attr(test, derive(ExhaustiveSet))]
pub struct VetKdPayload {
    pub vet_key_agreements: BTreeMap<CallbackId, CompletedVetKey>,
}

pub type Summary = Option<VetKdPayload>;

pub type Payload = Option<VetKdPayload>;

impl From<&VetKdPayload> for pb::VetKdPayload {
    fn from(payload: &VetKdPayload) -> Self {
        let mut vet_key_agreements = Vec::new();
        for (callback_id, completed) in &payload.vet_key_agreements {
            let unreported = match completed {
                CompletedVetKey::Unreported(response) => Some(response.into()),
                CompletedVetKey::ReportedToExecution => None,
            };
            vet_key_agreements.push(pb::CompletedVetKey {
                callback_id: callback_id.get(),
                unreported,
            });
        }

        Self { vet_key_agreements }
    }
}

impl TryFrom<&pb::VetKdPayload> for VetKdPayload {
    type Error = ProxyDecodeError;
    fn try_from(payload: &pb::VetKdPayload) -> Result<Self, Self::Error> {
        let mut vet_key_agreements = BTreeMap::new();
        for completed_vetkey in &payload.vet_key_agreements {
            let callback_id = CallbackId::from(completed_vetkey.callback_id);
            let signature = if let Some(unreported) = &completed_vetkey.unreported {
                let response = crate::batch::ConsensusResponse::try_from(unreported.clone())?;
                CompletedVetKey::Unreported(response)
            } else {
                CompletedVetKey::ReportedToExecution
            };
            vet_key_agreements.insert(callback_id, signature);
        }

        Ok(Self { vet_key_agreements })
    }
}
