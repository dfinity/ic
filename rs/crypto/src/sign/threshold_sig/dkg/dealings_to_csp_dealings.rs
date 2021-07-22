use super::*;
use ic_crypto_internal_csp::types::{CspDealing, CspPop};
use ic_crypto_internal_types::sign::threshold_sig::dkg::encryption_public_key::CspEncryptionPublicKey;
use serde::{Deserialize, Serialize};

#[cfg(test)]
mod tests;

// because the type definitions for results get too complex, we us an alias:
pub type CspDealings = Vec<((CspEncryptionPublicKey, CspPop), CspDealing)>;

pub trait DealingsToCspDealings {
    fn convert(
        &self,
        keys: &BTreeMap<NodeId, EncryptionPublicKeyWithPop>,
        dealings: &BTreeMap<NodeId, Dealing>,
    ) -> Result<CspDealings, DealingsToCspDealingsError>;
}

pub struct DealingsToCspDealingsImpl {}

impl DealingsToCspDealings for DealingsToCspDealingsImpl {
    fn convert(
        &self,
        keys: &BTreeMap<NodeId, EncryptionPublicKeyWithPop>,
        dealings: &BTreeMap<NodeId, Dealing>,
    ) -> Result<CspDealings, DealingsToCspDealingsError> {
        ensure_keys_and_dealings_non_empty(keys, dealings)?;
        dealings
            .iter()
            .map(|(dealer, dealing)| {
                let csp_enc_pk_with_pop = csp_enc_pk_with_pop(keys, *dealer)?;
                let csp_dealing = CspDealing::from(dealing);
                Ok((csp_enc_pk_with_pop, csp_dealing))
            })
            .collect()
    }
}

fn ensure_keys_and_dealings_non_empty(
    keys: &BTreeMap<NodeId, EncryptionPublicKeyWithPop>,
    dealings: &BTreeMap<NodeId, Dealing>,
) -> Result<(), DealingsToCspDealingsError> {
    if dealings.is_empty() {
        return Err(DealingsToCspDealingsError::DealingsEmpty {});
    }
    if keys.is_empty() {
        return Err(DealingsToCspDealingsError::KeysEmpty {});
    }
    Ok(())
}

fn csp_enc_pk_with_pop(
    keys: &BTreeMap<NodeId, EncryptionPublicKeyWithPop>,
    dealer: NodeId,
) -> Result<(CspEncryptionPublicKey, CspPop), DealingsToCspDealingsError> {
    let key = key_for_node(dealer, keys)?;
    let csp_enc_pk = CspEncryptionPublicKey::from(&key.key);
    let csp_pop = CspPop::from(&key.proof_of_possession);
    Ok((csp_enc_pk, csp_pop))
}

fn key_for_node(
    dealer: NodeId,
    keys: &BTreeMap<NodeId, EncryptionPublicKeyWithPop>,
) -> Result<&EncryptionPublicKeyWithPop, DealingsToCspDealingsError> {
    keys.get(&dealer)
        .ok_or(DealingsToCspDealingsError::KeyForDealerNotFound {
            dealer_node_id: dealer,
        })
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DealingsToCspDealingsError {
    KeysEmpty {},
    DealingsEmpty {},
    KeyForDealerNotFound { dealer_node_id: NodeId },
}

// TODO (CRP-361): Map the errors to specific IDKM errors.
impl From<DealingsToCspDealingsError> for CryptoError {
    fn from(conversion_error: DealingsToCspDealingsError) -> Self {
        match conversion_error {
            DealingsToCspDealingsError::DealingsEmpty {} => CryptoError::InvalidArgument {
                message: "Error while mapping the dealings: The dealings must not be empty.".to_string(),
            },
            DealingsToCspDealingsError::KeysEmpty {} => CryptoError::InvalidArgument {
                message: "Error while mapping the dealings: The keys must not be empty.".to_string(),
            },
            DealingsToCspDealingsError::KeyForDealerNotFound { dealer_node_id } => {
                CryptoError::InvalidArgument {
                    message: format!(
                        "Error while mapping the dealings: The key for dealer with node id \"{:?}\" was not found.",
                        dealer_node_id
                    ),
                }
            }
        }
    }
}
