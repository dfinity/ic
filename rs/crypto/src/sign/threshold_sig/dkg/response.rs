//! Implements the response methods of `DkgAlgorithm`.

use super::*;
use crate::sign::threshold_sig::dkg::dealings_to_csp_dealings::DealingsToCspDealings;
use crate::sign::threshold_sig::dkg::shared_utils::ensure_node_id_has_key;
use ic_crypto_internal_csp::api::DistributedKeyGenerationCspClient;
use ic_crypto_internal_csp::types::{CspPop, CspResponse};
use ic_crypto_internal_types::sign::threshold_sig::dkg::encryption_public_key::CspEncryptionPublicKey;
use ic_types::crypto::dkg::Receivers;

pub use create::create_response;
pub use verify::verify_response;

#[cfg(test)]
mod tests;

mod create {
    use super::*;

    pub fn create_response<C: DistributedKeyGenerationCspClient, D: DealingsToCspDealings>(
        dkg_csp_client: &C,
        dealings_to_csp_dealings: D,
        config: &DkgConfig,
        verified_keys: &BTreeMap<NodeId, EncryptionPublicKeyWithPop>,
        verified_dealings: &BTreeMap<NodeId, Dealing>,
        node_id: NodeId,
    ) -> CryptoResult<Response> {
        ensure_node_id_has_key(node_id, verified_keys)?;
        Ok(dkg_csp_client
            .dkg_create_response(
                config.dkg_id(),
                &dealings_to_csp_dealings.convert(verified_keys, verified_dealings)?,
                receiver_index(node_id, config.receivers())?,
            )
            .map(|csp_response| Response::from(&csp_response))?)
    }
}

mod verify {
    use super::*;
    use crate::sign::threshold_sig::dkg::shared_utils::key_for_node_id;

    pub fn verify_response<C: DistributedKeyGenerationCspClient, D: DealingsToCspDealings>(
        dkg_csp_client: &C,
        dealings_to_csp_dealings: D,
        config: &DkgConfig,
        verified_keys: &BTreeMap<NodeId, EncryptionPublicKeyWithPop>,
        verified_dealings: &BTreeMap<NodeId, Dealing>,
        receiver: NodeId,
        response: &Response,
    ) -> CryptoResult<()> {
        let receiver_key = key_for_node_id(receiver, &verified_keys)?;
        let receiver_index = receiver_index(receiver, config.receivers())?;
        let verified_csp_dealings =
            dealings_to_csp_dealings.convert(verified_keys, verified_dealings)?;
        Ok(dkg_csp_client.dkg_verify_response(
            config.dkg_id(),
            &verified_csp_dealings,
            receiver_index,
            csp_enc_pk_with_pop(receiver_key),
            CspResponse::from(response),
        )?)
    }

    fn csp_enc_pk_with_pop(
        enc_pk_with_pop: &EncryptionPublicKeyWithPop,
    ) -> (CspEncryptionPublicKey, CspPop) {
        let csp_enc_pk = CspEncryptionPublicKey::from(&enc_pk_with_pop.key);
        let csp_pop = CspPop::from(&enc_pk_with_pop.proof_of_possession);
        (csp_enc_pk, csp_pop)
    }
}

fn receiver_index(node_id: NodeId, receivers: &Receivers) -> CryptoResult<NodeIndex> {
    receivers
        .get()
        .iter()
        .position(|current_node_id| *current_node_id == node_id)
        .ok_or_else(|| CryptoError::InvalidArgument {
            message: format!(
                "The provided node id \"{:?}\" is not a receiver. Only receivers are allowed for \
                this operation.",
                node_id
            ),
        })
        .map(|index| NodeIndex::try_from(index).expect("node index overflow"))
}
