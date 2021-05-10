//! Implements `DkgAlgorithm`.

use super::*;
use crate::sign::threshold_sig::dkg::dealings_to_csp_dealings::DealingsToCspDealingsImpl;
use ic_crypto_internal_csp::CryptoServiceProvider;
use ic_interfaces::crypto::DkgAlgorithm;
use ic_types::crypto::dkg::{
    Config, Dealing, DkgConfig, DkgConfigData, EncryptionPublicKeyWithPop, Response, Transcript,
    TranscriptBytes,
};
use ic_types::crypto::CryptoResult;
use std::collections::BTreeMap;

mod dealing;
mod dealings_to_csp_dealings;
mod encryption_keys;
mod response;
mod shared_utils;
mod transcript;

#[cfg(test)]
mod test_utils;

impl<C: CryptoServiceProvider> DkgAlgorithm for CryptoComponentFatClient<C> {
    fn generate_encryption_keys(
        &self,
        dkg_config: &Config,
        node_id: NodeId,
    ) -> CryptoResult<EncryptionPublicKeyWithPop> {
        // TODO (CRP-311): use DkgConfig as parameter and adapt callers
        encryption_keys::generate_encryption_keys(&self.csp, &new_dkg_config(dkg_config), node_id)
    }

    fn verify_encryption_public_key(
        &self,
        dkg_config: &Config,
        sender: NodeId,
        key: &EncryptionPublicKeyWithPop,
    ) -> CryptoResult<()> {
        // TODO (CRP-311): use DkgConfig as parameter and adapt callers
        encryption_keys::verify_encryption_public_key(
            &self.csp,
            &new_dkg_config(dkg_config),
            sender,
            key,
        )
    }

    fn create_dealing(
        &self,
        config: &Config,
        verified_keys: &BTreeMap<NodeId, EncryptionPublicKeyWithPop>,
        node_id: NodeId,
    ) -> CryptoResult<Dealing> {
        // TODO (CRP-311): use DkgConfig as parameter and adapt callers
        dealing::create_dealing(&self.csp, &new_dkg_config(config), verified_keys, node_id)
    }

    fn verify_dealing(
        &self,
        config: &Config,
        verified_keys: &BTreeMap<NodeId, EncryptionPublicKeyWithPop>,
        dealer: NodeId,
        dealing: &Dealing,
    ) -> CryptoResult<()> {
        // TODO (CRP-311): use DkgConfig as parameter and adapt callers
        dealing::verify_dealing(
            &self.csp,
            &new_dkg_config(config),
            verified_keys,
            dealer,
            dealing,
        )
    }

    fn create_response(
        &self,
        config: &Config,
        verified_keys: &BTreeMap<NodeId, EncryptionPublicKeyWithPop>,
        verified_dealings: &BTreeMap<NodeId, Dealing>,
        node_id: NodeId,
    ) -> CryptoResult<Response> {
        // TODO (CRP-311): use DkgConfig as parameter and adapt callers
        response::create_response(
            &self.csp,
            DealingsToCspDealingsImpl {},
            &new_dkg_config(config),
            verified_keys,
            verified_dealings,
            node_id,
        )
    }

    fn verify_response(
        &self,
        config: &Config,
        verified_keys: &BTreeMap<NodeId, EncryptionPublicKeyWithPop>,
        verified_dealings: &BTreeMap<NodeId, Dealing>,
        receiver: NodeId,
        response: &Response,
    ) -> CryptoResult<()> {
        // TODO (CRP-311): use DkgConfig as parameter and adapt callers
        response::verify_response(
            &self.csp,
            DealingsToCspDealingsImpl {},
            &new_dkg_config(config),
            verified_keys,
            verified_dealings,
            receiver,
            response,
        )
    }

    fn create_transcript(
        &self,
        config: &Config,
        verified_keys: &BTreeMap<NodeId, EncryptionPublicKeyWithPop>,
        verified_dealings: &BTreeMap<NodeId, Dealing>,
        verified_responses: &BTreeMap<NodeId, Response>,
    ) -> CryptoResult<Transcript> {
        // TODO (CRP-311): use DkgConfig as parameter and adapt callers
        transcript::create_transcript(
            &self.csp,
            DealingsToCspDealingsImpl {},
            &new_dkg_config(config),
            verified_keys,
            verified_dealings,
            verified_responses,
        )
    }

    fn load_transcript(&self, transcript: &Transcript, receiver: NodeId) -> CryptoResult<()> {
        transcript::load_transcript(
            &self.lockable_threshold_sig_data_store,
            &self.csp,
            transcript,
            receiver,
        )
    }
}

// TODO (CRP-311): Remove this once the APIs are adapted.
fn new_dkg_config(dkg_config: &Config) -> DkgConfig {
    let dkg_config_data = DkgConfigData {
        dkg_id: dkg_config.dkg_id,
        dealers: dkg_config.dealers.clone(),
        receivers: dkg_config.receivers.clone(),
        threshold: dkg_config.threshold,
        resharing_transcript: dkg_config.resharing_transcript.clone(),
    };
    DkgConfig::new(dkg_config_data).expect("unable to create dkg config")
}
