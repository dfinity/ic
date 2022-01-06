//! Common utils for the ECDSA implementation.
use crate::consensus::ConsensusCrypto;
use ic_interfaces::crypto::IDkgProtocol;
use ic_logger::{warn, ReplicaLogger};
use ic_types::crypto::canister_threshold_sig::{
    error::IDkgLoadTranscriptError,
    idkg::{IDkgComplaint, IDkgTranscript},
};

// Load idkg transcript and log errors.
pub fn crypto_load_idkg_transcript(
    crypto: &dyn ConsensusCrypto,
    transcript: &IDkgTranscript,
    log: &ReplicaLogger,
) -> Result<Vec<IDkgComplaint>, IDkgLoadTranscriptError> {
    IDkgProtocol::load_transcript(crypto, transcript).map_err(|error| {
        warn!(
            log,
            "Failed to load transcript: transcript_id = {:?}, error = {:?}",
            transcript.transcript_id,
            error
        );
        error
    })
}

#[cfg(test)]
pub(crate) mod test_utils {
    use crate::consensus::mocks::{dependencies, Dependencies};
    use crate::ecdsa::pre_signer::EcdsaPreSignerImpl;
    use crate::ecdsa::signer::EcdsaSignerImpl;
    use ic_artifact_pool::ecdsa_pool::EcdsaPoolImpl;
    use ic_config::artifact_pool::ArtifactPoolConfig;
    use ic_interfaces::ecdsa::EcdsaChangeAction;
    use ic_logger::ReplicaLogger;
    use ic_metrics::MetricsRegistry;
    use ic_test_utilities::consensus::fake::*;
    use ic_test_utilities::crypto::{
        dummy_idkg_dealing_for_tests, dummy_idkg_transcript_id_for_tests,
        dummy_sig_inputs_for_tests,
    };
    use ic_test_utilities::types::ids::NODE_1;
    use ic_types::artifact::EcdsaMessageId;
    use ic_types::consensus::ecdsa::{
        EcdsaBlockReader, EcdsaDealing, EcdsaDealingSupport, EcdsaMessage, EcdsaSigShare,
        EcdsaSignedDealing, RequestId,
    };
    use ic_types::consensus::{BasicSignature, MultiSignatureShare};
    use ic_types::crypto::canister_threshold_sig::idkg::{
        IDkgDealers, IDkgReceivers, IDkgTranscriptId, IDkgTranscriptOperation, IDkgTranscriptParams,
    };
    use ic_types::crypto::canister_threshold_sig::{
        ThresholdEcdsaSigInputs, ThresholdEcdsaSigShare,
    };
    use ic_types::crypto::AlgorithmId;
    use ic_types::{Height, RegistryVersion};
    use ic_types::{NodeId, PrincipalId};
    use std::collections::BTreeSet;
    use std::convert::TryFrom;

    // Test implementation of EcdsaBlockReader to inject the test transcript params
    pub(crate) struct TestEcdsaBlockReader {
        height: Height,
        requested_transcripts: Vec<IDkgTranscriptParams>,
        requested_signatures: Vec<(RequestId, ThresholdEcdsaSigInputs)>,
    }

    impl TestEcdsaBlockReader {
        pub(crate) fn for_pre_signer_test(
            height: Height,
            requested_transcripts: Vec<IDkgTranscriptParams>,
        ) -> Self {
            Self {
                height,
                requested_transcripts,
                requested_signatures: vec![],
            }
        }

        pub(crate) fn for_signer_test(
            height: Height,
            requested_signatures: Vec<(RequestId, ThresholdEcdsaSigInputs)>,
        ) -> Self {
            Self {
                height,
                requested_transcripts: vec![],
                requested_signatures,
            }
        }
    }

    impl EcdsaBlockReader for TestEcdsaBlockReader {
        fn height(&self) -> Height {
            self.height
        }

        fn requested_transcripts(&self) -> Box<dyn Iterator<Item = &IDkgTranscriptParams> + '_> {
            Box::new(self.requested_transcripts.iter())
        }

        fn requested_signatures(
            &self,
        ) -> Box<dyn Iterator<Item = (&RequestId, &ThresholdEcdsaSigInputs)> + '_> {
            Box::new(
                self.requested_signatures
                    .iter()
                    .map(|(id, sig_inputs)| (id, sig_inputs)),
            )
        }
    }

    // Sets up the dependencies and creates the pre signer
    pub(crate) fn create_pre_signer_dependencies(
        pool_config: ArtifactPoolConfig,
        logger: ReplicaLogger,
    ) -> (EcdsaPoolImpl, EcdsaPreSignerImpl) {
        let metrics_registry = MetricsRegistry::new();
        let Dependencies {
            pool,
            replica_config: _,
            membership: _,
            registry: _,
            crypto,
            ..
        } = dependencies(pool_config, 1);

        let pre_signer = EcdsaPreSignerImpl::new(
            NODE_1,
            pool.get_cache(),
            crypto,
            metrics_registry.clone(),
            logger.clone(),
        );
        let ecdsa_pool = EcdsaPoolImpl::new(logger, metrics_registry);

        (ecdsa_pool, pre_signer)
    }

    // Sets up the dependencies and creates the signer
    pub(crate) fn create_signer_dependencies(
        pool_config: ArtifactPoolConfig,
        logger: ReplicaLogger,
    ) -> (EcdsaPoolImpl, EcdsaSignerImpl) {
        let metrics_registry = MetricsRegistry::new();
        let Dependencies {
            pool,
            replica_config: _,
            membership: _,
            registry: _,
            crypto,
            ..
        } = dependencies(pool_config, 1);

        let signer = EcdsaSignerImpl::new(
            NODE_1,
            pool.get_cache(),
            crypto,
            metrics_registry.clone(),
            logger.clone(),
        );
        let ecdsa_pool = EcdsaPoolImpl::new(logger, metrics_registry);

        (ecdsa_pool, signer)
    }

    // Creates a TranscriptID for tests
    pub(crate) fn create_transcript_id(id: usize) -> IDkgTranscriptId {
        dummy_idkg_transcript_id_for_tests(id)
    }

    // Creates a RequestId for tests
    pub(crate) fn create_request_id(id: u8) -> RequestId {
        RequestId::from(vec![id])
    }

    // Creates a test transcript param
    pub(crate) fn create_transcript_param(
        transcript_id: IDkgTranscriptId,
        dealer_list: &[NodeId],
        receiver_list: &[NodeId],
    ) -> IDkgTranscriptParams {
        let mut dealers = BTreeSet::new();
        dealer_list.iter().for_each(|val| {
            dealers.insert(*val);
        });
        let mut receivers = BTreeSet::new();
        receiver_list.iter().for_each(|val| {
            receivers.insert(*val);
        });
        IDkgTranscriptParams::new(
            transcript_id,
            IDkgDealers::new(dealers).unwrap(),
            IDkgReceivers::new(receivers).unwrap(),
            RegistryVersion::from(0),
            AlgorithmId::ThresholdEcdsaSecp256k1,
            IDkgTranscriptOperation::Random,
        )
        .unwrap()
    }

    // Creates a test dealing
    fn create_dealing_content(transcript_id: IDkgTranscriptId, dealer_id: NodeId) -> EcdsaDealing {
        let mut idkg_dealing = dummy_idkg_dealing_for_tests();
        idkg_dealing.dealer_id = dealer_id;
        idkg_dealing.transcript_id = transcript_id;
        EcdsaDealing {
            requested_height: Height::from(10),
            idkg_dealing,
        }
    }

    // Creates a test signed dealing
    pub(crate) fn create_dealing(
        transcript_id: IDkgTranscriptId,
        dealer_id: NodeId,
    ) -> EcdsaSignedDealing {
        EcdsaSignedDealing {
            content: create_dealing_content(transcript_id, dealer_id),
            signature: BasicSignature::fake(dealer_id),
        }
    }

    // Creates a test dealing support
    pub(crate) fn create_support(
        transcript_id: IDkgTranscriptId,
        dealer_id: NodeId,
        signer: NodeId,
    ) -> EcdsaDealingSupport {
        EcdsaDealingSupport {
            content: create_dealing_content(transcript_id, dealer_id),
            signature: MultiSignatureShare::fake(signer),
        }
    }

    // Creates a test signature input
    pub(crate) fn create_sig_inputs(caller: u8) -> ThresholdEcdsaSigInputs {
        dummy_sig_inputs_for_tests(PrincipalId::try_from(&vec![caller]).unwrap())
    }

    // Creates a test signature share
    pub(crate) fn create_signature_share(
        signer_id: NodeId,
        request_id: RequestId,
    ) -> EcdsaSigShare {
        EcdsaSigShare {
            requested_height: Height::from(10),
            signer_id,
            request_id,
            share: ThresholdEcdsaSigShare {
                sig_share_raw: vec![],
            },
        }
    }

    // Checks that the dealing with the given id is being added to the validated
    // pool
    pub(crate) fn is_dealing_added_to_validated(
        change_set: &[EcdsaChangeAction],
        transcript_id: &IDkgTranscriptId,
        requested_height: Height,
    ) -> bool {
        for action in change_set {
            if let EcdsaChangeAction::AddToValidated(EcdsaMessage::EcdsaSignedDealing(
                signed_dealing,
            )) = action
            {
                let dealing = signed_dealing.get();
                if dealing.requested_height == requested_height
                    && dealing.idkg_dealing.transcript_id == *transcript_id
                    && dealing.idkg_dealing.dealer_id == NODE_1
                {
                    return true;
                }
            }
        }
        false
    }

    // Checks that the dealing support for the given dealing is being added to the
    // validated pool
    pub(crate) fn is_dealing_support_added_to_validated(
        change_set: &[EcdsaChangeAction],
        transcript_id: &IDkgTranscriptId,
        dealer_id: &NodeId,
    ) -> bool {
        for action in change_set {
            if let EcdsaChangeAction::AddToValidated(EcdsaMessage::EcdsaDealingSupport(support)) =
                action
            {
                let dealing = &support.content;
                if dealing.idkg_dealing.transcript_id == *transcript_id
                    && dealing.idkg_dealing.dealer_id == *dealer_id
                    && support.signature.signer == NODE_1
                {
                    return true;
                }
            }
        }
        false
    }

    // Checks that the signature share with the given request is being added to the
    // validated pool
    pub(crate) fn is_signature_share_added_to_validated(
        change_set: &[EcdsaChangeAction],
        request_id: &RequestId,
        requested_height: Height,
    ) -> bool {
        for action in change_set {
            if let EcdsaChangeAction::AddToValidated(EcdsaMessage::EcdsaSigShare(share)) = action {
                if share.requested_height == requested_height
                    && share.request_id == *request_id
                    && share.signer_id == NODE_1
                {
                    return true;
                }
            }
        }
        false
    }

    // Checks that artifact is being moved from unvalidated to validated pool
    pub(crate) fn is_moved_to_validated(
        change_set: &[EcdsaChangeAction],
        msg_id: &EcdsaMessageId,
    ) -> bool {
        for action in change_set {
            if let EcdsaChangeAction::MoveToValidated(id) = action {
                if *id == *msg_id {
                    return true;
                }
            }
        }
        false
    }

    // Checks that artifact is being removed from validated pool
    pub(crate) fn is_removed_from_validated(
        change_set: &[EcdsaChangeAction],
        msg_id: &EcdsaMessageId,
    ) -> bool {
        for action in change_set {
            if let EcdsaChangeAction::RemoveValidated(id) = action {
                if *id == *msg_id {
                    return true;
                }
            }
        }
        false
    }

    // Checks that artifact is being removed from unvalidated pool
    pub(crate) fn is_removed_from_unvalidated(
        change_set: &[EcdsaChangeAction],
        msg_id: &EcdsaMessageId,
    ) -> bool {
        for action in change_set {
            if let EcdsaChangeAction::RemoveUnvalidated(id) = action {
                if *id == *msg_id {
                    return true;
                }
            }
        }
        false
    }

    // Checks that artifact is being dropped as invalid
    pub(crate) fn is_handle_invalid(
        change_set: &[EcdsaChangeAction],
        msg_id: &EcdsaMessageId,
    ) -> bool {
        for action in change_set {
            if let EcdsaChangeAction::HandleInvalid(id, _) = action {
                if *id == *msg_id {
                    return true;
                }
            }
        }
        false
    }
}
