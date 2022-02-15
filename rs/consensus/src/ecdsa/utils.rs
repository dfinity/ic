//! Common utils for the ECDSA implementation.

use crate::ecdsa::complaints::{EcdsaTranscriptLoader, TranscriptLoadStatus};
use ic_interfaces::consensus_pool::ConsensusBlockChain;
use ic_interfaces::ecdsa::{EcdsaChangeAction, EcdsaChangeSet, EcdsaPool};
use ic_types::consensus::ecdsa::{EcdsaBlockReader, TranscriptRef};
use ic_types::consensus::ecdsa::{
    EcdsaDataPayload, EcdsaMessage, IDkgTranscriptParamsRef, RequestId, ThresholdEcdsaSigInputsRef,
    TranscriptLookupError,
};
use ic_types::consensus::{Block, BlockPayload, HasHeight};
use ic_types::crypto::canister_threshold_sig::idkg::{IDkgTranscript, IDkgTranscriptId};
use ic_types::Height;
use std::collections::BTreeMap;
use std::sync::Arc;

pub(crate) struct EcdsaBlockReaderImpl {
    chain: Arc<dyn ConsensusBlockChain>,
    tip: Block,
    tip_ecdsa_payload: Option<EcdsaDataPayload>,
}

impl EcdsaBlockReaderImpl {
    pub(crate) fn new(chain: Arc<dyn ConsensusBlockChain>) -> Self {
        let tip = chain.tip();
        let tip_ecdsa_payload = if !tip.payload.is_summary() {
            BlockPayload::from(tip.clone().payload).into_data().ecdsa
        } else {
            None
        };
        Self {
            chain,
            tip,
            tip_ecdsa_payload,
        }
    }
}

impl EcdsaBlockReader for EcdsaBlockReaderImpl {
    fn tip_height(&self) -> Height {
        self.tip.height()
    }

    fn requested_transcripts(&self) -> Box<dyn Iterator<Item = &IDkgTranscriptParamsRef> + '_> {
        self.tip_ecdsa_payload
            .as_ref()
            .map_or(Box::new(std::iter::empty()), |ecdsa_payload| {
                ecdsa_payload.iter_transcript_configs_in_creation()
            })
    }

    fn requested_signatures(
        &self,
    ) -> Box<dyn Iterator<Item = (&RequestId, &ThresholdEcdsaSigInputsRef)> + '_> {
        self.tip_ecdsa_payload
            .as_ref()
            .map_or(Box::new(std::iter::empty()), |ecdsa_payload| {
                Box::new(ecdsa_payload.ongoing_signatures.iter())
            })
    }

    fn active_transcripts(&self) -> BTreeMap<IDkgTranscriptId, TranscriptRef> {
        self.tip_ecdsa_payload
            .as_ref()
            .map_or(BTreeMap::new(), |ecdsa_payload| {
                let mut active_refs = Vec::new();

                for obj in ecdsa_payload.ongoing_signatures.values() {
                    active_refs.append(&mut obj.get_refs());
                }
                for obj in ecdsa_payload.available_quadruples.values() {
                    active_refs.append(&mut obj.get_refs());
                }
                for obj in ecdsa_payload.quadruples_in_creation.values() {
                    active_refs.append(&mut obj.get_refs());
                }
                if let Some(key) = &ecdsa_payload.next_key_transcript_creation {
                    active_refs.append(&mut key.get_refs());
                }

                let mut ret = BTreeMap::new();
                for active_ref in active_refs {
                    ret.insert(active_ref.transcript_id, active_ref);
                }
                ret
            })
    }

    fn transcript(
        &self,
        transcript_ref: &TranscriptRef,
    ) -> Result<IDkgTranscript, TranscriptLookupError> {
        let block = self
            .chain
            .block(transcript_ref.height)
            .ok_or(TranscriptLookupError::BlockNotFound(*transcript_ref))?;
        let is_summary_block = block.payload.is_summary();
        let block_payload = BlockPayload::from(block.payload);

        let idkg_transcripts = if is_summary_block {
            block_payload
                .into_summary()
                .ecdsa
                .ok_or(TranscriptLookupError::NoEcdsaSummary(*transcript_ref))?
                .idkg_transcripts
        } else {
            block_payload
                .into_data()
                .ecdsa
                .ok_or(TranscriptLookupError::NoEcdsaPayload(*transcript_ref))?
                .idkg_transcripts
        };

        idkg_transcripts
            .get(&transcript_ref.transcript_id)
            .ok_or_else(|| {
                TranscriptLookupError::TranscriptNotFound(*transcript_ref, is_summary_block)
            })
            .map(|entry| entry.clone())
    }
}

/// Load the given transcripts
/// Returns None if all the transcripts could be loaded successfully.
/// Otherwise, returns the complaint change set to be added to the pool
pub(crate) fn load_transcripts(
    ecdsa_pool: &dyn EcdsaPool,
    transcript_loader: &dyn EcdsaTranscriptLoader,
    transcripts: &[&IDkgTranscript],
    height: Height,
) -> Option<EcdsaChangeSet> {
    let mut new_complaints = Vec::new();
    for transcript in transcripts {
        match transcript_loader.load_transcript(ecdsa_pool, transcript, height) {
            TranscriptLoadStatus::Success => (),
            TranscriptLoadStatus::Failure => return Some(Default::default()),
            TranscriptLoadStatus::Complaints(complaints) => {
                for complaint in complaints {
                    new_complaints.push(EcdsaChangeAction::AddToValidated(
                        EcdsaMessage::EcdsaComplaint(complaint),
                    ));
                }
            }
        }
    }

    if new_complaints.is_empty() {
        None
    } else {
        Some(new_complaints)
    }
}

#[cfg(test)]
pub(crate) mod test_utils {
    use crate::consensus::mocks::{dependencies, Dependencies};
    use crate::ecdsa::complaints::{EcdsaTranscriptLoader, TranscriptLoadStatus};
    use crate::ecdsa::pre_signer::EcdsaPreSignerImpl;
    use crate::ecdsa::signer::EcdsaSignerImpl;
    use ic_artifact_pool::ecdsa_pool::EcdsaPoolImpl;
    use ic_config::artifact_pool::ArtifactPoolConfig;
    use ic_interfaces::ecdsa::{EcdsaChangeAction, EcdsaPool};
    use ic_logger::ReplicaLogger;
    use ic_metrics::MetricsRegistry;
    use ic_test_utilities::consensus::fake::*;
    use ic_test_utilities::crypto::{
        dummy_idkg_dealing_for_tests, dummy_idkg_transcript_id_for_tests,
    };
    use ic_test_utilities::types::ids::{node_test_id, NODE_1};
    use ic_types::artifact::EcdsaMessageId;
    use ic_types::consensus::ecdsa::{
        EcdsaBlockReader, EcdsaDealing, EcdsaDealingSupport, EcdsaMessage, EcdsaSigShare,
        EcdsaSignedDealing, IDkgTranscriptParamsRef, MaskedTranscript, PreSignatureQuadrupleRef,
        RequestId, ReshareOfMaskedParams, ThresholdEcdsaSigInputsRef, TranscriptLookupError,
        TranscriptRef, UnmaskedTranscript,
    };
    use ic_types::crypto::canister_threshold_sig::idkg::{
        IDkgDealers, IDkgMaskedTranscriptOrigin, IDkgReceivers, IDkgTranscript, IDkgTranscriptId,
        IDkgTranscriptType, IDkgUnmaskedTranscriptOrigin,
    };
    use ic_types::crypto::canister_threshold_sig::{
        ExtendedDerivationPath, ThresholdEcdsaSigShare,
    };
    use ic_types::crypto::AlgorithmId;
    use ic_types::signature::*;
    use ic_types::{Height, NodeId, PrincipalId, Randomness, RegistryVersion};
    use std::collections::{BTreeMap, BTreeSet};
    use std::convert::TryFrom;

    pub(crate) struct TestTranscriptParams {
        idkg_transcripts: BTreeMap<TranscriptRef, IDkgTranscript>,
        transcript_params_ref: IDkgTranscriptParamsRef,
    }

    pub(crate) struct TestSigInputs {
        pub(crate) idkg_transcripts: BTreeMap<TranscriptRef, IDkgTranscript>,
        pub(crate) sig_inputs_ref: ThresholdEcdsaSigInputsRef,
    }

    // Test implementation of EcdsaBlockReader to inject the test transcript params
    pub(crate) struct TestEcdsaBlockReader {
        height: Height,
        requested_transcripts: Vec<IDkgTranscriptParamsRef>,
        requested_signatures: Vec<(RequestId, ThresholdEcdsaSigInputsRef)>,
        idkg_transcripts: BTreeMap<TranscriptRef, IDkgTranscript>,
    }

    impl TestEcdsaBlockReader {
        pub(crate) fn new() -> Self {
            Self {
                height: Height::new(0),
                requested_transcripts: Vec::new(),
                requested_signatures: Vec::new(),
                idkg_transcripts: BTreeMap::new(),
            }
        }

        pub(crate) fn for_pre_signer_test(
            height: Height,
            transcript_params: Vec<TestTranscriptParams>,
        ) -> Self {
            let mut idkg_transcripts = BTreeMap::new();
            let mut requested_transcripts = Vec::new();
            for t in transcript_params {
                for (transcript_ref, transcript) in t.idkg_transcripts {
                    idkg_transcripts.insert(transcript_ref, transcript);
                }
                requested_transcripts.push(t.transcript_params_ref);
            }

            Self {
                height,
                requested_transcripts,
                requested_signatures: vec![],
                idkg_transcripts,
            }
        }

        pub(crate) fn for_signer_test(
            height: Height,
            sig_inputs: Vec<(RequestId, TestSigInputs)>,
        ) -> Self {
            let mut idkg_transcripts = BTreeMap::new();
            let mut requested_signatures = Vec::new();
            for (request_id, sig_inputs) in sig_inputs {
                for (transcript_ref, transcript) in sig_inputs.idkg_transcripts {
                    idkg_transcripts.insert(transcript_ref, transcript);
                }
                requested_signatures.push((request_id, sig_inputs.sig_inputs_ref));
            }

            Self {
                height,
                requested_transcripts: vec![],
                requested_signatures,
                idkg_transcripts,
            }
        }

        pub(crate) fn add_transcript(
            &mut self,
            transcript_ref: TranscriptRef,
            transcript: IDkgTranscript,
        ) {
            self.idkg_transcripts.insert(transcript_ref, transcript);
        }
    }

    impl EcdsaBlockReader for TestEcdsaBlockReader {
        fn tip_height(&self) -> Height {
            self.height
        }

        fn requested_transcripts(&self) -> Box<dyn Iterator<Item = &IDkgTranscriptParamsRef> + '_> {
            Box::new(self.requested_transcripts.iter())
        }

        fn requested_signatures(
            &self,
        ) -> Box<dyn Iterator<Item = (&RequestId, &ThresholdEcdsaSigInputsRef)> + '_> {
            Box::new(
                self.requested_signatures
                    .iter()
                    .map(|(id, sig_inputs)| (id, sig_inputs)),
            )
        }

        fn transcript(
            &self,
            transcript_ref: &TranscriptRef,
        ) -> Result<IDkgTranscript, TranscriptLookupError> {
            Ok(self.idkg_transcripts.get(transcript_ref).unwrap().clone())
        }

        fn active_transcripts(&self) -> BTreeMap<IDkgTranscriptId, TranscriptRef> {
            BTreeMap::new()
        }
    }

    pub(crate) struct TestEcdsaTranscriptLoader;
    impl TestEcdsaTranscriptLoader {
        pub(crate) fn new() -> Self {
            Self
        }
    }

    impl EcdsaTranscriptLoader for TestEcdsaTranscriptLoader {
        fn load_transcript(
            &self,
            _ecdsa_pool: &dyn EcdsaPool,
            _transcript: &IDkgTranscript,
            _height: Height,
        ) -> TranscriptLoadStatus {
            TranscriptLoadStatus::Success
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
            pool.get_block_cache(),
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
            pool.get_block_cache(),
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

    // Creates a test transcript
    pub(crate) fn create_transcript(
        transcript_id: IDkgTranscriptId,
        receiver_list: &[NodeId],
    ) -> IDkgTranscript {
        let mut receivers = BTreeSet::new();
        receiver_list.iter().for_each(|val| {
            receivers.insert(*val);
        });
        IDkgTranscript {
            transcript_id,
            receivers: IDkgReceivers::new(receivers).unwrap(),
            registry_version: RegistryVersion::from(1),
            verified_dealings: BTreeMap::new(),
            transcript_type: IDkgTranscriptType::Masked(IDkgMaskedTranscriptOrigin::Random),
            algorithm_id: AlgorithmId::ThresholdEcdsaSecp256k1,
            internal_transcript_raw: vec![],
        }
    }

    // Creates a test transcript param
    pub(crate) fn create_transcript_param(
        transcript_id: IDkgTranscriptId,
        dealer_list: &[NodeId],
        receiver_list: &[NodeId],
    ) -> TestTranscriptParams {
        let mut dealers = BTreeSet::new();
        dealer_list.iter().for_each(|val| {
            dealers.insert(*val);
        });
        let mut receivers = BTreeSet::new();
        receiver_list.iter().for_each(|val| {
            receivers.insert(*val);
        });

        // The random transcript
        let random_transcript_id = create_transcript_id(transcript_id.id() * 214365 + 1);
        let random_transcript = create_transcript(random_transcript_id, dealer_list);
        let random_masked =
            MaskedTranscript::try_from((Height::new(0), &random_transcript)).unwrap();
        let mut idkg_transcripts = BTreeMap::new();
        idkg_transcripts.insert(*random_masked.as_ref(), random_transcript);

        // The transcript that points to the random transcript
        let transcript_params_ref = ReshareOfMaskedParams::new(
            transcript_id,
            IDkgDealers::new(dealers).unwrap(),
            IDkgReceivers::new(receivers).unwrap(),
            RegistryVersion::from(0),
            AlgorithmId::ThresholdEcdsaSecp256k1,
            random_masked,
        );

        TestTranscriptParams {
            idkg_transcripts,
            transcript_params_ref: transcript_params_ref.as_ref().clone(),
        }
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
    pub(crate) fn create_sig_inputs_with_height(caller: u8, height: Height) -> TestSigInputs {
        let transcript_id = |offset| {
            let val = caller as usize;
            create_transcript_id(val * 214365 + offset)
        };

        let mut nodes = BTreeSet::new();
        nodes.insert(node_test_id(1));

        let kappa_masked_id = transcript_id(10);
        let kappa_unmasked_id = transcript_id(20);
        let lambda_masked_id = transcript_id(30);
        let key_masked_id = transcript_id(40);
        let key_unmasked_id = transcript_id(50);
        let kappa_unmasked_times_lambda_masked_id = transcript_id(60);
        let key_unmasked_times_lambda_masked_id = transcript_id(70);
        let mut idkg_transcripts = BTreeMap::new();

        let kappa_masked = IDkgTranscript {
            transcript_id: kappa_masked_id,
            receivers: IDkgReceivers::new(nodes.clone()).unwrap(),
            registry_version: RegistryVersion::from(1),
            verified_dealings: BTreeMap::new(),
            transcript_type: IDkgTranscriptType::Masked(IDkgMaskedTranscriptOrigin::Random),
            algorithm_id: AlgorithmId::ThresholdEcdsaSecp256k1,
            internal_transcript_raw: vec![],
        };
        let kappa_masked_ref = MaskedTranscript::try_from((height, &kappa_masked)).unwrap();
        idkg_transcripts.insert(*kappa_masked_ref.as_ref(), kappa_masked);

        let kappa_unmasked = IDkgTranscript {
            transcript_id: kappa_unmasked_id,
            receivers: IDkgReceivers::new(nodes.clone()).unwrap(),
            registry_version: RegistryVersion::from(1),
            verified_dealings: BTreeMap::new(),
            transcript_type: IDkgTranscriptType::Unmasked(
                IDkgUnmaskedTranscriptOrigin::ReshareMasked(kappa_masked_id),
            ),
            algorithm_id: AlgorithmId::ThresholdEcdsaSecp256k1,
            internal_transcript_raw: vec![],
        };
        let kappa_unmasked_ref = UnmaskedTranscript::try_from((height, &kappa_unmasked)).unwrap();
        idkg_transcripts.insert(*kappa_unmasked_ref.as_ref(), kappa_unmasked);

        let lambda_masked = IDkgTranscript {
            transcript_id: lambda_masked_id,
            receivers: IDkgReceivers::new(nodes.clone()).unwrap(),
            registry_version: RegistryVersion::from(1),
            verified_dealings: BTreeMap::new(),
            transcript_type: IDkgTranscriptType::Masked(IDkgMaskedTranscriptOrigin::Random),
            algorithm_id: AlgorithmId::ThresholdEcdsaSecp256k1,
            internal_transcript_raw: vec![],
        };
        let lambda_masked_ref = MaskedTranscript::try_from((height, &lambda_masked)).unwrap();
        idkg_transcripts.insert(*lambda_masked_ref.as_ref(), lambda_masked);

        let key_masked = IDkgTranscript {
            transcript_id: key_masked_id,
            receivers: IDkgReceivers::new(nodes.clone()).unwrap(),
            registry_version: RegistryVersion::from(1),
            verified_dealings: BTreeMap::new(),
            transcript_type: IDkgTranscriptType::Masked(IDkgMaskedTranscriptOrigin::Random),
            algorithm_id: AlgorithmId::ThresholdEcdsaSecp256k1,
            internal_transcript_raw: vec![],
        };
        let key_masked_ref = MaskedTranscript::try_from((height, &key_masked)).unwrap();
        idkg_transcripts.insert(*key_masked_ref.as_ref(), key_masked);

        let key_unmasked = IDkgTranscript {
            transcript_id: key_unmasked_id,
            receivers: IDkgReceivers::new(nodes.clone()).unwrap(),
            registry_version: RegistryVersion::from(1),
            verified_dealings: BTreeMap::new(),
            transcript_type: IDkgTranscriptType::Unmasked(
                IDkgUnmaskedTranscriptOrigin::ReshareMasked(key_masked_id),
            ),
            algorithm_id: AlgorithmId::ThresholdEcdsaSecp256k1,
            internal_transcript_raw: vec![],
        };
        let key_unmasked_ref = UnmaskedTranscript::try_from((height, &key_unmasked)).unwrap();
        idkg_transcripts.insert(*key_unmasked_ref.as_ref(), key_unmasked);

        let kappa_unmasked_times_lambda_masked = IDkgTranscript {
            transcript_id: kappa_unmasked_times_lambda_masked_id,
            receivers: IDkgReceivers::new(nodes.clone()).unwrap(),
            registry_version: RegistryVersion::from(1),
            verified_dealings: BTreeMap::new(),
            transcript_type: IDkgTranscriptType::Masked(
                IDkgMaskedTranscriptOrigin::UnmaskedTimesMasked(
                    kappa_unmasked_id,
                    lambda_masked_id,
                ),
            ),
            algorithm_id: AlgorithmId::ThresholdEcdsaSecp256k1,
            internal_transcript_raw: vec![],
        };
        let kappa_unmasked_times_lambda_masked_ref =
            MaskedTranscript::try_from((height, &kappa_unmasked_times_lambda_masked)).unwrap();
        idkg_transcripts.insert(
            *kappa_unmasked_times_lambda_masked_ref.as_ref(),
            kappa_unmasked_times_lambda_masked,
        );

        let key_unmasked_times_lambda_masked = IDkgTranscript {
            transcript_id: key_unmasked_times_lambda_masked_id,
            receivers: IDkgReceivers::new(nodes.clone()).unwrap(),
            registry_version: RegistryVersion::from(1),
            verified_dealings: BTreeMap::new(),
            transcript_type: IDkgTranscriptType::Masked(
                IDkgMaskedTranscriptOrigin::UnmaskedTimesMasked(key_unmasked_id, lambda_masked_id),
            ),
            algorithm_id: AlgorithmId::ThresholdEcdsaSecp256k1,
            internal_transcript_raw: vec![],
        };
        let key_unmasked_times_lambda_masked_ref =
            MaskedTranscript::try_from((height, &key_unmasked_times_lambda_masked)).unwrap();
        idkg_transcripts.insert(
            *key_unmasked_times_lambda_masked_ref.as_ref(),
            key_unmasked_times_lambda_masked,
        );

        let presig_quadruple_ref = PreSignatureQuadrupleRef::new(
            kappa_unmasked_ref,
            lambda_masked_ref,
            kappa_unmasked_times_lambda_masked_ref,
            key_unmasked_times_lambda_masked_ref,
        );
        let sig_inputs_ref = ThresholdEcdsaSigInputsRef::new(
            ExtendedDerivationPath {
                caller: PrincipalId::try_from(&vec![caller]).unwrap(),
                derivation_path: vec![],
            },
            vec![],
            Randomness::from([0_u8; 32]),
            presig_quadruple_ref,
            key_unmasked_ref,
        );

        TestSigInputs {
            idkg_transcripts,
            sig_inputs_ref,
        }
    }

    // Creates a test signature input
    pub(crate) fn create_sig_inputs(caller: u8) -> TestSigInputs {
        create_sig_inputs_with_height(caller, Height::new(0))
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
