//! Utilities for testing IDkg and canister threshold signature operations.

use ic_crypto::utils::TempCryptoComponent;
use ic_crypto_internal_threshold_sig_ecdsa::test_utils::corrupt_dealing;
use ic_crypto_internal_threshold_sig_ecdsa::IDkgDealingInternal;
use ic_interfaces::crypto::{IDkgProtocol, MultiSigVerifier, MultiSigner};
use ic_registry_client_fake::FakeRegistryClient;
use ic_registry_keys::make_crypto_node_key;
use ic_registry_proto_data_provider::ProtoRegistryDataProvider;
use ic_types::consensus::ecdsa::EcdsaDealing;
use ic_types::crypto::canister_threshold_sig::idkg::{
    IDkgDealing, IDkgMaskedTranscriptOrigin, IDkgMultiSignedDealing, IDkgReceivers, IDkgTranscript,
    IDkgTranscriptId, IDkgTranscriptOperation, IDkgTranscriptParams, IDkgTranscriptType,
    IDkgUnmaskedTranscriptOrigin,
};
use ic_types::crypto::canister_threshold_sig::PreSignatureQuadruple;
use ic_types::crypto::canister_threshold_sig::ThresholdEcdsaSigInputs;
use ic_types::crypto::{AlgorithmId, KeyPurpose};
use ic_types::{Height, NodeId, PrincipalId, RegistryVersion, SubnetId};
use rand::prelude::*;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

pub fn create_params_for_dealers(
    dealer_set: &BTreeSet<NodeId>,
    operation: IDkgTranscriptOperation,
) -> IDkgTranscriptParams {
    IDkgTranscriptParams::new(
        random_transcript_id(),
        dealer_set.clone(),
        dealer_set.clone(),
        RegistryVersion::from(0),
        AlgorithmId::ThresholdEcdsaSecp256k1,
        operation,
    )
    .expect("Should be able to create IDKG params")
}

pub fn mock_unmasked_transcript_type() -> IDkgTranscriptType {
    IDkgTranscriptType::Unmasked(IDkgUnmaskedTranscriptOrigin::ReshareMasked(
        random_transcript_id(),
    ))
}

pub fn mock_masked_transcript_type() -> IDkgTranscriptType {
    IDkgTranscriptType::Masked(IDkgMaskedTranscriptOrigin::Random)
}

pub fn mock_transcript(
    receivers: Option<BTreeSet<NodeId>>,
    transcript_type: IDkgTranscriptType,
) -> IDkgTranscript {
    let receivers = match receivers {
        Some(receivers) => receivers,
        None => {
            let mut receivers = BTreeSet::new();
            for i in 1..10 {
                receivers.insert(node_id(i));
            }
            receivers
        }
    };

    IDkgTranscript {
        transcript_id: random_transcript_id(),
        receivers: IDkgReceivers::new(receivers).unwrap(),
        registry_version: RegistryVersion::from(314),
        verified_dealings: BTreeMap::new(),
        transcript_type,
        algorithm_id: AlgorithmId::ThresholdEcdsaSecp256k1,
        internal_transcript_raw: vec![],
    }
}

pub fn create_and_verify_dealing(
    params: &IDkgTranscriptParams,
    crypto_components: &BTreeMap<NodeId, TempCryptoComponent>,
    dealer_id: NodeId,
) -> IDkgDealing {
    let dealing = crypto_for(dealer_id, crypto_components)
        .create_dealing(params)
        .unwrap_or_else(|error| {
            panic!(
                "failed to create IDkg dealing for {:?}: {:?}",
                dealer_id, error
            )
        });

    // Verify the dealing is publicly valid
    let csp = crypto_for(dealer_id, crypto_components);
    csp.verify_dealing_public(params, dealer_id, &dealing)
        .expect("unexpectedly invalid dealing");

    // Verify the dealing is privately valid for all receivers
    for receiver in params.receivers().get() {
        crypto_for(*receiver, crypto_components)
            .verify_dealing_private(params, dealer_id, &dealing)
            .expect("unexpectedly invalid dealing (private verification)");
    }

    dealing
}

pub fn create_dealings(
    params: &IDkgTranscriptParams,
    crypto_components: &BTreeMap<NodeId, TempCryptoComponent>,
) -> BTreeMap<NodeId, IDkgDealing> {
    params
        .dealers()
        .get()
        .iter()
        .map(|node| {
            let dealing = create_and_verify_dealing(params, crypto_components, *node);
            (*node, dealing)
        })
        .collect()
}

pub fn multisign_dealing(
    params: &IDkgTranscriptParams,
    crypto_components: &BTreeMap<NodeId, TempCryptoComponent>,
    dealing: &IDkgDealing,
) -> IDkgMultiSignedDealing {
    let ecdsa_dealing = EcdsaDealing {
        requested_height: Height::from(1),
        idkg_dealing: dealing.clone(),
    };

    let signature = {
        let signatures: BTreeMap<_, _> = params
            .receivers()
            .get()
            .iter()
            .map(|signer_id| {
                let signature = crypto_for(*signer_id, crypto_components)
                    .sign_multi(&ecdsa_dealing, *signer_id, params.registry_version())
                    .expect("failed to generate multi-signature share");

                (*signer_id, signature)
            })
            .collect();

        let combiner_id = random_receiver_id(params);
        crypto_for(combiner_id, crypto_components)
            .combine_multi_sig_individuals(signatures, params.registry_version())
            .expect("failed to combine individual signatures")
    };

    IDkgMultiSignedDealing {
        signature,
        signers: params.receivers().get().clone(),
        dealing: ecdsa_dealing,
    }
}

pub fn multisign_dealings(
    params: &IDkgTranscriptParams,
    crypto_components: &BTreeMap<NodeId, TempCryptoComponent>,
    dealings: &BTreeMap<NodeId, IDkgDealing>,
) -> BTreeMap<NodeId, IDkgMultiSignedDealing> {
    dealings
        .iter()
        .map(|(dealer_id, dealing)| {
            let multisigned_dealing = multisign_dealing(params, crypto_components, dealing);

            (*dealer_id, multisigned_dealing)
        })
        .collect()
}

pub fn create_transcript(
    params: &IDkgTranscriptParams,
    crypto_components: &BTreeMap<NodeId, TempCryptoComponent>,
    dealings: &BTreeMap<NodeId, IDkgMultiSignedDealing>,
    creator_id: NodeId,
) -> IDkgTranscript {
    crypto_for(creator_id, crypto_components)
        .create_transcript(params, dealings)
        .unwrap_or_else(|error| {
            panic!(
                "failed to create transcript for {:?}: {:?}",
                creator_id, error
            )
        })
}

pub fn load_transcript(
    transcript: &IDkgTranscript,
    crypto_components: &BTreeMap<NodeId, TempCryptoComponent>,
    loader_id: NodeId,
) {
    crypto_for(loader_id, crypto_components)
        .load_transcript(transcript)
        .unwrap_or_else(|error| {
            panic!("failed to load transcript for {:?}: {:?}", loader_id, error)
        });
}

pub fn load_input_transcripts(
    crypto_components: &BTreeMap<NodeId, TempCryptoComponent>,
    loader_id: NodeId,
    inputs: &ThresholdEcdsaSigInputs,
) {
    load_transcript(
        inputs.presig_quadruple().kappa_unmasked(),
        crypto_components,
        loader_id,
    );
    load_transcript(
        inputs.presig_quadruple().lambda_masked(),
        crypto_components,
        loader_id,
    );
    load_transcript(
        inputs.presig_quadruple().kappa_times_lambda(),
        crypto_components,
        loader_id,
    );
    load_transcript(
        inputs.presig_quadruple().key_times_lambda(),
        crypto_components,
        loader_id,
    );
    load_transcript(inputs.key_transcript(), crypto_components, loader_id);
}

pub fn load_previous_transcripts_and_create_dealing(
    params: &IDkgTranscriptParams,
    crypto_components: &BTreeMap<NodeId, TempCryptoComponent>,
    loader_id: NodeId,
) -> IDkgDealing {
    match params.operation_type() {
        IDkgTranscriptOperation::Random => (),
        IDkgTranscriptOperation::ReshareOfMasked(transcript)
        | IDkgTranscriptOperation::ReshareOfUnmasked(transcript) => {
            load_transcript(transcript, crypto_components, loader_id);
        }
        IDkgTranscriptOperation::UnmaskedTimesMasked(transcript_1, transcript_2) => {
            load_transcript(transcript_1, crypto_components, loader_id);
            load_transcript(transcript_2, crypto_components, loader_id);
        }
    }

    create_and_verify_dealing(params, crypto_components, loader_id)
}

pub fn load_previous_transcripts_and_create_dealings(
    params: &IDkgTranscriptParams,
    crypto_components: &BTreeMap<NodeId, TempCryptoComponent>,
) -> BTreeMap<NodeId, IDkgDealing> {
    params
        .dealers()
        .get()
        .iter()
        .map(|node| {
            let dealing =
                load_previous_transcripts_and_create_dealing(params, crypto_components, *node);
            (*node, dealing)
        })
        .collect()
}

/// Load previous transcripts on each node (if resharing or multiplying),
/// create all dealings, multi-sign them, and build a transcript from those
/// multi-signed dealings.
pub fn run_idkg_and_create_and_verify_transcript(
    params: &IDkgTranscriptParams,
    crypto_components: &BTreeMap<NodeId, TempCryptoComponent>,
) -> IDkgTranscript {
    let dealings = load_previous_transcripts_and_create_dealings(params, crypto_components);
    let multisigned_dealings = multisign_dealings(params, crypto_components, &dealings);
    let transcript_creator = params.dealers().get().iter().next().unwrap();
    let transcript = create_transcript(
        params,
        crypto_components,
        &multisigned_dealings,
        *transcript_creator,
    );
    assert!(crypto_for(random_receiver_id(params), crypto_components)
        .verify_transcript(params, &transcript)
        .is_ok());
    transcript
}

pub fn generate_key_transcript(
    env: &CanisterThresholdSigTestEnvironment,
    algorithm_id: AlgorithmId,
) -> IDkgTranscript {
    let masked_key_params = env.params_for_random_sharing(algorithm_id);

    let masked_key_transcript =
        run_idkg_and_create_and_verify_transcript(&masked_key_params, &env.crypto_components);

    let unmasked_key_params = build_params_from_previous(
        masked_key_params,
        IDkgTranscriptOperation::ReshareOfMasked(masked_key_transcript),
    );

    run_idkg_and_create_and_verify_transcript(&unmasked_key_params, &env.crypto_components)
}

pub fn generate_presig_quadruple(
    env: &CanisterThresholdSigTestEnvironment,
    algorithm_id: AlgorithmId,
    key_transcript: &IDkgTranscript,
) -> PreSignatureQuadruple {
    let lambda_params = env.params_for_random_sharing(algorithm_id);
    let lambda_transcript =
        run_idkg_and_create_and_verify_transcript(&lambda_params, &env.crypto_components);

    let kappa_transcript = {
        let masked_kappa_params = env.params_for_random_sharing(algorithm_id);

        let masked_kappa_transcript =
            run_idkg_and_create_and_verify_transcript(&masked_kappa_params, &env.crypto_components);

        let unmasked_kappa_params = build_params_from_previous(
            masked_kappa_params,
            IDkgTranscriptOperation::ReshareOfMasked(masked_kappa_transcript),
        );

        run_idkg_and_create_and_verify_transcript(&unmasked_kappa_params, &env.crypto_components)
    };

    let kappa_times_lambda_transcript = {
        let kappa_times_lambda_params = build_params_from_previous(
            lambda_params.clone(),
            IDkgTranscriptOperation::UnmaskedTimesMasked(
                kappa_transcript.clone(),
                lambda_transcript.clone(),
            ),
        );

        run_idkg_and_create_and_verify_transcript(
            &kappa_times_lambda_params,
            &env.crypto_components,
        )
    };

    let key_times_lambda_transcript = {
        let key_times_lambda_params = build_params_from_previous(
            lambda_params,
            IDkgTranscriptOperation::UnmaskedTimesMasked(
                key_transcript.clone(),
                lambda_transcript.clone(),
            ),
        );

        run_idkg_and_create_and_verify_transcript(&key_times_lambda_params, &env.crypto_components)
    };

    PreSignatureQuadruple::new(
        kappa_transcript,
        lambda_transcript,
        kappa_times_lambda_transcript,
        key_times_lambda_transcript,
    )
    .unwrap_or_else(|error| panic!("failed to create pre-signature quadruple: {:?}", error))
}

/// Creates a new `IDkgTranscriptParams` with all information copied from a
/// previous one, except the operation (as given) and the Id
/// (randomly-generated, to avoid collisions).
pub fn build_params_from_previous(
    previous_params: IDkgTranscriptParams,
    operation_type: IDkgTranscriptOperation,
) -> IDkgTranscriptParams {
    IDkgTranscriptParams::new(
        random_transcript_id(),
        previous_params.dealers().get().clone(),
        previous_params.receivers().get().clone(),
        previous_params.registry_version(),
        previous_params.algorithm_id(),
        operation_type,
    )
    .expect("failed to create resharing/multiplication IDkgTranscriptParams")
}

pub struct CanisterThresholdSigTestEnvironment {
    pub crypto_components: BTreeMap<NodeId, TempCryptoComponent>,
    pub registry_data: Arc<ProtoRegistryDataProvider>,
    pub registry: Arc<FakeRegistryClient>,
    pub newest_registry_version: RegistryVersion,
}

impl CanisterThresholdSigTestEnvironment {
    /// Creates a new test environment with the given number of nodes.
    pub fn new(num_of_nodes: usize) -> Self {
        let registry_data = Arc::new(ProtoRegistryDataProvider::new());
        let registry = Arc::new(FakeRegistryClient::new(Arc::clone(&registry_data) as Arc<_>));
        let registry_version = random_registry_version();

        let mut env = Self {
            crypto_components: BTreeMap::new(),
            registry_data,
            registry,
            newest_registry_version: registry_version,
        };

        for node_id in n_random_node_ids(num_of_nodes) {
            env.create_crypto_component_with_mega_and_multisign_keys_in_registry(
                node_id,
                registry_version,
            );
        }
        env.registry.update_to_latest_version();

        env
    }

    /// Returns an `IDkgTranscriptParams` appropriate for creating a random
    /// sharing in this environment.
    pub fn params_for_random_sharing(&self, algorithm_id: AlgorithmId) -> IDkgTranscriptParams {
        let nodes: BTreeSet<NodeId> = self.crypto_components.keys().copied().collect();

        IDkgTranscriptParams::new(
            random_transcript_id(),
            nodes.clone(),
            nodes,
            self.newest_registry_version,
            algorithm_id,
            IDkgTranscriptOperation::Random,
        )
        .expect("failed to create random IDkgTranscriptParams")
    }

    pub fn receivers(&self) -> BTreeSet<NodeId> {
        self.crypto_components.keys().cloned().collect()
    }

    fn create_crypto_component_with_mega_and_multisign_keys_in_registry(
        &mut self,
        node_id: NodeId,
        registry_version: RegistryVersion,
    ) {
        if self.crypto_components.contains_key(&node_id) {
            return;
        }

        let registry = Arc::clone(&self.registry) as Arc<_>;
        let (temp_crypto, node_keys) =
            TempCryptoComponent::new_with_idkg_dealing_encryption_and_multisigning_keys_generation(
                registry, node_id,
            );
        self.crypto_components.insert(node_id, temp_crypto);

        self.registry_data
            .add(
                &make_crypto_node_key(node_id, KeyPurpose::CommitteeSigning),
                registry_version,
                Some(node_keys.multisign_pubkey),
            )
            .expect("failed to add committee public key to registry");

        self.registry_data
            .add(
                &make_crypto_node_key(node_id, KeyPurpose::IDkgMEGaEncryption),
                registry_version,
                Some(node_keys.mega_pubkey),
            )
            .expect("Could not add MEGa public key to registry");
    }
}

pub fn random_receiver_for_inputs(inputs: &ThresholdEcdsaSigInputs) -> NodeId {
    *inputs
        .receivers()
        .get()
        .iter()
        .choose(&mut thread_rng())
        .expect("receivers is empty")
}

/// Returns a randomly-generate `NodeId` that is *not* in `exclusions`.
pub fn random_node_id_excluding(exclusions: &BTreeSet<NodeId>) -> NodeId {
    *random_node_ids_excluding(exclusions, 1)
        .iter()
        .next()
        .expect("we know this is non-empty")
}

/// Returns `n` randomly-generate `NodeId`s that are *not* in `exclusions`.
pub fn random_node_ids_excluding(exclusions: &BTreeSet<NodeId>, n: usize) -> BTreeSet<NodeId> {
    let rng = &mut thread_rng();
    let mut node_ids = BTreeSet::new();
    while node_ids.len() < n {
        let candidate = node_id(rng.gen());
        if !exclusions.contains(&candidate) {
            node_ids.insert(candidate);
        }
    }
    assert!(node_ids.is_disjoint(exclusions));
    node_ids
}

pub fn node_id(id: u64) -> NodeId {
    NodeId::from(PrincipalId::new_node_test_id(id))
}

pub fn set_of_nodes(ids: &[u64]) -> BTreeSet<NodeId> {
    let mut nodes = BTreeSet::new();
    for id in ids.iter() {
        nodes.insert(node_id(*id));
    }
    nodes
}

fn random_registry_version() -> RegistryVersion {
    RegistryVersion::new(thread_rng().gen_range(1, u32::MAX) as u64)
}

fn random_transcript_id() -> IDkgTranscriptId {
    let mut rng = thread_rng();

    let id = rng.gen::<u64>();
    let subnet = SubnetId::from(PrincipalId::new_subnet_test_id(rng.gen::<u64>()));
    let height = Height::from(rng.gen::<u64>());

    IDkgTranscriptId::new(subnet, id, height)
}

fn n_random_node_ids(n: usize) -> BTreeSet<NodeId> {
    let rng = &mut thread_rng();
    let mut node_ids = BTreeSet::new();
    while node_ids.len() < n {
        node_ids.insert(NodeId::from(PrincipalId::new_node_test_id(rng.gen())));
    }
    node_ids
}

fn crypto_for<T>(node_id: NodeId, crypto_components: &BTreeMap<NodeId, T>) -> &T {
    crypto_components
        .get(&node_id)
        .unwrap_or_else(|| panic!("missing crypto component for {:?}", node_id))
}

pub fn random_receiver_id(params: &IDkgTranscriptParams) -> NodeId {
    *params
        .receivers()
        .get()
        .iter()
        .choose(&mut thread_rng())
        .expect("receivers is empty")
}

pub fn random_receiver_id_excluding(receivers: &IDkgReceivers, exclusion: NodeId) -> NodeId {
    if receivers.get().len() == 1 {
        let (_receiver_idx, receiver_id) = receivers.iter().next().unwrap();
        if receiver_id == exclusion {
            panic!("the only possible receiver is excluded")
        }
    }
    let rng = &mut thread_rng();
    loop {
        let random_receiver_id = *receivers.get().iter().choose(rng).expect("receivers empty");
        if random_receiver_id != exclusion {
            return random_receiver_id;
        }
    }
}

pub fn random_dealer_id(params: &IDkgTranscriptParams) -> NodeId {
    *params
        .dealers()
        .get()
        .iter()
        .choose(&mut thread_rng())
        .expect("dealers is empty")
}

/// Corrupts the dealing for a single randomly picked receiver.
/// node_id is the self Node Id. The shares for the receivers specified
/// in exclude_receivers won't be corrupted.
/// The transcript params used to create the dealing is passed in with the
/// dealing to be corrupted.
pub fn corrupt_idkg_dealing<R: CryptoRng + RngCore>(
    idkg_dealing: &IDkgDealing,
    transcript_params: &IDkgTranscriptParams,
    exclude_receivers: &BTreeSet<NodeId>,
    rng: &mut R,
) -> Result<IDkgDealing, CorruptIDkgDealingError> {
    let internal_dealing = IDkgDealingInternal::deserialize(&idkg_dealing.internal_dealing_raw)
        .map_err(|e| CorruptIDkgDealingError::SerializationError(format!("{:?}", e)))?;

    let receivers: Vec<_> = transcript_params
        .receivers()
        .get()
        .difference(exclude_receivers)
        .collect();
    if receivers.is_empty() {
        return Err(CorruptIDkgDealingError::NoReceivers);
    }
    let receiver = receivers[rng.gen_range(0, receivers.len())];
    let node_index = transcript_params.receivers().position(*receiver).unwrap();

    let corrupted_dealing = corrupt_dealing(&internal_dealing, &[node_index], rng)
        .map_err(|e| CorruptIDkgDealingError::FailedToCorruptDealing(format!("{:?}", e)))?;
    let internal_dealing_raw = corrupted_dealing
        .serialize()
        .map_err(|e| CorruptIDkgDealingError::SerializationError(format!("{:?}", e)))?;
    Ok(IDkgDealing {
        transcript_id: idkg_dealing.transcript_id,
        dealer_id: idkg_dealing.dealer_id,
        internal_dealing_raw,
    })
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CorruptIDkgDealingError {
    SerializationError(String),
    FailedToCorruptDealing(String),
    NoReceivers,
}
