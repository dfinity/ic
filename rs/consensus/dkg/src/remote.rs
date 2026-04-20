use crate::{
    MAX_REMOTE_DKG_ATTEMPTS, REMOTE_DKG_REPEATED_FAILURE_ERROR,
    payload_builder::{
        create_low_high_remote_dkg_configs, create_remote_dkg_config_for_key_id, get_node_list,
    },
};
use ic_interfaces_registry::RegistryClient;
use ic_logger::ReplicaLogger;
use ic_replicated_state::{
    ReplicatedState,
    metadata_state::subnet_call_context_manager::{ReshareChainKeyContext, SetupInitialDkgContext},
};
use ic_types::{
    Height, RegistryVersion, SubnetId,
    consensus::dkg::{DkgPayloadCreationError, DkgSummary},
    crypto::threshold_sig::ni_dkg::{
        NiDkgId, NiDkgMasterPublicKeyId, NiDkgTag, NiDkgTargetId, NiDkgTargetSubnet,
        NiDkgTranscript, config::NiDkgConfig,
    },
    messages::CallbackId,
};
use std::collections::BTreeMap;

/// The result of creating DKG configs for a given request context.
pub(crate) type ConfigResult = Result<Vec<NiDkgConfig>, Vec<(NiDkgId, String)>>;

/// A wrapper around the ReshareChainKeyContexts to be handled by the NiDKG module.
struct NiDkgReshareChainKeyContext<'a> {
    context: &'a ReshareChainKeyContext,
    key_id: NiDkgMasterPublicKeyId,
}

impl<'a> TryFrom<&'a ReshareChainKeyContext> for NiDkgReshareChainKeyContext<'a> {
    type Error = &'static str;

    fn try_from(context: &'a ReshareChainKeyContext) -> Result<Self, Self::Error> {
        let key_id = NiDkgMasterPublicKeyId::try_from(context.key_id.clone())?;
        Ok(NiDkgReshareChainKeyContext { context, key_id })
    }
}

enum RemoteDkgContext<'a> {
    SetupInitialDKG(&'a SetupInitialDkgContext),
    ReshareChainKey(NiDkgReshareChainKeyContext<'a>),
}

impl<'a> RemoteDkgContext<'a> {
    fn target_id(&self) -> &'a NiDkgTargetId {
        match self {
            RemoteDkgContext::SetupInitialDKG(context) => &context.target_id,
            RemoteDkgContext::ReshareChainKey(context) => &context.context.target_id,
        }
    }

    fn registry_version(&self) -> RegistryVersion {
        match self {
            RemoteDkgContext::SetupInitialDKG(context) => context.registry_version,
            RemoteDkgContext::ReshareChainKey(context) => context.context.registry_version,
        }
    }

    fn generate_timeout_errors(
        &self,
        start_block_height: Height,
        dealer_subnet: SubnetId,
    ) -> Vec<(NiDkgId, String)> {
        let tags = match self {
            RemoteDkgContext::SetupInitialDKG(_) => {
                vec![NiDkgTag::LowThreshold, NiDkgTag::HighThreshold]
            }
            RemoteDkgContext::ReshareChainKey(context) => {
                vec![NiDkgTag::HighThresholdForKey(context.key_id.clone())]
            }
        };
        tags.into_iter()
            .map(|dkg_tag| {
                (
                    NiDkgId {
                        start_block_height,
                        dealer_subnet,
                        dkg_tag,
                        target_subnet: NiDkgTargetSubnet::Remote(*self.target_id()),
                    },
                    REMOTE_DKG_REPEATED_FAILURE_ERROR.to_string(),
                )
            })
            .collect()
    }

    fn create_configs(
        &self,
        start_block_height: Height,
        dealer_subnet: SubnetId,
        registry_client: &dyn RegistryClient,
        get_reshare_transcript: impl Fn(&NiDkgTag) -> Option<NiDkgTranscript>,
        logger: &ReplicaLogger,
    ) -> Result<ConfigResult, DkgPayloadCreationError> {
        let config_result = match self {
            RemoteDkgContext::SetupInitialDKG(context) => {
                let dealers =
                    get_node_list(dealer_subnet, registry_client, context.registry_version)?;
                create_low_high_remote_dkg_configs(
                    start_block_height,
                    dealer_subnet,
                    context.target_id,
                    dealers,
                    context.nodes_in_target_subnet.clone(),
                    &context.registry_version,
                    logger,
                )
                .map(|(config0, config1)| vec![config0, config1])
            }
            RemoteDkgContext::ReshareChainKey(context) => create_remote_dkg_config_for_key_id(
                context.key_id.clone(),
                start_block_height,
                dealer_subnet,
                context.context.target_id,
                context.context.nodes.clone(),
                get_reshare_transcript,
                &context.context.registry_version,
            )
            .map(|config| vec![config])
            .map_err(|err_box| vec![*err_box]),
        };
        Ok(config_result)
    }
}

/// Builds a map from callback ids to config results for all remote DKG contexts
/// found in the given replicated state.
pub(crate) fn build_callback_id_config_map(
    this_subnet_id: SubnetId,
    registry_client: &dyn RegistryClient,
    state: &ReplicatedState,
    registry_version: RegistryVersion,
    dkg_summary: &DkgSummary,
    logger: &ReplicaLogger,
) -> Result<BTreeMap<CallbackId, ConfigResult>, DkgPayloadCreationError> {
    let mut callback_id_config_map = BTreeMap::new();
    let call_contexts = &state.metadata.subnet_call_context_manager;
    let remote_dkg_attempts = &dkg_summary.initial_dkg_attempts;

    let setup_contexts = call_contexts
        .setup_initial_dkg_contexts
        .iter()
        .map(|(&callback_id, context)| (callback_id, RemoteDkgContext::SetupInitialDKG(context)));
    let reshare_contexts =
        call_contexts
            .reshare_chain_key_contexts
            .iter()
            .filter_map(|(&callback_id, context)| {
                NiDkgReshareChainKeyContext::try_from(context)
                    .ok()
                    .map(|context| (callback_id, RemoteDkgContext::ReshareChainKey(context)))
            });

    let get_reshare_transcript = |tag: &NiDkgTag| {
        dkg_summary
            .next_transcripts()
            .get(tag)
            .cloned()
            .or_else(|| dkg_summary.current_transcripts().get(tag).cloned())
    };

    for (callback_id, context) in setup_contexts.chain(reshare_contexts) {
        if context.registry_version() > registry_version {
            continue;
        }

        if let Some(&attempts) = remote_dkg_attempts.get(context.target_id()) {
            if attempts == 0 {
                continue;
            }
            if attempts >= MAX_REMOTE_DKG_ATTEMPTS {
                callback_id_config_map.insert(
                    callback_id,
                    Err(context.generate_timeout_errors(dkg_summary.height, this_subnet_id)),
                );
                continue;
            }
        }

        callback_id_config_map.insert(
            callback_id,
            context.create_configs(
                dkg_summary.height,
                this_subnet_id,
                registry_client,
                get_reshare_transcript,
                logger,
            )?,
        );
    }

    Ok(callback_id_config_map)
}

/// Merges the configs from the summary and the configs from the request contexts.
pub(crate) fn merge_configs<'a>(
    summary_configs: &'a BTreeMap<NiDkgId, NiDkgConfig>,
    config_results: &'a BTreeMap<CallbackId, ConfigResult>,
) -> BTreeMap<&'a NiDkgId, &'a NiDkgConfig> {
    let mut merged_configs: BTreeMap<&NiDkgId, &NiDkgConfig> = summary_configs.iter().collect();
    for configs in config_results.values().flatten() {
        for config in configs {
            merged_configs.insert(config.dkg_id(), config);
        }
    }
    merged_configs
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_crypto_test_utils_ni_dkg::dummy_transcript_for_tests_with_params;
    use ic_logger::replica_logger::no_op_logger;
    use ic_management_canister_types_private::{
        EcdsaCurve, EcdsaKeyId, MasterPublicKeyId, VetKdCurve, VetKdKeyId,
    };
    use ic_replicated_state::metadata_state::subnet_call_context_manager::{
        ReshareChainKeyContext, SetupInitialDkgContext,
    };
    use ic_test_utilities_registry::{SubnetRecordBuilder, setup_registry};
    use ic_test_utilities_state::ReplicatedStateBuilder;
    use ic_test_utilities_types::ids::{node_test_id, subnet_test_id};
    use ic_test_utilities_types::messages::RequestBuilder;
    use ic_types::{
        NodeId, NumberOfNodes, RegistryVersion,
        crypto::threshold_sig::ni_dkg::{NiDkgTag, NiDkgTargetSubnet, config::NiDkgConfigData},
        messages::CallbackId,
        time::UNIX_EPOCH,
    };
    use std::collections::BTreeSet;

    fn test_dkg_summary(
        height: Height,
        current_transcripts: BTreeMap<NiDkgTag, NiDkgTranscript>,
        next_transcripts: BTreeMap<NiDkgTag, NiDkgTranscript>,
        initial_dkg_attempts: BTreeMap<NiDkgTargetId, u32>,
    ) -> DkgSummary {
        DkgSummary::new(
            vec![],
            current_transcripts,
            next_transcripts,
            vec![],
            RegistryVersion::from(1),
            Height::from(10),
            Height::from(10),
            height,
            initial_dkg_attempts,
        )
    }

    fn test_setup_initial_dkg_context(
        target_id: NiDkgTargetId,
        registry_version: RegistryVersion,
        nodes_in_target_subnet: BTreeSet<NodeId>,
    ) -> SetupInitialDkgContext {
        SetupInitialDkgContext {
            request: RequestBuilder::default().build(),
            nodes_in_target_subnet,
            target_id,
            registry_version,
            time: UNIX_EPOCH,
        }
    }

    fn test_reshare_chain_key_context(
        key_id: MasterPublicKeyId,
        target_id: NiDkgTargetId,
        registry_version: RegistryVersion,
        nodes: BTreeSet<NodeId>,
    ) -> ReshareChainKeyContext {
        ReshareChainKeyContext {
            request: RequestBuilder::default().build(),
            key_id,
            nodes,
            registry_version,
            time: UNIX_EPOCH,
            target_id,
        }
    }

    fn make_test_config(dkg_id: NiDkgId, max_corrupt_dealers: u32) -> NiDkgConfig {
        let nodes: BTreeSet<_> = (0..10).map(node_test_id).collect();
        NiDkgConfig::new(NiDkgConfigData {
            dkg_id,
            max_corrupt_dealers: NumberOfNodes::from(max_corrupt_dealers),
            dealers: nodes.clone(),
            max_corrupt_receivers: NumberOfNodes::from(1),
            receivers: nodes,
            threshold: NumberOfNodes::from(2),
            registry_version: RegistryVersion::from(1),
            resharing_transcript: None,
        })
        .unwrap()
    }

    fn local_dkg_id(tag: NiDkgTag) -> NiDkgId {
        NiDkgId {
            start_block_height: Height::from(0),
            dealer_subnet: subnet_test_id(0),
            dkg_tag: tag,
            target_subnet: NiDkgTargetSubnet::Local,
        }
    }

    fn remote_dkg_id_with_target(tag: NiDkgTag, target_id: [u8; 32]) -> NiDkgId {
        NiDkgId {
            start_block_height: Height::from(0),
            dealer_subnet: subnet_test_id(0),
            dkg_tag: tag,
            target_subnet: NiDkgTargetSubnet::Remote(NiDkgTargetId::new(target_id)),
        }
    }

    #[test]
    fn test_build_callback_id_config_map_setup_initial_dkg() {
        let this_subnet_id = subnet_test_id(10);
        let dealers: Vec<_> = (0..4).map(node_test_id).collect();
        let registry = setup_registry(
            this_subnet_id,
            vec![(1, SubnetRecordBuilder::from(&dealers).build())],
        );

        let target_id = NiDkgTargetId::new([1_u8; 32]);
        let target_id2 = NiDkgTargetId::new([2_u8; 32]);
        let target_id3 = NiDkgTargetId::new([3_u8; 32]);
        let callback_id = CallbackId::from(1);
        let mut state = ReplicatedStateBuilder::new()
            .with_subnet_id(this_subnet_id)
            .build();
        state
            .metadata
            .subnet_call_context_manager
            .setup_initial_dkg_contexts
            .insert(
                callback_id,
                test_setup_initial_dkg_context(
                    target_id,
                    RegistryVersion::from(1),
                    (10..14).map(node_test_id).collect(),
                ),
            );
        state
            .metadata
            .subnet_call_context_manager
            .setup_initial_dkg_contexts
            .insert(
                CallbackId::from(2),
                test_setup_initial_dkg_context(
                    target_id2,
                    RegistryVersion::from(10),
                    (10..14).map(node_test_id).collect(),
                ),
            );
        state
            .metadata
            .subnet_call_context_manager
            .reshare_chain_key_contexts
            .insert(
                CallbackId::from(3),
                test_reshare_chain_key_context(
                    MasterPublicKeyId::Ecdsa(EcdsaKeyId {
                        curve: EcdsaCurve::Secp256k1,
                        name: "idkg_key".to_string(),
                    }),
                    target_id3,
                    RegistryVersion::from(1),
                    (10..14).map(node_test_id).collect(),
                ),
            );

        let dkg_summary = test_dkg_summary(
            Height::from(100),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
        );
        let map = build_callback_id_config_map(
            this_subnet_id,
            registry.as_ref(),
            &state,
            RegistryVersion::from(1),
            &dkg_summary,
            &no_op_logger(),
        )
        .expect("expected callback-id config map");
        assert_eq!(map.len(), 1);
        let configs = map
            .get(&callback_id)
            .expect("missing callback entry")
            .as_ref()
            .expect("expected successful configs");
        assert_eq!(configs.len(), 2);

        let tags = configs
            .iter()
            .map(|config| config.dkg_id().dkg_tag.clone())
            .collect::<BTreeSet<_>>();
        assert_eq!(
            tags,
            BTreeSet::from([NiDkgTag::LowThreshold, NiDkgTag::HighThreshold])
        );
        assert!(configs.iter().all(|config| {
            config.dkg_id().dealer_subnet == this_subnet_id
                && config.dkg_id().target_subnet == NiDkgTargetSubnet::Remote(target_id)
        }));

        let zero_attempts_summary = test_dkg_summary(
            Height::from(101),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::from([(target_id, 0), (target_id2, 0), (target_id3, 0)]),
        );
        let zero_attempts_map = build_callback_id_config_map(
            this_subnet_id,
            registry.as_ref(),
            &state,
            RegistryVersion::from(1),
            &zero_attempts_summary,
            &no_op_logger(),
        )
        .expect("expected callback-id config map");
        assert!(zero_attempts_map.is_empty());

        let max_attempts_summary = test_dkg_summary(
            Height::from(102),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::from([
                (target_id, MAX_REMOTE_DKG_ATTEMPTS),
                (target_id2, MAX_REMOTE_DKG_ATTEMPTS),
                (target_id3, MAX_REMOTE_DKG_ATTEMPTS),
            ]),
        );
        let max_attempts_map = build_callback_id_config_map(
            this_subnet_id,
            registry.as_ref(),
            &state,
            RegistryVersion::from(1),
            &max_attempts_summary,
            &no_op_logger(),
        )
        .expect("expected callback-id config map");
        assert_eq!(max_attempts_map.len(), 1);
        let timeout_errors = max_attempts_map
            .get(&callback_id)
            .expect("missing callback entry for timeout path")
            .as_ref()
            .expect_err("expected timeout errors");
        assert_eq!(timeout_errors.len(), 2);
        assert!(
            timeout_errors
                .iter()
                .all(|(_, err)| err == REMOTE_DKG_REPEATED_FAILURE_ERROR)
        );
        assert_eq!(
            timeout_errors
                .iter()
                .map(|(id, _)| id.dkg_tag.clone())
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([NiDkgTag::LowThreshold, NiDkgTag::HighThreshold])
        );

        state
            .metadata
            .subnet_call_context_manager
            .setup_initial_dkg_contexts
            .insert(
                CallbackId::from(2),
                test_setup_initial_dkg_context(
                    target_id2,
                    RegistryVersion::from(2),
                    (10..14).map(node_test_id).collect(),
                ),
            );
        let setup_error_summary = test_dkg_summary(
            Height::from(103),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
        );
        let result = build_callback_id_config_map(
            this_subnet_id,
            registry.as_ref(),
            &state,
            RegistryVersion::from(2),
            &setup_error_summary,
            &no_op_logger(),
        );
        assert!(matches!(
            result,
            Err(DkgPayloadCreationError::FailedToGetSubnetMemberListFromRegistry(_))
        ));
    }

    #[test]
    fn test_build_callback_id_config_map_reshare_chain_key() {
        let this_subnet_id = subnet_test_id(20);
        let dealers: Vec<_> = (0..4).map(node_test_id).collect();
        let registry = setup_registry(
            this_subnet_id,
            vec![(1, SubnetRecordBuilder::from(&dealers).build())],
        );

        let vet_key_id = VetKdKeyId {
            curve: VetKdCurve::Bls12_381_G2,
            name: "key_a".to_string(),
        };
        let ni_dkg_key_id = NiDkgMasterPublicKeyId::VetKd(vet_key_id.clone());
        let tag = NiDkgTag::HighThresholdForKey(ni_dkg_key_id.clone());
        let transcript_committee: Vec<_> = (50..54).map(node_test_id).collect();
        let transcript = dummy_transcript_for_tests_with_params(
            transcript_committee.clone(),
            tag.clone(),
            tag.threshold_for_subnet_of_size(transcript_committee.len()) as u32,
            1,
        );
        let current_transcript_committee: Vec<_> = (90..94).map(node_test_id).collect();
        let current_transcript = dummy_transcript_for_tests_with_params(
            current_transcript_committee.clone(),
            tag.clone(),
            tag.threshold_for_subnet_of_size(current_transcript_committee.len()) as u32,
            1,
        );

        let target_id = NiDkgTargetId::new([2_u8; 32]);
        let callback_id = CallbackId::from(2);
        let mut state = ReplicatedStateBuilder::new()
            .with_subnet_id(this_subnet_id)
            .build();
        state
            .metadata
            .subnet_call_context_manager
            .reshare_chain_key_contexts
            .insert(
                callback_id,
                test_reshare_chain_key_context(
                    MasterPublicKeyId::VetKd(vet_key_id),
                    target_id,
                    RegistryVersion::from(1),
                    (60..64).map(node_test_id).collect(),
                ),
            );

        let dkg_summary = test_dkg_summary(
            Height::from(101),
            BTreeMap::from([(tag.clone(), current_transcript.clone())]),
            BTreeMap::from([(tag, transcript.clone())]),
            BTreeMap::new(),
        );
        let map = build_callback_id_config_map(
            this_subnet_id,
            registry.as_ref(),
            &state,
            RegistryVersion::from(1),
            &dkg_summary,
            &no_op_logger(),
        )
        .expect("expected callback-id config map");

        let configs = map
            .get(&callback_id)
            .expect("missing callback entry")
            .as_ref()
            .expect("expected successful configs");
        assert_eq!(configs.len(), 1);
        let config = &configs[0];
        assert_eq!(config.resharing_transcript().as_ref(), Some(&transcript));
        assert_ne!(
            config.resharing_transcript().as_ref(),
            Some(&current_transcript)
        );
        assert_eq!(config.dealers().get(), transcript.committee.get());
        assert_ne!(config.dealers().get(), current_transcript.committee.get());

        let missing_transcript_summary = test_dkg_summary(
            Height::from(102),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
        );
        let missing_transcript_map = build_callback_id_config_map(
            this_subnet_id,
            registry.as_ref(),
            &state,
            RegistryVersion::from(1),
            &missing_transcript_summary,
            &no_op_logger(),
        )
        .expect("expected callback-id config map");
        let errors = missing_transcript_map
            .get(&callback_id)
            .expect("missing callback entry")
            .as_ref()
            .expect_err("expected per-context reshare error");
        assert_eq!(errors.len(), 1);
        assert_eq!(
            errors[0].0.dkg_tag,
            NiDkgTag::HighThresholdForKey(ni_dkg_key_id)
        );
        assert!(
            errors[0]
                .1
                .contains("Failed to find resharing transcript for a remote dkg")
        );
    }

    #[test]
    fn test_merge_configs_merges_successes_and_ignores_errors() {
        let summary_only_id = local_dkg_id(NiDkgTag::LowThreshold);
        let overlap_id = remote_dkg_id_with_target(NiDkgTag::HighThreshold, [11_u8; 32]);
        let context_only_id = remote_dkg_id_with_target(NiDkgTag::LowThreshold, [11_u8; 32]);
        let error_only_id = remote_dkg_id_with_target(NiDkgTag::LowThreshold, [12_u8; 32]);

        let summary_only_config = make_test_config(summary_only_id.clone(), 1);
        let overlap_config = make_test_config(overlap_id.clone(), 1);
        let context_only_config = make_test_config(context_only_id.clone(), 1);

        let summary_configs: BTreeMap<_, _> = [
            (summary_only_id.clone(), summary_only_config),
            (overlap_id.clone(), overlap_config.clone()),
        ]
        .into();
        let config_results: BTreeMap<_, _> = [
            (
                CallbackId::from(1),
                Ok(vec![overlap_config.clone(), context_only_config.clone()]),
            ),
            (
                CallbackId::from(2),
                Err(vec![(error_only_id.clone(), "test error".to_string())]),
            ),
        ]
        .into();

        let merged = merge_configs(&summary_configs, &config_results);

        assert_eq!(merged.len(), 3);
        assert!(merged.contains_key(&summary_only_id));
        assert!(merged.contains_key(&overlap_id));
        assert!(merged.contains_key(&context_only_id));
        assert!(!merged.contains_key(&error_only_id));
    }
}
