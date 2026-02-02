//! This module contains functions for constructing CUPs from registry

use ic_consensus_dkg::payload_builder::get_dkg_summary_from_cup_contents;
use ic_consensus_idkg::{
    make_bootstrap_summary, make_bootstrap_summary_with_initial_dealings,
    utils::{get_idkg_chain_key_config_if_enabled, inspect_idkg_chain_key_initializations},
};
use ic_interfaces_registry::RegistryClient;
use ic_logger::{ReplicaLogger, warn};
use ic_protobuf::registry::subnet::v1::CatchUpPackageContents;
use ic_registry_client_helpers::subnet::SubnetRegistry;
use ic_types::{
    Height, RegistryVersion, SubnetId, Time,
    batch::ValidationContext,
    consensus::{
        Block, BlockPayload, CatchUpContent, CatchUpPackage, HashedBlock, HashedRandomBeacon,
        Payload, RandomBeaconContent, Rank, SummaryPayload, idkg,
    },
    crypto::{
        CombinedThresholdSig, CombinedThresholdSigOf, CryptoHash, Signed, crypto_hash,
        threshold_sig::ni_dkg::NiDkgTag,
    },
    signature::ThresholdSignature,
};
use phantom_newtype::Id;

/// Constructs a genesis/recovery CUP from the CUP contents associated with the
/// given subnet from the provided CUP contents
pub fn make_registry_cup_from_cup_contents(
    registry: &dyn RegistryClient,
    subnet_id: SubnetId,
    cup_contents: CatchUpPackageContents,
    registry_version: RegistryVersion,
    logger: &ReplicaLogger,
) -> Option<CatchUpPackage> {
    let replica_version = match registry.get_replica_version(subnet_id, registry_version) {
        Ok(Some(replica_version)) => replica_version,
        err => {
            warn!(
                logger,
                "Failed to retrieve subnet replica version at registry version {:?}: {:?}",
                registry_version,
                err
            );
            return None;
        }
    };
    let dkg_summary = match get_dkg_summary_from_cup_contents(
        cup_contents.clone(),
        subnet_id,
        registry,
        registry_version,
    ) {
        Ok(summary) => summary,
        Err(err) => {
            warn!(
                logger,
                "Failed constructing NiDKG summary block from CUP contents: {}.", err
            );

            return None;
        }
    };
    let cup_height = Height::new(cup_contents.height);

    let idkg_summary = match bootstrap_idkg_summary(
        &cup_contents,
        subnet_id,
        registry_version,
        registry,
        logger,
    ) {
        Ok(summary) => summary,
        Err(err) => {
            warn!(
                logger,
                "Failed constructing IDKG summary block from CUP contents: {}.", err
            );

            return None;
        }
    };

    let Some(low_threshold_transcript) = dkg_summary.current_transcript(&NiDkgTag::LowThreshold)
    else {
        warn!(
            logger,
            "No current low threshold transcript in registry CUP contents"
        );
        return None;
    };
    let low_dkg_id = low_threshold_transcript.dkg_id.clone();

    let Some(high_threshold_transcript) = dkg_summary.current_transcript(&NiDkgTag::HighThreshold)
    else {
        warn!(
            logger,
            "No current high threshold transcript in registry CUP contents"
        );
        return None;
    };
    let high_dkg_id = high_threshold_transcript.dkg_id.clone();

    // In a NNS subnet recovery case the block validation context needs to reference a registry
    // version of the NNS to be recovered. Otherwise the validation context points to a registry
    // version without the NNS subnet record.
    let block_registry_version = cup_contents
        .registry_store_uri
        .as_ref()
        .map(|v| RegistryVersion::from(v.registry_version))
        .unwrap_or(registry_version);
    let block = Block {
        version: replica_version.clone(),
        parent: Id::from(CryptoHash(Vec::new())),
        payload: Payload::new(
            crypto_hash,
            BlockPayload::Summary(SummaryPayload {
                dkg: dkg_summary,
                idkg: idkg_summary,
            }),
        ),
        height: cup_height,
        rank: Rank(0),
        context: ValidationContext {
            certified_height: cup_height,
            registry_version: block_registry_version,
            time: Time::from_nanos_since_unix_epoch(cup_contents.time),
        },
    };
    let random_beacon = Signed {
        content: RandomBeaconContent {
            version: replica_version,
            height: cup_height,
            parent: Id::from(CryptoHash(Vec::new())),
        },
        signature: ThresholdSignature {
            signer: low_dkg_id,
            signature: CombinedThresholdSigOf::new(CombinedThresholdSig(vec![])),
        },
    };

    Some(CatchUpPackage {
        content: CatchUpContent::new(
            HashedBlock::new(crypto_hash, block),
            HashedRandomBeacon::new(crypto_hash, random_beacon),
            Id::from(CryptoHash(cup_contents.state_hash)),
            /* oldest_registry_version_in_use_by_replicated_state */ None,
        ),
        signature: ThresholdSignature {
            signer: high_dkg_id,
            signature: CombinedThresholdSigOf::new(CombinedThresholdSig(vec![])),
        },
    })
}

/// Constructs a genesis/recovery CUP from the CUP contents associated with the
/// given subnet
pub fn make_registry_cup(
    registry: &dyn RegistryClient,
    subnet_id: SubnetId,
    logger: &ReplicaLogger,
) -> Option<CatchUpPackage> {
    let versioned_record = match registry.get_cup_contents(subnet_id, registry.get_latest_version())
    {
        Ok(versioned_record) => versioned_record,
        Err(e) => {
            warn!(
                logger,
                "Failed to retrieve versioned record from the registry {:?}", e,
            );
            return None;
        }
    };

    let Some(cup_contents) = versioned_record.value else {
        warn!(
            logger,
            "Missing registry CUP contents at version {}", versioned_record.version
        );
        return None;
    };

    make_registry_cup_from_cup_contents(
        registry,
        subnet_id,
        cup_contents,
        versioned_record.version,
        logger,
    )
}

fn bootstrap_idkg_summary_from_cup_contents(
    cup_contents: &CatchUpPackageContents,
    subnet_id: SubnetId,
    logger: &ReplicaLogger,
) -> Result<idkg::Summary, String> {
    let initial_dealings = inspect_idkg_chain_key_initializations(
        &cup_contents.ecdsa_initializations,
        &cup_contents.chain_key_initializations,
    )?;
    if initial_dealings.is_empty() {
        return Ok(None);
    };

    make_bootstrap_summary_with_initial_dealings(
        subnet_id,
        Height::new(cup_contents.height),
        initial_dealings,
        logger,
    )
    .map_err(|err| format!("Failed to create IDKG summary block: {err:?}"))
}

fn bootstrap_idkg_summary(
    cup_contents: &CatchUpPackageContents,
    subnet_id: SubnetId,
    registry_version: RegistryVersion,
    registry_client: &dyn RegistryClient,
    logger: &ReplicaLogger,
) -> Result<idkg::Summary, String> {
    if let Some(summary) =
        bootstrap_idkg_summary_from_cup_contents(cup_contents, subnet_id, logger)?
    {
        return Ok(Some(summary));
    }

    match get_idkg_chain_key_config_if_enabled(subnet_id, registry_version, registry_client)
        .map_err(|err| format!("Failed getting the chain key config: {err:?}"))?
    {
        Some(chain_key_config) => Ok(make_bootstrap_summary(
            subnet_id,
            chain_key_config
                .key_configs
                .iter()
                .map(|key_config| key_config.key_id.clone())
                .filter_map(|key_id| key_id.try_into().ok())
                .collect(),
            Height::new(cup_contents.height),
        )),
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use ic_crypto_test_utils_ni_dkg::dummy_initial_dkg_transcript;
    use ic_interfaces_registry::{RegistryClient, RegistryVersionedRecord};
    use ic_logger::no_op_logger;
    use ic_protobuf::registry::subnet::v1::{CatchUpPackageContents, SubnetRecord};
    use ic_types::{
        Height, NodeId, PrincipalId, RegistryVersion, ReplicaVersion, Time,
        consensus::HasVersion,
        crypto::{CryptoHash, threshold_sig::ni_dkg::NiDkgTag},
        registry::RegistryClientError,
    };
    use ic_types_test_utils::ids::subnet_test_id;

    #[test]
    fn test_make_registry_cup() {
        let registry_client = MockRegistryClient::new(RegistryVersion::from(12345), |key, _| {
            use prost::Message;
            if key.starts_with("catch_up_package_contents_") {
                // Build a dummy cup
                let committee = vec![NodeId::from(PrincipalId::new_node_test_id(0))];
                let cup =
                    CatchUpPackageContents {
                        initial_ni_dkg_transcript_low_threshold: Some(
                            dummy_initial_dkg_transcript(committee.clone(), NiDkgTag::LowThreshold),
                        ),
                        initial_ni_dkg_transcript_high_threshold: Some(
                            dummy_initial_dkg_transcript(committee, NiDkgTag::HighThreshold),
                        ),
                        height: 54321,
                        time: 1,
                        state_hash: vec![1, 2, 3, 4, 5],
                        registry_store_uri: None,
                        ecdsa_initializations: vec![],
                        chain_key_initializations: vec![],
                    };

                // Encode the cup to protobuf
                let mut value = Vec::with_capacity(cup.encoded_len());
                cup.encode(&mut value).unwrap();
                Some(value)
            } else if key.starts_with("subnet_record_") {
                // Build a dummy subnet record. The only value used from this are the
                // `membership` and `dkg_interval_length` fields.
                let subnet_record = SubnetRecord {
                    membership: vec![PrincipalId::new_subnet_test_id(1).to_vec()],
                    dkg_interval_length: 99,
                    replica_version_id: "TestID".to_string(),
                    ..SubnetRecord::default()
                };

                // Encode the `SubnetRecord` to protobuf
                let mut value = Vec::with_capacity(subnet_record.encoded_len());
                subnet_record.encode(&mut value).unwrap();
                Some(value)
            } else {
                None
            }
        });
        let result =
            make_registry_cup(&registry_client, subnet_test_id(0), &no_op_logger()).unwrap();

        assert_eq!(
            result.content.state_hash.get_ref(),
            &CryptoHash(vec![1, 2, 3, 4, 5])
        );
        assert_eq!(
            result.content.block.get_value().context.registry_version,
            RegistryVersion::from(12345)
        );
        assert_eq!(
            result.content.block.get_value().context.certified_height,
            Height::from(54321)
        );
        assert_eq!(
            result.content.version(),
            &ReplicaVersion::try_from("TestID").unwrap()
        );
        assert_eq!(result.signature.signer.dealer_subnet, subnet_test_id(0));
    }

    /// `RegistryClient` implementation that allows to provide a custom function
    /// to provide a `get_versioned_value`.
    struct MockRegistryClient<F>
    where
        F: Fn(&str, RegistryVersion) -> Option<Vec<u8>>,
    {
        latest_registry_version: RegistryVersion,
        get_versioned_value_fun: F,
    }

    impl<F> MockRegistryClient<F>
    where
        F: Fn(&str, RegistryVersion) -> Option<Vec<u8>>,
    {
        fn new(latest_registry_version: RegistryVersion, get_versioned_value_fun: F) -> Self {
            Self {
                latest_registry_version,
                get_versioned_value_fun,
            }
        }
    }

    impl<F> RegistryClient for MockRegistryClient<F>
    where
        F: Fn(&str, RegistryVersion) -> Option<Vec<u8>> + Send + Sync,
    {
        fn get_versioned_value(
            &self,
            key: &str,
            version: RegistryVersion,
        ) -> ic_interfaces_registry::RegistryClientVersionedResult<Vec<u8>> {
            let value = (self.get_versioned_value_fun)(key, version);
            Ok(RegistryVersionedRecord {
                key: key.to_string(),
                version,
                value,
            })
        }

        // Not needed for this test
        fn get_key_family(
            &self,
            _: &str,
            _: RegistryVersion,
        ) -> Result<Vec<String>, RegistryClientError> {
            Ok(vec![])
        }

        fn get_latest_version(&self) -> RegistryVersion {
            self.latest_registry_version
        }

        // Not needed for this test
        fn get_version_timestamp(&self, _: RegistryVersion) -> Option<Time> {
            None
        }
    }
}
