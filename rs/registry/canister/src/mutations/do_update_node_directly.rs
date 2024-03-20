use std::time::{Duration, SystemTime};

use crate::{common::LOG_PREFIX, mutations::common::encode_or_panic, registry::Registry};

use prost::Message;

use candid::{CandidType, Deserialize};
use dfn_core::api::now;
#[cfg(target_arch = "wasm32")]
use dfn_core::println;
use ic_base_types::NodeId;
use ic_crypto_node_key_validation::ValidIDkgDealingEncryptionPublicKey;
use ic_nns_common::registry::get_subnet_ids_from_subnet_list;
use ic_protobuf::registry::{crypto::v1::PublicKey, subnet::v1::SubnetRecord};
use ic_registry_keys::{make_crypto_node_key, make_node_record_key};
use ic_registry_transport::update;
use ic_types::{crypto::KeyPurpose, PrincipalId};

// Since nodes update their keys in turn, every potential update delay will carry over to all
// subsequent slots. At some point we might end up in a situation where many nodes race for an update,
// which is not harmful, but unnecessary. So we use a 15% time buffer compensating for a
// potential delay of the previous node. But since the key update of every node is still delayed by
// it's own expiration timestamp, they won't update too early.
const DELAY_COMPENSATION: f64 = 0.85;

impl Registry {
    /// Updates an existing node's config in the registry.
    ///
    /// This method is called directly by the node itself that needs to update its iDKG key.
    /// The update is only executed, if the previous key does not exist at all or is older than
    /// `ecdsa_config.idkg_key_rotation_period_ms` and the most recent key update in the node's
    /// subnet happened more than `ecdsa_config.idkg_key_rotation_period_ms / subnet_size` ago.
    pub fn do_update_node_directly(
        &mut self,
        payload: UpdateNodeDirectlyPayload,
    ) -> Result<(), String> {
        println!("{}do_update_node_directly: {:?}", LOG_PREFIX, payload);
        // We pull out the caller retrieval and determining of the current time, so that we can unit test the underlying function
        // with any node id.
        let node_id = NodeId::from(dfn_core::api::caller());
        self.do_update_node(now(), node_id, payload)
    }

    fn do_update_node(
        &mut self,
        now: SystemTime,
        node_id: NodeId,
        payload: UpdateNodeDirectlyPayload,
    ) -> Result<(), String> {
        // 1. Check that caller is a node with a node_id that exists
        let node_key = make_node_record_key(node_id);
        self
            .get(node_key.as_bytes(), self.latest_version())
            .ok_or_else(|| format!(
            "{}do_update_node_directly: Node Id {:} not found in the registry, aborting node update.",
            LOG_PREFIX, node_id))?;

        // 2. Disallow updating if the node is not on an ECDSA subnet or key rotation is disabled.
        let subnet_record = self.get_subnet_from_node_id_or_panic(node_id);
        let subnet_size = subnet_record.membership.len();
        if subnet_record
            .ecdsa_config
            .as_ref()
            .map(|config| config.key_ids.is_empty())
            .unwrap_or(true)
        {
            return Err("the node is not on an ECDSA subnet".to_string());
        }
        // Get key rotation period (delta) from config.
        let idkg_key_rotation_period_ms = subnet_record
            .ecdsa_config
            .as_ref()
            .and_then(|c| c.idkg_key_rotation_period_ms)
            .ok_or_else(|| "the key rotation feature is disabled".to_string())?;

        // 3. Disallow updating if the existing key is sufficiently fresh.
        let duration_since_unix_epoch = now
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|err| format!("couldn't get time since unix epoch: {}", err))?;

        let idkg_pk_key = make_crypto_node_key(node_id, KeyPurpose::IDkgMEGaEncryption);
        let previous_timestamp_set = match self.get(idkg_pk_key.as_bytes(), self.latest_version()) {
            Some(record) => {
                let pk = PublicKey::decode(record.value.as_slice()).map_err(|e| {
                    format!(
                        "idkg_dealing_encryption_pk is not in the expected format: {:?}",
                        e
                    )
                })?;
                // If the timestamp exists, we reject if it's recent enough, otherwise we accept the
                // update as this is a new node joining the ECDSA subnet.
                match pk.timestamp {
                    Some(last_update_timestamp) => {
                        let sum = last_update_timestamp
                            .checked_add(idkg_key_rotation_period_ms)
                            .ok_or_else(|| {
                                "Integer overflow when adding key rotation period.".to_string()
                            })?;
                        if Duration::from_millis(sum) > duration_since_unix_epoch {
                            return Err("the key of this node is sufficiently fresh".to_string());
                        }
                        true
                    }
                    None => false,
                }
            }
            None => false,
        };

        // 4. Disallow updating if the most recent key update on the subnet is not old enough.
        //    If the node has no timestamp, skip all checks.
        if previous_timestamp_set {
            if let Some(last_key_update_timestamp) = self.last_key_update_on_subnet(subnet_record) {
                // The node is on ECDSA subnet, and has a timestamp
                let key_rotation_period_on_subnet =
                    (idkg_key_rotation_period_ms as f64 / subnet_size as f64 * DELAY_COMPENSATION)
                        as u64;
                let sum = last_key_update_timestamp
                    .checked_add(key_rotation_period_on_subnet)
                    .ok_or_else(|| {
                        "Integer overflow when adding key rotation period on subnet.".to_string()
                    })?;
                if Duration::from_millis(sum) > duration_since_unix_epoch {
                    return Err("the ECDSA subnet had a key update recently".to_string());
                }
            }
        }

        // 5. Deserialize and validate the pk
        let valid_idkg_dealing_encryption_pk = {
            let mut pk = PublicKey::decode(
                &payload
                    .idkg_dealing_encryption_pk
                    .as_ref()
                    .map_or(&vec![], |v| v)[..],
            )
            .map_err(|e| {
                format!(
                    "idkg_dealing_encryption_pk is not in the expected format: {:?}",
                    e
                )
            })?;
            // Set the key timestamp to the current time.
            pk.timestamp = Some(duration_since_unix_epoch.as_millis() as u64);
            ValidIDkgDealingEncryptionPublicKey::try_from(pk)
                .map_err(|e| format!("key validation failed: {}", e))?
        };

        // 6. Create mutation for new record
        let insert_idkg_key = update(
            idkg_pk_key.as_bytes(),
            encode_or_panic(valid_idkg_dealing_encryption_pk.get()),
        );

        let mutations = vec![insert_idkg_key];

        // 7. Check invariants before applying mutations
        self.maybe_apply_mutation_internal(mutations);

        Ok(())
    }

    fn get_subnet_from_node_id_or_panic(&self, node_id: NodeId) -> SubnetRecord {
        get_subnet_ids_from_subnet_list(self.get_subnet_list_record())
            .into_iter()
            .map(|subnet_id| self.get_subnet_or_panic(subnet_id))
            .find(|subnet_record| subnet_record.membership.contains(&node_id.get().to_vec()))
            .unwrap_or_else(|| {
                panic!(
                    "{}subnet record for node {:} not found in the registry.",
                    LOG_PREFIX, node_id
                )
            })
    }

    // Get the latest idkg encryption key timestamp of all nodes in the given subnet record
    fn last_key_update_on_subnet(&self, subnet_record: SubnetRecord) -> Option<u64> {
        subnet_record
            .membership
            .into_iter()
            .filter_map(|node_id| {
                let idkg_pk_key = make_crypto_node_key(
                    NodeId::from(PrincipalId::try_from(node_id.as_slice()).unwrap_or_default()),
                    KeyPurpose::IDkgMEGaEncryption,
                );
                self.get(idkg_pk_key.as_bytes(), self.latest_version())
            })
            .filter_map(|value| {
                PublicKey::decode(value.value.as_slice())
                    .ok()
                    .and_then(|key| key.timestamp)
            })
            .max()
    }
}

/// The payload of an request to update keys of the existing node.
#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct UpdateNodeDirectlyPayload {
    pub idkg_dealing_encryption_pk: Option<Vec<u8>>,
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::common::test_helpers::{
        add_fake_subnet, get_invariant_compliant_subnet_record, invariant_compliant_registry,
        prepare_registry_with_nodes,
    };
    use ic_config::crypto::CryptoConfig;
    use ic_crypto_node_key_generation::generate_node_keys_once;
    use ic_crypto_node_key_validation::ValidNodePublicKeys;
    use ic_management_canister_types::{EcdsaCurve, EcdsaKeyId};
    use ic_protobuf::registry::subnet::v1::SubnetRecord;
    use ic_registry_subnet_features::{EcdsaConfig, DEFAULT_ECDSA_MAX_QUEUE_SIZE};
    use ic_test_utilities_types::ids::subnet_test_id;
    use std::ops::Add;

    fn valid_node_public_keys() -> ValidNodePublicKeys {
        let (config, _tepm_dir) = CryptoConfig::new_in_temp_dir();
        generate_node_keys_once(&config, None).expect("error generating node keys")
    }

    fn protobuf_to_vec<M: Message>(entry: M) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::new();
        entry.encode(&mut buf).expect("This must not fail");
        buf
    }

    #[test]
    #[should_panic(expected = "not found in the registry, aborting node update")]
    fn test_invalid_node_id() {
        let mut registry = invariant_compliant_registry(0);

        let now = SystemTime::now();

        let keys = valid_node_public_keys();
        let node_id = keys.node_id();
        let pk = keys.idkg_dealing_encryption_key().clone();

        registry
            .do_update_node(
                now,
                node_id,
                UpdateNodeDirectlyPayload {
                    idkg_dealing_encryption_pk: Some(protobuf_to_vec(pk)),
                },
            )
            .unwrap();
    }

    #[test]
    #[should_panic(expected = "the node is not on an ECDSA subnet")]
    fn test_node_not_on_ecdsa_subnet() {
        let mut registry = invariant_compliant_registry(0);

        let (mutate_request, node_ids_and_dkg_pks) = prepare_registry_with_nodes(1, 4);
        registry.maybe_apply_mutation_internal(mutate_request.mutations);

        let mut subnet_list_record = registry.get_subnet_list_record();

        let subnet_id = subnet_test_id(1000);

        // Create the subnet record with disabled ecdsa feature.
        let subnet_record: SubnetRecord =
            get_invariant_compliant_subnet_record(node_ids_and_dkg_pks.keys().copied().collect());
        registry.maybe_apply_mutation_internal(add_fake_subnet(
            subnet_id,
            &mut subnet_list_record,
            subnet_record,
            &node_ids_and_dkg_pks,
        ));

        let now = SystemTime::now();

        let keys = valid_node_public_keys();
        let pk = keys.idkg_dealing_encryption_key().clone();

        registry
            .do_update_node(
                now,
                *node_ids_and_dkg_pks
                    .keys()
                    .next()
                    .expect("should have at least one node ID"),
                UpdateNodeDirectlyPayload {
                    idkg_dealing_encryption_pk: Some(protobuf_to_vec(pk)),
                },
            )
            .unwrap();
    }

    #[test]
    #[should_panic(expected = "the key rotation feature is disabled")]
    fn test_idkg_key_update_disabled() {
        let mut registry = invariant_compliant_registry(0);

        let (mutate_request, node_ids_and_dkg_pks) = prepare_registry_with_nodes(1, 4);
        registry.maybe_apply_mutation_internal(mutate_request.mutations);

        let mut subnet_list_record = registry.get_subnet_list_record();

        let subnet_id = subnet_test_id(1000);

        // Create the subnet record with disabled key rotation feature.
        let mut subnet_record: SubnetRecord =
            get_invariant_compliant_subnet_record(node_ids_and_dkg_pks.keys().copied().collect());
        let key_id = EcdsaKeyId {
            curve: EcdsaCurve::Secp256k1,
            name: "test_key_id".to_string(),
        };
        subnet_record.ecdsa_config = Some(
            EcdsaConfig {
                quadruples_to_create_in_advance: 1,
                key_ids: vec![key_id],
                max_queue_size: Some(DEFAULT_ECDSA_MAX_QUEUE_SIZE),
                signature_request_timeout_ns: None,
                idkg_key_rotation_period_ms: None,
            }
            .into(),
        );
        registry.maybe_apply_mutation_internal(add_fake_subnet(
            subnet_id,
            &mut subnet_list_record,
            subnet_record,
            &node_ids_and_dkg_pks,
        ));

        let now = SystemTime::now();

        let keys = valid_node_public_keys();
        let pk = keys.idkg_dealing_encryption_key().clone();

        registry
            .do_update_node(
                now,
                *node_ids_and_dkg_pks
                    .keys()
                    .next()
                    .expect("should have at least one node ID"),
                UpdateNodeDirectlyPayload {
                    idkg_dealing_encryption_pk: Some(protobuf_to_vec(pk)),
                },
            )
            .unwrap();
    }

    #[test]
    // Tests failures with invalid keys during the key update.
    fn test_idkg_key_update_fail() {
        let mut registry = invariant_compliant_registry(0);

        let (mutate_request, node_ids_and_dkg_pks) = prepare_registry_with_nodes(1, 4);
        registry.maybe_apply_mutation_internal(mutate_request.mutations);

        let mut subnet_list_record = registry.get_subnet_list_record();

        let subnet_id = subnet_test_id(1000);
        let idkg_key_rotation_period_ms = 14 * 24 * 60 * 60 * 1000; // 2 weeks

        // Create the subnet record.
        let mut subnet_record: SubnetRecord =
            get_invariant_compliant_subnet_record(node_ids_and_dkg_pks.keys().copied().collect());
        let key_id = EcdsaKeyId {
            curve: EcdsaCurve::Secp256k1,
            name: "test_key_id".to_string(),
        };
        subnet_record.ecdsa_config = Some(
            EcdsaConfig {
                quadruples_to_create_in_advance: 1,
                key_ids: vec![key_id],
                max_queue_size: Some(DEFAULT_ECDSA_MAX_QUEUE_SIZE),
                signature_request_timeout_ns: None,
                idkg_key_rotation_period_ms: Some(idkg_key_rotation_period_ms),
            }
            .into(),
        );
        registry.maybe_apply_mutation_internal(add_fake_subnet(
            subnet_id,
            &mut subnet_list_record,
            subnet_record,
            &node_ids_and_dkg_pks,
        ));

        let now = SystemTime::now();
        let node_id0 = *node_ids_and_dkg_pks
            .keys()
            .next()
            .expect("should have at least one node ID");

        match registry.do_update_node(
            now,
            node_id0,
            UpdateNodeDirectlyPayload {
                idkg_dealing_encryption_pk: Default::default(),
            },
        ) {
            Err(msg) if msg.contains("KeyValidationError") => {}
            val => panic!("unexpected result: {:?}", val),
        };

        match registry.do_update_node(
            now,
            node_id0,
            UpdateNodeDirectlyPayload {
                idkg_dealing_encryption_pk: Some(vec![1]),
            },
        ) {
            Err(msg) if msg.contains("DecodeError") => {}
            val => panic!("unexpected result: {:?}", val),
        };
    }

    #[test]
    // Tests two successful key updates from two different nodes.
    fn test_idkg_key_update_success() {
        let mut registry = invariant_compliant_registry(0);

        let (mutate_request, node_ids_and_dkg_pks) = prepare_registry_with_nodes(1, 4);
        registry.maybe_apply_mutation_internal(mutate_request.mutations);

        let mut subnet_list_record = registry.get_subnet_list_record();

        let subnet_id = subnet_test_id(1000);
        let idkg_key_rotation_period_ms = 14 * 24 * 60 * 60 * 1000; // 2 weeks

        // Create the subnet record.
        let mut subnet_record: SubnetRecord =
            get_invariant_compliant_subnet_record(node_ids_and_dkg_pks.keys().copied().collect());
        let key_id = EcdsaKeyId {
            curve: EcdsaCurve::Secp256k1,
            name: "test_key_id".to_string(),
        };
        subnet_record.ecdsa_config = Some(
            EcdsaConfig {
                quadruples_to_create_in_advance: 1,
                key_ids: vec![key_id],
                max_queue_size: Some(DEFAULT_ECDSA_MAX_QUEUE_SIZE),
                signature_request_timeout_ns: None,
                idkg_key_rotation_period_ms: Some(idkg_key_rotation_period_ms),
            }
            .into(),
        );
        registry.maybe_apply_mutation_internal(add_fake_subnet(
            subnet_id,
            &mut subnet_list_record,
            subnet_record,
            &node_ids_and_dkg_pks,
        ));

        let mut now = SystemTime::now();

        // Update nodes' IDKG encryption public keys.
        registry.maybe_apply_mutation_internal(
            node_ids_and_dkg_pks
                .keys()
                .map(|id| {
                    let node_pub_keys = valid_node_public_keys();
                    let mut idkg_public_key = node_pub_keys.idkg_dealing_encryption_key().clone();
                    idkg_public_key.timestamp = Some(
                        now.duration_since(SystemTime::UNIX_EPOCH)
                            .unwrap()
                            .as_millis() as u64,
                    );
                    update(
                        make_crypto_node_key(*id, KeyPurpose::IDkgMEGaEncryption).as_bytes(),
                        encode_or_panic(&idkg_public_key),
                    )
                })
                .collect(),
        );

        // time passes ...
        now = now.add(Duration::from_millis(idkg_key_rotation_period_ms + 1));
        // generate new key
        let keys = valid_node_public_keys();
        let pk2 = keys.idkg_dealing_encryption_key();
        let mut node_ids_iter = node_ids_and_dkg_pks.keys();
        let node_id0 = *node_ids_iter
            .next()
            .expect("should have at least one node ID");
        let node_id1 = *node_ids_iter
            .next()
            .expect("should have at least two node IDs");

        // try to update the key of node 0 again
        assert_eq!(
            registry.do_update_node(
                now,
                node_id0,
                UpdateNodeDirectlyPayload {
                    idkg_dealing_encryption_pk: Some(protobuf_to_vec(pk2.clone())),
                }
            ),
            Ok(())
        );

        // 60 secs pass
        now = now.add(Duration::from_secs(60));

        // try to update the key of node 1 too early
        assert_eq!(
            registry.do_update_node(
                now,
                node_id1,
                UpdateNodeDirectlyPayload {
                    idkg_dealing_encryption_pk: Some(protobuf_to_vec(pk2.clone())),
                }
            ),
            Err("the ECDSA subnet had a key update recently".to_string())
        );

        // subnet limit passes
        now = now.add(Duration::from_millis(
            idkg_key_rotation_period_ms / node_ids_and_dkg_pks.len() as u64,
        ));

        // try to update the key of node 0 again
        assert_eq!(
            registry.do_update_node(
                now,
                node_id0,
                UpdateNodeDirectlyPayload {
                    idkg_dealing_encryption_pk: Some(protobuf_to_vec(pk2.clone())),
                }
            ),
            Err("the key of this node is sufficiently fresh".to_string())
        );

        // successfully update the key of node 1 with the same time as before, but it will work,
        // because it's the first update for node 1

        // use yet another new key (to ensure key uniqueness)
        let keys = valid_node_public_keys();
        let pk3 = keys.idkg_dealing_encryption_key();
        assert_eq!(
            registry.do_update_node(
                now,
                node_id1,
                UpdateNodeDirectlyPayload {
                    idkg_dealing_encryption_pk: Some(protobuf_to_vec(pk3.clone())),
                }
            ),
            Ok(())
        );
    }
}
