use crate::chain_key::{InitialChainKeyConfigInternal, KeyConfigRequestInternal};
use crate::{
    common::LOG_PREFIX,
    mutations::common::{get_subnet_ids_from_subnet_list, has_duplicates},
    registry::{Registry, Version},
};
use candid::Encode;
use dfn_core::call;
use ic_base_types::{
    CanisterId, NodeId, PrincipalId, RegistryVersion, SubnetId, subnet_id_into_protobuf,
};
use ic_cdk::println;
use ic_management_canister_types_private::{
    MasterPublicKeyId, ReshareChainKeyArgs, ReshareChainKeyResponse,
};
use ic_protobuf::registry::subnet::v1::chain_key_initialization::Initialization;
use ic_protobuf::registry::{
    crypto::v1::ChainKeyEnabledSubnetList,
    subnet::v1::{CatchUpPackageContents, ChainKeyInitialization, SubnetListRecord, SubnetRecord},
};
use ic_registry_keys::{
    make_catch_up_package_contents_key, make_chain_key_enabled_subnet_list_key,
    make_subnet_list_record_key, make_subnet_record_key,
};
use ic_registry_subnet_features::ChainKeyConfig;
use ic_registry_transport::{
    pb::v1::{RegistryMutation, RegistryValue},
    upsert,
};
use on_wire::bytes;
use prost::Message;
use std::{
    collections::{HashMap, HashSet},
    convert::TryFrom,
    iter::FromIterator,
};

impl Registry {
    /// Get the subnet record or panic on error with a message.
    pub fn get_subnet_or_panic(&self, subnet_id: SubnetId) -> SubnetRecord {
        self.get_subnet(subnet_id, self.latest_version())
            .unwrap_or_else(|err| {
                panic!("{LOG_PREFIX}Failed to get subnet record: {err}");
            })
    }

    pub fn get_subnet(
        &self,
        subnet_id: SubnetId,
        version: Version,
    ) -> Result<SubnetRecord, String> {
        let RegistryValue {
            value: subnet_record_vec,
            version: _,
            deletion_marker: _,
            timestamp_nanoseconds: _,
        } = self
            .get(&make_subnet_record_key(subnet_id).into_bytes(), version)
            .ok_or_else(|| format!("Subnet record for {subnet_id:} not found in the registry."))?;

        SubnetRecord::decode(subnet_record_vec.as_slice()).map_err(|err| err.to_string())
    }

    pub fn get_subnet_list_record(&self) -> SubnetListRecord {
        match self.get(
            make_subnet_list_record_key().as_bytes(),
            self.latest_version(),
        ) {
            Some(RegistryValue {
                value,
                version: _,
                deletion_marker: _,
                timestamp_nanoseconds: _,
            }) => SubnetListRecord::decode(value.as_slice()).unwrap(),
            None => panic!(
                "{LOG_PREFIX}set_subnet_membership_mutation: subnet list record not found in the registry.",
            ),
        }
    }

    /// Replace the given subnet record's membership with `new_membership`.
    /// Panic if any node in `new_membership` is already part of a subnet other than `subnet_id`.
    pub fn replace_subnet_record_membership(
        &self,
        subnet_id: SubnetId,
        subnet_record: &mut SubnetRecord,
        mut new_membership: Vec<NodeId>,
    ) {
        new_membership.dedup();

        let subnet_list_record = self.get_subnet_list_record();

        let proposed_members = new_membership.iter().cloned().collect::<HashSet<_>>();
        let all_subnets = subnet_list_record
            .subnets
            .iter()
            .map(|s| SubnetId::from(PrincipalId::try_from(s).unwrap()))
            // We don't check if any nodes in `new_membership` are already part of the
            // Subnet given by `subnet_id`
            .filter(|other_subnet_id| *other_subnet_id != subnet_id)
            .collect::<Vec<_>>();

        for s_id in all_subnets {
            let subnet_record = self.get_subnet_or_panic(s_id);
            let subnet_members: HashSet<NodeId> = subnet_record
                .membership
                .iter()
                .map(|v| NodeId::from(PrincipalId::try_from(v).unwrap()))
                .collect();

            let intersection = proposed_members
                .intersection(&subnet_members)
                .collect::<HashSet<_>>();
            if !intersection.is_empty() {
                panic!(
                    "{LOG_PREFIX}set_subnet_membership_mutation: Subnet {s_id:} already contains some members that are to be added: {intersection:?}"
                );
            }
        }

        subnet_record.membership = new_membership
            .iter()
            .map(|id| id.get().into_vec())
            .collect();
    }

    /// Retrieve the CUP for a given subnet at a registry version (or latest if not specified).
    pub fn get_subnet_catch_up_package(
        &self,
        subnet_id: SubnetId,
        version: Option<Version>,
    ) -> Result<CatchUpPackageContents, String> {
        let cup_contents_key = make_catch_up_package_contents_key(subnet_id);

        match self.get(
            &cup_contents_key.into_bytes(),
            version.unwrap_or_else(|| self.latest_version()),
        ) {
            Some(cup) => Ok(CatchUpPackageContents::decode(cup.value.as_slice()).unwrap()),
            None => Err(format!(
                "{LOG_PREFIX}CatchUpPackage not found for subnet: {subnet_id}"
            )),
        }
    }

    /// Get a map representing MasterPublicKeyId => Subnets that hold the key
    /// but do not need to be enabled for signing.
    pub fn get_master_public_keys_to_subnets_map(
        &self,
    ) -> HashMap<MasterPublicKeyId, Vec<SubnetId>> {
        let mut key_map: HashMap<MasterPublicKeyId, Vec<SubnetId>> = HashMap::new();

        get_subnet_ids_from_subnet_list(self.get_subnet_list_record())
            .iter()
            .for_each(|subnet_id| {
                let subnet_record = self.get_subnet_or_panic(*subnet_id);
                if let Some(chain_key_config) = subnet_record.chain_key_config {
                    let chain_key_config = ChainKeyConfig::try_from(chain_key_config)
                        .unwrap_or_else(|err| {
                            panic!("{LOG_PREFIX}Cannot interpret data as ChainKeyConfig: {err}");
                        });
                    chain_key_config.key_ids().iter().for_each(|key_id| {
                        if !key_map.contains_key(key_id) {
                            key_map.insert(key_id.clone(), vec![]);
                        }
                        let subnet_ids = key_map.get_mut(key_id).unwrap();
                        subnet_ids.push(*subnet_id);
                    })
                }
            });

        key_map
    }

    /// Get the initial key material (IDKG dealings or DKG transcripts)
    /// via a call to IC00 for a given InitialChainKeyConfig and a set of nodes to receive them.
    pub(crate) async fn get_all_chain_key_reshares_from_ic00(
        &self,
        initial_chain_key_config: &Option<InitialChainKeyConfigInternal>,
        receiver_nodes: Vec<NodeId>,
    ) -> Vec<ChainKeyInitialization> {
        let reshare_chain_key_futures = initial_chain_key_config
            .as_ref()
            .map(|initial_chain_key_config| {
                self.get_reshare_chain_key_args_from_initial_config(
                    initial_chain_key_config,
                    receiver_nodes,
                )
                .into_iter()
                .map(|reshare_request| self.get_chain_key_resharing_from_ic00(reshare_request))
                .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        futures::future::join_all(reshare_chain_key_futures).await
    }

    /// Helper function to build the request objects to send to IC00 for
    /// `reshare_chain_key`
    fn get_reshare_chain_key_args_from_initial_config(
        &self,
        initial_chain_key_config: &InitialChainKeyConfigInternal,
        receiver_nodes: Vec<NodeId>,
    ) -> Vec<ReshareChainKeyArgs> {
        let latest_version = self.latest_version();
        let registry_version = RegistryVersion::new(latest_version);
        initial_chain_key_config
            .key_configs
            .iter()
            .map(
                |KeyConfigRequestInternal {
                     key_config,
                     subnet_id,
                     ..
                 }| {
                    // create requests outside of async move context to avoid ownership problems
                    let key_id = key_config.key_id.clone();
                    let subnet_id = SubnetId::new(*subnet_id);
                    let nodes = receiver_nodes.iter().copied().collect();
                    ReshareChainKeyArgs::new(key_id, subnet_id, nodes, registry_version)
                },
            )
            .collect()
    }

    /// Helper function to make the request and decode the response for
    /// `reshare_chain_key`.
    async fn get_chain_key_resharing_from_ic00(
        &self,
        reshare_request: ReshareChainKeyArgs,
    ) -> ChainKeyInitialization {
        let response_bytes = call(
            CanisterId::ic_00(),
            "reshare_chain_key",
            bytes,
            Encode!(&reshare_request).unwrap(),
        )
        .await
        .unwrap();

        let response = ReshareChainKeyResponse::decode(&response_bytes).unwrap();
        println!(
            "{}response from reshare_chain_key successfully received",
            LOG_PREFIX
        );

        let initialization = match response {
            ReshareChainKeyResponse::IDkg(dealings) => Initialization::Dealings(dealings),
            ReshareChainKeyResponse::NiDkg(transcript_record) => {
                Initialization::TranscriptRecord(transcript_record)
            }
        };

        ChainKeyInitialization {
            key_id: Some((&reshare_request.key_id).into()),
            initialization: Some(initialization),
        }
    }

    /// Get the list of subnets that are enabled for a given MasterPublicKeyId.
    pub fn get_chain_key_enabled_subnet_list(
        &self,
        key_id: &MasterPublicKeyId,
    ) -> Option<ChainKeyEnabledSubnetList> {
        let chain_key_enabled_subnet_list_key_id = make_chain_key_enabled_subnet_list_key(key_id);
        self.get(
            chain_key_enabled_subnet_list_key_id.as_bytes(),
            self.latest_version(),
        )
        .map(|registry_value| {
            ChainKeyEnabledSubnetList::decode(registry_value.value.as_slice()).unwrap()
        })
    }

    /// Create the mutations that disable set of chain keys for a single subnet.
    pub fn mutations_to_disable_subnet_chain_key(
        &self,
        subnet_id: SubnetId,
        chain_key_disable: &Vec<MasterPublicKeyId>,
    ) -> Vec<RegistryMutation> {
        let mut mutations = vec![];
        for chain_key_id in chain_key_disable {
            let mut chain_key_signing_list_for_key = self
                .get_chain_key_enabled_subnet_list(chain_key_id)
                .unwrap_or_default();

            // If that key is already disabled on this subnet, do nothing.
            if !chain_key_signing_list_for_key
                .subnets
                .contains(&subnet_id_into_protobuf(subnet_id))
            {
                continue;
            }

            let protobuf_subnet_id = subnet_id_into_protobuf(subnet_id);
            // Preconditions are okay, so we remove the subnet from our list of signing subnets.
            chain_key_signing_list_for_key
                .subnets
                .retain(|subnet| subnet != &protobuf_subnet_id);

            mutations.push(upsert(
                make_chain_key_enabled_subnet_list_key(chain_key_id),
                chain_key_signing_list_for_key.encode_to_vec(),
            ));
        }
        mutations
    }

    /// Get a list of all MasterPublicKeyId's held by a given subnet.
    pub fn get_master_public_keys_held_by_subnet(
        &self,
        subnet_id: SubnetId,
    ) -> Vec<MasterPublicKeyId> {
        let subnet_record = self.get_subnet_or_panic(subnet_id);
        subnet_record
            .chain_key_config
            .map(|chain_key_config| {
                let chain_key_config =
                    ChainKeyConfig::try_from(chain_key_config).unwrap_or_else(|err| {
                        panic!("{LOG_PREFIX}Cannot interpret data as ChainKeyConfig: {err}");
                    });
                chain_key_config.key_ids()
            })
            .unwrap_or_default()
    }

    /// Get a list of keys that will be removed from a subnet given the complete list of keys to be
    /// held by that subnet.
    pub(crate) fn get_keys_that_will_be_removed_from_subnet(
        &self,
        subnet_id: SubnetId,
        updated_key_list: Vec<MasterPublicKeyId>,
    ) -> Vec<MasterPublicKeyId> {
        let current_keys = vec_to_set(self.get_master_public_keys_held_by_subnet(subnet_id));
        let requested_keys = vec_to_set(updated_key_list);
        current_keys.difference(&requested_keys).cloned().collect()
    }

    /// Get a list of keys that will be added to a subnet given the complete list of keys to be held
    /// by that subnet.
    pub fn get_keys_that_will_be_added_to_subnet(
        &self,
        subnet_id: SubnetId,
        updated_key_list: Vec<MasterPublicKeyId>,
    ) -> Vec<MasterPublicKeyId> {
        let current_keys = vec_to_set(self.get_master_public_keys_held_by_subnet(subnet_id));
        let requested_keys = vec_to_set(updated_key_list);
        requested_keys.difference(&current_keys).cloned().collect()
    }

    /// Validates InitialChainKeyConfig.  If own_subnet_id is supplied, this also validates that all
    /// requested keys are available on a different subnet (for the case of recovering a subnet)
    pub(crate) fn validate_initial_chain_key_config(
        &self,
        initial_chain_key_config: &InitialChainKeyConfigInternal,
        own_subnet_id: Option<PrincipalId>,
    ) -> Result<(), String> {
        let keys_to_subnets = self.get_master_public_keys_to_subnets_map();

        for KeyConfigRequestInternal {
            key_config,
            subnet_id,
        } in &initial_chain_key_config.key_configs
        {
            // Requested key must be a known key.
            let key_id = &key_config.key_id;

            let Some(subnets_for_key) = keys_to_subnets.get(key_id) else {
                return Err(format!(
                    "The requested chain key '{key_id}' was not found in any subnet."
                ));
            };

            // Ensure the subnet being targeted is not the same as the subnet being recovered.
            if let Some(own_subnet_id) = own_subnet_id
                && subnet_id == &own_subnet_id
            {
                return Err(format!(
                    "Attempted to recover chain key '{key_id}' by requesting it from itself. \
                         Subnets cannot recover chain keys from themselves.",
                ));
            }

            // Ensure that the targeted subnet actually holds the key.
            let subnet_id = SubnetId::new(*subnet_id);
            if !subnets_for_key.contains(&subnet_id) {
                return Err(format!(
                    "The requested chain key '{key_id}' is not available in targeted subnet '{subnet_id}'."
                ));
            }
        }

        let key_ids = initial_chain_key_config.key_ids();

        if has_duplicates(&key_ids) {
            return Err(format!(
                "The requested chain keys {key_ids:?} have duplicates"
            ));
        }

        Ok(())
    }
}

fn vec_to_set<T: std::hash::Hash + std::cmp::Eq>(vector: Vec<T>) -> HashSet<T> {
    HashSet::from_iter(vector)
}
