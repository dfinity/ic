use crate::{
    common::LOG_PREFIX,
    mutations::{
        common::{
            decode_registry_value, encode_or_panic, get_subnet_ids_from_subnet_list, has_duplicates,
        },
        do_create_subnet::EcdsaInitialConfig,
    },
    registry::{Registry, Version},
};
use candid::Encode;
use dfn_core::call;
use ic_base_types::{
    subnet_id_into_protobuf, CanisterId, NodeId, PrincipalId, RegistryVersion, SubnetId,
};
use ic_management_canister_types::{
    ComputeInitialEcdsaDealingsArgs, ComputeInitialEcdsaDealingsResponse, EcdsaKeyId,
};
use ic_protobuf::registry::{
    crypto::v1::EcdsaSigningSubnetList,
    subnet::v1::{CatchUpPackageContents, EcdsaInitialization, SubnetListRecord, SubnetRecord},
};
use ic_registry_keys::{
    make_catch_up_package_contents_key, make_ecdsa_signing_subnet_list_key,
    make_subnet_list_record_key, make_subnet_record_key,
};
use ic_registry_transport::{
    pb::v1::{RegistryMutation, RegistryValue},
    upsert,
};
use on_wire::bytes;
use prost::Message;
use std::{
    collections::{HashMap, HashSet},
    convert::{TryFrom, TryInto},
    iter::FromIterator,
};

impl Registry {
    /// Get the subnet record or panic on error with a message.
    pub fn get_subnet_or_panic(&self, subnet_id: SubnetId) -> SubnetRecord {
        self.get_subnet(subnet_id, self.latest_version())
            .unwrap_or_else(|err| {
                panic!("{}Failed to get subnet record: {}", LOG_PREFIX, err);
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
        } = self
            .get(&make_subnet_record_key(subnet_id).into_bytes(), version)
            .ok_or_else(|| {
                format!(
                    "Subnet record for {:} not found in the registry.",
                    subnet_id
                )
            })?;

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
            }) => decode_registry_value::<SubnetListRecord>(value.clone()),
            None => panic!(
                "{}set_subnet_membership_mutation: subnet list record not found in the registry.",
                LOG_PREFIX,
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
                panic!("{}set_subnet_membership_mutation: Subnet {:} already contains some members that are to be added: {:?}",
                   LOG_PREFIX,
                   s_id,
                   intersection);
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
            Some(cup) => Ok(decode_registry_value::<CatchUpPackageContents>(
                cup.value.clone(),
            )),
            None => Err(format!(
                "{}CatchUpPackage not found for subnet: {}",
                LOG_PREFIX, subnet_id
            )),
        }
    }

    /// Get a map representing EcdsaKeyId => Subnets that hold the key
    /// but do not need to be enabled for signing.
    pub fn get_ecdsa_keys_to_subnets_map(&self) -> HashMap<EcdsaKeyId, Vec<SubnetId>> {
        let mut key_map: HashMap<EcdsaKeyId, Vec<SubnetId>> = HashMap::new();

        get_subnet_ids_from_subnet_list(self.get_subnet_list_record())
            .iter()
            .for_each(|subnet_id| {
                let subnet_record = self.get_subnet_or_panic(*subnet_id);
                if let Some(ref ecdsa_conf) = subnet_record.ecdsa_config {
                    let key_ids: Vec<EcdsaKeyId> = ecdsa_conf
                        .key_ids
                        .clone()
                        .into_iter()
                        .map(|x| x.try_into().unwrap())
                        .collect::<Vec<_>>();
                    key_ids.iter().for_each(|key_id| {
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

    /// Get the initial ECDSA dealings via a call to IC00 for a given EcdsaInitialConfig and a set of
    /// nodes to receive them.
    pub async fn get_all_initial_ecdsa_dealings_from_ic00(
        &self,
        ecdsa_initial_config: &Option<EcdsaInitialConfig>,
        receiver_nodes: Vec<NodeId>,
    ) -> Vec<EcdsaInitialization> {
        let initial_ecdsa_dealings_futures = ecdsa_initial_config
            .as_ref()
            .map(|config| {
                self.get_compute_ecdsa_args_from_initial_config(config, receiver_nodes)
                    .into_iter()
                    .map(|request| self.get_ecdsa_initializations_from_ic00(request))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        futures::future::join_all(initial_ecdsa_dealings_futures).await
    }

    /// Helper function to build the request objects to send to IC00 for
    /// `compute_initial_ecdsa_dealings`
    fn get_compute_ecdsa_args_from_initial_config(
        &self,
        ecdsa_initial_config: &EcdsaInitialConfig,
        receiver_nodes: Vec<NodeId>,
    ) -> Vec<ComputeInitialEcdsaDealingsArgs> {
        let latest_version = self.latest_version();
        ecdsa_initial_config
            .keys
            .iter()
            .map(|key_request| {
                // create requests outside of async move context to avoid ownership problems
                let key_id = key_request.key_id.clone();
                let target_subnet = key_request
                    .subnet_id
                    .map(SubnetId::new)
                    .expect("subnet_id is required for EcdsaKeyRequests");
                ComputeInitialEcdsaDealingsArgs::new(
                    key_id,
                    target_subnet,
                    receiver_nodes.iter().copied().collect(),
                    RegistryVersion::new(latest_version),
                )
            })
            .collect()
    }

    /// Helper function to make the request and decode the response for
    /// `compute_initial_ecdsa_dealings`.
    async fn get_ecdsa_initializations_from_ic00(
        &self,
        dealing_request: ComputeInitialEcdsaDealingsArgs,
    ) -> EcdsaInitialization {
        let response_bytes = call(
            CanisterId::ic_00(),
            "compute_initial_ecdsa_dealings",
            bytes,
            Encode!(&dealing_request).unwrap(),
        )
        .await
        .unwrap();

        let response = ComputeInitialEcdsaDealingsResponse::decode(&response_bytes).unwrap();
        println!(
            "{}response from compute_initial_ecdsa_dealings successfully received",
            LOG_PREFIX
        );

        EcdsaInitialization {
            key_id: Some((&dealing_request.key_id).into()),
            dealings: Some(response.initial_dkg_dealings),
        }
    }

    /// Get the list of subnets that can sign for a given EcdsaKeyId.
    pub fn get_ecdsa_signing_subnet_list(
        &self,
        key_id: &EcdsaKeyId,
    ) -> Option<EcdsaSigningSubnetList> {
        let ecdsa_signing_subnet_list_key_id = make_ecdsa_signing_subnet_list_key(key_id);
        self.get(
            ecdsa_signing_subnet_list_key_id.as_bytes(),
            self.latest_version(),
        )
        .map(|registry_value| {
            decode_registry_value::<EcdsaSigningSubnetList>(registry_value.value.to_vec())
        })
    }

    /// Create the mutations that disable subnet signing for a single subnet and set of EcdsaKeyId's.
    pub fn mutations_to_disable_subnet_signing(
        &self,
        subnet_id: SubnetId,
        ecdsa_key_signing_disable: &Vec<EcdsaKeyId>,
    ) -> Vec<RegistryMutation> {
        let mut mutations = vec![];
        for key_id in ecdsa_key_signing_disable {
            let mut signing_list_for_key = self
                .get_ecdsa_signing_subnet_list(key_id)
                .unwrap_or_default();

            // If this subnet does not sign for that key, do nothing.
            if !signing_list_for_key
                .subnets
                .contains(&subnet_id_into_protobuf(subnet_id))
            {
                continue;
            }

            let protobuf_subnet_id = subnet_id_into_protobuf(subnet_id);
            // Preconditions are okay, so we remove the subnet from our list of signing subnets.
            signing_list_for_key
                .subnets
                .retain(|subnet| subnet != &protobuf_subnet_id);

            mutations.push(upsert(
                make_ecdsa_signing_subnet_list_key(key_id).into_bytes(),
                encode_or_panic(&signing_list_for_key),
            ));
        }
        mutations
    }

    /// Get a list of all EcdsaKeyId's held by a given subnet.
    pub fn get_ecdsa_keys_held_by_subnet(&self, subnet_id: SubnetId) -> Vec<EcdsaKeyId> {
        let subnet_record = self.get_subnet_or_panic(subnet_id);
        subnet_record
            .ecdsa_config
            .map(|c| {
                c.key_ids
                    .iter()
                    .map(|k| k.clone().try_into().unwrap())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get a list of keys that will be removed from a subnet given the complete list of keys to be
    /// held by that subnet.
    pub(crate) fn get_keys_that_will_be_removed_from_subnet(
        &self,
        subnet_id: SubnetId,
        updated_key_list: Vec<EcdsaKeyId>,
    ) -> Vec<EcdsaKeyId> {
        let current_keys = vec_to_set(self.get_ecdsa_keys_held_by_subnet(subnet_id));
        let requested_keys = vec_to_set(updated_key_list);
        current_keys.difference(&requested_keys).cloned().collect()
    }

    /// Get a list of keys that will be added to a subnet given the complete list of keys to be held
    /// by that subnet.
    pub fn get_keys_that_will_be_added_to_subnet(
        &self,
        subnet_id: SubnetId,
        updated_key_list: Vec<EcdsaKeyId>,
    ) -> Vec<EcdsaKeyId> {
        let current_keys = vec_to_set(self.get_ecdsa_keys_held_by_subnet(subnet_id));
        let requested_keys = vec_to_set(updated_key_list);
        requested_keys.difference(&current_keys).cloned().collect()
    }

    /// Validates EcdsaInitialConfig.  If own_subnet_id is supplied, this also validates that all
    /// requested keys are available on a different subnet (for the case of recovering a subnet)
    pub fn validate_ecdsa_initial_config(
        &self,
        ecdsa_initial_config: &EcdsaInitialConfig,
        own_subnet_id: Option<PrincipalId>,
    ) -> Result<(), String> {
        let ecdsa_subnet_map = self.get_ecdsa_keys_to_subnets_map();

        for key_request in &ecdsa_initial_config.keys {
            // Requested key must be a known key.
            if !ecdsa_subnet_map.contains_key(&key_request.key_id) {
                return Err(format!(
                    "The requested ECDSA key '{}' was not found in any subnet.",
                    key_request.key_id
                ));
            }

            let subnets_for_key = ecdsa_subnet_map.get(&key_request.key_id).unwrap();

            // Require that a subnet is targeted.
            let subnet_id_principal = match key_request.subnet_id.as_ref() {
                None => {
                    return Err(format!(
                        "EcdsaKeyRequest for key '{}' did not specify subnet_id.",
                        key_request.key_id
                    ))
                }
                Some(id) => id,
            };

            // Ensure the subnet being targeted is not the same as the subnet being recovered.
            if let Some(own_subnet_principal) = own_subnet_id {
                if subnet_id_principal == &own_subnet_principal {
                    return Err(format!(
                        "Attempted to recover ECDSA key '{}' by \
                     requesting it from itself.  Subnets cannot recover ECDSA keys from themselves.",
                        key_request.key_id
                    ));
                }
            }

            // Ensure that the targeted subnet actually holds the key.
            let subnet_id = SubnetId::new(*subnet_id_principal);
            if !subnets_for_key.contains(&subnet_id) {
                return Err(format!(
                    "The requested ECDSA key '{}' \
                     is not available in targeted subnet '{}'.",
                    key_request.key_id, subnet_id_principal
                ));
            }
        }

        let ecdsa_key_ids: Vec<_> = ecdsa_initial_config
            .keys
            .iter()
            .map(|key| key.key_id.clone())
            .collect();
        if has_duplicates(&ecdsa_key_ids) {
            return Err(format!(
                "The requested ECDSA key ids {:?} have duplicates",
                ecdsa_key_ids
            ));
        }

        Ok(())
    }
}

fn vec_to_set<T: std::hash::Hash + std::cmp::Eq>(vector: Vec<T>) -> HashSet<T> {
    HashSet::from_iter(vector)
}
