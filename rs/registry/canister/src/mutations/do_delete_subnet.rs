use candid::{CandidType, Principal};
#[cfg(target_arch = "wasm32")]
use dfn_core::println;
use ic_protobuf::registry::subnet::v1::SubnetListRecord;
use ic_registry_keys::{
    make_catch_up_package_contents_key, make_crypto_threshold_signing_pubkey_key,
    make_subnet_list_record_key, make_subnet_record_key,
};
use ic_registry_subnet_type::SubnetType;
use ic_registry_transport::{delete, update};
use ic_types::{PrincipalId, SubnetId};
use prost::Message;
use serde::{Deserialize, Serialize};

use crate::{common::LOG_PREFIX, registry::Registry};

impl Registry {
    /// Note: Currently, only CloudEngine subnets can be deleted.
    ///       General subnet deletion requires changes in the deterministic state machine!
    ///
    /// Deleting a subnet means to:
    /// - Remove its subnet ID from the key `subnet_list`.
    /// - Remove its subnet record.
    /// - Remove all routing table shards that its subnet ID maps to.
    /// - Remove the catch up package.
    /// - Remove the subnet public key.
    ///
    /// Consumers of `subnet_list`, the subnet record and the routing table assume live subnets, whereas
    /// consumers that must take deleted subnets into account do so via old registry versions (the
    /// registry client method `get_versioned_value` allows the caller to distinguish between deleted
    /// and non-existing values via `version ?= 0`).
    pub fn do_delete_subnet(&mut self, payload: DeleteSubnetPayload) -> Result<(), String> {
        println!("{LOG_PREFIX}do_delete_subnet: {payload:?}");

        let DeleteSubnetPayload { subnet_id } = payload;
        let subnet_id_ = SubnetId::from(PrincipalId::from(subnet_id));
        let subnet_record = self.get_subnet(subnet_id_, self.latest_version())?;

        // Currently, only CloudEngines can be deleted.
        if subnet_record.subnet_type != i32::from(SubnetType::CloudEngine) {
            return Err("Only CloudEngines may be deleted".to_string());
        }

        // Remove from `subnet_list`.
        let mut subnet_list = self.get_subnet_list_record().subnets;
        let len_before = subnet_list.len();
        subnet_list.retain(|s| s != subnet_id.as_slice());
        if subnet_list.len() > len_before - 1 {
            println!(
                "{LOG_PREFIX}do_delete_subnet: Subnet {} was not present in subnet_list.",
                subnet_id
            );
        }
        let new_subnet_list_record = SubnetListRecord {
            subnets: subnet_list,
        };
        let subnet_list_mutation = update(
            make_subnet_list_record_key().as_bytes(),
            new_subnet_list_record.encode_to_vec(),
        );

        // Remove catch up package.
        let subnet_dkg_mutation = delete(make_catch_up_package_contents_key(subnet_id_).as_bytes());

        // Remove pubkey.
        let subnet_threshold_signing_pubkey_mutation =
            delete(make_crypto_threshold_signing_pubkey_key(subnet_id_).as_bytes());

        // Remove subnet record.
        let remove_subnet_mutation = delete(make_subnet_record_key(subnet_id_).into_bytes());

        // Remove routing table shards.
        let mut remove_from_routing_table_mutations =
            self.remove_subnet_from_routing_table(self.latest_version(), subnet_id_);
        let mut mutations = vec![
            subnet_list_mutation,
            subnet_dkg_mutation,
            subnet_threshold_signing_pubkey_mutation,
            remove_subnet_mutation,
        ];
        mutations.append(&mut remove_from_routing_table_mutations);

        // Check invariants before applying mutations
        self.maybe_apply_mutation_internal(mutations);
        Ok(())
    }
}

#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize, Serialize)]
pub struct DeleteSubnetPayload {
    pub subnet_id: Principal,
}
