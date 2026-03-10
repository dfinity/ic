use candid::{CandidType, Principal};
#[cfg(target_arch = "wasm32")]
use dfn_core::println;
use ic_protobuf::registry::subnet::v1::{
    CanisterCyclesCostSchedule as CanisterCyclesCostSchedulePb, DeletedSubnetListRecord,
    SubnetListRecord,
};
use ic_registry_keys::{
    make_deleted_subnet_list_record_key, make_subnet_list_record_key, make_subnet_record_key,
};
use ic_registry_subnet_type::SubnetType;
use ic_registry_transport::pb::v1::{RegistryMutation, registry_mutation};
use ic_types::{PrincipalId, SubnetId};
use prost::Message;
use serde::{Deserialize, Serialize};

use crate::{
    common::LOG_PREFIX, mutations::do_create_subnet::CanisterCyclesCostSchedule, registry::Registry,
};

#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize, Serialize)]
pub struct DeleteSubnetPayload {
    subnet_id: Principal,
}

impl Registry {
    /// Note: Currently, only CloudEngines can be deleted.
    ///       Subnet deletion requires changes in the deterministic state machine!
    ///
    /// Deleting a subnet means to:
    /// - Remove its subnet ID from the key `subnet_list`.
    /// - Remove its subnet record.
    /// - Remove all routing table shards that its subnet ID maps to.
    /// - Add its subnet ID to key `deleted_subnet_list`.
    ///
    /// Consumers of `subnet_list`, the subnet record and the routing table assume live subnets.
    /// Consumers that must take deleted subnets into account do so via `deleted_subnet_list` and old registry versions.
    pub async fn do_delete_subnet(&mut self, payload: DeleteSubnetPayload) -> Result<(), String> {
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
        if !subnet_list.contains(&subnet_id.as_slice().to_vec()) {
            return Err(format!(
                "Failed to delete subnet_id {}: Subnet not found.",
                subnet_id
            ));
        }
        subnet_list.retain_mut(|s| s != subnet_id.as_slice());
        let new_subnet_list_record = SubnetListRecord {
            subnets: subnet_list,
        };
        let subnet_list_mutation = RegistryMutation {
            mutation_type: registry_mutation::Type::Update as i32,
            key: make_subnet_list_record_key().as_bytes().to_vec(),
            value: new_subnet_list_record.encode_to_vec(),
        };

        // Add to `deleted_subnet_list`.
        let mut deleted_subnet_list = self.get_deleted_subnet_list_record().deleted_subnets;
        deleted_subnet_list.push(subnet_id.as_slice().to_vec());
        let new_deleted_subnet_list_record = DeletedSubnetListRecord {
            deleted_subnets: deleted_subnet_list,
        };
        let deleted_subnet_list_mutation = RegistryMutation {
            mutation_type: registry_mutation::Type::Update as i32,
            key: make_deleted_subnet_list_record_key().as_bytes().to_vec(),
            value: new_deleted_subnet_list_record.encode_to_vec(),
        };

        // Remove subnet record.
        let remove_subnet_mutation = RegistryMutation {
            mutation_type: registry_mutation::Type::Delete as i32,
            key: make_subnet_record_key(subnet_id_).into_bytes(),
            value: vec![],
        };

        // Remove routing table shards.
        let mut remove_from_routing_table_mutations =
            self.remove_subnet_from_routing_table(self.latest_version(), subnet_id_);
        let mut mutations = vec![
            subnet_list_mutation,
            deleted_subnet_list_mutation,
            remove_subnet_mutation,
        ];
        mutations.append(&mut remove_from_routing_table_mutations);

        // Check invariants before applying mutations
        self.maybe_apply_mutation_internal(mutations);
        Ok(())
    }
}
