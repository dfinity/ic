use candid::{CandidType, Principal};
use ic_protobuf::registry::subnet::v1::SubnetListRecord;
use ic_registry_keys::{make_subnet_list_record_key, make_subnet_record_key};
use ic_registry_transport::pb::v1::{RegistryMutation, registry_mutation};
use ic_types::{PrincipalId, SubnetId};
use prost::Message;
use serde::{Deserialize, Serialize};

use crate::registry::Registry;

#[derive(Clone, Eq, PartialEq, Debug, CandidType, Deserialize, Serialize)]
pub struct DeleteSubnetPayload {
    subnet_id: Principal,
}

impl Registry {
    pub async fn do_delete_subnet(&mut self, payload: DeleteSubnetPayload) -> Result<(), String> {
        let DeleteSubnetPayload { subnet_id } = payload;
        let subnet_id_ = SubnetId::from(PrincipalId::from(subnet_id));
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
        let remove_subnet_mutation = RegistryMutation {
            mutation_type: registry_mutation::Type::Delete as i32,
            key: make_subnet_record_key(subnet_id_).into_bytes(),
            value: vec![],
        };
        let routing_table = self.get_routing_table_or_panic(self.latest_version());
        let deleted_subnet_ranges = routing_table.ranges(subnet_id_);
        let mut remove_from_routing_table_mutations =
            self.remove_subnet_from_routing_table(self.latest_version(), subnet_id_);
        let mut mutations = vec![subnet_list_mutation, remove_subnet_mutation];
        mutations.append(&mut remove_from_routing_table_mutations);

        // TODO: put subnet_id and deleted_subnet_ranges into new deleted_subnet_list

        // Check invariants before applying mutations
        self.maybe_apply_mutation_internal(mutations);
        Ok(())
    }
}
