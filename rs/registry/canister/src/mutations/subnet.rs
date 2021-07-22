use crate::{
    common::LOG_PREFIX,
    mutations::common::{decode_registry_value, encode_or_panic},
    registry::Registry,
};

use std::{collections::HashSet, convert::TryFrom};

use ic_base_types::{NodeId, PrincipalId, SubnetId};
use ic_protobuf::registry::subnet::v1::{SubnetListRecord, SubnetRecord};
use ic_registry_keys::{make_subnet_list_record_key, make_subnet_record_key};
use ic_registry_transport::pb::v1::{registry_mutation, RegistryMutation, RegistryValue};

impl Registry {
    /// Get the subnet record or panic on error with a message.
    pub fn get_subnet_or_panic(&self, subnet_id: SubnetId) -> SubnetRecord {
        let RegistryValue {
            value: subnet_record_vec,
            version: _,
            deletion_marker: _,
        } = self
            .get(
                &make_subnet_record_key(subnet_id).into_bytes(),
                self.latest_version(),
            )
            .unwrap_or_else(|| {
                panic!(
                    "{}subnet record for {:} not found in the registry.",
                    LOG_PREFIX, subnet_id
                )
            });

        decode_registry_value::<SubnetRecord>(subnet_record_vec.clone())
    }

    pub fn get_subnet_list_record(&self) -> SubnetListRecord {
        match self.get(
            &make_subnet_list_record_key().as_bytes(),
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

    /// Return the mutation that can be used to replace the given subnet's
    /// membership with `new_membership`.
    pub fn make_replace_subnet_membership_mutation(
        &self,
        subnet_id: SubnetId,
        mut new_membership: Vec<NodeId>,
    ) -> RegistryMutation {
        new_membership.dedup();
        let mut subnet_record = self.get_subnet_or_panic(subnet_id);

        subnet_record.membership = new_membership
            .iter()
            .map(|id| id.get().into_vec())
            .collect();

        let update_subnet_record = RegistryMutation {
            mutation_type: registry_mutation::Type::Update as i32,
            key: make_subnet_record_key(subnet_id).into_bytes(),
            value: encode_or_panic(&subnet_record),
        };

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

        update_subnet_record
    }
}
