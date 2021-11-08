use crate::{common::LOG_PREFIX, mutations::common::encode_or_panic, registry::Registry};

use ic_protobuf::registry::dc::v1::AddOrRemoveDataCentersProposalPayload;
use ic_registry_keys::make_data_center_record_key;
use ic_registry_transport::pb::v1::{registry_mutation, RegistryMutation};

impl Registry {
    /// Add or remove data center records to the Registry
    pub fn do_add_or_remove_data_centers(
        &mut self,
        payload: AddOrRemoveDataCentersProposalPayload,
    ) {
        println!(
            "{}do_add_or_remove_data_centers: {:?}",
            LOG_PREFIX, &payload
        );

        let mut mutations = vec![];

        for dc_id in payload.data_centers_to_remove {
            mutations.push(RegistryMutation {
                mutation_type: registry_mutation::Type::Delete as i32,
                key: make_data_center_record_key(&dc_id).into(),
                value: vec![],
            });
        }

        for dc in payload.data_centers_to_add {
            match dc.validate() {
                Ok(_) => mutations.push(RegistryMutation {
                    mutation_type: registry_mutation::Type::Upsert as i32,
                    key: make_data_center_record_key(&dc.id).into(),
                    value: encode_or_panic(&dc),
                }),
                Err(msg) => {
                    println!(
                        "{}do_add_or_remove_data_centers: invalid DataCenterRecord: {}, {:?}",
                        LOG_PREFIX, msg, &dc
                    );
                }
            }
        }

        // Check invariants before applying mutations
        self.maybe_apply_mutation_internal(mutations);
    }
}
