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

        let latest_version = self.latest_version();
        for dc in payload.data_centers_to_add {
            let key = make_data_center_record_key(&dc.id);

            // panic if we already have a record for that data center
            if self.get(key.as_bytes(), latest_version).is_some() {
                panic!(
                    "{}do_add_or_remove_data_centers: Cannot add DataCenterRecord with ID: '{}' already exists",
                    LOG_PREFIX, &dc.id
                );
            }

            match dc.validate() {
                Ok(_) => mutations.push(RegistryMutation {
                    mutation_type: registry_mutation::Type::Upsert as i32,
                    key: key.into(),
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

#[cfg(test)]
mod test {
    use crate::mutations::common::decode_registry_value;
    use crate::registry::Registry;
    use ic_nns_test_utils::registry::invariant_compliant_mutation;
    use ic_protobuf::registry::dc::v1::{AddOrRemoveDataCentersProposalPayload, DataCenterRecord};
    use ic_registry_keys::make_data_center_record_key;

    #[test]
    #[should_panic(
        expected = "do_add_or_remove_data_centers: Cannot add DataCenterRecord with ID: 'AN1' already exists"
    )]
    fn cannot_add_second_data_center_with_same_id() {
        // Given a registry instance
        let mut registry = Registry::new();
        registry.maybe_apply_mutation_internal(invariant_compliant_mutation());
        // when we try to add two data centers with same id
        let first_record = DataCenterRecord {
            id: "AN1".into(),
            region: "BEL".into(),
            owner: "Alice".into(),
            gps: None,
        };

        let payload = AddOrRemoveDataCentersProposalPayload {
            data_centers_to_add: vec![first_record.clone()],
            data_centers_to_remove: vec![],
        };

        registry.do_add_or_remove_data_centers(payload);

        let dc_record_1 = get_dc_record(&registry, "AN1");
        // assert first record is entered
        assert_eq!(dc_record_1, first_record);

        let second_record = DataCenterRecord {
            id: "AN1".into(),
            region: "OTHER".into(),
            owner: "Anti-alice".into(),
            gps: None,
        };

        let payload = AddOrRemoveDataCentersProposalPayload {
            data_centers_to_add: vec![second_record],
            data_centers_to_remove: vec![],
        };

        // second addition fails with same ID and panics
        registry.do_add_or_remove_data_centers(payload);
    }

    #[test]
    fn can_add_data_center_after_removing() {
        // Given a registry instance
        let mut registry = Registry::new();
        registry.maybe_apply_mutation_internal(invariant_compliant_mutation());
        // when we try to add two data centers with same id
        let first_record = DataCenterRecord {
            id: "AN1".into(),
            region: "BEL".into(),
            owner: "Alice".into(),
            gps: None,
        };

        let payload = AddOrRemoveDataCentersProposalPayload {
            data_centers_to_add: vec![first_record.clone()],
            data_centers_to_remove: vec![],
        };

        registry.do_add_or_remove_data_centers(payload);

        // assert first record is entered
        let dc_record_1 = get_dc_record(&registry, "AN1");
        assert_eq!(dc_record_1, first_record);

        // remove record
        let payload = AddOrRemoveDataCentersProposalPayload {
            data_centers_to_add: vec![],
            data_centers_to_remove: vec![first_record.id],
        };

        registry.do_add_or_remove_data_centers(payload);
        assert_no_dc_record(&registry, "AN1");

        let second_record = DataCenterRecord {
            id: "AN1".into(),
            region: "OTHER".into(),
            owner: "Anti-alice".into(),
            gps: None,
        };

        let payload = AddOrRemoveDataCentersProposalPayload {
            data_centers_to_add: vec![second_record],
            data_centers_to_remove: vec![],
        };

        // second addition fails with same ID and panics
        registry.do_add_or_remove_data_centers(payload);
        let dc_record_2 = get_dc_record(&registry, "AN1");
        assert_eq!(dc_record_2.id, "AN1");
        assert_eq!(dc_record_2.region, "OTHER");
    }

    fn get_dc_record(registry: &Registry, id_string: &str) -> DataCenterRecord {
        let latest_version = registry.latest_version();
        let record = registry
            .get(
                make_data_center_record_key(id_string).as_bytes(),
                latest_version,
            )
            .unwrap();
        decode_registry_value::<DataCenterRecord>(record.value.clone())
    }

    fn assert_no_dc_record(registry: &Registry, id_string: &str) {
        let latest_version = registry.latest_version();
        let record = registry.get(
            make_data_center_record_key(id_string).as_bytes(),
            latest_version,
        );
        assert_eq!(record, None);
    }
}
