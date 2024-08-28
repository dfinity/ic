use crate::{common::LOG_PREFIX, registry::Registry};

#[cfg(target_arch = "wasm32")]
use dfn_core::println;
use ic_protobuf::registry::dc::v1::{AddOrRemoveDataCentersProposalPayload, DataCenterRecord};
use ic_registry_keys::make_data_center_record_key;
use ic_registry_transport::pb::v1::{registry_mutation, RegistryMutation};
use prost::Message;

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
            let dc = DataCenterRecord {
                id: dc.id.to_lowercase(),
                ..dc
            };
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
                    value: dc.encode_to_vec(),
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
    use crate::registry::Registry;
    use ic_nns_test_utils::registry::invariant_compliant_mutation;
    use ic_protobuf::registry::dc::v1::{AddOrRemoveDataCentersProposalPayload, DataCenterRecord};
    use ic_registry_keys::make_data_center_record_key;
    use prost::Message;

    #[test]
    #[should_panic(
        expected = "do_add_or_remove_data_centers: Cannot add DataCenterRecord with ID: 'an1' already exists"
    )]
    fn cannot_add_second_data_center_with_same_id() {
        // Given a registry instance
        let mut registry = Registry::new();
        registry.maybe_apply_mutation_internal(invariant_compliant_mutation(0));
        // when we try to add two data centers with same id
        let first_record = DataCenterRecord {
            id: "an1".into(),
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
        registry.maybe_apply_mutation_internal(invariant_compliant_mutation(0));
        // when we try to add two data centers with same id
        let first_record = DataCenterRecord {
            id: "an1".into(),
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
        assert_eq!(dc_record_2.id, "an1");
        assert_eq!(dc_record_2.region, "OTHER");
    }

    #[test]
    fn lower_upper_case_data_center() {
        // Given a registry instance
        let mut registry = Registry::new();
        registry.maybe_apply_mutation_internal(invariant_compliant_mutation(0));
        // when we try to add two data centers with same id
        let first_record_uppercase = DataCenterRecord {
            id: "AN1".into(),
            region: "BEL".into(),
            owner: "Alice".into(),
            gps: None,
        };
        let first_record_lowercase = DataCenterRecord {
            id: first_record_uppercase.id.to_lowercase(),
            ..first_record_uppercase.clone()
        };

        let second_record = DataCenterRecord {
            id: "fr1".into(),
            region: "DE".into(),
            owner: "Alice".into(),
            gps: None,
        };

        let payload = AddOrRemoveDataCentersProposalPayload {
            data_centers_to_add: vec![first_record_uppercase.clone(), second_record.clone()],
            data_centers_to_remove: vec![],
        };

        registry.do_add_or_remove_data_centers(payload);

        // assert first record can be retrieved both with lower and upper case
        let dc_record_1 = get_dc_record(&registry, "an1");
        assert_eq!(dc_record_1, first_record_lowercase);

        let dc_record_1 = get_dc_record(&registry, "AN1");
        assert_eq!(dc_record_1, first_record_lowercase);

        let dc_record_2 = get_dc_record(&registry, "fr1");
        assert_eq!(dc_record_2, second_record);

        let dc_record_2 = get_dc_record(&registry, "FR1");
        assert_eq!(dc_record_2, second_record);

        // remove record
        let payload = AddOrRemoveDataCentersProposalPayload {
            data_centers_to_add: vec![],
            data_centers_to_remove: vec![first_record_uppercase.id],
        };

        registry.do_add_or_remove_data_centers(payload);
        assert_no_dc_record(&registry, "AN1");
        assert_no_dc_record(&registry, "an1");

        let dc_record_2 = get_dc_record(&registry, "fr1");
        assert_eq!(dc_record_2, second_record);

        let dc_record_2 = get_dc_record(&registry, "FR1");
        assert_eq!(dc_record_2, second_record);

        let payload = AddOrRemoveDataCentersProposalPayload {
            data_centers_to_add: vec![],
            data_centers_to_remove: vec![second_record.id],
        };

        // second addition fails with same ID and panics
        registry.do_add_or_remove_data_centers(payload);

        assert_no_dc_record(&registry, "AN1");
        assert_no_dc_record(&registry, "an1");
        assert_no_dc_record(&registry, "FR1");
        assert_no_dc_record(&registry, "fr1");
    }

    fn get_dc_record(registry: &Registry, id_string: &str) -> DataCenterRecord {
        let latest_version = registry.latest_version();
        let record = registry
            .get(
                make_data_center_record_key(id_string).as_bytes(),
                latest_version,
            )
            .unwrap();
        DataCenterRecord::decode(record.value.as_slice()).unwrap()
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
