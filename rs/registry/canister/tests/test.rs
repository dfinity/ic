mod test {
    use assert_matches::assert_matches;
    use candid::Encode;
    use canister_test::{Canister, Project, Runtime};
    use ic_crypto_tree_hash::{flatmap, Label, LabeledTree, MixedHashTree};
    use ic_nns_test_utils::{
        itest_helpers::{
            local_test_on_nns_subnet, maybe_upgrade_to_self,
            registry_init_payload_allow_anonymous_user_for_tests, UpgradeTestingScenario,
        },
        registry::invariant_compliant_mutation_as_atomic_req,
    };
    use ic_nns_test_utils_macros::parameterized_upgrades;
    use ic_registry_transport::{
        insert,
        pb::v1::{
            registry_error::Code, CertifiedResponse, RegistryAtomicMutateRequest,
            RegistryAtomicMutateResponse, RegistryError, RegistryGetChangesSinceRequest,
            RegistryGetLatestVersionResponse, RegistryGetValueRequest, RegistryGetValueResponse,
        },
        precondition, update, upsert,
    };
    use registry_canister::{
        init::{RegistryCanisterInitPayload, RegistryCanisterInitPayloadBuilder},
        proto_on_wire::protobuf,
    };
    use std::convert::TryInto;

    pub async fn install_registry_canister(
        runtime: &Runtime,
        init_payload: RegistryCanisterInitPayload,
    ) -> Canister<'_> {
        try_to_install_registry_canister(runtime, init_payload)
            .await
            .unwrap()
    }

    async fn try_to_install_registry_canister(
        runtime: &Runtime,
        init_payload: RegistryCanisterInitPayload,
    ) -> Result<Canister<'_>, String> {
        let encoded = Encode!(&init_payload).unwrap();
        let proj = Project::new(env!("CARGO_MANIFEST_DIR"));
        proj.cargo_bin("registry-canister")
            .install(&runtime)
            .bytes(encoded)
            .await
    }

    fn get_value_request(key: impl AsRef<[u8]>, version: Option<u64>) -> RegistryGetValueRequest {
        RegistryGetValueRequest {
            version,
            key: key.as_ref().to_vec(),
        }
    }

    fn changes_since(version: u64) -> RegistryGetChangesSinceRequest {
        RegistryGetChangesSinceRequest { version }
    }

    fn data_part(certified_response: &CertifiedResponse) -> LabeledTree<Vec<u8>> {
        let tree: MixedHashTree = certified_response
            .hash_tree
            .clone()
            .expect("certified response doesn't include a hash tree")
            .try_into()
            .expect("failed to decode mixed hash tree");
        let data_part: LabeledTree<Vec<u8>> = tree
            .try_into()
            .expect("failed to convert mixed hash tree into a labeled tree");
        data_part
    }

    /// This is a simple end-to-end test of the Registry canister, in which
    /// key/value pairs are first inserted, and in a second time the value
    /// for one key is retrieved.
    #[parameterized_upgrades]
    async fn registry(runtime: &Runtime, upgrade_scenario: UpgradeTestingScenario) {
        // Set up: install the registry canister
        let mut canister = install_registry_canister(
            runtime,
            registry_init_payload_allow_anonymous_user_for_tests(),
        )
        .await;

        // Exercise the "atomic_mutate" method
        let mutation_request = RegistryAtomicMutateRequest {
            mutations: vec![
                insert("zurich", "switzerland"),
                insert("coimbra", "portugal"),
            ],
            preconditions: vec![],
        };
        let mutation_resp: RegistryAtomicMutateResponse = canister
            .update_("atomic_mutate", protobuf, mutation_request)
            .await
            .unwrap();
        assert_eq!(
            mutation_resp,
            RegistryAtomicMutateResponse {
                errors: vec![],
                version: 2 as u64,
            }
        );

        maybe_upgrade_to_self(&mut canister, upgrade_scenario).await;

        // Exercise the "get_value" method
        let get_value_res: RegistryGetValueResponse = canister
            .query_("get_value", protobuf, get_value_request("coimbra", None))
            .await
            .unwrap();
        assert_eq!(
            get_value_res,
            RegistryGetValueResponse {
                error: None,
                version: 2 as u64,
                value: b"portugal".to_vec()
            }
        );

        // Exercise the "get_latest_version" method
        let get_latest_version_resp: RegistryGetLatestVersionResponse = canister
            .query_("get_latest_version", protobuf, vec![])
            .await
            .unwrap();
        assert_eq!(
            get_latest_version_resp,
            RegistryGetLatestVersionResponse { version: 2 as u64 }
        );

        // Mutate an existing key to be able to test the existence of several values for
        // one key.
        let atomic_mutate_resp: RegistryAtomicMutateResponse = canister
            .update_(
                "atomic_mutate",
                protobuf,
                RegistryAtomicMutateRequest {
                    mutations: vec![update("zurich", "die Schweiz")],
                    preconditions: vec![],
                },
            )
            .await
            .unwrap();

        assert_eq!(
            atomic_mutate_resp,
            RegistryAtomicMutateResponse {
                errors: vec![],
                version: 3 as u64,
            }
        );

        maybe_upgrade_to_self(&mut canister, upgrade_scenario).await;

        // We can still access both values
        let get_value_v1_resp: RegistryGetValueResponse = canister
            .query_("get_value", protobuf, get_value_request("zurich", Some(2)))
            .await
            .unwrap();
        let get_value_v2_resp: RegistryGetValueResponse = canister
            .query_("get_value", protobuf, get_value_request("zurich", Some(3)))
            .await
            .unwrap();

        assert_eq!(get_value_v1_resp.value, b"switzerland");
        assert_eq!(get_value_v2_resp.value, b"die Schweiz");

        // Exercise the "get_latest_version" method again
        let get_latest_version_res: RegistryGetLatestVersionResponse = canister
            .query_("get_latest_version", protobuf, vec![])
            .await
            .unwrap();

        assert_eq!(
            get_latest_version_res,
            RegistryGetLatestVersionResponse { version: 3 as u64 }
        );

        // Try to get a non-existing key
        let get_value_resp_non_existent: RegistryGetValueResponse = canister
            .query_(
                "get_value",
                protobuf,
                get_value_request("Oh no, that key does not exist!", None),
            )
            .await
            .unwrap();

        assert_eq!(
            get_value_resp_non_existent,
            RegistryGetValueResponse {
                error: Some(RegistryError {
                    code: Code::KeyNotPresent as i32,
                    key: b"Oh no, that key does not exist!".to_vec(),
                    reason: "".to_string()
                }),
                version: 3,
                value: vec![]
            }
        );
    }

    #[parameterized_upgrades]
    async fn get_latest_version_certified(
        runtime: &Runtime,
        upgrade_scenario: UpgradeTestingScenario,
    ) {
        type T = LabeledTree<Vec<u8>>;

        let mut canister = install_registry_canister(
            runtime,
            registry_init_payload_allow_anonymous_user_for_tests(),
        )
        .await;

        let mutation_request = RegistryAtomicMutateRequest {
            mutations: vec![insert("key1", "value1")],
            preconditions: vec![],
        };
        let mutation_res: RegistryAtomicMutateResponse = canister
            .update_("atomic_mutate", protobuf, mutation_request)
            .await
            .unwrap();

        assert_eq!(
            mutation_res,
            RegistryAtomicMutateResponse {
                errors: vec![],
                version: 2u64,
            }
        );

        maybe_upgrade_to_self(&mut canister, upgrade_scenario).await;

        let certified_response: CertifiedResponse = canister
            .query_("get_certified_latest_version", protobuf, vec![])
            .await
            .unwrap();

        assert_eq!(
            data_part(&certified_response),
            T::SubTree(flatmap!(Label::from("current_version") => T::Leaf(vec![0x02])))
        );
    }

    #[parameterized_upgrades]
    async fn get_changes_since_certified(
        runtime: &Runtime,
        upgrade_scenario: UpgradeTestingScenario,
    ) {
        type T = LabeledTree<Vec<u8>>;

        let mut canister = install_registry_canister(
            runtime,
            registry_init_payload_allow_anonymous_user_for_tests(),
        )
        .await;

        let certified_response: CertifiedResponse = canister
            .query_("get_certified_changes_since", protobuf, changes_since(1))
            .await
            .unwrap();

        assert_eq!(
            data_part(&certified_response),
            T::SubTree(flatmap!(
                Label::from("current_version") => T::Leaf(vec![0x01]),
            ))
        );

        let mutation_request = RegistryAtomicMutateRequest {
            mutations: vec![insert("key1", "value1")],
            preconditions: vec![],
        };

        let mutation_res: RegistryAtomicMutateResponse = canister
            .update_("atomic_mutate", protobuf, mutation_request.clone())
            .await
            .unwrap();

        assert_eq!(
            mutation_res,
            RegistryAtomicMutateResponse {
                errors: vec![],
                version: 2u64,
            }
        );

        maybe_upgrade_to_self(&mut canister, upgrade_scenario).await;

        let certified_response: CertifiedResponse = canister
            .query_("get_certified_changes_since", protobuf, changes_since(2))
            .await
            .unwrap();

        assert_eq!(
            data_part(&certified_response),
            T::SubTree(flatmap!(
                Label::from("current_version") => T::Leaf(vec![0x02]),
            ))
        );
    }

    #[test]
    fn test_canister_installation_traps_on_bad_init_payload() {
        local_test_on_nns_subnet(|runtime| async move {
            assert_matches!(
            Project::new(env!("CARGO_MANIFEST_DIR"))
            .cargo_bin("registry-canister")
                .install(&runtime)
                .bytes(b"This is not legal candid".to_vec())
                .await,
                Err(msg) if msg.contains("must be a Candid-encoded RegistryCanisterInitPayload"));
            Ok(())
        });
    }

    #[test]
    fn test_mutations_are_rejected_from_non_authorized_sources() {
        local_test_on_nns_subnet(|runtime| async move {
            let mut canister = install_registry_canister(
                &runtime,
                RegistryCanisterInitPayloadBuilder::new()
                    .push_init_mutate_request(invariant_compliant_mutation_as_atomic_req())
                    .build(),
            )
            .await;

            let mutation_request = RegistryAtomicMutateRequest {
                mutations: vec![insert("key1", "value1")],
                preconditions: vec![],
            };
            let response: Result<RegistryAtomicMutateResponse, String> = canister
                .update_("atomic_mutate", protobuf, mutation_request.clone())
                .await;
            assert_matches!(response,
                Err(s) if s.contains("is not authorized to call this method: atomic_mutate"));

            // Go through an upgrade cycle, and verify that it still works the same
            canister.upgrade_to_self_binary(vec![]).await.unwrap();
            let response: Result<RegistryAtomicMutateResponse, String> = canister
                .update_("atomic_mutate", protobuf, mutation_request.clone())
                .await;
            assert_matches!(response,
                Err(s) if s.contains("is not authorized to call this method: atomic_mutate"));

            Ok(())
        });
    }

    /// Tests that the state of the registry after initialization includes what
    /// was set by the initial mutations, when they all succeed.
    #[test]
    fn test_initial_mutations_ok() {
        local_test_on_nns_subnet(|runtime| async move {
            let init_payload = RegistryCanisterInitPayloadBuilder::new()
                .push_init_mutate_request(invariant_compliant_mutation_as_atomic_req())
                .push_init_mutate_request(RegistryAtomicMutateRequest {
                    mutations: vec![
                        upsert(b"dufourspitze", b"4634 m"),
                        upsert(b"dom", b"4545 m"),
                    ],
                    preconditions: vec![],
                })
                .push_init_mutate_request(RegistryAtomicMutateRequest {
                    mutations: vec![upsert(b"matterhorn", b"4478 m")],
                    preconditions: vec![precondition(b"dom", 1)],
                })
                .build();
            let canister = install_registry_canister(&runtime, init_payload).await;
            // The following assert_eq have the expected value first and expression second,
            // otherwise type inference does not work
            assert_eq!(
                RegistryGetValueResponse {
                    error: None,
                    version: 2 as u64,
                    value: b"4634 m".to_vec()
                },
                canister
                    .query_(
                        "get_value",
                        protobuf,
                        get_value_request("dufourspitze", None)
                    )
                    .await
                    .unwrap()
            );
            assert_eq!(
                RegistryGetValueResponse {
                    error: None,
                    version: 2 as u64,
                    value: b"4545 m".to_vec()
                },
                canister
                    .query_("get_value", protobuf, get_value_request("dom", None))
                    .await
                    .unwrap(),
            );
            assert_eq!(
                RegistryGetValueResponse {
                    error: None,
                    version: 3 as u64,
                    value: b"4478 m".to_vec()
                },
                canister
                    .query_("get_value", protobuf, get_value_request("matterhorn", None))
                    .await
                    .unwrap(),
            );
            Ok(())
        });
    }

    /// Tests that the canister init traps if any initial mutation fails, even
    /// if previous ones have succeeded
    #[test]
    fn test_that_init_traps_if_any_init_mutation_fails() {
        local_test_on_nns_subnet(|runtime| async move {
            let init_payload = RegistryCanisterInitPayloadBuilder::new()
                .push_init_mutate_request(invariant_compliant_mutation_as_atomic_req())
                .push_init_mutate_request(RegistryAtomicMutateRequest {
                    mutations: vec![
                        upsert(b"rock steady", b"jamaica"),
                        upsert(b"jazz", b"usa"),
                        upsert(b"dub", b"uk"),
                    ],
                    preconditions: vec![],
                })
                .push_init_mutate_request(RegistryAtomicMutateRequest {
                    mutations: vec![insert(b"dub", b"uk")],
                    preconditions: vec![],
                })
                .build();
            assert_matches!(
                try_to_install_registry_canister(&runtime, init_payload).await,
                Err(msg) if msg.contains("Transaction rejected"));
            Ok(())
        });
    }
}
