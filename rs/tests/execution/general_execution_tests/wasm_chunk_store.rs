use candid::Decode;
use ic_agent::{
    AgentError,
    agent::{RejectCode, RejectResponse},
};
use ic_base_types::CanisterId;
use ic_management_canister_types_private::{
    CanisterInstallModeV2, InstallChunkedCodeArgs, Payload, UploadChunkArgs, UploadChunkReply,
};
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::driver::test_env::TestEnv;
use ic_system_test_driver::driver::test_env_api::{
    GetFirstHealthyNodeSnapshot, HasPublicApiUrl, HasTopologySnapshot,
};
use ic_system_test_driver::util::{UniversalCanister, block_on};
use ic_types::Cycles;
use ic_universal_canister::{UNIVERSAL_CANISTER_WASM, call_args, wasm};
use ic_utils::interfaces::ManagementCanister;

pub fn install_large_wasm(env: TestEnv) {
    let logger = env.logger();
    let app_node = env.get_first_healthy_application_node_snapshot();
    let agent = app_node.build_default_agent();
    block_on({
        async move {
            // Create a canister a controller.
            let mgr = ManagementCanister::create(&agent);
            let controller_canister = UniversalCanister::new_with_retries(
                &agent,
                app_node.effective_canister_id(),
                &logger,
            )
            .await;
            let canister_id = mgr
                .create_canister()
                .as_provisional_create_with_amount(None)
                .with_effective_canister_id(app_node.effective_canister_id())
                .with_controller(controller_canister.canister_id())
                .call_and_wait()
                .await
                .expect("Couldn't create canister with provisional API.")
                .0;

            // Upload universal canister in two chunks.
            let data = &*UNIVERSAL_CANISTER_WASM;
            let data_hash = ic_crypto_sha2::Sha256::hash(data);
            let chunk1 = &data[..200];
            let chunk1_hash = ic_crypto_sha2::Sha256::hash(chunk1);
            let chunk2 = &data[200..];
            let chunk2_hash = ic_crypto_sha2::Sha256::hash(chunk2);

            // Upload chunk 1
            let hash = controller_canister
                .update(
                    wasm().call_with_cycles(
                        CanisterId::ic_00(),
                        ic_management_canister_types_private::Method::UploadChunk,
                        call_args()
                            .other_side(
                                UploadChunkArgs {
                                    canister_id: canister_id.into(),
                                    chunk: chunk1.to_vec(),
                                }
                                .encode(),
                            )
                            .on_reject(wasm().reject_message().reject()),
                        Cycles::new(1_000_000_000_000),
                    ),
                )
                .await
                .map(|res| Decode!(res.as_slice(), UploadChunkReply).unwrap().hash)
                .unwrap();
            assert_eq!(hash, chunk1_hash);

            // Upload chunk 2
            let hash = controller_canister
                .update(
                    wasm().call_with_cycles(
                        CanisterId::ic_00(),
                        ic_management_canister_types_private::Method::UploadChunk,
                        call_args()
                            .other_side(
                                UploadChunkArgs {
                                    canister_id: canister_id.into(),
                                    chunk: chunk2.to_vec(),
                                }
                                .encode(),
                            )
                            .on_reject(wasm().reject_message().reject()),
                        Cycles::new(1_000_000_000_000),
                    ),
                )
                .await
                .map(|res| Decode!(res.as_slice(), UploadChunkReply).unwrap().hash)
                .unwrap();
            assert_eq!(hash, chunk2_hash);

            // Install from chunks
            let _ = controller_canister
                .update(
                    wasm().call_with_cycles(
                        CanisterId::ic_00(),
                        ic_management_canister_types_private::Method::InstallChunkedCode,
                        call_args()
                            .other_side(
                                InstallChunkedCodeArgs::new(
                                    CanisterInstallModeV2::Install,
                                    CanisterId::unchecked_from_principal(canister_id.into()),
                                    None,
                                    vec![chunk1_hash.to_vec(), chunk2_hash.to_vec()],
                                    data_hash.to_vec(),
                                    vec![],
                                )
                                .encode(),
                            )
                            .on_reject(wasm().reject_message().reject()),
                        Cycles::new(1_000_000_000_000),
                    ),
                )
                .await
                .unwrap();
        }
    });
}

pub fn install_large_wasm_with_other_store(env: TestEnv) {
    let logger = env.logger();
    let app_node = env.get_first_healthy_application_node_snapshot();
    let agent = app_node.build_default_agent();
    block_on({
        async move {
            // Create a canister a controller.
            let mgr = ManagementCanister::create(&agent);
            let controller_canister = UniversalCanister::new_with_retries(
                &agent,
                app_node.effective_canister_id(),
                &logger,
            )
            .await;
            let target_canister_id = mgr
                .create_canister()
                .as_provisional_create_with_amount(None)
                .with_effective_canister_id(app_node.effective_canister_id())
                .with_controller(controller_canister.canister_id())
                .call_and_wait()
                .await
                .expect("Couldn't create canister with provisional API.")
                .0;
            let store_canister_id = mgr
                .create_canister()
                .as_provisional_create_with_amount(None)
                .with_effective_canister_id(app_node.effective_canister_id())
                .with_controller(controller_canister.canister_id())
                .call_and_wait()
                .await
                .expect("Couldn't create canister with provisional API.")
                .0;

            // Upload universal canister in one chunk.
            let data = &*UNIVERSAL_CANISTER_WASM;
            let data_hash = ic_crypto_sha2::Sha256::hash(data);

            let hash = controller_canister
                .update(
                    wasm().call_with_cycles(
                        CanisterId::ic_00(),
                        ic_management_canister_types_private::Method::UploadChunk,
                        call_args()
                            .other_side(
                                UploadChunkArgs {
                                    canister_id: store_canister_id.into(),
                                    chunk: data.to_vec(),
                                }
                                .encode(),
                            )
                            .on_reject(wasm().reject_message().reject()),
                        Cycles::new(1_000_000_000_000),
                    ),
                )
                .await
                .map(|res| Decode!(res.as_slice(), UploadChunkReply).unwrap().hash)
                .unwrap();
            assert_eq!(hash, data_hash);

            // Install from chunks
            let _ = controller_canister
                .update(
                    wasm().call_with_cycles(
                        CanisterId::ic_00(),
                        ic_management_canister_types_private::Method::InstallChunkedCode,
                        call_args()
                            .other_side(
                                InstallChunkedCodeArgs::new(
                                    CanisterInstallModeV2::Install,
                                    CanisterId::unchecked_from_principal(target_canister_id.into()),
                                    Some(CanisterId::unchecked_from_principal(
                                        store_canister_id.into(),
                                    )),
                                    vec![data_hash.to_vec()],
                                    data_hash.to_vec(),
                                    vec![],
                                )
                                .encode(),
                            )
                            .on_reject(wasm().reject_message().reject()),
                        Cycles::new(1_000_000_000_000),
                    ),
                )
                .await
                .unwrap();
        }
    });
}

pub fn install_large_wasm_with_other_store_fails_cross_subnet(env: TestEnv) {
    let logger = env.logger();
    let app_node = env.get_first_healthy_application_node_snapshot();
    let verified_app_node = env.get_first_healthy_verified_application_node_snapshot();
    let agent = app_node.build_default_agent();
    let verified_agent = verified_app_node.build_default_agent();
    let app_subnet_id = env
        .topology_snapshot()
        .subnets()
        .find(|s| s.subnet_type() == SubnetType::Application)
        .unwrap()
        .subnet_id;
    block_on({
        async move {
            // Create a canister a controller.
            let mgr = ManagementCanister::create(&agent);
            let verified_mgr = ManagementCanister::create(&verified_agent);
            let controller_canister = UniversalCanister::new_with_retries(
                &agent,
                app_node.effective_canister_id(),
                &logger,
            )
            .await;
            let target_canister_id = mgr
                .create_canister()
                .as_provisional_create_with_amount(None)
                .with_effective_canister_id(app_node.effective_canister_id())
                .with_controller(controller_canister.canister_id())
                .call_and_wait()
                .await
                .expect("Couldn't create canister with provisional API.")
                .0;
            // Put the store canister on a different subnet.
            let store_canister_id = verified_mgr
                .create_canister()
                .as_provisional_create_with_amount(None)
                .with_effective_canister_id(verified_app_node.effective_canister_id())
                .with_controller(controller_canister.canister_id())
                .call_and_wait()
                .await
                .expect("Couldn't create canister with provisional API.")
                .0;

            // Upload universal canister in one chunk.
            let data = &*UNIVERSAL_CANISTER_WASM;
            let data_hash = ic_crypto_sha2::Sha256::hash(data);

            let hash = controller_canister
                .update(
                    wasm().call_with_cycles(
                        CanisterId::ic_00(),
                        ic_management_canister_types_private::Method::UploadChunk,
                        call_args()
                            .other_side(
                                UploadChunkArgs {
                                    canister_id: store_canister_id.into(),
                                    chunk: data.to_vec(),
                                }
                                .encode(),
                            )
                            .on_reject(wasm().reject_message().reject()),
                        Cycles::new(1_000_000_000_000),
                    ),
                )
                .await
                .map(|res| Decode!(res.as_slice(), UploadChunkReply).unwrap().hash)
                .unwrap();
            assert_eq!(hash, data_hash);

            // Install from chunks
            let err = controller_canister
                .update(
                    wasm().call_with_cycles(
                        CanisterId::ic_00(),
                        ic_management_canister_types_private::Method::InstallChunkedCode,
                        call_args()
                            .other_side(
                                InstallChunkedCodeArgs::new(
                                    CanisterInstallModeV2::Install,
                                    CanisterId::unchecked_from_principal(target_canister_id.into()),
                                    Some(CanisterId::unchecked_from_principal(
                                        store_canister_id.into(),
                                    )),
                                    vec![data_hash.to_vec()],
                                    data_hash.to_vec(),
                                    vec![],
                                )
                                .encode(),
                            )
                            .on_reject(wasm().reject_message().reject()),
                        Cycles::new(1_000_000_000_000),
                    ),
                )
                .await
                .unwrap_err();
            let expected_reject = RejectResponse {
                reject_code: RejectCode::CanisterReject,
                reject_message: format!(
                    "InstallChunkedCode Error: Store canister {store_canister_id} was not found on subnet {app_subnet_id} of target canister {target_canister_id}"
                ),
                error_code: Some("IC0406".to_string()),
            };
            match err {
                AgentError::CertifiedReject { reject, .. } => assert_eq!(reject, expected_reject),
                _ => panic!("Unexpected error: {err:?}"),
            };
        }
    });
}
