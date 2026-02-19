use candid::Principal;
use ic_cdk::api::canister_self;
use ic_cdk::management_canister::*;
use ic_cdk::update;
use sha2::Digest;

#[update]
async fn basic() {
    // create_canister
    let self_id = canister_self();
    let arg = CreateCanisterArgs {
        settings: Some(CanisterSettings {
            controllers: Some(vec![self_id]),
            compute_allocation: Some(0u8.into()),
            memory_allocation: Some(0u8.into()),
            // Since around 2025-04, the freezing threshold is enforced to be at least 604800 seconds (7 days).
            freezing_threshold: Some(604_800u32.into()),
            reserved_cycles_limit: Some(0u8.into()),
            log_visibility: Some(LogVisibility::Public),
            wasm_memory_limit: Some(0u8.into()),
            wasm_memory_threshold: Some(0u8.into()),
            environment_variables: Some(vec![]),
        }),
    };
    // 500 B is the minimum cycles required to create a canister.
    // Here we set 1 T cycles for other operations below.
    let canister_id = create_canister_with_extra_cycles(&arg, 1_000_000_000_000u128)
        .await
        .unwrap()
        .canister_id;

    // canister_status
    let arg = CanisterStatusArgs { canister_id };
    let result = canister_status(&arg).await.unwrap();
    assert_eq!(result.status, CanisterStatusType::Running);
    assert_eq!(result.reserved_cycles.0, 0u128.into());
    let definite_canister_setting = result.settings;
    assert_eq!(definite_canister_setting.controllers, vec![self_id]);
    assert_eq!(definite_canister_setting.compute_allocation, 0u8);
    assert_eq!(definite_canister_setting.memory_allocation, 0u8);
    assert_eq!(definite_canister_setting.freezing_threshold, 604_800u32);
    assert_eq!(definite_canister_setting.reserved_cycles_limit, 0u8);
    assert_eq!(
        definite_canister_setting.log_visibility,
        LogVisibility::Public
    );
    assert_eq!(definite_canister_setting.wasm_memory_limit, 0u8);
    assert_eq!(definite_canister_setting.wasm_memory_threshold, 0u8);

    // update_settings
    let arg = UpdateSettingsArgs {
        canister_id,
        settings: CanisterSettings {
            freezing_threshold: Some(2_592_000u32.into()),
            log_visibility: Some(LogVisibility::AllowedViewers(vec![self_id])),

            ..Default::default()
        },
    };
    update_settings(&arg).await.unwrap();

    // wat2wasm "(module (@custom "icp:public X" "content of X"))"
    let wasm_module = b"\x00asm\x01\x00\x00\x00\x00\x19\x0c\
    icp:public\x20Xcontent\x20of\x20X"
        .to_vec();

    // install_code
    let arg = InstallCodeArgs {
        mode: CanisterInstallMode::Install,
        canister_id,
        // A minimal valid wasm module
        // wat2wasm "(module)"
        wasm_module,
        arg: vec![],
    };
    install_code(&arg).await.unwrap();

    // canister_metadata
    let arg = CanisterMetadataArgs {
        canister_id,
        name: "X".to_string(),
    };
    let result = canister_metadata(&arg).await.unwrap();
    assert_eq!(result.value, b"content of X".to_vec());

    // uninstall_code
    let arg = UninstallCodeArgs { canister_id };
    uninstall_code(&arg).await.unwrap();

    // start_canister
    let arg = StartCanisterArgs { canister_id };
    start_canister(&arg).await.unwrap();

    // stop_canister
    let arg = StopCanisterArgs { canister_id };
    stop_canister(&arg).await.unwrap();

    // deposit_cycles
    let arg = DepositCyclesArgs { canister_id };
    deposit_cycles(&arg, 1_000_000_000_000u128).await.unwrap();

    // delete_canister
    let arg = DeleteCanisterArgs { canister_id };
    delete_canister(&arg).await.unwrap();

    // raw_rand
    let bytes = raw_rand().await.unwrap();
    assert_eq!(bytes.len(), 32);
}

#[update]
async fn env_var() {
    let arg = CreateCanisterArgs {
        settings: Some(CanisterSettings {
            environment_variables: Some(vec![EnvironmentVariable {
                name: "key1".to_string(),
                value: "value1".to_string(),
            }]),
            ..Default::default()
        }),
    };
    // 500 B is the minimum cycles required to create a canister.
    // Here we set 1 T cycles for other operations below.
    let canister_id = create_canister_with_extra_cycles(&arg, 1_000_000_000_000u128)
        .await
        .unwrap()
        .canister_id;

    // canister_status
    let arg = CanisterStatusArgs { canister_id };
    let result = canister_status(&arg).await.unwrap();
    let definite_canister_setting = result.settings;
    assert_eq!(
        definite_canister_setting.environment_variables,
        vec![EnvironmentVariable {
            name: "key1".to_string(),
            value: "value1".to_string(),
        }]
    );

    // update_settings
    let arg = UpdateSettingsArgs {
        canister_id,
        settings: CanisterSettings {
            environment_variables: Some(vec![
                EnvironmentVariable {
                    name: "key2".to_string(),
                    value: "value2".to_string(),
                },
                EnvironmentVariable {
                    name: "key3".to_string(),
                    value: "value3".to_string(),
                },
            ]),
            ..Default::default()
        },
    };
    update_settings(&arg).await.unwrap();
}

#[update]
async fn ecdsa() {
    // ecdsa_public_key
    let key_id = EcdsaKeyId {
        curve: EcdsaCurve::Secp256k1,
        name: "test_key_1".to_string(),
    };
    let derivation_path = vec![];
    let arg = EcdsaPublicKeyArgs {
        canister_id: None,
        derivation_path: derivation_path.clone(),
        key_id: key_id.clone(),
    };
    let EcdsaPublicKeyResult {
        public_key,
        chain_code,
    } = ecdsa_public_key(&arg).await.unwrap();
    assert_eq!(public_key.len(), 33);
    assert_eq!(chain_code.len(), 32);

    let message = "hello world";
    let message_hash = sha2::Sha256::digest(message).to_vec();
    let arg = SignWithEcdsaArgs {
        message_hash,
        derivation_path,
        key_id,
    };
    let SignWithEcdsaResult { signature } = sign_with_ecdsa(&arg).await.unwrap();
    assert_eq!(signature.len(), 64);
}

#[update]
async fn schnorr() {
    // schnorr_public_key
    let key_id = SchnorrKeyId {
        algorithm: SchnorrAlgorithm::Bip340secp256k1,
        name: "test_key_1".to_string(),
    };
    let derivation_path = vec![];
    let arg = SchnorrPublicKeyArgs {
        canister_id: None,
        derivation_path: derivation_path.clone(),
        key_id: key_id.clone(),
    };
    let SchnorrPublicKeyResult {
        public_key,
        chain_code,
    } = schnorr_public_key(&arg).await.unwrap();
    assert_eq!(public_key.len(), 33);
    assert_eq!(chain_code.len(), 32);
    let arg = SchnorrPublicKeyArgs {
        canister_id: None,
        derivation_path: derivation_path.clone(),
        key_id: SchnorrKeyId {
            algorithm: SchnorrAlgorithm::Ed25519,
            name: "test_key_1".to_string(),
        },
    };
    let SchnorrPublicKeyResult {
        public_key,
        chain_code,
    } = schnorr_public_key(&arg).await.unwrap();
    assert_eq!(public_key.len(), 32);
    assert_eq!(chain_code.len(), 32);

    // sign_with_schnorr
    let message = "hello world".into();
    let arg = SignWithSchnorrArgs {
        message,
        derivation_path,
        key_id,
        aux: None,
    };
    let SignWithSchnorrResult { signature } = sign_with_schnorr(&arg).await.unwrap();
    assert_eq!(signature.len(), 64);
}

#[update]
async fn vetkd(transport_public_key: Vec<u8>) {
    // vetkd_public_key
    let key_id = VetKDKeyId {
        curve: VetKDCurve::Bls12_381_G2,
        name: "test_key_1".to_string(),
    };
    let arg = VetKDPublicKeyArgs {
        canister_id: None,
        context: vec![],
        key_id: key_id.clone(),
    };
    let VetKDPublicKeyResult { public_key } = vetkd_public_key(&arg).await.unwrap();
    assert!(!public_key.is_empty());
    // vetkd_derive_key
    let arg = VetKDDeriveKeyArgs {
        input: vec![],
        context: vec![],
        transport_public_key,
        key_id,
    };
    let VetKDDeriveKeyResult { encrypted_key } = vetkd_derive_key(&arg).await.unwrap();
    assert!(!encrypted_key.is_empty());
}

#[update]
async fn metrics(subnet_id: Principal) {
    // node_metrics_history
    let arg = NodeMetricsHistoryArgs {
        subnet_id,
        start_at_timestamp_nanos: 0,
    };
    let result = node_metrics_history(&arg).await.unwrap();
    for record in result {
        assert!(record.timestamp_nanos > 0);
        assert!(!record.node_metrics.is_empty());
    }
}

#[update]
async fn subnet(subnet_id: Principal) {
    // subnet_info
    let arg = SubnetInfoArgs { subnet_id };
    let result = subnet_info(&arg).await.unwrap();
    assert!(!result.replica_version.is_empty());
}

#[update]
async fn provisional() {
    // provisional_create_canister_with_cycles
    let settings = CanisterSettings {
        log_visibility: Some(LogVisibility::Controllers),
        ..Default::default()
    };
    // Using Cycles Ledger (on the II subnet) Canister ID as specified_id.
    // The test canister is deployed on the II subnet, it can provisional create a canister on the same subnet.
    let specified_id = Principal::from_text("um5iw-rqaaa-aaaaq-qaaba-cai").unwrap();
    let arg = ProvisionalCreateCanisterWithCyclesArgs {
        amount: Some(10_000_000_000_000u64.into()),
        settings: Some(settings),
        specified_id: Some(specified_id),
    };
    let canister_id = provisional_create_canister_with_cycles(&arg)
        .await
        .unwrap()
        .canister_id;

    // provisional_top_up_canister
    let arg = ProvisionalTopUpCanisterArgs {
        canister_id,
        amount: 1_000_000_000u64.into(),
    };
    provisional_top_up_canister(&arg).await.unwrap();
}

#[update]
async fn snapshots() {
    let arg = CreateCanisterArgs::default();
    let canister_id = create_canister_with_extra_cycles(&arg, 2_000_000_000_000u128)
        .await
        .unwrap()
        .canister_id;

    // Cannot take a snapshot of a canister that is empty.
    // So we install a minimal wasm module.
    // A minimal valid wasm module
    // wat2wasm "(module)"
    let wasm_module = b"\x00asm\x01\x00\x00\x00".to_vec();
    let arg = InstallCodeArgs {
        mode: CanisterInstallMode::Install,
        canister_id,
        wasm_module: wasm_module.clone(),
        arg: vec![],
    };
    install_code(&arg).await.unwrap();

    // take_canister_snapshot
    let arg = TakeCanisterSnapshotArgs {
        canister_id,
        replace_snapshot: None,
        uninstall_code: None,
        sender_canister_version: None,
    };
    let snapshot1 = take_canister_snapshot(&arg).await.unwrap();

    // load_canister_snapshot
    let arg = LoadCanisterSnapshotArgs {
        canister_id,
        snapshot_id: snapshot1.id.clone(),
    };
    assert!(load_canister_snapshot(&arg).await.is_ok());

    // read_canister_snapshot_metadata
    let arg = ReadCanisterSnapshotMetadataArgs {
        canister_id,
        snapshot_id: snapshot1.id.clone(),
    };
    let snapshot_metadata = read_canister_snapshot_metadata(&arg).await.unwrap();

    // read_canister_snapshot_data
    let arg = ReadCanisterSnapshotDataArgs {
        canister_id,
        snapshot_id: snapshot1.id.clone(),
        kind: SnapshotDataKind::WasmModule { offset: 0, size: 8 },
    };
    let result = read_canister_snapshot_data(&arg).await.unwrap();
    assert_eq!(result.chunk, wasm_module);

    // upload_canister_snapshot_metadata
    let globals = snapshot_metadata.globals.into_iter().flatten().collect();
    let arg = UploadCanisterSnapshotMetadataArgs {
        canister_id,
        replace_snapshot: None,
        wasm_module_size: snapshot_metadata.wasm_module_size,
        globals,
        wasm_memory_size: snapshot_metadata.wasm_memory_size,
        stable_memory_size: snapshot_metadata.stable_memory_size,
        certified_data: snapshot_metadata.certified_data,
        global_timer: snapshot_metadata.global_timer,
        on_low_wasm_memory_hook_status: snapshot_metadata.on_low_wasm_memory_hook_status,
    };
    let snapshot2 = upload_canister_snapshot_metadata(&arg).await.unwrap();
    assert!(!snapshot2.snapshot_id.is_empty());

    // upload_canister_snapshot_data
    let arg = UploadCanisterSnapshotDataArgs {
        canister_id,
        snapshot_id: snapshot2.snapshot_id.clone(),
        kind: SnapshotDataOffset::WasmModule { offset: 0 },
        chunk: wasm_module.clone(),
    };
    assert!(upload_canister_snapshot_data(&arg).await.is_ok());

    // list_canister_snapshots
    let args = ListCanisterSnapshotsArgs { canister_id };
    let snapshots = list_canister_snapshots(&args).await.unwrap();
    assert_eq!(snapshots.len(), 2);
    assert_eq!(snapshots[0].id, snapshot1.id);
    assert_eq!(snapshots[1].id, snapshot2.snapshot_id);

    // delete_canister_snapshot
    let arg = DeleteCanisterSnapshotArgs {
        canister_id,
        snapshot_id: snapshot1.id.clone(),
    };
    assert!(delete_canister_snapshot(&arg).await.is_ok());

    // check the above snapshot operations are recorded in the canister's history.
    let arg = CanisterInfoArgs {
        canister_id,
        num_requested_changes: Some(1),
    };
    let canister_info_result = canister_info(&arg).await.unwrap();
    assert_eq!(canister_info_result.total_num_changes, 3);
    assert_eq!(canister_info_result.recent_changes.len(), 1);
    if let Change {
        details: Some(ChangeDetails::LoadSnapshot(load_snapshot_record)),
        ..
    } = &canister_info_result.recent_changes[0]
    {
        assert_eq!(load_snapshot_record.snapshot_id, snapshot1.id);
    } else {
        panic!("Expected the most recent change to be LoadSnapshot");
    }
}
fn main() {}
