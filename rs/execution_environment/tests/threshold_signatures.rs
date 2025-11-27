use candid::Decode;
use ic_base_types::PrincipalId;
use ic_management_canister_types_private::{
    self as ic00, CanisterInstallMode, DerivationPath, ECDSAPublicKeyResponse, EcdsaCurve,
    EcdsaKeyId, MasterPublicKeyId, Method, Payload as Ic00Payload, SchnorrAlgorithm, SchnorrKeyId,
    SchnorrPublicKeyResponse, SignWithBip341Aux, SignWithECDSAReply, SignWithSchnorrAux,
    SignWithSchnorrReply, VetKdCurve, VetKdDeriveKeyResult, VetKdKeyId, VetKdPublicKeyResult,
};
use ic_registry_subnet_type::SubnetType;
use ic_state_machine_tests::{StateMachine, StateMachineBuilder, UserError};
use ic_test_utilities::universal_canister::{UNIVERSAL_CANISTER_WASM, call_args, wasm};
use ic_types::{CanisterId, Cycles, RegistryVersion, SubnetId, ingress::WasmResult};
use ic_types_test_utils::ids::{node_test_id, subnet_test_id};
use itertools::Itertools;
use serde::Deserialize;

fn create_universal_canister(env: &StateMachine) -> CanisterId {
    let canister_id =
        env.create_canister_with_cycles(None, Cycles::from(100_000_000_000_u128), None);
    env.install_wasm_in_mode(
        canister_id,
        CanisterInstallMode::Install,
        UNIVERSAL_CANISTER_WASM.to_vec(),
        vec![],
    )
    .unwrap();
    canister_id
}

fn make_ecdsa_key(name: &str) -> MasterPublicKeyId {
    MasterPublicKeyId::Ecdsa(EcdsaKeyId {
        curve: EcdsaCurve::Secp256k1,
        name: name.to_string(),
    })
}

fn make_ed25519_key(name: &str) -> MasterPublicKeyId {
    MasterPublicKeyId::Schnorr(SchnorrKeyId {
        algorithm: SchnorrAlgorithm::Ed25519,
        name: name.to_string(),
    })
}

fn make_bip340_key(name: &str) -> MasterPublicKeyId {
    MasterPublicKeyId::Schnorr(SchnorrKeyId {
        algorithm: SchnorrAlgorithm::Bip340Secp256k1,
        name: name.to_string(),
    })
}

fn make_vetkd_key(name: &str) -> MasterPublicKeyId {
    MasterPublicKeyId::VetKd(VetKdKeyId {
        curve: VetKdCurve::Bls12_381_G2,
        name: name.to_string(),
    })
}

fn into_inner_ecdsa(key_id: MasterPublicKeyId) -> EcdsaKeyId {
    match key_id {
        MasterPublicKeyId::Ecdsa(key) => key,
        _ => panic!("unexpected key_id type"),
    }
}

fn into_inner_schnorr(key_id: MasterPublicKeyId) -> SchnorrKeyId {
    match key_id {
        MasterPublicKeyId::Schnorr(key) => key,
        _ => panic!("unexpected key_id type"),
    }
}

fn into_inner_vetkd(key_id: MasterPublicKeyId) -> VetKdKeyId {
    match key_id {
        MasterPublicKeyId::VetKd(key) => key,
        _ => panic!("unexpected key_id type"),
    }
}

fn reshare_chain_key_payload(
    method: Method,
    key_id: MasterPublicKeyId,
    subnet_id: SubnetId,
) -> Vec<u8> {
    let nodes = vec![node_test_id(1), node_test_id(2)].into_iter().collect();
    let registry_version = RegistryVersion::from(100);
    match method {
        Method::ReshareChainKey => {
            ic00::ReshareChainKeyArgs::new(key_id, subnet_id, nodes, registry_version).encode()
        }
        _ => panic!("unexpected method"),
    }
}

fn sign_with_threshold_key_payload(method: Method, key_id: MasterPublicKeyId) -> Vec<u8> {
    match method {
        Method::SignWithECDSA => ic00::SignWithECDSAArgs {
            message_hash: [1; 32],
            derivation_path: DerivationPath::new(vec![]),
            key_id: into_inner_ecdsa(key_id),
        }
        .encode(),
        Method::SignWithSchnorr => {
            let key_id = into_inner_schnorr(key_id);

            let aux = match key_id.algorithm {
                SchnorrAlgorithm::Bip340Secp256k1 => {
                    let aux = SignWithBip341Aux {
                        merkle_root_hash: vec![0; 32].into(),
                    };
                    Some(SignWithSchnorrAux::Bip341(aux))
                }
                _ => None,
            };

            ic00::SignWithSchnorrArgs {
                message: vec![],
                derivation_path: DerivationPath::new(vec![]),
                key_id,
                aux,
            }
        }
        .encode(),
        Method::VetKdDeriveKey => {
            let key_id = into_inner_vetkd(key_id);

            ic00::VetKdDeriveKeyArgs {
                context: vec![],
                input: vec![],
                key_id,
                transport_public_key: ic_crypto_test_utils_vetkd::dummy_transport_public_key(),
            }
        }
        .encode(),
        _ => panic!("unexpected method"),
    }
}

fn threshold_public_key_payload(method: Method, key_id: MasterPublicKeyId) -> Vec<u8> {
    match method {
        Method::ECDSAPublicKey => ic00::ECDSAPublicKeyArgs {
            canister_id: None,
            derivation_path: DerivationPath::new(vec![]),
            key_id: into_inner_ecdsa(key_id),
        }
        .encode(),
        Method::SchnorrPublicKey => ic00::SchnorrPublicKeyArgs {
            canister_id: None,
            derivation_path: DerivationPath::new(vec![]),
            key_id: into_inner_schnorr(key_id),
        }
        .encode(),
        Method::VetKdPublicKey => ic00::VetKdPublicKeyArgs {
            canister_id: None,
            context: vec![],
            key_id: into_inner_vetkd(key_id),
        }
        .encode(),
        _ => panic!("unexpected method"),
    }
}

fn execute_threshold_public_key(
    env: &StateMachine,
    canister_id: CanisterId,
    public_key_method: Method,
    key_id: MasterPublicKeyId,
) -> Result<WasmResult, UserError> {
    env.execute_ingress(
        canister_id,
        "update",
        wasm()
            .call_with_cycles(
                ic00::IC_00,
                public_key_method,
                call_args()
                    .other_side(threshold_public_key_payload(public_key_method, key_id))
                    .on_reject(wasm().reject_message().reject()),
                Cycles::from(100_000_000_000u128),
            )
            .build(),
    )
}

fn execute_sign_with_threshold(
    env: &StateMachine,
    canister_id: CanisterId,
    sign_with_method: Method,
    key_id: MasterPublicKeyId,
) -> Result<WasmResult, UserError> {
    env.execute_ingress(
        canister_id,
        "update",
        wasm()
            .call_with_cycles(
                ic00::IC_00,
                sign_with_method,
                call_args()
                    .other_side(sign_with_threshold_key_payload(sign_with_method, key_id))
                    .on_reject(wasm().reject_message().reject()),
                Cycles::from(100_000_000_000u128),
            )
            .build(),
    )
}

pub fn expect_reply<T>(result: Result<WasmResult, UserError>) -> T
where
    T: for<'de> Deserialize<'de> + candid::CandidType,
{
    match result {
        Ok(wasm_result) => match wasm_result {
            WasmResult::Reply(bytes) => Decode!(&bytes, T).unwrap(),
            WasmResult::Reject(msg) => panic!("Unexpected reject: {msg}"),
        },
        Err(err) => panic!("Unexpected error: {err}"),
    }
}

pub fn get_reject_message(result: Result<WasmResult, UserError>) -> String {
    match result {
        Ok(wasm_result) => match wasm_result {
            WasmResult::Reply(bytes) => panic!("Unexpected reply: {bytes:?}"),
            WasmResult::Reject(msg) => msg,
        },
        Err(err) => panic!("Unexpected error: {err}"),
    }
}

macro_rules! expect_contains {
    ($message:expr_2021, $expected:expr_2021) => {
        assert!(
            $message.contains($expected),
            "Expected: {}\nActual: {}",
            $expected,
            $message
        );
    };
}

fn reshare_chain_key_test_cases() -> Vec<(Method, MasterPublicKeyId)> {
    vec![
        (Method::ReshareChainKey, make_ecdsa_key("some_key")),
        (Method::ReshareChainKey, make_ed25519_key("some_key")),
        (Method::ReshareChainKey, make_bip340_key("some_key")),
        (Method::ReshareChainKey, make_vetkd_key("some_key")),
    ]
}

/// Formats a list of keys and returns them in a sorted order.
fn format_keys(keys: Vec<MasterPublicKeyId>) -> String {
    format!(
        "[{}]",
        keys.iter().map(ToString::to_string).sorted().join(", ")
    )
}

#[test]
fn test_reshare_chain_keys_sender_on_nns() {
    for (method, key_id) in reshare_chain_key_test_cases() {
        let nns_subnet = subnet_test_id(1);
        let env = StateMachineBuilder::new()
            .with_checkpoints_enabled(false)
            .with_subnet_id(nns_subnet)
            .with_nns_subnet_id(nns_subnet)
            .with_chain_key(key_id.clone())
            .build();
        let canister_id = create_universal_canister(&env);

        // Expect no dealings contexts before the call.
        assert_eq!(
            env.get_latest_state()
                .metadata
                .subnet_call_context_manager
                .reshare_chain_key_contexts
                .len(),
            0
        );

        // Make the call.
        let _msg_id = env.send_ingress(
            PrincipalId::new_anonymous(),
            canister_id,
            "update",
            wasm()
                .call_simple(
                    ic00::IC_00,
                    method,
                    call_args()
                        .other_side(reshare_chain_key_payload(
                            method,
                            key_id.clone(),
                            nns_subnet,
                        ))
                        .on_reject(wasm().reject_message().reject()),
                )
                .build(),
        );
        env.tick();

        // Expect dealings context added to the context manager after the call.
        assert_eq!(
            env.get_latest_state()
                .metadata
                .subnet_call_context_manager
                .reshare_chain_key_contexts
                .len(),
            1
        );
    }
}

#[test]
fn test_reshare_chain_keys_sender_not_on_nns() {
    for (method, key_id) in reshare_chain_key_test_cases() {
        let own_subnet = subnet_test_id(1);
        let nns_subnet = subnet_test_id(2);
        let env = StateMachineBuilder::new()
            .with_checkpoints_enabled(false)
            .with_subnet_id(own_subnet)
            .with_nns_subnet_id(nns_subnet)
            .with_chain_key(key_id.clone())
            .build();

        let canister_id = create_universal_canister(&env);
        let result = env.execute_ingress(
            canister_id,
            "update",
            wasm()
                .call_simple(
                    ic00::IC_00,
                    method,
                    call_args()
                        .other_side(reshare_chain_key_payload(method, key_id, own_subnet))
                        .on_reject(wasm().reject_message().reject()),
                )
                .build(),
        );

        assert_eq!(
            result,
            Ok(WasmResult::Reject(format!(
                "{method} is called by {canister_id}. It can only be called by NNS."
            ))),
        );
    }
}

#[test]
fn test_reshare_chain_key_with_unknown_key() {
    for (method, unknown_key) in reshare_chain_key_test_cases() {
        let nns_subnet = subnet_test_id(2);
        let env = StateMachineBuilder::new()
            .with_checkpoints_enabled(false)
            .with_subnet_id(nns_subnet)
            .with_nns_subnet_id(nns_subnet)
            .build();

        let canister_id = create_universal_canister(&env);
        let result = env.execute_ingress(
            canister_id,
            "update",
            wasm()
                .call_simple(
                    ic00::IC_00,
                    method,
                    call_args()
                        .other_side(reshare_chain_key_payload(
                            method,
                            unknown_key.clone(),
                            nns_subnet,
                        ))
                        .on_reject(wasm().reject_message().reject()),
                )
                .build(),
        );

        assert_eq!(
            result,
            Ok(WasmResult::Reject(format!(
                "Unable to route management canister request {method}: ChainKeyError(\"Requested unknown threshold key {unknown_key} on subnet {nns_subnet}, subnet has keys: []\")",
            ))),
        );
    }
}

#[test]
fn test_sign_with_threshold_key_fee_charged() {
    let test_cases = vec![
        (
            Method::SignWithECDSA,
            make_ecdsa_key("some_key"),
            1_000_000,
            2_000_000,
        ),
        (
            Method::SignWithSchnorr,
            make_ed25519_key("some_key"),
            1_000_000,
            2_000_000,
        ),
        (
            Method::SignWithSchnorr,
            make_bip340_key("some_key"),
            1_000_000,
            2_000_000,
        ),
        (
            Method::VetKdDeriveKey,
            make_vetkd_key("some_key"),
            1_000_000,
            2_000_000,
        ),
    ];
    for (method, key_id, fee, payment) in test_cases {
        let own_subnet = subnet_test_id(1);
        let nns_subnet = subnet_test_id(2);
        let mut env = StateMachineBuilder::new()
            .with_checkpoints_enabled(false)
            .with_subnet_id(own_subnet)
            .with_nns_subnet_id(nns_subnet)
            .with_ecdsa_signature_fee(fee)
            .with_schnorr_signature_fee(fee)
            .with_vetkd_derive_key_fee(fee)
            .with_chain_key(key_id.clone())
            .build();

        let canister_id = create_universal_canister(&env);
        let msg_id = env.send_ingress(
            PrincipalId::new_anonymous(),
            canister_id,
            "update",
            wasm()
                .call_with_cycles(
                    ic00::IC_00,
                    method,
                    call_args().other_side(sign_with_threshold_key_payload(method, key_id)),
                    Cycles::new(payment),
                )
                .build(),
        );

        // Disable automatic signing to be able to read the request payment value.
        env.set_ecdsa_signing_enabled(false);
        env.set_schnorr_signing_enabled(false);
        env.set_vetkd_enabled(false);
        env.tick();

        // Assert that the request payment is equal to the payment minus the fee.
        let contexts = match method {
            Method::SignWithECDSA => env.sign_with_ecdsa_contexts(),
            Method::SignWithSchnorr => env.sign_with_schnorr_contexts(),
            Method::VetKdDeriveKey => env.vetkd_derive_key_contexts(),
            _ => panic!("Unexpected method"),
        };
        let (_, context) = contexts.iter().next().unwrap();
        assert_eq!(context.request.payment.get(), payment - fee);

        // Enable automatic signing to complete the request.
        env.set_ecdsa_signing_enabled(true);
        env.set_schnorr_signing_enabled(true);
        env.set_vetkd_enabled(true);
        let max_ticks = 100;
        let result = env.await_ingress(msg_id, max_ticks);
        let signature = match method {
            Method::SignWithECDSA => expect_reply::<SignWithECDSAReply>(result).signature,
            Method::SignWithSchnorr => expect_reply::<SignWithSchnorrReply>(result).signature,
            Method::VetKdDeriveKey => expect_reply::<VetKdDeriveKeyResult>(result).encrypted_key,
            _ => panic!("Unexpected method"),
        };
        // Expect non-empty signature.
        assert!(!signature.is_empty());
    }
}

#[test]
fn test_sign_with_threshold_key_rejected_without_fee() {
    let test_cases = vec![
        (Method::SignWithECDSA, make_ecdsa_key("some_key"), 2_000_000),
        (
            Method::SignWithSchnorr,
            make_ed25519_key("some_key"),
            2_000_000,
        ),
        (
            Method::SignWithSchnorr,
            make_bip340_key("some_key"),
            2_000_000,
        ),
        (
            Method::VetKdDeriveKey,
            make_vetkd_key("some_key"),
            2_000_000,
        ),
    ];
    for (method, key_id, fee) in test_cases {
        let own_subnet = subnet_test_id(1);
        let nns_subnet = subnet_test_id(2);
        let env = StateMachineBuilder::new()
            .with_checkpoints_enabled(false)
            .with_subnet_id(own_subnet)
            .with_nns_subnet_id(nns_subnet)
            .with_ecdsa_signature_fee(fee)
            .with_schnorr_signature_fee(fee)
            .with_vetkd_derive_key_fee(fee)
            .with_chain_key(key_id.clone())
            .build();

        let canister_id = create_universal_canister(&env);
        let result = env.execute_ingress(
            canister_id,
            "update",
            wasm()
                .call_with_cycles(
                    ic00::IC_00,
                    method,
                    call_args()
                        .other_side(sign_with_threshold_key_payload(method, key_id))
                        .on_reject(wasm().reject_message().reject()),
                    Cycles::new(fee - 1),
                )
                .build(),
        );

        assert_eq!(
            result,
            Ok(WasmResult::Reject(format!(
                "{method} request sent with 1_999_999 cycles, but 2_000_000 cycles are required."
            )))
        );
    }
}

#[test]
fn test_sign_with_threshold_key_unknown_key_rejected() {
    let test_cases = vec![
        (
            Method::SignWithECDSA,
            make_ecdsa_key("correct_key"),
            make_ecdsa_key("wrong_key"),
        ),
        (
            Method::SignWithSchnorr,
            make_ed25519_key("correct_key"),
            make_ed25519_key("wrong_key"),
        ),
        (
            Method::SignWithSchnorr,
            make_bip340_key("correct_key"),
            make_bip340_key("wrong_key"),
        ),
        (
            Method::VetKdDeriveKey,
            make_vetkd_key("correct_key"),
            make_vetkd_key("wrong_key"),
        ),
    ];
    for (method, correct_key, wrong_key) in test_cases {
        let own_subnet = subnet_test_id(1);
        let nns_subnet = subnet_test_id(2);
        let env = StateMachineBuilder::new()
            .with_checkpoints_enabled(false)
            .with_subnet_id(own_subnet)
            .with_nns_subnet_id(nns_subnet)
            .with_chain_key(correct_key.clone())
            .build();

        let canister_id = create_universal_canister(&env);
        let result = execute_sign_with_threshold(&env, canister_id, method, wrong_key.clone());

        assert_eq!(
            result,
            Ok(WasmResult::Reject(format!(
                "Unable to route management canister request {}: ChainKeyError(\"Requested unknown or disabled threshold key: {}, existing enabled keys: {}\")",
                method,
                wrong_key,
                format_keys(vec![correct_key]),
            )))
        );
    }
}

#[test]
fn test_schnorr_sign_with_invalid_aux_field_rejected() {
    let test_cases = vec![
        (make_bip340_key("bip340_key"), 8),
        (make_bip340_key("bip340_key"), 100),
        (make_ed25519_key("ed25519_key"), 0),
        (make_ed25519_key("ed25519_key"), 32),
    ];

    let method = Method::SignWithSchnorr;

    for (key, aux_len) in test_cases {
        let own_subnet = subnet_test_id(1);
        let nns_subnet = subnet_test_id(2);
        let env = StateMachineBuilder::new()
            .with_checkpoints_enabled(false)
            .with_subnet_id(own_subnet)
            .with_nns_subnet_id(nns_subnet)
            .with_chain_key(key.clone())
            .build();

        let canister_id = create_universal_canister(&env);

        let sign_with_schnorr_args = {
            let aux = SignWithSchnorrAux::Bip341(SignWithBip341Aux {
                merkle_root_hash: vec![0; aux_len].into(),
            });

            ic00::SignWithSchnorrArgs {
                message: vec![],
                derivation_path: DerivationPath::new(vec![]),
                key_id: into_inner_schnorr(key.clone()),
                aux: Some(aux),
            }
        };

        let result = env.execute_ingress(
            canister_id,
            "update",
            wasm()
                .call_with_cycles(
                    ic00::IC_00,
                    method,
                    call_args()
                        .other_side(sign_with_schnorr_args.encode())
                        .on_reject(wasm().reject_message().reject()),
                    Cycles::from(100_000_000_000u128),
                )
                .build(),
        );

        let expected_reason = match key {
            MasterPublicKeyId::Schnorr(kid) => match kid.algorithm {
                SchnorrAlgorithm::Bip340Secp256k1 => "Invalid aux field for Bip340Secp256k1",
                SchnorrAlgorithm::Ed25519 => "Schnorr algorithm Ed25519 does not support aux input",
            },
            _ => panic!("Unexpected master key type for this test"),
        };

        assert_eq!(result, Ok(WasmResult::Reject(expected_reason.to_string())));
    }
}

#[test]
fn test_signing_disabled_vs_unknown_key_on_public_key_and_signing_requests() {
    // Test the disabled key succeeds for public key request but fails for signing,
    // and the unknown key fails for both.
    let test_cases = vec![
        (
            Method::ECDSAPublicKey,
            Method::SignWithECDSA,
            make_ecdsa_key("signing_disabled_key"),
            make_ecdsa_key("unknown_key"),
        ),
        (
            Method::SchnorrPublicKey,
            Method::SignWithSchnorr,
            make_ed25519_key("signing_disabled_key"),
            make_ed25519_key("unknown_key"),
        ),
        (
            Method::SchnorrPublicKey,
            Method::SignWithSchnorr,
            make_bip340_key("signing_disabled_key"),
            make_bip340_key("unknown_key"),
        ),
        (
            Method::VetKdPublicKey,
            Method::VetKdDeriveKey,
            make_vetkd_key("signing_disabled_key"),
            make_vetkd_key("unknown_key"),
        ),
    ];
    for (public_key_method, sign_with_method, signing_disabled_key, unknown_key) in test_cases {
        let own_subnet = subnet_test_id(1);
        let nns_subnet = subnet_test_id(2);
        let env = StateMachineBuilder::new()
            .with_checkpoints_enabled(false)
            .with_subnet_type(SubnetType::System)
            .with_subnet_id(own_subnet)
            .with_nns_subnet_id(nns_subnet)
            .with_disabled_chain_key(signing_disabled_key.clone())
            .build();

        let canister_id = create_universal_canister(&env);

        // Requesting disabled public key (should succeed).
        let result = execute_threshold_public_key(
            &env,
            canister_id,
            public_key_method,
            signing_disabled_key.clone(),
        );
        match public_key_method {
            Method::ECDSAPublicKey => {
                let response = expect_reply::<ECDSAPublicKeyResponse>(result);
                assert!(!response.public_key.is_empty() && !response.chain_code.is_empty());
            }
            Method::SchnorrPublicKey => {
                let response = expect_reply::<SchnorrPublicKeyResponse>(result);
                assert!(!response.public_key.is_empty() && !response.chain_code.is_empty());
            }
            Method::VetKdPublicKey => {
                let response = expect_reply::<VetKdPublicKeyResult>(result);
                assert!(!response.public_key.is_empty());
            }
            _ => panic!("Unexpected method"),
        }

        // Signing with disabled key (should fail).
        expect_contains!(
            get_reject_message(execute_sign_with_threshold(
                &env,
                canister_id,
                sign_with_method,
                signing_disabled_key.clone(),
            )),
            "Requested unknown or disabled threshold key"
        );

        // Requesting non-existent public key (should fail).
        expect_contains!(
            get_reject_message(execute_threshold_public_key(
                &env,
                canister_id,
                public_key_method,
                unknown_key.clone(),
            )),
            "Requested unknown threshold key"
        );

        // Signing with non-existent key (should fail).
        expect_contains!(
            get_reject_message(execute_sign_with_threshold(
                &env,
                canister_id,
                sign_with_method,
                unknown_key.clone(),
            )),
            "Requested unknown or disabled threshold key"
        );
    }
}

#[test]
fn test_threshold_key_public_key_req_with_unknown_key_rejected() {
    let test_cases = vec![
        (
            Method::ECDSAPublicKey,
            make_ecdsa_key("correct_key"),
            make_ecdsa_key("wrong_key"),
        ),
        (
            Method::SchnorrPublicKey,
            make_ed25519_key("correct_key"),
            make_ed25519_key("wrong_key"),
        ),
        (
            Method::SchnorrPublicKey,
            make_bip340_key("correct_key"),
            make_bip340_key("wrong_key"),
        ),
        (
            Method::VetKdPublicKey,
            make_vetkd_key("correct_key"),
            make_vetkd_key("wrong_key"),
        ),
    ];
    for (method, correct_key, wrong_key) in test_cases {
        let own_subnet = subnet_test_id(1);
        let nns_subnet = subnet_test_id(2);
        let env = StateMachineBuilder::new()
            .with_checkpoints_enabled(false)
            .with_subnet_id(own_subnet)
            .with_nns_subnet_id(nns_subnet)
            .with_chain_key(correct_key.clone())
            .build();

        let canister_id = create_universal_canister(&env);
        let result = execute_threshold_public_key(&env, canister_id, method, wrong_key.clone());

        assert_eq!(
            result,
            Ok(WasmResult::Reject(format!(
                "Unable to route management canister request {}: ChainKeyError(\"Requested unknown threshold key: {}, existing keys: {}\")",
                method,
                wrong_key,
                format_keys(vec![correct_key]),
            )))
        );
    }
}

#[test]
fn test_sign_with_threshold_key_fee_ignored_for_nns() {
    let test_cases = vec![
        (Method::SignWithECDSA, make_ecdsa_key("some_key")),
        (Method::SignWithSchnorr, make_ed25519_key("some_key")),
        (Method::SignWithSchnorr, make_bip340_key("some_key")),
        (Method::VetKdDeriveKey, make_vetkd_key("some_key")),
    ];
    for (method, key_id) in test_cases {
        let fee = 1_000_000;
        let nns_subnet = subnet_test_id(1);
        let env = StateMachineBuilder::new()
            .with_checkpoints_enabled(false)
            .with_subnet_type(SubnetType::System)
            .with_subnet_id(nns_subnet)
            .with_nns_subnet_id(nns_subnet)
            .with_ecdsa_signature_fee(fee)
            .with_schnorr_signature_fee(fee)
            .with_vetkd_derive_key_fee(fee)
            .with_chain_key(key_id.clone())
            .build();

        let canister_id = create_universal_canister(&env);
        let _msg_id = env.send_ingress(
            PrincipalId::new_anonymous(),
            canister_id,
            "update",
            wasm()
                .call_simple(
                    ic00::IC_00,
                    method,
                    call_args()
                        .other_side(sign_with_threshold_key_payload(method, key_id))
                        .on_reject(wasm().reject_message().reject()),
                )
                .build(),
        );

        env.tick();

        // Assert that the request payment is zero.
        let contexts = match method {
            Method::SignWithECDSA => env.sign_with_ecdsa_contexts(),
            Method::SignWithSchnorr => env.sign_with_schnorr_contexts(),
            Method::VetKdDeriveKey => env.vetkd_derive_key_contexts(),
            _ => panic!("Unexpected method"),
        };
        let (_, context) = contexts.iter().next().unwrap();
        assert_eq!(context.request.payment, Cycles::zero());
    }
}

#[test]
fn test_sign_with_threshold_key_queue_fills_up() {
    let test_cases = vec![
        (Method::SignWithECDSA, make_ecdsa_key("some_key"), 20),
        (Method::SignWithSchnorr, make_ed25519_key("some_key"), 20),
        (Method::SignWithSchnorr, make_bip340_key("some_key"), 20),
        (Method::VetKdDeriveKey, make_vetkd_key("some_key"), 20),
    ];
    for (method, key_id, max_queue_size) in test_cases {
        let fee = 1_000_000;
        let payment = 2_000_000u128;
        let own_subnet = subnet_test_id(1);
        let nns_subnet = subnet_test_id(2);
        let env = StateMachineBuilder::new()
            .with_checkpoints_enabled(false)
            .with_subnet_type(SubnetType::System)
            .with_subnet_id(own_subnet)
            .with_nns_subnet_id(nns_subnet)
            .with_ecdsa_signature_fee(fee)
            .with_schnorr_signature_fee(fee)
            .with_vetkd_derive_key_fee(fee)
            .with_chain_key(key_id.clone())
            // Turn off automatic ECDSA signatures to fill up the queue.
            .with_ecdsa_signing_enabled(false)
            // Turn off automatic Schnorr signatures to fill up the queue.
            .with_schnorr_signing_enabled(false)
            // Turn off automatic VetKey derivation to fill up the queue.
            .with_vetkd_enabled(false)
            .build();

        let canister_id = create_universal_canister(&env);
        let payload = wasm()
            .call_with_cycles(
                ic00::IC_00,
                method,
                call_args()
                    .other_side(sign_with_threshold_key_payload(method, key_id.clone()))
                    .on_reject(wasm().reject_message().reject()),
                Cycles::from(payment),
            )
            .build();
        for _i in 0..max_queue_size {
            let _msg_id = env.send_ingress(
                PrincipalId::new_anonymous(),
                canister_id,
                "update",
                payload.clone(),
            );
        }
        let result = env.execute_ingress(canister_id, "update", payload.clone());

        assert_eq!(
            result,
            Ok(WasmResult::Reject(format!(
                "{method} request failed: request queue for key {key_id} is full.",
            )))
        );
    }
}
