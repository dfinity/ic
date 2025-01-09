use anyhow::{bail, Context, Result};
use attestation::protocol::{
    GenerateAttestationTokenError, GenerateAttestationTokenRequest,
    GenerateAttestationTokenResponse,
};
use attestation::verify::verify_generate_attestation_token_request;
use attestation_token::{AttestationToken, AttestationTokenPayload};
use candid::{export_service, CandidType, Principal};
use ic_cbor::CertificateToCbor;
use ic_cdk::{init, post_upgrade, query, update};
use ic_certification::{
    fork, labeled, leaf, pruned, AsHashTree, Certificate, Hash, HashTree, HashTreeNode,
    LookupResult, RbTree,
};
use serde::Deserialize;
use std::cell::RefCell;
use std::ops::Add;
use std::str::FromStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const ATTESTATION_TOKEN_DEFAULT_EXPIRATION: Duration = Duration::from_secs(90 * 24 * 3600);

thread_local! {
    static ATTESTION_TOKENS: RefCell<RbTree<Principal, Vec<u8>>> = RefCell::new(RbTree::new());
    // static INITIATION: RefCell<RbTree<Principal, AttestationTokenPayload>> = RefCell::new(RbTree::new());
}

// #[post_upgrade]
// fn on_init() {
//     ATTESTION_TOKENS.with_borrow_mut(|attestation_tokens| {
//         attestation_tokens.insert(
//             Principal::management_canister(),
//             AttestationTokenPayload {
//                 tls_public_key: vec![],
//                 issued_epoch_sec: 0,
//                 expires_epoch_sec: 0,
//             },
//         );
//
//         let root = labeled("attestation_tokens", pruned(attestation_tokens.root_hash()));
//         ic_cdk::api::set_certified_data(&root.digest());
//     });
// }

#[update]
fn generate_attestation_token(
    request: GenerateAttestationTokenRequest,
) -> Result<GenerateAttestationTokenResponse, GenerateAttestationTokenError> {
    verify_generate_attestation_token_request(&request, &[])?;

    let node_id = ic_cdk::caller();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Now should be later than epoch");
    ATTESTION_TOKENS.with_borrow_mut(
        |attestation_tokens| -> Result<(), GenerateAttestationTokenError> {
            let serialized_payload = serde_cbor::to_vec(&AttestationTokenPayload {
                tls_public_key: request.tls_public_key,
                issued_epoch_sec: now.as_secs(),
                expires_epoch_sec: now.add(ATTESTATION_TOKEN_DEFAULT_EXPIRATION).as_secs(),
                node_id: node_id,
            })
            .map_err(|err| GenerateAttestationTokenError::Internal(err.to_string()))?;

            attestation_tokens.insert(node_id, serialized_payload);

            let root = build_complex_hash_tree(pruned(attestation_tokens.root_hash()));
            ic_cdk::api::set_certified_data(&root.digest());
            Ok(())
        },
    )?;

    Ok(GenerateAttestationTokenResponse {})
}

#[derive(CandidType)]
struct AttestationTokenNotFound;

#[derive(CandidType)]
struct AttestationTokenResponse {
    attestation_token: Result<Vec<u8>, AttestationTokenNotFound>,
}

#[derive(Deserialize, CandidType)]
struct AttestationTokenRequest {}

#[query]
fn get_attestation_token(_request: AttestationTokenRequest) -> AttestationTokenResponse {
    let node_id = ic_cdk::caller();
    ATTESTION_TOKENS.with_borrow(|attestation_tokens| {
        let attestation_token = AttestationToken {
            node_id,
            hash_tree: build_complex_hash_tree(
                attestation_tokens.witness(ic_cdk::caller().as_slice()),
            ),
            certificate: Certificate::from_cbor(
                &ic_cdk::api::data_certificate().expect("Missing data certificate"),
            )
            .expect("Deserialization failed"),
        };

        let attestation_token = if attestation_tokens.get(node_id.as_slice()).is_some() {
            Ok(serde_cbor::to_vec(&attestation_token).expect("Serialization failed"))
        } else {
            Err(AttestationTokenNotFound)
        };

        AttestationTokenResponse { attestation_token }
    })
}

fn build_complex_hash_tree(attestation_tokens: HashTree) -> HashTree {
    labeled("attestation_tokens", attestation_tokens)
}
