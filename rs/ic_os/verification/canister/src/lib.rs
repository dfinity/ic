use anyhow::{bail, Context, Result};
use attestation_token::{AttestationToken, AttestationTokenPayload};
use candid::{CandidType, Principal};
use ic_cbor::CertificateToCbor;
use ic_cdk::{post_upgrade, query, update};
use ic_certification::{AsHashTree, Certificate, RbTree};
use serde::Deserialize;
use std::cell::RefCell;
use std::str::FromStr;

thread_local! {
    static ATTESTION_TOKENS: RefCell<RbTree<Principal, AttestationTokenPayload>> = RefCell::new(RbTree::new());
    // static INITIATION: RefCell<RbTree<Principal, AttestationTokenPayload>> = RefCell::new(RbTree::new());
}

#[post_upgrade]
fn on_post_upgrade() {
    ATTESTION_TOKENS.with_borrow_mut(|attestation_tokens| {
        attestation_tokens.insert(
            Principal::management_canister(),
            AttestationTokenPayload {
                tls_public_key: vec![],
                issued_epoch_sec: 0,
                expires_epoch_sec: 0,
            },
        );
        ic_cdk::api::set_certified_data(&attestation_tokens.root_hash());
    });
}

// #[update]
// fn initiate_attestation_token(node_id: &Principal) -> Result<AttestationToken> {
//
// }

#[derive(CandidType)]
struct AttestationTokenNotFound;

#[derive(CandidType)]
struct AttestationTokenResponse {
    attestation_token: Result<Vec<u8>, AttestationTokenNotFound>,
}

#[derive(Deserialize, CandidType)]
struct AttestationTokenRequest {
    node_id: Principal,
}

#[query]
fn attestation_token(request: AttestationTokenRequest) -> AttestationTokenResponse {
    let node_id = &request.node_id;
    ATTESTION_TOKENS.with_borrow(|attestation_tokens| {
        let attestation_token = if attestation_tokens.get(node_id.as_slice()).is_some() {
            Ok(serde_cbor::to_vec(&AttestationToken {
                hash_tree: attestation_tokens.witness(node_id.as_slice()),
                certificate: Certificate::from_cbor(
                    &ic_cdk::api::data_certificate().expect("Missing data certificate"),
                )
                .expect("Derialization failed"),
            })
            .expect("Serialization failed"))
        } else {
            Err(AttestationTokenNotFound)
        };

        AttestationTokenResponse { attestation_token }
    })
}
