//! Module that deals with requests to /api/{v2,v3}/canister/.../read_state and /api/{v2,v3}/subnet/.../read_state

use crate::{
    common::{into_cbor, Cbor},
    HttpError,
};
use axum::response::IntoResponse;
use hyper::StatusCode;
use ic_crypto_tree_hash::{sparse_labeled_tree_from_paths, Label, Path, TooLongPathError};
use ic_interfaces_state_manager::CertifiedStateSnapshot;
use ic_replicated_state::ReplicatedState;
use ic_types::{
    messages::{Blob, Certificate, CertificateDelegation, HttpReadStateResponse},
    PrincipalId,
};

pub mod canister;
pub mod subnet;

fn parse_principal_id(principal_id: &[u8]) -> Result<PrincipalId, HttpError> {
    match PrincipalId::try_from(principal_id) {
        Ok(principal_id) => Ok(principal_id),
        Err(err) => Err(HttpError {
            status: StatusCode::BAD_REQUEST,
            message: format!("Could not parse principal ID: {}.", err),
        }),
    }
}

fn verify_principal_ids(
    principal_id: &PrincipalId,
    effective_principal_id: &PrincipalId,
) -> Result<(), HttpError> {
    if principal_id != effective_principal_id {
        return Err(HttpError {
            status: StatusCode::BAD_REQUEST,
            message: format!(
                "Effective principal id in URL {} does not match requested principal id: {}.",
                effective_principal_id, principal_id
            ),
        });
    }
    Ok(())
}

fn make_service_unavailable_response() -> axum::response::Response {
    let status = StatusCode::SERVICE_UNAVAILABLE;
    let text = "Certified state is not available yet. Please try again...".to_string();
    (status, text).into_response()
}

fn get_certificate_and_create_response(
    mut paths: Vec<Path>,
    delegation_from_nns: Option<CertificateDelegation>,
    certified_state_reader: &dyn CertifiedStateSnapshot<State = ReplicatedState>,
) -> axum::response::Response {
    // Create labeled tree. This may be an expensive operation and by
    // creating the labeled tree after verifying the paths we know that
    // the depth is max 4.
    // Always add "time" to the paths even if not explicitly requested.
    paths.push(Path::from(Label::from("time")));
    let labeled_tree = match sparse_labeled_tree_from_paths(&paths) {
        Ok(tree) => tree,
        Err(TooLongPathError) => {
            let status = StatusCode::BAD_REQUEST;
            let text = "Failed to parse requested paths: path is too long.".to_string();
            return (status, text).into_response();
        }
    };

    let Some((tree, certification)) = certified_state_reader.read_certified_state(&labeled_tree)
    else {
        return make_service_unavailable_response();
    };

    let signature = certification.signed.signature.signature.get().0;

    let res = HttpReadStateResponse {
        certificate: Blob(into_cbor(&Certificate {
            tree,
            signature: Blob(signature),
            delegation: delegation_from_nns,
        })),
    };
    Cbor(res).into_response()
}

#[cfg(test)]
mod test {
    use ic_crypto_tree_hash::{LabeledTree, MixedHashTree};
    use ic_test_utilities_consensus::fake::Fake;
    use ic_types::{
        consensus::certification::{Certification, CertificationContent},
        crypto::{CryptoHash, Signed},
        signature::ThresholdSignature,
        CryptoHashOfPartialState, Height,
    };

    use super::*;

    struct FakeCertifiedStateReader {
        tree: MixedHashTree,
        certification: Certification,
    }

    impl CertifiedStateSnapshot for FakeCertifiedStateReader {
        type State = ReplicatedState;

        fn get_state(&self) -> &Self::State {
            unimplemented!()
        }

        fn get_height(&self) -> ic_types::Height {
            unimplemented!()
        }

        fn read_certified_state(
            &self,
            _paths: &LabeledTree<()>,
        ) -> Option<(MixedHashTree, Certification)> {
            Some((self.tree.clone(), self.certification.clone()))
        }
    }

    #[test]
    fn test() {
        let tree = MixedHashTree::Empty;
        let certification = Certification {
            height: Height::new(0),
            signed: Signed {
                content: CertificationContent::new(CryptoHashOfPartialState::from(CryptoHash(
                    vec![],
                ))),
                signature: ThresholdSignature::fake(),
            },
        };
        let reader = FakeCertifiedStateReader {
            tree,
            certification,
        };
        let response = get_certificate_and_create_response(Vec::new(), None, &reader);
        assert_eq!(response.status(), StatusCode::OK);
    }
}
