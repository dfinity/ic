//! Module that deals with requests to /api/{v2,v3}/canister/.../read_state and /api/{v2,v3}/subnet/.../read_state

use crate::{
    HttpError,
    common::{Cbor, into_cbor},
};
use axum::response::IntoResponse;
use hyper::StatusCode;
use ic_crypto_tree_hash::{
    Label, MatchPattern, Path, TooLongPathError, sparse_labeled_tree_from_paths,
};
use ic_interfaces_state_manager::CertifiedStateSnapshot;
use ic_replicated_state::ReplicatedState;
use ic_types::{
    PrincipalId, SubnetId,
    messages::{Blob, Certificate, CertificateDelegation, HttpReadStateResponse},
};

pub mod canister;
pub mod subnet;

fn parse_principal_id(principal_id: &[u8]) -> Result<PrincipalId, HttpError> {
    match PrincipalId::try_from(principal_id) {
        Ok(principal_id) => Ok(principal_id),
        Err(err) => Err(HttpError {
            status: StatusCode::BAD_REQUEST,
            message: format!("Could not parse principal ID: {err}."),
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
                "Effective principal id in URL {effective_principal_id} does \
                not match requested principal id: {principal_id}."
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

/// Used to instruct the state reader to perhaps filter out the deprecated canister ranges paths
/// from the state tree.
enum DeprecatedCanisterRangesFilter {
    /// Will keep all paths of the form `/subnet/<subnet_id>/canister_ranges` for all subnet ids.
    KeepAll,
    /// Will prune all paths of the form `/subnet/<subnet_id>/canister_ranges` for all subnet ids
    /// except for the provided NNS subnet id.
    KeepOnlyNNS(SubnetId),
}

fn get_certificate_and_create_response(
    mut paths: Vec<Path>,
    delegation_from_nns: Option<CertificateDelegation>,
    certified_state_reader: &dyn CertifiedStateSnapshot<State = ReplicatedState>,
    deprecated_canister_ranges_filter: DeprecatedCanisterRangesFilter,
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

    let exclusion_rule = match deprecated_canister_ranges_filter {
        DeprecatedCanisterRangesFilter::KeepAll => None,
        DeprecatedCanisterRangesFilter::KeepOnlyNNS(nns_subnet_id) => {
            let deprecated_canister_ranges_except_the_nns_subnet_id_pattern = vec![
                MatchPattern::Inclusive(Label::from("subnet")),
                MatchPattern::Exclusive(Label::from(nns_subnet_id.get_ref())),
                MatchPattern::Inclusive(Label::from("canister_ranges")),
            ];

            Some(deprecated_canister_ranges_except_the_nns_subnet_id_pattern)
        }
    };

    let Some((tree, certification)) = certified_state_reader
        .read_certified_state_with_exclusion(&labeled_tree, exclusion_rule.as_ref())
    else {
        return make_service_unavailable_response();
    };

    let signature = certification.signed.signature.signature.get().0;

    Cbor(HttpReadStateResponse {
        certificate: Blob(into_cbor(&Certificate {
            tree,
            signature: Blob(signature),
            delegation: delegation_from_nns,
        })),
    })
    .into_response()
}

#[cfg(test)]
mod test {
    use ic_crypto_tree_hash::{LabeledTree, MatchPatternPath, MixedHashTree};
    use ic_test_utilities_consensus::fake::Fake;
    use ic_types::{SubnetId, consensus::certification::Certification};

    use super::*;

    const NNS_SUBNET_ID: SubnetId = ic_test_utilities_types::ids::SUBNET_0;

    struct FakeCertifiedStateReader {
        expects_exclusion: bool,
    }

    impl CertifiedStateSnapshot for FakeCertifiedStateReader {
        type State = ReplicatedState;

        fn get_state(&self) -> &Self::State {
            unimplemented!("Not expected to be called")
        }

        fn get_height(&self) -> ic_types::Height {
            unimplemented!("Not expected to be called")
        }

        fn read_certified_state(
            &self,
            _paths: &LabeledTree<()>,
        ) -> Option<(MixedHashTree, Certification)> {
            unimplemented!("Not expected to be called")
        }

        fn read_certified_state_with_exclusion(
            &self,
            _paths: &LabeledTree<()>,
            exclusion: Option<&MatchPatternPath>,
        ) -> Option<(MixedHashTree, Certification)> {
            assert!(exclusion.is_some() == self.expects_exclusion);

            Some((MixedHashTree::Empty, Certification::fake()))
        }
    }

    #[test]
    fn test_does_not_request_to_exclude_paths_from_the_state_tree() {
        let reader = FakeCertifiedStateReader {
            expects_exclusion: false,
        };

        let response = get_certificate_and_create_response(
            Vec::new(),
            /*delegation_from_nns=*/ None,
            &reader,
            DeprecatedCanisterRangesFilter::KeepAll,
        );

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[test]
    fn test_requests_to_exclude_paths_from_the_state_tree() {
        let reader = FakeCertifiedStateReader {
            expects_exclusion: true,
        };

        let response = get_certificate_and_create_response(
            Vec::new(),
            /*delegation_from_nns=*/ None,
            &reader,
            DeprecatedCanisterRangesFilter::KeepOnlyNNS(NNS_SUBNET_ID),
        );

        assert_eq!(response.status(), StatusCode::OK);
    }
}
