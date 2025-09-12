//! Module that deals with requests to /api/{v2,v3}/canister/.../read_state and /api/{v2,v3}/subnet/.../read_state

use crate::{
    common::{into_cbor, Cbor},
    HttpError,
};
use axum::response::IntoResponse;
use hyper::StatusCode;
use ic_crypto_tree_hash::{
    lookup_path, sparse_labeled_tree_from_paths, Label, LabeledTree, Path, TooLongPathError,
};
use ic_interfaces_state_manager::CertifiedStateSnapshot;
use ic_logger::{error, ReplicaLogger};
use ic_replicated_state::ReplicatedState;
use ic_types::{
    messages::{Blob, Certificate, CertificateDelegation, HttpReadStateResponse},
    PrincipalId, SubnetId,
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

enum DeprecatedCanisterRangesFilter {
    KeepAll,
    KeepOnly(SubnetId),
}

fn get_certificate_and_create_response(
    mut paths: Vec<Path>,
    delegation_from_nns: Option<CertificateDelegation>,
    certified_state_reader: &dyn CertifiedStateSnapshot<State = ReplicatedState>,
    // if `Some(root_subnet_id)`, we will prune the paths `/subnet/<subnet_id>/canister_ranges` for all
    // subnet ids except the `root_subnet_id`.
    deprecated_canister_ranges_filter: DeprecatedCanisterRangesFilter,
    logger: &ReplicaLogger,
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

    // A function which tries to prune the deprecated canister ranges from the tree.
    // If it encounters any error, it logs it and returns the *original* tree.
    let maybe_prune_tree = || {
        let subnet_id_filter = match deprecated_canister_ranges_filter {
            DeprecatedCanisterRangesFilter::KeepAll => return tree,
            DeprecatedCanisterRangesFilter::KeepOnly(subnet_id) => subnet_id,
        };

        let labeled_tree = match LabeledTree::try_from(tree.clone()) {
            Ok(tree) => tree,
            Err(err) => {
                error!(
                    logger,
                    "Failed to create LabeledTree from MixedHashTree: {err:?}"
                );
                return tree;
            }
        };

        let paths_to_prune = match lookup_path(&labeled_tree, &[b"subnet"]) {
            Some(LabeledTree::SubTree(subtree)) => subtree
                .keys()
                .iter()
                .filter(|subnet_id| {
                    Label::from(subnet_id_filter.as_ref().as_slice()) != **subnet_id
                })
                .map(|subnet_id| {
                    Path::new(vec![
                        b"subnet".into(),
                        subnet_id.clone(),
                        b"canister_ranges".into(),
                    ])
                })
                .collect(),
            Some(LabeledTree::Leaf(_)) => vec![],
            None => vec![],
        };

        if paths_to_prune.is_empty() {
            return tree;
        }

        let filter = match sparse_labeled_tree_from_paths(&paths_to_prune) {
            Ok(filter) => filter,
            Err(err) => {
                error!(logger, "Failed to create LabeledTree from paths: {err:?}");
                return tree;
            }
        };

        match tree.filter_builder().pruned(&filter) {
            Ok(pruned_tree) => pruned_tree,
            Err(err) => {
                error!(logger, "Failed to filter the tree: {err:?}");
                tree
            }
        }
    };

    let pruned_tree = maybe_prune_tree();

    let signature = certification.signed.signature.signature.get().0;

    Cbor(HttpReadStateResponse {
        certificate: Blob(into_cbor(&Certificate {
            tree: pruned_tree,
            signature: Blob(signature),
            delegation: delegation_from_nns,
        })),
    })
    .into_response()
}

#[cfg(test)]
mod test {
    use axum::body::to_bytes;
    use ic_certification_test_utils::{
        create_certificate_labeled_tree, generate_root_of_trust, CertificateBuilder,
        CertificateData,
    };
    use ic_crypto_tree_hash::{LabeledTree, MixedHashTree};
    use ic_logger::no_op_logger;
    use ic_test_utilities_consensus::fake::Fake;
    use ic_test_utilities_types::ids::{SUBNET_0, SUBNET_1};
    use ic_types::{
        consensus::certification::{Certification, CertificationContent},
        crypto::{CryptoHash, Signed},
        signature::ThresholdSignature,
        CanisterId, CryptoHashOfPartialState, Height, SubnetId,
    };
    use rand::thread_rng;

    use super::*;

    const NNS_SUBNET_ID: SubnetId = SUBNET_0;
    const APP_SUBNET_ID: SubnetId = SUBNET_1;

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

    fn set_up_state_reader(subnet_id: SubnetId) -> FakeCertifiedStateReader {
        let certification = Certification {
            height: Height::new(0),
            signed: Signed {
                content: CertificationContent::new(CryptoHashOfPartialState::from(CryptoHash(
                    vec![],
                ))),
                signature: ThresholdSignature::fake(),
            },
        };

        FakeCertifiedStateReader {
            tree: fake_certificate(
                subnet_id,
                &vec![(CanisterId::from(0), CanisterId::from(10))],
                /*with_flat_canister_ranges=*/ true,
            )
            .tree(),
            certification,
        }
    }

    async fn parse_response(response: axum::response::Response) -> LabeledTree<Vec<u8>> {
        let response_bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let response: HttpReadStateResponse = serde_cbor::from_slice(&response_bytes).unwrap();
        let certificate: Certificate = serde_cbor::from_slice(&response.certificate).unwrap();
        LabeledTree::try_from(certificate.tree).unwrap()
    }

    #[tokio::test]
    async fn test_does_not_purge_when_requested_to_keep_all_deprecated_canister_ranges() {
        let reader = set_up_state_reader(APP_SUBNET_ID);

        let response = get_certificate_and_create_response(
            Vec::new(),
            /*delegation_from_nns=*/ None,
            &reader,
            DeprecatedCanisterRangesFilter::KeepAll,
            &no_op_logger(),
        );

        assert_eq!(response.status(), StatusCode::OK);
        let labeled_tree = parse_response(response).await;
        assert!(
            lookup_path(
                &labeled_tree,
                &[
                    b"subnet",
                    APP_SUBNET_ID.get_ref().as_ref(),
                    b"canister_ranges",
                ],
            )
            .is_some(),
            "/subnet/subnet_id/canister_ranges path should not have been purged from the certificate"
        );
    }

    #[tokio::test]
    async fn test_purges_when_requested_to_purge_deprecated_canister_ranges_except_for_the_given_subnet_id(
    ) {
        let reader = set_up_state_reader(APP_SUBNET_ID);

        let response = get_certificate_and_create_response(
            Vec::new(),
            /*delegation_from_nns=*/ None,
            &reader,
            DeprecatedCanisterRangesFilter::KeepOnly(APP_SUBNET_ID),
            &no_op_logger(),
        );

        assert_eq!(response.status(), StatusCode::OK);
        let labeled_tree = parse_response(response).await;
        assert!(
            lookup_path(
                &labeled_tree,
                &[
                    b"subnet",
                    APP_SUBNET_ID.get_ref().as_ref(),
                    b"canister_ranges",
                ],
            )
            .is_some(),
            "/subnet/subnet_id/canister_ranges path should not have been purged from the certificate"
        );
    }

    #[tokio::test]
    async fn test_does_purge_when_requested() {
        let reader = set_up_state_reader(APP_SUBNET_ID);

        let response = get_certificate_and_create_response(
            Vec::new(),
            /*delegation_from_nns=*/ None,
            &reader,
            DeprecatedCanisterRangesFilter::KeepOnly(NNS_SUBNET_ID),
            &no_op_logger(),
        );

        assert_eq!(response.status(), StatusCode::OK);
        let labeled_tree = parse_response(response).await;
        assert_eq!(
            lookup_path(
                &labeled_tree,
                &[
                    b"subnet",
                    APP_SUBNET_ID.get_ref().as_ref(),
                    b"canister_ranges",
                ],
            ),
            None,
            "/subnet/subnet_id/canister_ranges path should have been purged from the certificate"
        );
    }

    fn fake_certificate(
        subnet_id: SubnetId,
        canister_id_ranges: &Vec<(CanisterId, CanisterId)>,
        with_flat_canister_ranges: bool,
    ) -> ic_certification_test_utils::Certificate {
        const MAX_RANGES_PER_ROUTING_TABLE_LEAF: usize = 5;

        let (non_nns_public_key, _non_nns_secret_key) = generate_root_of_trust(&mut thread_rng());
        let (nns_public_key, nns_secret_key) = generate_root_of_trust(&mut thread_rng());
        let certificate_tree = create_certificate_labeled_tree(
            canister_id_ranges,
            subnet_id,
            non_nns_public_key,
            MAX_RANGES_PER_ROUTING_TABLE_LEAF,
            /*time=*/ 42,
            /*with_tree_canister_ranges=*/ true,
            with_flat_canister_ranges,
        );

        let (certificate, _root_pk, _cbor) =
            CertificateBuilder::new(CertificateData::CustomTree(certificate_tree))
                .with_root_of_trust(nns_public_key, nns_secret_key)
                .build();

        certificate
    }
}
