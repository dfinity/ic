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
    // if `true`, we will prune the paths `/subnet/<subnet_id>/canister_ranges` for all
    // subnet ids
    should_prune_deprecated_canister_ranges: bool,
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

    let maybe_prune_tree = || {
        if !should_prune_deprecated_canister_ranges {
            return tree;
        }

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
                .map(|label| {
                    Path::new(vec![
                        b"subnet".into(),
                        label.clone(),
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
    use ic_test_utilities_types::ids::subnet_test_id;
    use ic_types::{
        consensus::certification::{Certification, CertificationContent},
        crypto::{CryptoHash, Signed},
        signature::ThresholdSignature,
        CanisterId, CryptoHashOfPartialState, Height, SubnetId,
    };
    use rand::thread_rng;

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

    #[tokio::test]
    async fn test_does_not_purge_when_not_requested() {
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
            tree: fake_certificate(
                subnet_test_id(42),
                &vec![(CanisterId::from(0), CanisterId::from(10))],
                /*with_flat_canister_ranges=*/ true,
            )
            .tree(),
            certification,
        };
        let response = get_certificate_and_create_response(
            Vec::new(),
            /*delegation_from_nns=*/ None,
            &reader,
            /*purge_deprecated_canister_ranges=*/ false,
            &no_op_logger(),
        );
        assert_eq!(response.status(), StatusCode::OK);
        let response_bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let response: HttpReadStateResponse = serde_cbor::from_slice(&response_bytes).unwrap();
        let certificate: Certificate = serde_cbor::from_slice(&response.certificate).unwrap();
        let labeled_tree = LabeledTree::try_from(certificate.tree).unwrap();
        assert!(
            lookup_path(
                &labeled_tree,
                &[
                    b"subnet",
                    subnet_test_id(42).get_ref().as_ref(),
                    b"canister_ranges",
                ],
            )
            .is_some(),
            "/subnet/subnet_id/canister_ranges path should not have been purged from the certificate"
        );
    }

    #[tokio::test]
    async fn test_does_purge_when_requested() {
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
            tree: fake_certificate(
                subnet_test_id(42),
                &vec![(CanisterId::from(0), CanisterId::from(10))],
                /*with_flat_canister_ranges=*/ true,
            )
            .tree(),
            certification,
        };
        let response = get_certificate_and_create_response(
            Vec::new(),
            /*delegation_from_nns=*/ None,
            &reader,
            /*purge_deprecated_canister_ranges=*/ true,
            &no_op_logger(),
        );
        assert_eq!(response.status(), StatusCode::OK);
        let response_bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let response: HttpReadStateResponse = serde_cbor::from_slice(&response_bytes).unwrap();
        let certificate: Certificate = serde_cbor::from_slice(&response.certificate).unwrap();
        let labeled_tree = LabeledTree::try_from(certificate.tree).unwrap();
        assert_eq!(
            lookup_path(
                &labeled_tree,
                &[
                    b"subnet",
                    subnet_test_id(42).get_ref().as_ref(),
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
