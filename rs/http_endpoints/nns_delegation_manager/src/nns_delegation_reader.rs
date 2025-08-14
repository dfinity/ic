use ic_crypto_tree_hash::{
    lookup_lower_bound, sparse_labeled_tree_from_paths, FilterBuilder, LabeledTree,
    LookupLowerBoundStatus, Path,
};
use ic_types::{
    messages::{Blob, Certificate, CertificateDelegation},
    CanisterId, SubnetId,
};
use tokio::sync::watch;

use crate::metrics::DelegationManagerMetrics;

#[derive(Clone, Copy)]
/// Filter for the canister ranges in the NNS delegation.
pub enum CanisterRangesFilter {
    /// Keep the `/subnet/<subnet_id>/canister_ranges` leaf and purge
    /// the whole `/canister_ranges` subtree.
    Flat,
    /// Keep only the `/canister_ranges/subnet_id/canister_id_label` leaf
    /// and purge all other leaves under `/canister_ranges/subnet_id` and
    /// the `/subnet/<subnet_id>/canister_ranges` leaf.
    Tree(CanisterId),
    /// Purge both the `/canister_ranges` subtree and the `/subnet/<subnet_id>/canister_ranges`
    /// leaf.
    None,
}

#[derive(Clone)]
// TODO(CON-1487): Consider caching the delegations per canister range.
pub struct NNSDelegationReader {
    pub(crate) receiver: watch::Receiver<Option<NNSDelegationBuilder>>,
}

impl NNSDelegationReader {
    /// Returns the most recent NNS delegation known to the replica.
    /// Consecutive calls might return different delegations.
    pub fn get_delegation(
        &self,
        canister_ranges_filter: CanisterRangesFilter,
    ) -> Option<CertificateDelegation> {
        self.receiver
            .borrow()
            .as_ref()
            .map(|builder| builder.build_or_original(canister_ranges_filter))
    }

    pub(crate) fn new(receiver: watch::Receiver<Option<NNSDelegationBuilder>>) -> Self {
        Self { receiver }
    }

    pub async fn wait_until_initialized(&mut self) -> Result<(), watch::error::RecvError> {
        self.receiver.changed().await
    }
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub(crate) struct NNSDelegationBuilder {
    builder: NNSDelegationBuilderPriv,
    precomputed_delegation_with_flat_canister_ranges: CertificateDelegation,
    precomputed_delegation_without_canister_ranges: CertificateDelegation,
}

impl NNSDelegationBuilder {
    pub(crate) fn new(
        full_certificate: Certificate,
        full_labeled_tree: LabeledTree<Vec<u8>>,
        raw_certificate: Blob,
        subnet_id: SubnetId,
        metrics: &DelegationManagerMetrics,
    ) -> Self {
        let builder = NNSDelegationBuilderPriv::new(
            full_certificate,
            full_labeled_tree,
            raw_certificate,
            subnet_id,
        );
        let precomputed_delegation_without_canister_ranges =
            builder.build_or_original(CanisterRangesFilter::None);
        let precomputed_delegation_with_flat_canister_ranges =
            builder.build_or_original(CanisterRangesFilter::Flat);

        metrics
            .delegation_size
            .with_label_values(&["both_canister_ranges"])
            .observe(builder.original_delegation.certificate.len() as f64);
        metrics
            .delegation_size
            .with_label_values(&["no_canister_ranges"])
            .observe(
                precomputed_delegation_without_canister_ranges
                    .certificate
                    .len() as f64,
            );
        metrics
            .delegation_size
            .with_label_values(&["flat_canister_ranges"])
            .observe(
                precomputed_delegation_with_flat_canister_ranges
                    .certificate
                    .len() as f64,
            );

        Self {
            builder,
            precomputed_delegation_with_flat_canister_ranges,
            precomputed_delegation_without_canister_ranges,
        }
    }

    pub(crate) fn build_or_original(
        &self,
        canister_ranges_filter: CanisterRangesFilter,
    ) -> CertificateDelegation {
        match canister_ranges_filter {
            CanisterRangesFilter::Flat => self
                .precomputed_delegation_with_flat_canister_ranges
                .clone(),
            CanisterRangesFilter::None => {
                self.precomputed_delegation_without_canister_ranges.clone()
            }
            CanisterRangesFilter::Tree(_canister_id) => {
                self.builder.build_or_original(canister_ranges_filter)
            }
        }
    }
}

#[derive(Clone, Eq, PartialEq, Debug)]
struct NNSDelegationBuilderPriv {
    full_certificate: Certificate,
    full_labeled_tree: LabeledTree<Vec<u8>>,
    full_filter_builder: FilterBuilder,
    subnet_id: SubnetId,
    original_delegation: CertificateDelegation,
}

impl NNSDelegationBuilderPriv {
    fn new(
        full_certificate: Certificate,
        full_labeled_tree: LabeledTree<Vec<u8>>,
        raw_certificate: Blob,
        subnet_id: SubnetId,
    ) -> Self {
        Self {
            full_filter_builder: full_certificate.tree.filter_builder(),
            full_certificate,
            full_labeled_tree,
            subnet_id,
            original_delegation: CertificateDelegation {
                subnet_id: Blob(subnet_id.get().to_vec()),
                certificate: raw_certificate,
            },
        }
    }

    fn build_or_original(&self, filter: CanisterRangesFilter) -> CertificateDelegation {
        match self.try_build(filter) {
            Ok(delegation) => delegation,
            // FIXME(kpop): log something
            Err(_) => self.original_delegation.clone(),
        }
    }

    fn try_build(&self, filter: CanisterRangesFilter) -> Result<CertificateDelegation, String> {
        let mut paths = vec![
            Path::new(vec![
                b"subnet".into(),
                self.subnet_id.get().into(),
                b"public_key".into(),
            ]),
            Path::new(vec![b"time".into()]),
        ];

        match filter {
            // Don't include any extra paths.
            CanisterRangesFilter::None => {}
            // Additionally include `/subnet/<subnet_id>/canister_ranges`
            CanisterRangesFilter::Flat => {
                paths.push(Path::new(vec![
                    b"subnet".into(),
                    self.subnet_id.get().into(),
                    b"canister_ranges".into(),
                ]));
            }
            // Additionally include `/canister_ranges/<subnet_id>/<canister_id_label>`
            CanisterRangesFilter::Tree(canister_id) => {
                let label = match lookup_lower_bound(
                    &self.full_labeled_tree,
                    &[b"canister_ranges".as_ref(), &self.subnet_id.get().to_vec()],
                    &canister_id.get().to_vec(),
                ) {
                    LookupLowerBoundStatus::Found(label, _labeled_subtree) => label,
                    LookupLowerBoundStatus::PrefixNotFound
                    | LookupLowerBoundStatus::LabelNotFound => {
                        // The canister id is not assigned to the subnet according to the NNS delegation.
                        // This could mean that the routing table has changed but we haven't refreshed the
                        // NNS delegation just yet.
                        // In that case, we return the delegation without canister ranges.
                        return Err(String::from("Not found"));
                    }
                };

                paths.push(Path::new(vec![
                    b"canister_ranges".into(),
                    self.subnet_id.get().into(),
                    label.clone(),
                ]));
            }
        }

        let tree = sparse_labeled_tree_from_paths(&paths).map_err(|err| {
            format!("Failed to build labeled tree from paths ({paths:?}): {err:?}")
        })?;

        let filtered_tree = self
            .full_filter_builder
            .filtered(&tree)
            .map_err(|err| format!("Failed to filter tree: {err:?}"))?;

        let certificate = Certificate {
            tree: filtered_tree,
            signature: self.full_certificate.signature.clone(),
            delegation: self.full_certificate.delegation.clone(),
        };

        Ok(CertificateDelegation {
            subnet_id: Blob(self.subnet_id.get().to_vec()),
            certificate: Blob(
                serde_cbor::ser::to_vec(&certificate)
                    .map_err(|err| format!("Failed to serialize certificate: {err}"))?,
            ),
        })
    }
}

impl NNSDelegationReader {
    /// DON'T USE IN PRODUCTION!!!
    pub fn new_for_test_only(
        delegation: Option<CertificateDelegation>,
        subnet_id: SubnetId,
    ) -> Self {
        let builder = delegation.map(|delegation| {
            let certificate: Certificate = serde_cbor::from_slice(&delegation.certificate).unwrap();
            NNSDelegationBuilder::new(
                certificate.clone(),
                LabeledTree::try_from(certificate.tree.clone()).unwrap(),
                Blob(vec![]),
                subnet_id,
                &DelegationManagerMetrics::new(&ic_metrics::MetricsRegistry::new()),
            )
        });
        let (_sender, receiver) = watch::channel(builder);

        Self { receiver }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use ic_certification::verify_delegation_certificate;
    use ic_crypto_tree_hash::lookup_path;
    use ic_nns_delegation_manager_test_utils::create_fake_certificate_delegation;
    use ic_test_utilities_types::ids::SUBNET_0;

    fn path_exists(delegation: &CertificateDelegation, path: &[&[u8]]) -> bool {
        let parsed_delegation: Certificate =
            serde_cbor::from_slice(&delegation.certificate).unwrap();

        let labeled_tree = LabeledTree::try_from(parsed_delegation.tree.clone()).unwrap();
        lookup_path(&labeled_tree, path).is_some()
    }

    #[test]
    fn no_ranges_test() {
        let (full_delegation, root_public_key) = create_fake_certificate_delegation(
            &vec![
                (CanisterId::from(0), CanisterId::from(10)),
                (CanisterId::from(100), CanisterId::from(200)),
            ],
            SUBNET_0,
        );
        let reader = NNSDelegationReader::new_for_test_only(Some(full_delegation), SUBNET_0);

        let delegation = reader
            .get_delegation(CanisterRangesFilter::None)
            .expect("Should succeed");

        assert!(
            !path_exists(&delegation, &[b"canister_ranges"]),
            "New canister ranges should have been purged"
        );
        assert!(
            !path_exists(
                &delegation,
                &[b"subnet", SUBNET_0.get().as_ref(), b"canister_ranges"],
            ),
            "Old canister ranges should have been purged"
        );
        verify_delegation_certificate(
            &delegation.certificate,
            &SUBNET_0,
            &root_public_key,
            None,
            /*use_signature_cache=*/ false,
        )
        .expect("The delegation should still be verifiable");
    }

    #[test]
    fn flat_ranges_test() {
        let (full_delegation, root_public_key) = create_fake_certificate_delegation(
            &vec![
                (CanisterId::from(0), CanisterId::from(10)),
                (CanisterId::from(100), CanisterId::from(200)),
            ],
            SUBNET_0,
        );
        let reader = NNSDelegationReader::new_for_test_only(Some(full_delegation), SUBNET_0);

        let delegation = reader
            .get_delegation(CanisterRangesFilter::Flat)
            .expect("Should succeed");

        assert!(
            !path_exists(&delegation, &[b"canister_ranges"]),
            "New canister ranges should have been purged"
        );
        assert!(
            path_exists(
                &delegation,
                &[b"subnet", SUBNET_0.get().as_ref(), b"canister_ranges"],
            ),
            "Old canister ranges should NOT have been purged"
        );
        verify_delegation_certificate(
            &delegation.certificate,
            &SUBNET_0,
            &root_public_key,
            Some(&CanisterId::from(150)),
            /*use_signature_cache=*/ false,
        )
        .expect("The delegation should still be verifiable");
    }

    #[test]
    fn tree_ranges_test() {
        let (full_delegation, root_public_key) = create_fake_certificate_delegation(
            &vec![
                (CanisterId::from(0), CanisterId::from(10)),
                (CanisterId::from(11), CanisterId::from(20)),
                (CanisterId::from(21), CanisterId::from(30)),
                (CanisterId::from(31), CanisterId::from(31)),
                (CanisterId::from(41), CanisterId::from(41)),
                (CanisterId::from(100), CanisterId::from(200)),
            ],
            SUBNET_0,
        );
        let reader = NNSDelegationReader::new_for_test_only(Some(full_delegation), SUBNET_0);

        let delegation = reader
            .get_delegation(CanisterRangesFilter::Tree(CanisterId::from(150)))
            .expect("Should succeed");

        assert!(
            path_exists(&delegation, &[b"canister_ranges"]),
            "New canister ranges should NOT have been purged"
        );
        assert!(
            !path_exists(
                &delegation,
                &[b"subnet", SUBNET_0.get().as_ref(), b"canister_ranges"],
            ),
            "Old canister ranges should have been purged"
        );
        verify_delegation_certificate(
            &delegation.certificate,
            &SUBNET_0,
            &root_public_key,
            Some(&CanisterId::from(150)),
            /*use_signature_cache=*/ false,
        )
        .expect(
            "Should succeed because 150 is within the range [100, 200] which \
            should not have been pruned",
        );
        verify_delegation_certificate(
            &delegation.certificate,
            &SUBNET_0,
            &root_public_key,
            Some(&CanisterId::from(5)),
            /*use_signature_cache=*/ false,
        )
        .expect_err("Should fail because the range [0, 10] should have been pruned from the tree");
    }
}
