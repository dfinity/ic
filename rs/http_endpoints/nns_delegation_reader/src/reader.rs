use ic_crypto_tree_hash::{
    FilterBuilder, LabeledTree, LookupLowerBoundStatus, Path, lookup_lower_bound,
    sparse_labeled_tree_from_paths,
};
use ic_registry_routing_table::RoutingTable;
use ic_types::{
    CanisterId, SubnetId,
    messages::{
        Blob, Certificate, CertificateDelegation, CertificateDelegationFormat,
        CertificateDelegationMetadata,
    },
};
use serde::ser::Serialize;
use std::sync::Arc;
use tokio::sync::watch;

use crate::validation::{
    CanisterRangesCheck, DelegationValidationError, DelegationVerificationError,
    is_tree_consistent_with,
};

#[derive(Clone, Copy, Debug)]
/// Filter for the canister ranges in the NNS delegation.
enum CanisterRangesFilter {
    /// Keep the `/subnet/<subnet_id>/canister_ranges` leaf and purge
    /// the whole `/canister_ranges` subtree.
    Flat,
    /// Keep only the `/canister_ranges/<subnet_id>/<canister_id_lower_bound>` leaf,
    /// where `canister_id_lower_bound` is the largest label in the `/canister_ranges/<subnet_id>/`
    /// subtree which is not greater than `CanisterId`, and purge all other leaves under
    /// `/canister_ranges/<subnet_id>` and the `/subnet/<subnet_id>/canister_ranges` leaf.
    Tree(CanisterId),
    /// Purge both the `/canister_ranges` subtree and the `/subnet/<subnet_id>/canister_ranges`
    /// leaf.
    None,
}

impl From<CanisterRangesFilter> for CertificateDelegationMetadata {
    fn from(canister_ranges_filter: CanisterRangesFilter) -> Self {
        Self {
            format: match canister_ranges_filter {
                CanisterRangesFilter::Flat => CertificateDelegationFormat::Flat,
                CanisterRangesFilter::Tree(_canister_id) => CertificateDelegationFormat::Tree,
                CanisterRangesFilter::None => CertificateDelegationFormat::Pruned,
            },
        }
    }
}

impl From<CanisterRangesCheck> for CanisterRangesFilter {
    fn from(ranges_check: CanisterRangesCheck) -> Self {
        match ranges_check {
            CanisterRangesCheck::AllSubnetRanges => CanisterRangesFilter::Flat,
            CanisterRangesCheck::CanisterInFlat(_canister_id) => CanisterRangesFilter::Flat,
            CanisterRangesCheck::CanisterInTree(canister_id) => {
                CanisterRangesFilter::Tree(canister_id)
            }
            CanisterRangesCheck::NoCheck => CanisterRangesFilter::None,
        }
    }
}

#[derive(Clone)]
/// Wrapper around [`tokio::sync::watch::Receiver`] with some utility methods.
// TODO(CON-1487): Consider caching the delegations per canister range.
pub struct NNSDelegationReader {
    receiver: watch::Receiver<Option<Arc<NNSDelegationBuilder>>>,
}

impl NNSDelegationReader {
    pub fn new(receiver: watch::Receiver<Option<Arc<NNSDelegationBuilder>>>) -> Self {
        Self { receiver }
    }

    /// Returns a snapshot of the most recent NNS delegation known to the replica.
    /// Consecutive calls might return different delegations.
    /// Note: on the NNS subnet this always returns `None`.
    ///
    /// The snapshot is immutable, so it can be used to verify the delegation against a
    /// certified state and to build exactly the verified delegation (see
    /// [`NNSDelegationBuilder::build_verified`]), without having to worry about the
    /// delegation being concurrently replaced.
    pub fn builder(&self) -> Option<Arc<NNSDelegationBuilder>> {
        self.receiver.borrow().clone()
    }

    pub async fn wait_until_initialized(&mut self) -> Result<(), watch::error::RecvError> {
        self.receiver.changed().await
    }
}

#[derive(Debug)]
pub struct NNSDelegationBuilder {
    builder: NNSDelegationBuilderInner,
    precomputed_delegation_with_flat_canister_ranges: CertificateDelegation,
    precomputed_delegation_without_canister_ranges: CertificateDelegation,
}

impl NNSDelegationBuilder {
    pub fn try_new(raw_certificate: Blob, subnet_id: SubnetId) -> Result<Self, String> {
        let full_certificate: Certificate = serde_cbor::from_slice(&raw_certificate)
            .map_err(|err| format!("Failed to parse delegation certificate: {err}"))?;

        let full_labeled_tree = LabeledTree::try_from(full_certificate.tree.clone())
            .map_err(|err| format!("Invalid hash tree in the delegation certificate: {err:?}"))?;

        Ok(Self::new(
            full_certificate,
            full_labeled_tree,
            raw_certificate,
            subnet_id,
        ))
    }

    pub fn new(
        full_certificate: Certificate,
        full_labeled_tree: LabeledTree<Vec<u8>>,
        raw_certificate: Blob,
        subnet_id: SubnetId,
    ) -> Self {
        let builder = NNSDelegationBuilderInner::new(
            full_certificate,
            full_labeled_tree,
            raw_certificate,
            subnet_id,
        );
        let precomputed_delegation_without_canister_ranges =
            builder.build_uncached_or_original(CanisterRangesFilter::None);
        let precomputed_delegation_with_flat_canister_ranges =
            builder.build_uncached_or_original(CanisterRangesFilter::Flat);

        Self {
            builder,
            precomputed_delegation_with_flat_canister_ranges,
            precomputed_delegation_without_canister_ranges,
        }
    }

    /// Verifies that the delegation is consistent with the given view of the subnet
    /// information recorded in a replicated state and, only if it is, builds it
    /// according to the ranges check to be applied and returns it. The builder is
    /// an immutable snapshot of the delegation, so the returned delegation is
    /// guaranteed to be exactly the one which was verified.
    ///
    /// `ranges_check` specifies what to check the certified canister ranges against
    /// (see [`CanisterRangesCheck`]). For the meaning of `routing_table` and
    /// `public_key_for_subnet`, see [`Self::is_consistent_with`].
    pub fn build_verified<'a>(
        &self,
        ranges_check: CanisterRangesCheck,
        routing_table: &RoutingTable,
        public_key_for_subnet: impl FnOnce(SubnetId) -> Option<&'a [u8]>,
    ) -> Result<(CertificateDelegation, CertificateDelegationMetadata), DelegationVerificationError>
    {
        let ranges_filter = CanisterRangesFilter::from(ranges_check);

        match self.is_consistent_with(ranges_check, routing_table, public_key_for_subnet) {
            Ok(true) => Ok((self.build_unverified(ranges_filter), ranges_filter.into())),
            Ok(false) => Err(DelegationVerificationError::Inconsistent),
            Err(err) => Err(DelegationVerificationError::Validation(err)),
        }
    }

    /// Checks whether the delegation is consistent with the given view of the subnet
    /// information recorded in a replicated state.
    ///
    /// `routing_table` should be the state's routing table used for certification, i.e.
    /// `network_topology.routing_table_for_certification()`. `public_key_for_subnet`
    /// should resolve the threshold public key which the state assigns to the delegated
    /// subnet, e.g.
    /// ```ignore
    /// |subnet_id| {
    ///     network_topology
    ///         .subnets_for_certification()
    ///         .get(&subnet_id)
    ///         .map(|topology| topology.public_key.as_slice())
    /// }
    /// ```
    /// Resolving to `None` maps to [`DelegationValidationError::UnknownSubnet`].
    /// `ranges_check` specifies what to check the certified canister ranges against
    /// (see [`CanisterRangesCheck`]).
    ///
    /// See [`is_tree_consistent_with`] for the exact semantics.
    pub fn is_consistent_with<'a>(
        &self,
        ranges_check: CanisterRangesCheck,
        routing_table: &RoutingTable,
        public_key_for_subnet: impl FnOnce(SubnetId) -> Option<&'a [u8]>,
    ) -> Result<bool, DelegationValidationError> {
        let subnet_public_key = public_key_for_subnet(self.builder.subnet_id).ok_or(
            DelegationValidationError::UnknownSubnet(self.builder.subnet_id),
        )?;

        is_tree_consistent_with(
            &self.builder.full_labeled_tree,
            self.builder.subnet_id,
            subnet_public_key,
            routing_table,
            ranges_check,
        )
    }

    /// Builds an NNS delegation with the given canister ranges filter, WITHOUT checking
    /// that the delegation is consistent with any replicated state. When serving the
    /// delegation alongside a certificate, prefer [`Self::build_verified`], which only
    /// returns the delegation after verifying it against the certified state which the
    /// certificate is built from.
    ///
    /// If for some reasons the delegation cannot be built, it returns the full delegation
    /// as received from the NNS. This means the returned delegation might contain
    /// both formats of the canister ranges.
    fn build_unverified(
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
            CanisterRangesFilter::Tree(_canister_id) => self
                .builder
                .build_uncached_or_original(canister_ranges_filter),
        }
    }

    /// The size, in bytes, of the certificate as received from the NNS, which contains
    /// the canister ranges in both locations.
    pub fn original_certificate_size_bytes(&self) -> usize {
        self.builder.original_delegation.certificate.len()
    }

    /// The size, in bytes, of the certificate with the canister ranges in the
    /// `/subnet/<subnet_id>/canister_ranges` leaf only.
    pub fn flat_certificate_size_bytes(&self) -> usize {
        self.precomputed_delegation_with_flat_canister_ranges
            .certificate
            .len()
    }

    /// The size, in bytes, of the certificate with the canister ranges pruned out.
    pub fn pruned_certificate_size_bytes(&self) -> usize {
        self.precomputed_delegation_without_canister_ranges
            .certificate
            .len()
    }
}

#[derive(Debug)]
struct NNSDelegationBuilderInner {
    full_certificate: Certificate,
    full_labeled_tree: LabeledTree<Vec<u8>>,
    full_filter_builder: FilterBuilder,
    subnet_id: SubnetId,
    original_delegation: CertificateDelegation,
}

impl NNSDelegationBuilderInner {
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

    /// Builds the delegation from scratch instead of consulting the precomputed delegations.
    fn build_uncached_or_original(&self, filter: CanisterRangesFilter) -> CertificateDelegation {
        match self.try_build(filter) {
            Ok(delegation) => delegation,
            Err(err) => {
                if cfg!(debug_assertions) {
                    panic!("Failed to build an NNS delegation with filter {filter:?}: {err}");
                }
                self.original_delegation.clone()
            }
        }
    }

    fn try_build(&self, filter: CanisterRangesFilter) -> Result<CertificateDelegation, String> {
        // Always include `/subnet/<subnet_id>/public_key`, `/time`, and
        // `/subnet/<subnet_id>/type` paths.
        let mut paths = vec![
            Path::new(vec![
                b"subnet".into(),
                self.subnet_id.get().into(),
                b"public_key".into(),
            ]),
            Path::new(vec![b"time".into()]),
            Path::new(vec![
                b"subnet".into(),
                self.subnet_id.get().into(),
                b"type".into(),
            ]),
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
            // Additionally include `/canister_ranges/<subnet_id>/<canister_id_lower_bound>`
            CanisterRangesFilter::Tree(canister_id) => {
                match lookup_lower_bound(
                    &self.full_labeled_tree,
                    &[b"canister_ranges".as_ref(), &self.subnet_id.get().to_vec()],
                    &canister_id.get().to_vec(),
                ) {
                    LookupLowerBoundStatus::Found(label, _labeled_subtree) => {
                        // Note: This only means that the given canister id *might* be covered by
                        // the ranges in the found leaf. For performance reasons, we don't
                        // deserialize the subtree to check if the canister id is actually covered.
                        // It could happen that the NNS delegation is old and has an old view of
                        // the routing table and not have the canister id assigned to the subnet.
                        paths.push(Path::new(vec![
                            b"canister_ranges".into(),
                            self.subnet_id.get().into(),
                            label.clone(),
                        ]));
                    }
                    LookupLowerBoundStatus::LabelNotFound => {
                        // The canister id is not assigned to the subnet according to the NNS delegation.
                        // This could mean that the routing table has changed but we haven't refreshed the
                        // NNS delegation just yet.
                        // In that case, we return the delegation without canister ranges.
                    }
                    LookupLowerBoundStatus::PrefixNotFound => {
                        return Err(format!(
                            "Path `/canister_ranges/{}` not found",
                            self.subnet_id,
                        ));
                    }
                };
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
                into_cbor(&certificate)
                    .map_err(|err| format!("Failed to serialize certificate to cbor: {err}"))?,
            ),
        })
    }
}

fn into_cbor(certificate: &Certificate) -> Result<Vec<u8>, String> {
    let mut serializer = serde_cbor::Serializer::new(Vec::new());
    serializer
        .self_describe()
        .map_err(|err| format!("Could not write magic tag: {err}"))?;
    certificate
        .serialize(&mut serializer)
        .map_err(|err| format!("Failed to serialize the object: {err}"))?;
    Ok(serializer.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;

    use assert_matches::assert_matches;
    use ic_certification::verify_delegation_certificate;
    use ic_crypto_tree_hash::lookup_path;
    use ic_nns_delegation_reader_test_utils::create_fake_certificate_delegation;
    use ic_registry_routing_table::CanisterIdRange;
    use ic_test_utilities_types::ids::SUBNET_0;

    /// Returns whether the given path exists in the delegation's certificate tree.
    fn path_exists(delegation: &CertificateDelegation, path: &[&[u8]]) -> bool {
        let parsed_delegation: Certificate =
            serde_cbor::from_slice(&delegation.certificate).unwrap();

        let labeled_tree = LabeledTree::try_from(parsed_delegation.tree.clone()).unwrap();
        lookup_path(&labeled_tree, path).is_some()
    }

    fn create_builder(delegation: CertificateDelegation) -> NNSDelegationBuilder {
        NNSDelegationBuilder::try_new(delegation.certificate, SUBNET_0).unwrap()
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
        let builder = create_builder(full_delegation);

        let delegation = builder.build_unverified(CanisterRangesFilter::None);

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
        let builder = create_builder(full_delegation);

        let delegation = builder.build_unverified(CanisterRangesFilter::Flat);

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
        let builder = create_builder(full_delegation);

        let delegation =
            builder.build_unverified(CanisterRangesFilter::Tree(CanisterId::from(150)));

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

    #[test]
    fn canister_out_of_range_test() {
        let (full_delegation, root_public_key) = create_fake_certificate_delegation(
            &vec![
                (CanisterId::from(1), CanisterId::from(10)),
                (CanisterId::from(11), CanisterId::from(20)),
                (CanisterId::from(21), CanisterId::from(30)),
                (CanisterId::from(31), CanisterId::from(31)),
                (CanisterId::from(41), CanisterId::from(41)),
                (CanisterId::from(100), CanisterId::from(200)),
            ],
            SUBNET_0,
        );
        let builder = create_builder(full_delegation);

        let delegation = builder.build_unverified(CanisterRangesFilter::Tree(CanisterId::from(0)));

        assert!(
            !path_exists(&delegation, &[b"canister_ranges"]),
            "New canister ranges should have been purged because no leaf contains the \
            specified canister id"
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

    /// The canister ranges the consistency check fixture's delegation certifies.
    const RANGES: &[(u64, u64)] = &[(0, 10), (100, 200)];

    /// A routing table assigning `ranges` to `SUBNET_0`.
    fn routing_table_with(ranges: &[(u64, u64)]) -> RoutingTable {
        let mut routing_table = RoutingTable::default();
        for (start, end) in ranges {
            routing_table
                .insert(
                    CanisterIdRange {
                        start: CanisterId::from(*start),
                        end: CanisterId::from(*end),
                    },
                    SUBNET_0,
                )
                .unwrap();
        }
        routing_table
    }

    /// Creates a builder holding a fake delegation for `SUBNET_0` certifying [`RANGES`],
    /// and returns it together with the public key certified in the delegation.
    fn create_consistency_check_fixture() -> (NNSDelegationBuilder, Vec<u8>) {
        let (full_delegation, _root_public_key) = create_fake_certificate_delegation(
            &RANGES
                .iter()
                .map(|(start, end)| (CanisterId::from(*start), CanisterId::from(*end)))
                .collect(),
            SUBNET_0,
        );
        let builder = create_builder(full_delegation);
        // Extract the public key certified in the delegation so that the consistency
        // check on it can succeed.
        let certified_public_key = match lookup_path(
            &builder.builder.full_labeled_tree,
            &[b"subnet", SUBNET_0.get().as_ref(), b"public_key"],
        ) {
            Some(LabeledTree::Leaf(public_key)) => public_key.clone(),
            _ => panic!("The fake delegation should certify a public key"),
        };

        (builder, certified_public_key)
    }

    #[test]
    fn matching_delegation_is_consistent_with_state() {
        let (builder, public_key) = create_consistency_check_fixture();

        assert_matches!(
            builder.is_consistent_with(
                CanisterRangesCheck::AllSubnetRanges,
                &routing_table_with(RANGES),
                |_subnet_id| Some(&public_key),
            ),
            Ok(true)
        );
    }

    #[test]
    fn delegation_with_mismatching_public_key_is_inconsistent_with_state() {
        let (builder, _public_key) = create_consistency_check_fixture();

        let different_public_key = vec![9, 9, 9];
        assert_matches!(
            builder.is_consistent_with(
                CanisterRangesCheck::AllSubnetRanges,
                &routing_table_with(RANGES),
                |_subnet_id| Some(&different_public_key),
            ),
            Ok(false)
        );
    }

    #[test]
    fn delegation_with_mismatching_ranges_is_inconsistent_with_state() {
        let (builder, public_key) = create_consistency_check_fixture();

        assert_matches!(
            builder.is_consistent_with(
                CanisterRangesCheck::AllSubnetRanges,
                // The state assigns an extra range to the subnet which is not certified
                // in the delegation.
                &routing_table_with(&[(0, 10), (100, 200), (300, 400)]),
                |_subnet_id| Some(&public_key),
            ),
            Ok(false)
        );
    }

    #[test]
    fn unknown_subnet_is_an_error() {
        let (builder, _public_key) = create_consistency_check_fixture();

        assert_matches!(
            builder.is_consistent_with(
                CanisterRangesCheck::AllSubnetRanges,
                &routing_table_with(RANGES),
                |_subnet_id| None,
            ),
            Err(DelegationValidationError::UnknownSubnet(subnet_id)) if subnet_id == SUBNET_0
        );
    }

    #[test]
    fn build_verified_returns_a_consistent_delegation() {
        let (builder, public_key) = create_consistency_check_fixture();

        let (delegation, metadata) = builder
            .build_verified(
                CanisterRangesCheck::AllSubnetRanges,
                &routing_table_with(RANGES),
                |_subnet_id| Some(&public_key),
            )
            .expect("the delegation should be consistent with the state view");

        assert_eq!(
            metadata,
            CertificateDelegationMetadata {
                format: CertificateDelegationFormat::Flat
            }
        );
        // The returned delegation should be built with the requested filter.
        assert!(
            path_exists(
                &delegation,
                &[b"subnet", SUBNET_0.get().as_ref(), b"canister_ranges"],
            ),
            "The delegation should carry the flat canister ranges"
        );
        assert!(
            !path_exists(&delegation, &[b"canister_ranges"]),
            "The tree canister ranges should have been purged"
        );
    }

    #[test]
    fn build_verified_on_an_inconsistent_delegation_is_an_error() {
        let (builder, _public_key) = create_consistency_check_fixture();

        // A public key which does not match the certified one.
        let different_public_key = vec![9, 9, 9];
        assert_matches!(
            builder.build_verified(
                CanisterRangesCheck::AllSubnetRanges,
                &routing_table_with(RANGES),
                |_subnet_id| Some(&different_public_key),
            ),
            Err(DelegationVerificationError::Inconsistent)
        );
    }

    #[test]
    fn build_verified_with_an_unknown_subnet_is_an_error() {
        let (builder, _public_key) = create_consistency_check_fixture();

        assert_matches!(
            builder.build_verified(
                CanisterRangesCheck::AllSubnetRanges,
                &routing_table_with(RANGES),
                |_subnet_id| None,
            ),
            Err(DelegationVerificationError::Validation(
                DelegationValidationError::UnknownSubnet(subnet_id)
            )) if subnet_id == SUBNET_0
        );
    }
}
