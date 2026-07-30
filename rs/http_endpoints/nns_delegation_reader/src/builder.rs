use ic_crypto_tree_hash::{
    FilterBuilder, LabeledTree, LookupLowerBoundStatus, Path, lookup_lower_bound,
    sparse_labeled_tree_from_paths,
};
use ic_logger::{ReplicaLogger, warn};
use ic_registry_routing_table::CanisterIdRanges;
use ic_types::{
    SubnetId,
    messages::{Blob, Certificate, CertificateDelegation},
};
use serde::ser::Serialize;

use crate::{
    reader::CanisterRangesFilter,
    validation::{CanisterRangesCheck, DelegationValidationError, is_tree_consistent_with},
};

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct NNSDelegationBuilder {
    builder: NNSDelegationBuilderInner,
    precomputed_delegation_with_flat_canister_ranges: CertificateDelegation,
    precomputed_delegation_without_canister_ranges: CertificateDelegation,
}

impl NNSDelegationBuilder {
    pub fn try_new(
        raw_certificate: Blob,
        subnet_id: SubnetId,
        logger: &ReplicaLogger,
    ) -> Result<Self, String> {
        let full_certificate: Certificate = serde_cbor::from_slice(&raw_certificate)
            .map_err(|err| format!("Failed to parse delegation certificate: {err}"))?;

        let full_labeled_tree = LabeledTree::try_from(full_certificate.tree.clone())
            .map_err(|err| format!("Invalid hash tree in the delegation certificate: {err:?}"))?;

        Ok(Self::new(
            full_certificate,
            full_labeled_tree,
            raw_certificate,
            subnet_id,
            logger,
        ))
    }

    pub fn new(
        full_certificate: Certificate,
        full_labeled_tree: LabeledTree<Vec<u8>>,
        raw_certificate: Blob,
        subnet_id: SubnetId,
        logger: &ReplicaLogger,
    ) -> Self {
        let builder = NNSDelegationBuilderInner::new(
            full_certificate,
            full_labeled_tree,
            raw_certificate,
            subnet_id,
        );
        let precomputed_delegation_without_canister_ranges =
            builder.build_or_original(CanisterRangesFilter::None, logger);
        let precomputed_delegation_with_flat_canister_ranges =
            builder.build_or_original(CanisterRangesFilter::Flat, logger);

        Self {
            builder,
            precomputed_delegation_with_flat_canister_ranges,
            precomputed_delegation_without_canister_ranges,
        }
    }

    /// Builds an NNS delegation with the given canister ranges filter.
    /// If for some reasons the delegation cannot be built, it returns the full delegation
    /// as received from the NNS. This means the returned delegation might contain
    /// both formats of the canister ranges.
    pub fn build_or_original(
        &self,
        canister_ranges_filter: CanisterRangesFilter,
        logger: &ReplicaLogger,
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
                .build_or_original(canister_ranges_filter, logger),
        }
    }

    /// The id of the subnet to which the delegation was issued.
    pub fn subnet_id(&self) -> SubnetId {
        self.builder.subnet_id
    }

    /// Checks whether the delegation is consistent with the given view of the subnet
    /// information recorded in a replicated state: `expected_public_key` and
    /// `subnet_ranges` should be the delegated subnet's threshold public key and the
    /// canister ranges which the state assigns to it, as used for certification, i.e.
    /// `network_topology.subnets_for_certification()[&subnet_id].public_key` and
    /// `network_topology.routing_table_for_certification().ranges(subnet_id)`.
    /// `ranges_check` specifies what to check the certified canister ranges against
    /// (see [`CanisterRangesCheck`]).
    ///
    /// See [`is_tree_consistent_with`] for the exact semantics.
    pub fn is_consistent_with(
        &self,
        expected_public_key: &[u8],
        subnet_ranges: &CanisterIdRanges,
        ranges_check: CanisterRangesCheck,
    ) -> Result<bool, DelegationValidationError> {
        is_tree_consistent_with(
            &self.builder.full_labeled_tree,
            self.builder.subnet_id,
            expected_public_key,
            subnet_ranges,
            ranges_check,
        )
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

#[derive(Clone, Eq, PartialEq, Debug)]
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

    fn build_or_original(
        &self,
        filter: CanisterRangesFilter,
        logger: &ReplicaLogger,
    ) -> CertificateDelegation {
        match self.try_build(filter) {
            Ok(delegation) => delegation,
            Err(err) => {
                warn!(
                    every_n_seconds => 30,
                    logger,
                    "Failed to build an NNS delegation with filter {filter:?}: {err}. \
                    Returning the original delegation."
                );
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
