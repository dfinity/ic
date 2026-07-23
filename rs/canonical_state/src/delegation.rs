//! Validation of an NNS [`CertificateDelegation`] against a [`ReplicatedState`].
//!
//! A subnet delegation issued by the NNS certifies, for a given subnet, its
//! threshold public key and the set of canister ID ranges assigned to it. This
//! module checks that the contents of such a delegation agree with the subnet
//! information recorded in a [`ReplicatedState`] (as it is exposed in the
//! certified state tree): the certified public key must match the one in the
//! state, and the certified canister ranges must match the ranges the state
//! assigns to that subnet.
//!
//! In some cases, the delegation fetched from the NNS could mismatch the information
//! stored in the state, for example right after a subnet split: the subnet starts
//! certifying with a fresh threshold key while the cached NNS delegation may still
//! carry the previous key for up to a few minutes. Similarly, right before a subnet
//! split, the delegation might already carry the new key while the certified state
//! still carries the old key.
use ic_crypto_tree_hash::{LabeledTree, lookup_path};
use ic_registry_routing_table::CanisterIdRange;
use ic_replicated_state::ReplicatedState;
use ic_types::{
    CanisterId, PrincipalId, SubnetId,
    messages::{Certificate, CertificateDelegation, CertificateDelegationFormat},
};
use std::fmt;

/// An error encountered while checking a delegation against a replicated state.
///
/// These indicate that validity could *not be determined* (e.g. a malformed
/// certificate), as opposed to the delegation being found inconsistent with the
/// state.
#[derive(Debug, Eq, PartialEq)]
pub enum DelegationValidationError {
    /// The delegation's `subnet_id` is not a valid principal.
    InvalidSubnetId(String),
    /// The embedded certificate could not be CBOR-decoded.
    MalformedCertificate(String),
    /// The certificate's mixed hash tree could not be converted into a labeled tree.
    MalformedHashTree(String),
    /// An expected path was missing from the certificate or had an unexpected shape.
    UnexpectedTreeShape(String),
    /// A certified canister-ranges leaf could not be CBOR-decoded.
    MalformedCanisterRanges(String),
    /// The state has no topology for the delegated subnet.
    UnknownSubnet(SubnetId),
}

impl fmt::Display for DelegationValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSubnetId(err) => write!(f, "invalid subnet id in delegation: {err}"),
            Self::MalformedCertificate(err) => {
                write!(f, "failed to decode delegation certificate: {err}")
            }
            Self::MalformedHashTree(err) => {
                write!(f, "invalid hash tree in delegation certificate: {err}")
            }
            Self::UnexpectedTreeShape(err) => write!(f, "unexpected certificate tree shape: {err}"),
            Self::MalformedCanisterRanges(err) => {
                write!(f, "failed to decode certified canister ranges: {err}")
            }
            Self::UnknownSubnet(subnet_id) => {
                write!(f, "state has no topology for subnet {subnet_id}")
            }
        }
    }
}

impl std::error::Error for DelegationValidationError {}

/// Checks whether `delegation` is consistent with `state`.
///
/// Returns `Ok(true)` if, for the subnet the delegation refers to, both:
/// * the threshold public key certified by the delegation matches the subnet's
///   public key in `state`; and
/// * the canister ID ranges certified by the delegation match the ranges
///   assigned to the subnet in `state`.
///
/// Returns `Ok(false)` if either of those does not match. Any error that
/// prevents the comparison (malformed certificate, missing tree paths, unknown
/// subnet, ...) is returned as `Err`.
///
/// `format` indicates where the certified canister ranges are located in the
/// delegation's certificate (it must match the format the delegation was built
/// with):
/// * [`CertificateDelegationFormat::Flat`]: under `/subnet/<subnet_id>/canister_ranges`;
/// * [`CertificateDelegationFormat::Tree`]: under `/canister_ranges/<subnet_id>`;
/// * [`CertificateDelegationFormat::Pruned`]: the ranges are pruned out of the
///   certificate, so only the public key is checked.
///
/// Both sides are compared using the *certification* view of the state's
/// network topology ([`subnets_for_certification`] and
/// [`routing_table_for_certification`]), i.e. exactly the data that the
/// certified state tree (and hence a delegation) is derived from.
///
/// [`subnets_for_certification`]: ic_replicated_state::metadata_state::NetworkTopology::subnets_for_certification
/// [`routing_table_for_certification`]: ic_replicated_state::metadata_state::NetworkTopology::routing_table_for_certification
pub fn is_delegation_valid_with_respect_to_state(
    delegation: &CertificateDelegation,
    format: CertificateDelegationFormat,
    state: &ReplicatedState,
) -> Result<bool, DelegationValidationError> {
    let subnet_id = SubnetId::from(
        PrincipalId::try_from(delegation.subnet_id.0.as_slice())
            .map_err(|err| DelegationValidationError::InvalidSubnetId(err.to_string()))?,
    );

    let certificate: Certificate = serde_cbor::from_slice(delegation.certificate.0.as_slice())
        .map_err(|err| DelegationValidationError::MalformedCertificate(err.to_string()))?;
    let tree = LabeledTree::try_from(certificate.tree)
        .map_err(|err| DelegationValidationError::MalformedHashTree(format!("{err:?}")))?;

    Ok(does_public_key_match(&tree, state, subnet_id)?
        && do_canister_ranges_match(&tree, state, format, subnet_id)?)
}

/// Returns whether the public key certified in `tree` matches the public key
/// assigned to `subnet_id` in `state`.
fn does_public_key_match(
    tree: &LabeledTree<Vec<u8>>,
    state: &ReplicatedState,
    subnet_id: SubnetId,
) -> Result<bool, DelegationValidationError> {
    let subnet_topology = state
        .metadata
        .network_topology
        .subnets_for_certification()
        .get(&subnet_id)
        .ok_or(DelegationValidationError::UnknownSubnet(subnet_id))?;

    let certified_public_key = match lookup_path(
        tree,
        &[b"subnet", subnet_id.get_ref().as_slice(), b"public_key"],
    ) {
        Some(LabeledTree::Leaf(public_key)) => public_key,
        _ => {
            return Err(DelegationValidationError::UnexpectedTreeShape(format!(
                "missing /subnet/{subnet_id}/public_key leaf"
            )));
        }
    };
    Ok(certified_public_key.as_slice() == subnet_topology.public_key.as_slice())
}

/// Returns whether the canister ranges certified in `tree` match the ranges
/// assigned to `subnet_id` in `state`. The check differs depending on the
/// `format` of the delegation:
///   - In the `Flat` layout, all ranges must match exactly.
///   - In the `Tree` layout, only the ranges that are present in the delegation
///     are compared against the state. Any additional ranges in the state that
///     are not present in the delegation are ignored.
///   - In the `Pruned` layout, there are no ranges to compare and the function
///     always returns `Ok(true)`.
fn do_canister_ranges_match(
    tree: &LabeledTree<Vec<u8>>,
    state: &ReplicatedState,
    format: CertificateDelegationFormat,
    subnet_id: SubnetId,
) -> Result<bool, DelegationValidationError> {
    let subnet_id_bytes = subnet_id.get_ref().as_slice();
    // Canister ranges are stored as self-describing CBOR of `(start, end)`
    // principal pairs (see `encoding::encode_subnet_canister_ranges`).
    let decode = |bytes: &[u8]| {
        serde_cbor::from_slice::<Vec<(PrincipalId, PrincipalId)>>(bytes)
            .map_err(|err| DelegationValidationError::MalformedCanisterRanges(err.to_string()))
    };

    let state_routing_table = state
        .metadata
        .network_topology
        .routing_table_for_certification();

    match format {
        // A single leaf at /subnet/<subnet_id>/canister_ranges.
        CertificateDelegationFormat::Flat => {
            match lookup_path(tree, &[b"subnet", subnet_id_bytes, b"canister_ranges"]) {
                Some(LabeledTree::Leaf(bytes)) => {
                    // In the flat layout, all certified ranges must match the state ranges exactly.
                    let certified_ranges = decode(bytes)?;
                    let state_ranges: Vec<(PrincipalId, PrincipalId)> = state_routing_table
                        .ranges(subnet_id)
                        .iter()
                        .map(|range| (range.start.get(), range.end.get()))
                        .collect();

                    Ok(certified_ranges == state_ranges)
                }
                _ => Err(DelegationValidationError::UnexpectedTreeShape(format!(
                    "missing /subnet/{subnet_id}/canister_ranges leaf"
                ))),
            }
        }
        // Ranges split across the leaves of the /canister_ranges/<subnet_id> subtree.
        CertificateDelegationFormat::Tree => {
            match lookup_path(tree, &[b"canister_ranges", subnet_id_bytes]) {
                Some(LabeledTree::SubTree(children)) => {
                    // In the tree layout, we only check that the ranges present in the delegation
                    // match the ranges assigned to the subnet in the state.
                    if children.is_empty() {
                        // This could genuinely happen if the routing table has changed but we
                        // haven't refreshed the NNS delegation just yet.
                        return Ok(false);
                    }
                    for (_label, child) in children.iter() {
                        match child {
                            LabeledTree::Leaf(bytes) => {
                                for (start, end) in decode(bytes)? {
                                    let certified_range = CanisterIdRange {
                                        start: CanisterId::unchecked_from_principal(start),
                                        end: CanisterId::unchecked_from_principal(end),
                                    };

                                    // Return early if the state does not assign this range to the
                                    // subnet or if it assigns it to a different subnet.
                                    let Some(assigned_subnet) =
                                        state_routing_table.lookup_range(certified_range)
                                    else {
                                        return Ok(false);
                                    };
                                    if assigned_subnet != subnet_id {
                                        return Ok(false);
                                    }
                                }
                            }
                            LabeledTree::SubTree(_) => {
                                return Err(DelegationValidationError::UnexpectedTreeShape(
                                    format!(
                                        "unexpected subtree under /canister_ranges/{subnet_id}"
                                    ),
                                ));
                            }
                        }
                    }

                    // At this point, all certified ranges have been checked and match the state.
                    Ok(true)
                }
                _ => Err(DelegationValidationError::UnexpectedTreeShape(format!(
                    "missing /canister_ranges/{subnet_id} subtree"
                ))),
            }
        }
        CertificateDelegationFormat::Pruned => Ok(true),
    }
}

#[cfg(test)]
mod tests {
    use super::{DelegationValidationError, is_delegation_valid_with_respect_to_state};
    use crate::encoding::encode_subnet_canister_ranges;
    use assert_matches::assert_matches;
    use ic_canonical_state_tree_hash_test_utils::build_witness_gen;
    use ic_crypto_tree_hash::{FlatMap, Label, LabeledTree, WitnessGenerator, flatmap};
    use ic_registry_routing_table::CanisterIdRange;
    use ic_registry_subnet_type::SubnetType;
    use ic_replicated_state::{
        ReplicatedState, SubnetTopology,
        metadata_state::testing::{NetworkTopologyTesting, SystemMetadataTesting},
    };
    use ic_test_utilities_types::ids::{SUBNET_1, SUBNET_2};
    use ic_types::{
        CanisterId, PrincipalId, SubnetId,
        messages::{Blob, Certificate, CertificateDelegation, CertificateDelegationFormat},
    };
    use rstest::rstest;
    use serde::Serialize;

    fn range(start: u64, end: u64) -> CanisterIdRange {
        CanisterIdRange {
            start: CanisterId::from_u64(start),
            end: CanisterId::from_u64(end),
        }
    }

    /// Encodes canister ranges into a leaf, exactly as the canonical state does
    /// (see [`encode_subnet_canister_ranges`]).
    fn ranges_leaf(ranges: &[CanisterIdRange]) -> LabeledTree<Vec<u8>> {
        let pairs: Vec<(PrincipalId, PrincipalId)> = ranges
            .iter()
            .map(|r| (r.start.get(), r.end.get()))
            .collect();
        LabeledTree::Leaf(encode_subnet_canister_ranges(Some(&pairs)))
    }

    /// `/subnet/<subnet_id>/{canister_ranges, public_key}` (the `Flat` layout).
    fn flat_tree(
        subnet_id: SubnetId,
        public_key: &[u8],
        ranges: &[CanisterIdRange],
    ) -> LabeledTree<Vec<u8>> {
        LabeledTree::SubTree(flatmap![
            Label::from("subnet") => LabeledTree::SubTree(flatmap![
                Label::from(subnet_id.get().to_vec()) => LabeledTree::SubTree(flatmap![
                    Label::from("canister_ranges") => ranges_leaf(ranges),
                    Label::from("public_key") => LabeledTree::Leaf(public_key.to_vec()),
                ]),
            ]),
        ])
    }

    /// `/subnet/<subnet_id>/public_key` plus a `/canister_ranges/<subnet_id>`
    /// subtree holding one leaf per range, keyed by the range's start (the `Tree`
    /// layout).
    fn tree_layout(
        subnet_id: SubnetId,
        public_key: &[u8],
        ranges: &[CanisterIdRange],
    ) -> LabeledTree<Vec<u8>> {
        let leaves: Vec<(Label, LabeledTree<Vec<u8>>)> = ranges
            .iter()
            .map(|r| {
                (
                    Label::from(r.start.get().to_vec()),
                    ranges_leaf(std::slice::from_ref(r)),
                )
            })
            .collect();
        LabeledTree::SubTree(flatmap![
            Label::from("canister_ranges") => LabeledTree::SubTree(flatmap![
                Label::from(subnet_id.get().to_vec()) =>
                    LabeledTree::SubTree(FlatMap::from_key_values(leaves)),
            ]),
            Label::from("subnet") => LabeledTree::SubTree(flatmap![
                Label::from(subnet_id.get().to_vec()) => LabeledTree::SubTree(flatmap![
                    Label::from("public_key") => LabeledTree::Leaf(public_key.to_vec()),
                ]),
            ]),
        ])
    }

    /// `/subnet/<subnet_id>/public_key` only (the `Pruned` layout).
    fn pruned_tree(subnet_id: SubnetId, public_key: &[u8]) -> LabeledTree<Vec<u8>> {
        LabeledTree::SubTree(flatmap![
            Label::from("subnet") => LabeledTree::SubTree(flatmap![
                Label::from(subnet_id.get().to_vec()) => LabeledTree::SubTree(flatmap![
                    Label::from("public_key") => LabeledTree::Leaf(public_key.to_vec()),
                ]),
            ]),
        ])
    }

    /// Builds the certificate tree carrying `public_key` and `ranges` for
    /// `subnet_id` in the layout matching `format`. The `Pruned` layout carries
    /// no ranges, so `ranges` is ignored for it.
    fn build_tree(
        format: CertificateDelegationFormat,
        subnet_id: SubnetId,
        public_key: &[u8],
        ranges: &[CanisterIdRange],
    ) -> LabeledTree<Vec<u8>> {
        match format {
            CertificateDelegationFormat::Flat => flat_tree(subnet_id, public_key, ranges),
            CertificateDelegationFormat::Tree => tree_layout(subnet_id, public_key, ranges),
            CertificateDelegationFormat::Pruned => pruned_tree(subnet_id, public_key),
        }
    }

    /// Wraps `tree` into a delegation for `subnet_id`. The signature is
    /// irrelevant: the validator never verifies it.
    fn delegation(subnet_id: SubnetId, tree: &LabeledTree<Vec<u8>>) -> CertificateDelegation {
        let certificate = Certificate {
            tree: build_witness_gen(tree)
                .mixed_hash_tree(tree)
                .expect("failed to build a MixedHashTree"),
            signature: Blob(vec![]),
            delegation: None,
        };
        let mut serializer = serde_cbor::Serializer::new(Vec::new());
        serializer.self_describe().unwrap();
        certificate.serialize(&mut serializer).unwrap();
        CertificateDelegation {
            subnet_id: Blob(subnet_id.get().to_vec()),
            certificate: Blob(serializer.into_inner()),
        }
    }

    /// A replicated state whose certification view maps `subnet_id` to
    /// `public_key` and `ranges`.
    fn state_with(
        subnet_id: SubnetId,
        public_key: Vec<u8>,
        ranges: &[CanisterIdRange],
    ) -> ReplicatedState {
        let mut state = ReplicatedState::new(subnet_id, SubnetType::Application);
        state.metadata.modify_network_topology(|topology| {
            topology.subnets_mut().insert(
                subnet_id,
                SubnetTopology {
                    public_key,
                    ..SubnetTopology::default()
                },
            );
            let routing_table = topology.routing_table_mut();
            for range in ranges {
                routing_table.insert(*range, subnet_id).unwrap();
            }
        });
        state
    }

    /// A delegation whose certified public key and canister ranges agree with the
    /// state is valid, in every layout. In the `Pruned` layout the ranges are
    /// absent (and thus ignored), so a matching public key alone suffices even
    /// though the state does carry ranges.
    #[rstest]
    #[case::flat(CertificateDelegationFormat::Flat)]
    #[case::tree(CertificateDelegationFormat::Tree)]
    #[case::pruned(CertificateDelegationFormat::Pruned)]
    fn delegation_matching_public_key_and_ranges_is_valid(
        #[case] format: CertificateDelegationFormat,
    ) {
        let subnet_id = SUBNET_1;
        let public_key = vec![1, 2, 3];
        let ranges = [range(10, 20), range(100, 200)];
        let state = state_with(subnet_id, public_key.clone(), &ranges);
        let delegation = delegation(
            subnet_id,
            &build_tree(format, subnet_id, &public_key, &ranges),
        );

        assert_matches!(
            is_delegation_valid_with_respect_to_state(&delegation, format, &state),
            Ok(true)
        );
    }

    /// A mismatching public key makes the delegation invalid in every layout,
    /// regardless of whether the ranges match.
    #[rstest]
    #[case::flat(CertificateDelegationFormat::Flat)]
    #[case::tree(CertificateDelegationFormat::Tree)]
    #[case::pruned(CertificateDelegationFormat::Pruned)]
    fn mismatching_public_key_is_invalid(#[case] format: CertificateDelegationFormat) {
        let subnet_id = SUBNET_1;
        let ranges = [range(10, 20)];
        let state = state_with(subnet_id, vec![1, 2, 3], &ranges);
        // Same ranges, different public key.
        let delegation = delegation(
            subnet_id,
            &build_tree(format, subnet_id, &[9, 9, 9], &ranges),
        );

        assert_matches!(
            is_delegation_valid_with_respect_to_state(&delegation, format, &state),
            Ok(false)
        );
    }

    /// The state having no topology for the delegated subnet is an error in every
    /// layout: the subnet is looked up while checking the public key, before the
    /// ranges are considered.
    #[rstest]
    #[case::flat(CertificateDelegationFormat::Flat)]
    #[case::tree(CertificateDelegationFormat::Tree)]
    #[case::pruned(CertificateDelegationFormat::Pruned)]
    fn unknown_subnet_is_an_error(#[case] format: CertificateDelegationFormat) {
        let subnet_id = SUBNET_1;
        // The state does not know about SUBNET_1.
        let state = ReplicatedState::new(subnet_id, SubnetType::Application);
        let delegation = delegation(
            subnet_id,
            &build_tree(format, subnet_id, &[1, 2, 3], &[range(10, 20)]),
        );

        assert_matches!(
            is_delegation_valid_with_respect_to_state(&delegation, format, &state),
            Err(DelegationValidationError::UnknownSubnet(_))
        );
    }

    /// The `Flat` layout requires the certified ranges to match the state
    /// exactly, whereas the `Tree` layout only requires them to be a subset of
    /// what the state assigns to the subnet. Certifying a strict subset of the
    /// state's ranges is therefore invalid under `Flat` but valid under `Tree`.
    /// In the `Pruned` layout, the ranges are absent and thus ignored, so a matching
    /// public key alone suffices for validity.
    #[rstest]
    #[case::flat_requires_exact_match(CertificateDelegationFormat::Flat)]
    #[case::tree_accepts_a_subset(CertificateDelegationFormat::Tree)]
    #[case::pruned_accepts_a_subset(CertificateDelegationFormat::Pruned)]
    fn delegation_certifying_a_subset_of_state_ranges(#[case] format: CertificateDelegationFormat) {
        let subnet_id = SUBNET_1;
        let public_key = vec![1, 2, 3];
        let state = state_with(
            subnet_id,
            public_key.clone(),
            &[range(10, 20), range(100, 200), range(300, 400)],
        );
        // Certify only a subset of the ranges the state assigns to the subnet.
        let subset = [range(10, 20), range(300, 400)];
        let delegation = delegation(
            subnet_id,
            &build_tree(format, subnet_id, &public_key, &subset),
        );

        assert_matches!(
            is_delegation_valid_with_respect_to_state(&delegation, format, &state),
            Ok(is_valid) if is_valid == matches!(format, CertificateDelegationFormat::Tree | CertificateDelegationFormat::Pruned)
        );
    }

    /// A delegation certifying a range that the state does not assign to the subnet
    /// is invalid in the `Flat` and `Tree` layouts, but valid in the `Pruned` layout (which ignores
    /// ranges).
    #[rstest]
    #[case::different_end(vec![range(10, 999)])]
    #[case::extra_range(vec![range(10, 20), range(100, 200), range(500, 1000)])]
    #[case::replaced_range(vec![range(10, 20), range(500, 1000)])]
    #[case::disjoint_range(vec![range(30, 40)])]
    #[case::subset_range(vec![range(10, 13), range(16, 18), range(101, 120)])]
    #[case::merged_range(vec![range(10, 200)])]
    fn delegation_with_ranges_not_matching_state_is_invalid(
        #[case] certified_ranges: Vec<CanisterIdRange>,
        #[values(
            CertificateDelegationFormat::Flat,
            CertificateDelegationFormat::Tree,
            CertificateDelegationFormat::Pruned
        )]
        format: CertificateDelegationFormat,
    ) {
        let subnet_id = SUBNET_1;
        let public_key = vec![1, 2, 3];
        // The state assigns a single range to the subnet.
        let state = state_with(
            subnet_id,
            public_key.clone(),
            &[range(10, 20), range(100, 200)],
        );
        let delegation = delegation(
            subnet_id,
            &build_tree(format, subnet_id, &public_key, &certified_ranges),
        );

        assert_matches!(
            is_delegation_valid_with_respect_to_state(&delegation, format, &state),
            Ok(is_valid) if is_valid == matches!(format, CertificateDelegationFormat::Pruned)
        );
    }

    /// A delegation certifying no ranges at all is invalid in the `Flat` and `Tree` layouts, but
    /// valid in the `Pruned` layout (which ignores ranges).
    #[rstest]
    fn delegation_with_empty_ranges_is_invalid(
        #[values(
            CertificateDelegationFormat::Flat,
            CertificateDelegationFormat::Tree,
            CertificateDelegationFormat::Pruned
        )]
        format: CertificateDelegationFormat,
    ) {
        let subnet_id = SUBNET_1;
        let public_key = vec![1, 2, 3];
        // The state assigns a single range to the subnet.
        let state = state_with(subnet_id, public_key.clone(), &[range(10, 20)]);
        // The delegation certifies no ranges at all.
        let delegation = delegation(subnet_id, &build_tree(format, subnet_id, &public_key, &[]));

        assert_matches!(
            is_delegation_valid_with_respect_to_state(&delegation, format, &state),
            Ok(is_valid) if is_valid == matches!(format, CertificateDelegationFormat::Pruned)
        );
    }

    /// In the `Tree` layout a certified range that the state assigns to a
    /// *different* subnet makes the delegation invalid.
    #[rstest]
    #[case::flat(CertificateDelegationFormat::Flat)]
    #[case::tree(CertificateDelegationFormat::Tree)]
    fn tree_delegation_with_range_assigned_to_another_subnet_is_invalid(
        #[case] format: CertificateDelegationFormat,
    ) {
        let public_key = vec![1, 2, 3];
        // SUBNET_1 owns 10-20; SUBNET_2 owns 100-200.
        let mut state = state_with(SUBNET_1, public_key.clone(), &[range(10, 20)]);
        state.metadata.modify_network_topology(|topology| {
            topology
                .routing_table_mut()
                .insert(range(100, 200), SUBNET_2)
                .unwrap();
        });
        // The delegation for SUBNET_1 certifies a range the state assigns to SUBNET_2.
        let delegation = delegation(
            SUBNET_1,
            &build_tree(format, SUBNET_1, &public_key, &[range(100, 200)]),
        );

        assert_matches!(
            is_delegation_valid_with_respect_to_state(&delegation, format, &state),
            Ok(false)
        );
    }

    /// The canister-ranges path required by the layout being absent is an error (a
    /// missing `Flat` leaf or a missing `Tree` subtree). A `Pruned` tree carries
    /// the public key but neither ranges path, so validating it as `Flat` or
    /// `Tree` fails.
    #[rstest]
    #[case::flat(CertificateDelegationFormat::Flat)]
    #[case::tree(CertificateDelegationFormat::Tree)]
    fn delegation_missing_canister_ranges_is_an_error(#[case] format: CertificateDelegationFormat) {
        let public_key = vec![1, 2, 3];
        let state = state_with(SUBNET_1, public_key.clone(), &[range(10, 20)]);
        // The public key is present (so that check passes) but the ranges path
        // required by `format` is missing.
        let delegation = delegation(SUBNET_1, &pruned_tree(SUBNET_1, &public_key));

        assert_matches!(
            is_delegation_valid_with_respect_to_state(&delegation, format, &state),
            Err(DelegationValidationError::UnexpectedTreeShape(_))
        );
    }
}
