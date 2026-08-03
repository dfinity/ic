//! Validation of an NNS delegation against the subnet information recorded in a
//! replicated state.
//!
//! A subnet delegation issued by the NNS certifies, for a given subnet, its
//! threshold public key and the set of canister ID ranges assigned to it. This
//! module checks that the contents of such a delegation agree with the subnet
//! information recorded in a replicated state (as it is exposed in the
//! certified state tree): the certified public key must match the one in the
//! state, and the certified canister ranges must match the ranges the state
//! assigns to that subnet.
//!
//! The check works directly on the delegation certificate's [`LabeledTree`]. What is
//! checked in the certified canister ranges is specified by [`CanisterRangesCheck`].
//!
//! In some cases, the delegation fetched from the NNS could mismatch the information
//! stored in the state, for example right after a subnet split: the subnet starts
//! certifying with a fresh threshold key while the cached NNS delegation may still
//! carry the previous key for up to a few minutes. Similarly, right before a subnet
//! split, the delegation might already carry the new key while the certified state
//! still carries the old key.

use ic_crypto_tree_hash::{LabeledTree, LookupLowerBoundStatus, lookup_lower_bound, lookup_path};
use ic_registry_routing_table::CanisterIdRanges;
use ic_types::{CanisterId, PrincipalId, SubnetId};
use std::fmt;

/// What to check the canister ranges certified in a delegation against.
///
/// The certified threshold public key is always checked, independently of the variant.
#[derive(Clone, Copy, Eq, PartialEq, Debug)]
pub enum CanisterRangesCheck {
    /// Check that the certified canister ranges at `/subnet/<subnet_id>/canister_ranges`
    /// exactly match all the ranges which the state assigns to the delegated subnet. Ranges
    /// certified at `/canister_ranges/<subnet_id>` are ignored.
    AllSubnetRanges,
    // TODO: Add more variants to check for the existence of a specific canister
}

/// An error encountered while checking a delegation against a replicated state.
///
/// These indicate that validity could *not be determined* (e.g. a malformed
/// canister ranges leaf), as opposed to the delegation being found inconsistent
/// with the state.
#[derive(Debug)]
pub enum DelegationValidationError {
    /// An expected path was missing from the certificate or had an unexpected shape.
    UnexpectedTreeShape(String),
    /// A certified canister-ranges leaf could not be CBOR-decoded.
    MalformedCanisterRanges(serde_cbor::Error),
    /// The state has no topology for the delegated subnet.
    UnknownSubnet(SubnetId),
}

impl fmt::Display for DelegationValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
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

/// An error encountered while verifying a delegation against a replicated state before
/// serving it.
#[derive(Debug)]
pub enum DelegationVerificationError {
    /// The delegation disagrees with the state view. This is typically transient (e.g.
    /// right after a subnet split) — retry once the manager has refetched the delegation.
    Inconsistent,
    /// Consistency could not be determined.
    Validation(DelegationValidationError),
}

impl fmt::Display for DelegationVerificationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Inconsistent => {
                write!(f, "the delegation is inconsistent with the certified state")
            }
            Self::Validation(err) => {
                write!(
                    f,
                    "failed to verify the delegation against the state: {err}"
                )
            }
        }
    }
}

impl std::error::Error for DelegationVerificationError {}

/// Checks whether the delegation certificate tree is consistent with the given view
/// of the subnet information recorded in a replicated state.
///
/// Returns `Ok(true)` if, for the subnet the delegation refers to, both:
/// * the threshold public key certified in `tree` (at `/subnet/<subnet_id>/public_key`)
///   matches `expected_subnet_public_key`; and
/// * the canister ranges certified in `tree` pass the check specified by
///   `ranges_check`, against `expected_subnet_ranges`, the ranges which the state assigns to the
///   delegated subnet (see [`CanisterRangesCheck`]).
///
/// Returns `Ok(false)` if either of those does not match. Any error that
/// prevents the comparison (malformed canister ranges, missing public key,
/// missing canister ranges leaf, ...) is returned as `Err`.
pub(crate) fn is_tree_consistent_with(
    tree: &LabeledTree<Vec<u8>>,
    subnet_id: SubnetId,
    expected_subnet_public_key: &[u8],
    expected_subnet_ranges: &CanisterIdRanges,
    ranges_check: CanisterRangesCheck,
) -> Result<bool, DelegationValidationError> {
    if !does_public_key_match(tree, subnet_id, expected_subnet_public_key)? {
        return Ok(false);
    }

    match ranges_check {
        CanisterRangesCheck::AllSubnetRanges => {
            do_all_subnet_ranges_match(tree, subnet_id, expected_subnet_ranges)
        }
    }
}

/// Returns whether the public key certified in `tree` matches `expected_public_key`.
fn does_public_key_match(
    tree: &LabeledTree<Vec<u8>>,
    subnet_id: SubnetId,
    expected_public_key: &[u8],
) -> Result<bool, DelegationValidationError> {
    match lookup_path(
        tree,
        &[b"subnet", subnet_id.get_ref().as_slice(), b"public_key"],
    ) {
        Some(LabeledTree::Leaf(public_key)) => Ok(public_key.as_slice() == expected_public_key),
        _ => Err(DelegationValidationError::UnexpectedTreeShape(format!(
            "missing /subnet/{subnet_id}/public_key leaf"
        ))),
    }
}

/// Returns whether the canister ranges certified in `tree` exactly match `subnet_ranges` at
/// `/subnet/<subnet_id>/canister_ranges`.
fn do_all_subnet_ranges_match(
    tree: &LabeledTree<Vec<u8>>,
    subnet_id: SubnetId,
    subnet_ranges: &CanisterIdRanges,
) -> Result<bool, DelegationValidationError> {
    let subnet_ranges: Vec<(PrincipalId, PrincipalId)> = subnet_ranges
        .iter()
        .map(|range| (range.start.get(), range.end.get()))
        .collect();

    do_flat_ranges_match(tree, subnet_id, &subnet_ranges)?.ok_or_else(|| {
        DelegationValidationError::UnexpectedTreeShape(format!(
            "missing /subnet/{subnet_id}/canister_ranges leaf"
        ))
    })
}

/// Returns whether the ranges certified in the `/subnet/<subnet_id>/canister_ranges`
/// leaf exactly match `state_ranges`, or `None` if the leaf is not present in `tree`.
fn do_flat_ranges_match(
    tree: &LabeledTree<Vec<u8>>,
    subnet_id: SubnetId,
    state_ranges: &[(PrincipalId, PrincipalId)],
) -> Result<Option<bool>, DelegationValidationError> {
    match lookup_path(
        tree,
        &[
            b"subnet",
            subnet_id.get_ref().as_slice(),
            b"canister_ranges",
        ],
    ) {
        Some(LabeledTree::Leaf(bytes)) => {
            Ok(Some(decode_ranges(bytes)?.as_slice() == state_ranges))
        }
        Some(LabeledTree::SubTree(_)) => Err(DelegationValidationError::UnexpectedTreeShape(
            format!("unexpected subtree at /subnet/{subnet_id}/canister_ranges"),
        )),
        None => Ok(None),
    }
}

/// Decodes a canister ranges leaf. Canister ranges are stored as self-describing CBOR
/// of `(start, end)` principal pairs (see the canonical state's
/// `encode_subnet_canister_ranges`).
fn decode_ranges(
    bytes: &[u8],
) -> Result<Vec<(PrincipalId, PrincipalId)>, DelegationValidationError> {
    serde_cbor::from_slice::<Vec<(PrincipalId, PrincipalId)>>(bytes)
        .map_err(DelegationValidationError::MalformedCanisterRanges)
}

#[cfg(test)]
mod tests {
    use super::{CanisterRangesCheck, DelegationValidationError, is_tree_consistent_with};
    use assert_matches::assert_matches;
    use ic_canonical_state::encoding::encode_subnet_canister_ranges;
    use ic_crypto_tree_hash::{FlatMap, Label, LabeledTree, flatmap};
    use ic_registry_routing_table::{CanisterIdRange, CanisterIdRanges};
    use ic_test_utilities_types::ids::{SUBNET_1, SUBNET_2};
    use ic_types::{CanisterId, PrincipalId, SubnetId};
    use rstest::rstest;

    /// Checks the tree against the given state view with the `AllSubnetRanges` check.
    fn validate_all_subnet_ranges(
        tree: &LabeledTree<Vec<u8>>,
        subnet_id: SubnetId,
        expected_public_key: &[u8],
        subnet_ranges: &[CanisterIdRange],
    ) -> Result<bool, DelegationValidationError> {
        is_tree_consistent_with(
            tree,
            subnet_id,
            expected_public_key,
            &CanisterIdRanges::try_from(subnet_ranges.to_vec()).unwrap(),
            CanisterRangesCheck::AllSubnetRanges,
        )
    }

    /// Which canister ranges locations the delegation certificate tree carries.
    #[derive(Copy, Clone, Debug)]
    enum Layout {
        /// Only the `/subnet/<subnet_id>/canister_ranges` leaf.
        FlatOnly,
        /// Only the `/canister_ranges/<subnet_id>` subtree.
        TreeOnly,
        /// Both locations (the layout of a delegation as received from the NNS).
        Both,
        /// Neither location, i.e. only the public key.
        KeyOnly,
    }

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

    /// The `/canister_ranges/<subnet_id>` subtree holding one leaf per range, keyed by
    /// the range's start.
    fn tree_ranges_subtree(ranges: &[CanisterIdRange]) -> LabeledTree<Vec<u8>> {
        let leaves: Vec<(Label, LabeledTree<Vec<u8>>)> = ranges
            .iter()
            .map(|r| {
                (
                    Label::from(r.start.get().to_vec()),
                    ranges_leaf(std::slice::from_ref(r)),
                )
            })
            .collect();
        LabeledTree::SubTree(FlatMap::from_key_values(leaves))
    }

    /// Builds the certificate tree certifying `public_key` for `subnet_id`, with the
    /// canister ranges in the locations dictated by `layout`: `flat_ranges` in the
    /// `/subnet/<subnet_id>/canister_ranges` leaf and/or `tree_ranges` in the
    /// `/canister_ranges/<subnet_id>` subtree.
    fn build_tree_with_distinct_ranges(
        layout: Layout,
        subnet_id: SubnetId,
        public_key: &[u8],
        flat_ranges: &[CanisterIdRange],
        tree_ranges: &[CanisterIdRange],
    ) -> LabeledTree<Vec<u8>> {
        let mut subnet_children: Vec<(Label, LabeledTree<Vec<u8>>)> = Vec::new();
        if matches!(layout, Layout::FlatOnly | Layout::Both) {
            subnet_children.push((Label::from("canister_ranges"), ranges_leaf(flat_ranges)));
        }
        subnet_children.push((
            Label::from("public_key"),
            LabeledTree::Leaf(public_key.to_vec()),
        ));

        let mut root_children: Vec<(Label, LabeledTree<Vec<u8>>)> = Vec::new();
        if matches!(layout, Layout::TreeOnly | Layout::Both) {
            root_children.push((
                Label::from("canister_ranges"),
                LabeledTree::SubTree(flatmap![
                    Label::from(subnet_id.get().to_vec()) => tree_ranges_subtree(tree_ranges),
                ]),
            ));
        }
        root_children.push((
            Label::from("subnet"),
            LabeledTree::SubTree(flatmap![
                Label::from(subnet_id.get().to_vec()) =>
                    LabeledTree::SubTree(FlatMap::from_key_values(subnet_children)),
            ]),
        ));

        LabeledTree::SubTree(FlatMap::from_key_values(root_children))
    }

    /// Builds the certificate tree certifying `public_key` and `ranges` for `subnet_id`,
    /// with the ranges in the locations dictated by `layout`.
    fn build_tree(
        layout: Layout,
        subnet_id: SubnetId,
        public_key: &[u8],
        ranges: &[CanisterIdRange],
    ) -> LabeledTree<Vec<u8>> {
        build_tree_with_distinct_ranges(layout, subnet_id, public_key, ranges, ranges)
    }

    /// A delegation whose certified public key and canister ranges (in the flat leaf,
    /// the only location the check considers) agree with the state is consistent with it.
    #[rstest]
    #[case::flat_only(Layout::FlatOnly)]
    #[case::both(Layout::Both)]
    fn delegation_matching_public_key_and_ranges_is_valid(#[case] layout: Layout) {
        let subnet_id = SUBNET_1;
        let public_key = vec![1, 2, 3];
        let ranges = [range(10, 20), range(100, 200)];
        let tree = build_tree(layout, subnet_id, &public_key, &ranges);

        assert_matches!(
            validate_all_subnet_ranges(&tree, subnet_id, &public_key, &ranges),
            Ok(true),
            "a delegation whose public key and ranges match the state should be valid in the {layout:?} layout"
        );
    }

    /// A mismatching public key makes the delegation invalid in every layout,
    /// regardless of whether the ranges match.
    #[rstest]
    #[case::flat_only(Layout::FlatOnly)]
    #[case::tree_only(Layout::TreeOnly)]
    #[case::both(Layout::Both)]
    #[case::key_only(Layout::KeyOnly)]
    fn mismatching_public_key_is_invalid(#[case] layout: Layout) {
        let subnet_id = SUBNET_1;
        let ranges = [range(10, 20)];
        // Same ranges, different public key.
        let tree = build_tree(layout, subnet_id, &[9, 9, 9], &ranges);

        assert_matches!(
            validate_all_subnet_ranges(&tree, subnet_id, &[1, 2, 3], &ranges),
            Ok(false),
            "a delegation with a mismatching public key should be invalid in the {layout:?} layout"
        );
    }

    /// A missing public key leaf is an error in every layout.
    #[rstest]
    #[case::flat_only(Layout::FlatOnly)]
    #[case::tree_only(Layout::TreeOnly)]
    #[case::both(Layout::Both)]
    #[case::key_only(Layout::KeyOnly)]
    fn missing_public_key_is_an_error(#[case] layout: Layout) {
        let ranges = [range(10, 20)];
        // The tree certifies SUBNET_2, so there is no public key (nor any other
        // information) for SUBNET_1.
        let tree = build_tree(layout, SUBNET_2, &[1, 2, 3], &ranges);

        assert_matches!(
            validate_all_subnet_ranges(&tree, SUBNET_1, &[1, 2, 3], &ranges),
            Err(DelegationValidationError::UnexpectedTreeShape(_)),
            "validating a delegation without a public key for the subnet should fail with \
             UnexpectedTreeShape in the {layout:?} layout"
        );
    }

    /// Certifying a strict subset of the state's ranges is invalid: all ranges which
    /// the state assigns to the subnet must be certified.
    #[rstest]
    #[case::flat_only(Layout::FlatOnly)]
    #[case::both(Layout::Both)]
    fn delegation_certifying_a_subset_of_state_ranges_is_invalid(#[case] layout: Layout) {
        let subnet_id = SUBNET_1;
        let public_key = vec![1, 2, 3];
        let state_ranges = [range(10, 20), range(100, 200), range(300, 400)];
        // Certify only a subset of the ranges the state assigns to the subnet.
        let subset = [range(10, 20), range(300, 400)];
        let tree = build_tree(layout, subnet_id, &public_key, &subset);

        assert_matches!(
            validate_all_subnet_ranges(&tree, subnet_id, &public_key, &state_ranges),
            Ok(false),
            "certifying a strict subset of the state's ranges should be invalid in the {layout:?} layout"
        );
    }

    /// A delegation certifying ranges in the flat leaf which do not exactly match the
    /// ranges the state assigns to the subnet is invalid.
    #[rstest]
    #[case::different_end(vec![range(10, 999)])]
    #[case::extra_range(vec![range(10, 20), range(100, 200), range(500, 1000)])]
    #[case::replaced_range(vec![range(10, 20), range(500, 1000)])]
    #[case::disjoint_range(vec![range(30, 40)])]
    #[case::subset_range(vec![range(10, 13), range(16, 18), range(101, 120)])]
    #[case::merged_range(vec![range(10, 200)])]
    fn delegation_with_ranges_not_matching_state_is_invalid(
        #[case] certified_ranges: Vec<CanisterIdRange>,
        #[values(Layout::FlatOnly, Layout::Both)] layout: Layout,
    ) {
        let subnet_id = SUBNET_1;
        let public_key = vec![1, 2, 3];
        let state_ranges = [range(10, 20), range(100, 200)];
        let tree = build_tree(layout, subnet_id, &public_key, &certified_ranges);

        assert_matches!(
            validate_all_subnet_ranges(&tree, subnet_id, &public_key, &state_ranges),
            Ok(false),
            "certifying ranges {certified_ranges:?} which the state does not assign to the \
             subnet should be invalid in the {layout:?} layout"
        );
    }

    /// Ranges certified in the `/canister_ranges/<subnet_id>` subtree are ignored:
    /// only the flat leaf decides whether the certified ranges match the state.
    #[rstest]
    #[case::mismatching_tree_location_is_ignored(&[range(10, 20)], &[range(10, 999)], true)]
    #[case::matching_tree_location_does_not_help(&[range(10, 999)], &[range(10, 20)], false)]
    fn tree_ranges_location_is_ignored(
        #[case] flat_ranges: &[CanisterIdRange],
        #[case] tree_ranges: &[CanisterIdRange],
        #[case] expected_validity: bool,
    ) {
        let subnet_id = SUBNET_1;
        let public_key = vec![1, 2, 3];
        let state_ranges = [range(10, 20)];
        let tree = build_tree_with_distinct_ranges(
            Layout::Both,
            subnet_id,
            &public_key,
            flat_ranges,
            tree_ranges,
        );

        assert_matches!(
            validate_all_subnet_ranges(&tree, subnet_id, &public_key, &state_ranges),
            Ok(is_valid) if is_valid == expected_validity,
            "only the flat leaf should decide the validity of the delegation; the \
             /canister_ranges/{subnet_id} subtree should be ignored"
        );
    }

    /// A missing `/subnet/<subnet_id>/canister_ranges` leaf is an error, regardless of
    /// whether the state assigns any ranges to the subnet and of any ranges certified
    /// in the (ignored) `/canister_ranges/<subnet_id>` subtree.
    #[rstest]
    fn delegation_without_flat_ranges_leaf_is_an_error(
        #[values(Layout::TreeOnly, Layout::KeyOnly)] layout: Layout,
        #[values(true, false)] state_has_ranges: bool,
    ) {
        let subnet_id = SUBNET_1;
        let public_key = vec![1, 2, 3];
        let ranges = [range(10, 20)];
        let state_ranges = if state_has_ranges { &ranges[..] } else { &[] };
        let tree = build_tree(layout, subnet_id, &public_key, &ranges);

        assert_matches!(
            validate_all_subnet_ranges(&tree, subnet_id, &public_key, state_ranges),
            Err(DelegationValidationError::UnexpectedTreeShape(_)),
            "a delegation without the /subnet/{subnet_id}/canister_ranges leaf should fail \
             with UnexpectedTreeShape in the {layout:?} layout \
             (state_has_ranges: {state_has_ranges})"
        );
    }

    /// An empty `/subnet/<subnet_id>/canister_ranges` leaf (certifying no ranges at all)
    /// is invalid when the state assigns ranges to the subnet, and valid when it does not.
    #[rstest]
    #[case::state_with_ranges(vec![range(10, 20)], false)]
    #[case::state_without_ranges(vec![], true)]
    fn delegation_with_empty_flat_ranges_leaf(
        #[case] state_ranges: Vec<CanisterIdRange>,
        #[case] expected_validity: bool,
    ) {
        let subnet_id = SUBNET_1;
        let public_key = vec![1, 2, 3];
        let tree = build_tree(Layout::FlatOnly, subnet_id, &public_key, &[]);

        assert_matches!(
            validate_all_subnet_ranges(&tree, subnet_id, &public_key, &state_ranges),
            Ok(is_valid) if is_valid == expected_validity,
            "a delegation certifying an empty list of ranges should be valid if and only \
             if the state assigns no ranges to the subnet, but the state assigns \
             {state_ranges:?}"
        );
    }

    /// A flat canister ranges leaf which cannot be CBOR-decoded is an error.
    #[test]
    fn delegation_with_malformed_flat_ranges_is_an_error() {
        let subnet_id = SUBNET_1;
        let public_key = vec![1, 2, 3];
        let tree = LabeledTree::SubTree(flatmap![
            Label::from("subnet") => LabeledTree::SubTree(flatmap![
                Label::from(subnet_id.get().to_vec()) => LabeledTree::SubTree(flatmap![
                    Label::from("canister_ranges") => LabeledTree::Leaf(vec![0xFF, 0xFF]),
                    Label::from("public_key") => LabeledTree::Leaf(public_key.clone()),
                ]),
            ]),
        ]);

        assert_matches!(
            validate_all_subnet_ranges(&tree, subnet_id, &public_key, &[range(10, 20)]),
            Err(DelegationValidationError::MalformedCanisterRanges(_)),
            "a delegation with a malformed /subnet/{subnet_id}/canister_ranges leaf should \
             fail with MalformedCanisterRanges"
        );
    }

    /// A malformed leaf under `/canister_ranges/<subnet_id>` does not affect the check:
    /// that location is never read.
    #[test]
    fn delegation_with_malformed_tree_ranges_is_valid() {
        let subnet_id = SUBNET_1;
        let public_key = vec![1, 2, 3];
        let ranges = [range(10, 20)];
        let tree = LabeledTree::SubTree(flatmap![
            Label::from("canister_ranges") => LabeledTree::SubTree(flatmap![
                Label::from(subnet_id.get().to_vec()) => LabeledTree::SubTree(flatmap![
                    Label::from(CanisterId::from_u64(10).get().to_vec()) =>
                        LabeledTree::Leaf(vec![0xFF, 0xFF]),
                ]),
            ]),
            Label::from("subnet") => LabeledTree::SubTree(flatmap![
                Label::from(subnet_id.get().to_vec()) => LabeledTree::SubTree(flatmap![
                    Label::from("canister_ranges") => ranges_leaf(&ranges),
                    Label::from("public_key") => LabeledTree::Leaf(public_key.clone()),
                ]),
            ]),
        ]);

        assert_matches!(
            validate_all_subnet_ranges(&tree, subnet_id, &public_key, &ranges),
            Ok(true),
            "a malformed leaf under /canister_ranges/{subnet_id} should be ignored as long \
             as the flat leaf matches the state"
        );
    }
}
