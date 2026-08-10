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
use ic_registry_routing_table::RoutingTable;
use ic_types::{CanisterId, PrincipalId, SubnetId};
use std::fmt;

/// What to check the canister ranges certified in a delegation against.
///
/// The certified threshold public key is always checked, independently of the variant.
#[derive(Clone, Copy, Eq, PartialEq, Debug)]
pub enum CanisterRangesCheck {
    /// Check that the certified canister ranges at `/subnet/<subnet_id>/canister_ranges`
    /// exactly match all the ranges which the state assigns to the delegated subnet. Ranges
    /// certified at `/canister_ranges/<subnet_id>` are ignored because if the delegation is built
    /// correctly, the two locations should always match.
    AllSubnetRanges,
    /// Check that the ranges certified at `/subnet/<subnet_id>/canister_ranges` cover the
    /// given canister id if and only if the state assigns it to the delegated subnet.
    /// It is not a problem if other parts of the certified ranges are inconsistent with
    /// the state. Ranges certified at `/canister_ranges/<subnet_id>` are ignored.
    CanisterInFlat(CanisterId),
    /// Check that the ranges certified at `/canister_ranges/<subnet_id>` cover the given
    /// canister id if and only if the state assigns it to the delegated subnet. Only the
    /// single leaf which could cover the canister id is read, so it is not a problem if
    /// other parts of the certified ranges are inconsistent with the state. The
    /// `/subnet/<subnet_id>/canister_ranges` leaf is ignored.
    CanisterInTree(CanisterId),
    /// Don't check the canister ranges at all (e.g. for pruned delegations which don't
    /// carry any).
    NoCheck,
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
///   `ranges_check`, against the state's `routing_table` (see [`CanisterRangesCheck`]).
///
/// Returns `Ok(false)` if either of those does not match. Any error that
/// prevents the comparison (malformed canister ranges, missing public key,
/// missing canister ranges leaf, ...) is returned as `Err`.
pub(crate) fn is_tree_consistent_with(
    tree: &LabeledTree<Vec<u8>>,
    subnet_id: SubnetId,
    expected_subnet_public_key: &[u8],
    routing_table: &RoutingTable,
    ranges_check: CanisterRangesCheck,
) -> Result<bool, DelegationValidationError> {
    if !does_public_key_match(tree, subnet_id, expected_subnet_public_key)? {
        return Ok(false);
    }

    match ranges_check {
        CanisterRangesCheck::AllSubnetRanges => {
            do_all_subnet_ranges_match(tree, subnet_id, routing_table)
        }
        CanisterRangesCheck::CanisterInFlat(canister_id) => {
            let state_covers = routing_table
                .lookup_entry(canister_id)
                .map(|(_, responsible_subnet)| responsible_subnet == subnet_id)
                .unwrap_or(false);
            Ok(do_flat_ranges_cover_canister(tree, subnet_id, canister_id)? == state_covers)
        }
        CanisterRangesCheck::CanisterInTree(canister_id) => {
            let state_covers = routing_table
                .lookup_entry(canister_id)
                .map(|(_, responsible_subnet)| responsible_subnet == subnet_id)
                .unwrap_or(false);
            Ok(do_tree_ranges_cover_canister(tree, subnet_id, canister_id)? == state_covers)
        }
        CanisterRangesCheck::NoCheck => Ok(true),
    }
}

/// Returns whether the canister ranges certified in `tree` at
/// `/subnet/<subnet_id>/canister_ranges` exactly match the ranges which `routing_table`
/// assigns to the subnet.
fn do_all_subnet_ranges_match(
    tree: &LabeledTree<Vec<u8>>,
    subnet_id: SubnetId,
    routing_table: &RoutingTable,
) -> Result<bool, DelegationValidationError> {
    let subnet_ranges: Vec<(PrincipalId, PrincipalId)> = routing_table
        .ranges(subnet_id)
        .iter()
        .map(|range| (range.start.get(), range.end.get()))
        .collect();

    do_flat_ranges_match(tree, subnet_id, &subnet_ranges)
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
        Some(LabeledTree::SubTree(_)) => Err(DelegationValidationError::UnexpectedTreeShape(
            format!("unexpected subtree at /subnet/{subnet_id}/public_key"),
        )),
        None => Err(DelegationValidationError::UnexpectedTreeShape(format!(
            "missing /subnet/{subnet_id}/public_key leaf"
        ))),
    }
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
        Some(LabeledTree::Leaf(bytes)) => Ok(decode_ranges(bytes)?.as_slice() == state_ranges),
        Some(LabeledTree::SubTree(_)) => Err(DelegationValidationError::UnexpectedTreeShape(
            format!("unexpected subtree at /subnet/{subnet_id}/canister_ranges"),
        )),
        None => Err(DelegationValidationError::UnexpectedTreeShape(format!(
            "missing /subnet/{subnet_id}/canister_ranges leaf"
        ))),
    }
}

/// Returns whether the ranges certified in the `/subnet/<subnet_id>/canister_ranges`
/// leaf cover `canister_id`.
fn do_flat_ranges_cover_canister(
    tree: &LabeledTree<Vec<u8>>,
    subnet_id: SubnetId,
    canister_id: CanisterId,
) -> Result<bool, DelegationValidationError> {
    match lookup_path(
        tree,
        &[
            b"subnet",
            subnet_id.get_ref().as_slice(),
            b"canister_ranges",
        ],
    ) {
        Some(LabeledTree::Leaf(bytes)) => Ok(do_ranges_cover_canister(
            &decode_ranges(bytes)?,
            canister_id,
        )),
        Some(LabeledTree::SubTree(_)) => Err(DelegationValidationError::UnexpectedTreeShape(
            format!("unexpected subtree at /subnet/{subnet_id}/canister_ranges"),
        )),
        None => Err(DelegationValidationError::UnexpectedTreeShape(format!(
            "missing /subnet/{subnet_id}/canister_ranges leaf"
        ))),
    }
}

/// Returns whether the ranges certified in the leaves of the `/canister_ranges/<subnet_id>`
/// subtree cover `canister_id`.
///
/// The leaves are keyed by the start of the first range they contain, so the only leaf
/// which could cover the canister id is the one with the largest label which is not
/// greater than the canister id; no other leaf is read.
fn do_tree_ranges_cover_canister(
    tree: &LabeledTree<Vec<u8>>,
    subnet_id: SubnetId,
    canister_id: CanisterId,
) -> Result<bool, DelegationValidationError> {
    match lookup_lower_bound(
        tree,
        &[b"canister_ranges", subnet_id.get_ref().as_slice()],
        canister_id.get_ref().as_slice(),
    ) {
        LookupLowerBoundStatus::Found(_label, LabeledTree::Leaf(bytes)) => Ok(
            do_ranges_cover_canister(&decode_ranges(bytes)?, canister_id),
        ),
        LookupLowerBoundStatus::Found(label, LabeledTree::SubTree(_)) => {
            Err(DelegationValidationError::UnexpectedTreeShape(format!(
                "unexpected subtree at /canister_ranges/{subnet_id}/{label}"
            )))
        }
        // All the leaves' ranges start beyond the canister id, so none covers it.
        LookupLowerBoundStatus::LabelNotFound => Ok(false),
        LookupLowerBoundStatus::PrefixNotFound => {
            Err(DelegationValidationError::UnexpectedTreeShape(format!(
                "missing /canister_ranges/{subnet_id} subtree"
            )))
        }
    }
}

/// Returns whether any of the decoded ranges covers `canister_id`.
fn do_ranges_cover_canister(
    ranges: &[(PrincipalId, PrincipalId)],
    canister_id: CanisterId,
) -> bool {
    ranges.iter().any(|(start, end)| {
        CanisterId::unchecked_from_principal(*start) <= canister_id
            && canister_id <= CanisterId::unchecked_from_principal(*end)
    })
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
    use ic_registry_routing_table::{CanisterIdRange, RoutingTable};
    use ic_test_utilities_types::ids::{SUBNET_1, SUBNET_2};
    use ic_types::{CanisterId, PrincipalId, SubnetId};
    use rstest::rstest;

    /// Checks the tree against the given state view.
    fn validate(
        tree: &LabeledTree<Vec<u8>>,
        subnet_id: SubnetId,
        expected_public_key: &[u8],
        subnet_ranges: &[CanisterIdRange],
        ranges_check: CanisterRangesCheck,
    ) -> Result<bool, DelegationValidationError> {
        let mut routing_table = RoutingTable::default();
        for range in subnet_ranges {
            routing_table.insert(*range, subnet_id).unwrap();
        }

        is_tree_consistent_with(
            tree,
            subnet_id,
            expected_public_key,
            &routing_table,
            ranges_check,
        )
    }

    /// Checks the tree against the given state view with the `AllSubnetRanges` check,
    /// where the state's routing table assigns `subnet_ranges` to the subnet.
    fn validate_all_subnet_ranges(
        tree: &LabeledTree<Vec<u8>>,
        subnet_id: SubnetId,
        expected_public_key: &[u8],
        subnet_ranges: &[CanisterIdRange],
    ) -> Result<bool, DelegationValidationError> {
        validate(
            tree,
            subnet_id,
            expected_public_key,
            subnet_ranges,
            CanisterRangesCheck::AllSubnetRanges,
        )
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

    /// Builds the full certificate tree certifying `public_key` for `subnet_id`, as
    /// received from the NNS: the canister ranges are certified in both locations,
    /// `flat_ranges` in the `/subnet/<subnet_id>/canister_ranges` leaf and `tree_ranges`
    /// in the `/canister_ranges/<subnet_id>` subtree.
    fn build_tree_with_distinct_ranges(
        subnet_id: SubnetId,
        public_key: &[u8],
        flat_ranges: &[CanisterIdRange],
        tree_ranges: &[CanisterIdRange],
    ) -> LabeledTree<Vec<u8>> {
        LabeledTree::SubTree(flatmap![
            Label::from("canister_ranges") => LabeledTree::SubTree(flatmap![
                Label::from(subnet_id.get().to_vec()) => tree_ranges_subtree(tree_ranges),
            ]),
            Label::from("subnet") => LabeledTree::SubTree(flatmap![
                Label::from(subnet_id.get().to_vec()) => LabeledTree::SubTree(flatmap![
                    Label::from("canister_ranges") => ranges_leaf(flat_ranges),
                    Label::from("public_key") => LabeledTree::Leaf(public_key.to_vec()),
                ]),
            ]),
        ])
    }

    /// Builds the full certificate tree certifying `public_key` and `ranges` (in both
    /// canister ranges locations) for `subnet_id`.
    fn build_tree(
        subnet_id: SubnetId,
        public_key: &[u8],
        ranges: &[CanisterIdRange],
    ) -> LabeledTree<Vec<u8>> {
        build_tree_with_distinct_ranges(subnet_id, public_key, ranges, ranges)
    }

    /// A delegation whose certified public key and canister ranges agree with the state
    /// is consistent with it.
    #[test]
    fn delegation_matching_public_key_and_ranges_is_valid() {
        let subnet_id = SUBNET_1;
        let public_key = vec![1, 2, 3];
        let ranges = [range(10, 20), range(100, 200)];
        let tree = build_tree(subnet_id, &public_key, &ranges);

        assert_matches!(
            validate_all_subnet_ranges(&tree, subnet_id, &public_key, &ranges),
            Ok(true),
            "a delegation whose public key and ranges match the state should be valid"
        );
    }

    /// A mismatching public key makes the delegation invalid, regardless of whether the
    /// ranges match.
    #[test]
    fn mismatching_public_key_is_invalid() {
        let subnet_id = SUBNET_1;
        let ranges = [range(10, 20)];
        // Same ranges, different public key.
        let tree = build_tree(subnet_id, &[9, 9, 9], &ranges);

        assert_matches!(
            validate_all_subnet_ranges(&tree, subnet_id, &[1, 2, 3], &ranges),
            Ok(false),
            "a delegation with a mismatching public key should be invalid"
        );
    }

    /// A missing public key leaf is an error.
    #[test]
    fn missing_public_key_is_an_error() {
        let ranges = [range(10, 20)];
        // The tree certifies SUBNET_2, so there is no public key (nor any other
        // information) for SUBNET_1.
        let tree = build_tree(SUBNET_2, &[1, 2, 3], &ranges);

        assert_matches!(
            validate_all_subnet_ranges(&tree, SUBNET_1, &[1, 2, 3], &ranges),
            Err(DelegationValidationError::UnexpectedTreeShape(err)) if err.contains("public_key leaf"),
            "a delegation without a public key for the subnet should fail with UnexpectedTreeShape"
        );
    }

    /// A subtree where the `/subnet/<subnet_id>/public_key` leaf is expected is an error.
    #[test]
    fn delegation_with_subtree_instead_of_public_key_leaf_is_an_error() {
        let subnet_id = SUBNET_1;
        let public_key = vec![1, 2, 3];
        let ranges = [range(10, 20)];
        let tree = LabeledTree::SubTree(flatmap![
            Label::from("canister_ranges") => LabeledTree::SubTree(flatmap![
                Label::from(subnet_id.get().to_vec()) => tree_ranges_subtree(&ranges),
            ]),
            Label::from("subnet") => LabeledTree::SubTree(flatmap![
                Label::from(subnet_id.get().to_vec()) => LabeledTree::SubTree(flatmap![
                    Label::from("canister_ranges") => ranges_leaf(&ranges),
                    Label::from("public_key") => LabeledTree::SubTree(flatmap![
                        Label::from("unexpected") => LabeledTree::Leaf(public_key.clone()),
                    ]),
                ]),
            ]),
        ]);

        assert_matches!(
            validate_all_subnet_ranges(&tree, subnet_id, &public_key, &ranges),
            Err(DelegationValidationError::UnexpectedTreeShape(err)) if err.contains("unexpected subtree"),
            "a subtree at /subnet/{subnet_id}/public_key (where a leaf is expected) should \
             fail with UnexpectedTreeShape"
        );
    }

    /// A delegation certifying ranges which do not exactly match the ranges the state
    /// assigns to the subnet is invalid.
    #[rstest]
    #[case::different_end(vec![range(10, 999)])]
    #[case::missing_range(vec![range(10, 20)])]
    #[case::extra_range(vec![range(10, 20), range(100, 200), range(500, 1000)])]
    #[case::replaced_range(vec![range(10, 20), range(500, 1000)])]
    #[case::disjoint_range(vec![range(30, 40)])]
    #[case::subset_range(vec![range(10, 13), range(16, 18), range(101, 120)])]
    #[case::merged_range(vec![range(10, 200)])]
    fn delegation_with_ranges_not_matching_state_is_invalid(
        #[case] certified_ranges: Vec<CanisterIdRange>,
    ) {
        let subnet_id = SUBNET_1;
        let public_key = vec![1, 2, 3];
        let state_ranges = [range(10, 20), range(100, 200)];
        let tree = build_tree(subnet_id, &public_key, &certified_ranges);

        assert_matches!(
            validate_all_subnet_ranges(&tree, subnet_id, &public_key, &state_ranges),
            Ok(false),
            "certifying ranges {certified_ranges:?} which the state does not assign to the \
             subnet should be invalid"
        );
    }

    /// A delegation certifying no ranges at all is valid if and only if the state
    /// assigns no ranges to the subnet either.
    #[rstest]
    #[case::state_with_ranges(vec![range(10, 20)], false)]
    #[case::state_without_ranges(vec![], true)]
    fn delegation_with_empty_ranges(
        #[case] state_ranges: Vec<CanisterIdRange>,
        #[case] expected_validity: bool,
    ) {
        let subnet_id = SUBNET_1;
        let public_key = vec![1, 2, 3];
        let tree = build_tree(subnet_id, &public_key, &[]);

        assert_matches!(
            validate_all_subnet_ranges(&tree, subnet_id, &public_key, &state_ranges),
            Ok(is_valid) if is_valid == expected_validity,
            "a delegation certifying no ranges should be valid if and only \
             if the state assigns no ranges to the subnet, but the state assigns \
             {state_ranges:?}"
        );
    }

    /// A missing `/subnet/<subnet_id>/canister_ranges` leaf is an error.
    #[test]
    fn missing_flat_ranges_is_an_error() {
        let subnet_id = SUBNET_1;
        let public_key = vec![1, 2, 3];
        let ranges = [range(10, 20)];
        let tree = LabeledTree::SubTree(flatmap![
            Label::from("canister_ranges") => LabeledTree::SubTree(flatmap![
                Label::from(subnet_id.get().to_vec()) => tree_ranges_subtree(&ranges),
            ]),
            Label::from("subnet") => LabeledTree::SubTree(flatmap![
                Label::from(subnet_id.get().to_vec()) => LabeledTree::SubTree(flatmap![
                    Label::from("public_key") => LabeledTree::Leaf(public_key.clone()),
                ]),
            ]),
        ]);

        assert_matches!(
            validate_all_subnet_ranges(&tree, subnet_id, &public_key, &ranges),
            Err(DelegationValidationError::UnexpectedTreeShape(err)) if err.contains("canister_ranges leaf"),
            "a delegation without flat canister ranges should fail with UnexpectedTreeShape"
        );
    }

    /// A subtree where the `/subnet/<subnet_id>/canister_ranges` leaf is expected is an
    /// error.
    #[test]
    fn subtree_instead_of_flat_ranges_leaf_is_an_error() {
        let subnet_id = SUBNET_1;
        let public_key = vec![1, 2, 3];
        let ranges = [range(10, 20)];
        let tree = LabeledTree::SubTree(flatmap![
            Label::from("canister_ranges") => LabeledTree::SubTree(flatmap![
                Label::from(subnet_id.get().to_vec()) => tree_ranges_subtree(&ranges),
            ]),
            Label::from("subnet") => LabeledTree::SubTree(flatmap![
                Label::from(subnet_id.get().to_vec()) => LabeledTree::SubTree(flatmap![
                    Label::from("canister_ranges") => LabeledTree::SubTree(flatmap![
                        Label::from("unexpected") => ranges_leaf(&ranges),
                    ]),
                    Label::from("public_key") => LabeledTree::Leaf(public_key.clone()),
                ]),
            ]),
        ]);

        assert_matches!(
            validate_all_subnet_ranges(&tree, subnet_id, &public_key, &ranges),
            Err(DelegationValidationError::UnexpectedTreeShape(err)) if err.contains("unexpected subtree"),
            "a subtree at /subnet/{subnet_id}/canister_ranges (where a leaf is expected) \
             should fail with UnexpectedTreeShape"
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
        let tree =
            build_tree_with_distinct_ranges(subnet_id, &public_key, flat_ranges, tree_ranges);

        assert_matches!(
            validate_all_subnet_ranges(&tree, subnet_id, &public_key, &state_ranges),
            Ok(is_valid) if is_valid == expected_validity,
            "only the flat leaf should decide the validity of the delegation; the \
             /canister_ranges/{subnet_id} subtree should be ignored"
        );
    }

    /// A flat canister ranges leaf which cannot be CBOR-decoded is an error.
    #[test]
    fn delegation_with_malformed_flat_ranges_is_an_error() {
        let subnet_id = SUBNET_1;
        let public_key = vec![1, 2, 3];
        let ranges = [range(10, 20)];
        let tree = LabeledTree::SubTree(flatmap![
            Label::from("canister_ranges") => LabeledTree::SubTree(flatmap![
                Label::from(subnet_id.get().to_vec()) => tree_ranges_subtree(&ranges),
            ]),
            Label::from("subnet") => LabeledTree::SubTree(flatmap![
                Label::from(subnet_id.get().to_vec()) => LabeledTree::SubTree(flatmap![
                    Label::from("canister_ranges") => LabeledTree::Leaf(vec![0xFF, 0xFF]),
                    Label::from("public_key") => LabeledTree::Leaf(public_key.clone()),
                ]),
            ]),
        ]);

        assert_matches!(
            validate_all_subnet_ranges(&tree, subnet_id, &public_key, &ranges),
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

    // TODO: review below

    /// Which canister ranges location a per-canister check reads.
    #[derive(Copy, Clone, Debug)]
    enum CanisterCheckLocation {
        Flat,
        Tree,
    }

    impl CanisterCheckLocation {
        fn check(&self, canister_id: u64) -> CanisterRangesCheck {
            match self {
                Self::Flat => {
                    CanisterRangesCheck::CanisterInFlat(CanisterId::from_u64(canister_id))
                }
                Self::Tree => {
                    CanisterRangesCheck::CanisterInTree(CanisterId::from_u64(canister_id))
                }
            }
        }

        /// The layout carrying the ranges only in the location this check reads.
        fn layout(&self) -> Layout {
            match self {
                Self::Flat => Layout::FlatOnly,
                Self::Tree => Layout::TreeOnly,
            }
        }
    }

    /// The per-canister checks only require the delegation and the state to agree on the
    /// given canister id's membership; inconsistencies in other parts of the certified
    /// ranges are ignored. The state assigns [10, 20] and [100, 200] to the subnet.
    #[rstest]
    #[case::covered_by_both(15, vec![range(10, 20), range(100, 200)], true)]
    #[case::covered_by_neither(50, vec![range(10, 20), range(100, 200)], true)]
    #[case::covered_by_state_only(150, vec![range(10, 20)], false)]
    #[case::covered_by_both_in_partially_certified_ranges(15, vec![range(10, 20)], true)]
    #[case::covered_by_delegation_only(300, vec![range(10, 20), range(290, 400)], false)]
    #[case::covered_by_neither_beyond_all_ranges(300, vec![range(10, 20), range(100, 200)], true)]
    fn per_canister_check_only_requires_agreement_on_the_canister(
        #[case] canister_id: u64,
        #[case] certified_ranges: Vec<CanisterIdRange>,
        #[case] expected_validity: bool,
        #[values(CanisterCheckLocation::Flat, CanisterCheckLocation::Tree)]
        location: CanisterCheckLocation,
    ) {
        let subnet_id = SUBNET_1;
        let public_key = vec![1, 2, 3];
        let state_ranges = [range(10, 20), range(100, 200)];
        let tree = build_tree(location.layout(), subnet_id, &public_key, &certified_ranges);

        assert_matches!(
            validate(&tree, subnet_id, &public_key, &state_ranges, location.check(canister_id)),
            Ok(is_valid) if is_valid == expected_validity,
            "with the delegation certifying {certified_ranges:?}, the {location:?} \
             per-canister check for canister {canister_id} should return {expected_validity}"
        );
    }

    /// Each per-canister check reads only its own ranges location: the other location is
    /// ignored even when both are present.
    #[rstest]
    #[case::flat_check_covered_in_both(CanisterCheckLocation::Flat, 15, true)]
    #[case::flat_check_covered_only_in_tree_location(CanisterCheckLocation::Flat, 150, false)]
    #[case::tree_check_covered_in_both(CanisterCheckLocation::Tree, 150, true)]
    #[case::tree_check_covered_only_in_flat_location(CanisterCheckLocation::Tree, 15, false)]
    fn per_canister_check_reads_only_its_own_location(
        #[case] location: CanisterCheckLocation,
        #[case] canister_id: u64,
        #[case] expected_validity: bool,
    ) {
        let subnet_id = SUBNET_1;
        let public_key = vec![1, 2, 3];
        // The state covers both canisters; the flat location only certifies [10, 20] and
        // the tree location only certifies [100, 200].
        let state_ranges = [range(10, 20), range(100, 200)];
        let tree = build_tree_with_distinct_ranges(
            Layout::Both,
            subnet_id,
            &public_key,
            &[range(10, 20)],
            &[range(100, 200)],
        );

        assert_matches!(
            validate(&tree, subnet_id, &public_key, &state_ranges, location.check(canister_id)),
            Ok(is_valid) if is_valid == expected_validity,
            "the {location:?} per-canister check for canister {canister_id} should return \
             {expected_validity} and ignore the other ranges location"
        );
    }

    /// A per-canister check whose ranges location is missing from the certificate tree is
    /// an error.
    #[rstest]
    #[case::flat_check_without_flat_location(CanisterCheckLocation::Flat, Layout::TreeOnly)]
    #[case::flat_check_with_key_only(CanisterCheckLocation::Flat, Layout::KeyOnly)]
    #[case::tree_check_without_tree_location(CanisterCheckLocation::Tree, Layout::FlatOnly)]
    #[case::tree_check_with_key_only(CanisterCheckLocation::Tree, Layout::KeyOnly)]
    fn per_canister_check_with_missing_location_is_an_error(
        #[case] location: CanisterCheckLocation,
        #[case] layout: Layout,
    ) {
        let subnet_id = SUBNET_1;
        let public_key = vec![1, 2, 3];
        let ranges = [range(10, 20)];
        let tree = build_tree(layout, subnet_id, &public_key, &ranges);

        assert_matches!(
            validate(&tree, subnet_id, &public_key, &ranges, location.check(15)),
            Err(DelegationValidationError::UnexpectedTreeShape(_)),
            "the {location:?} per-canister check should fail with UnexpectedTreeShape in \
             the {layout:?} layout"
        );
    }

    /// The tree-location per-canister check reads only the single leaf which could cover
    /// the canister id, so a malformed *other* leaf does not affect it.
    #[test]
    fn tree_location_check_ignores_malformed_other_leaves() {
        let subnet_id = SUBNET_1;
        let public_key = vec![1, 2, 3];
        let state_ranges = [range(10, 20), range(100, 200)];
        // Leaf keyed by 10 is garbage; leaf keyed by 100 correctly certifies [100, 200].
        let tree = LabeledTree::SubTree(flatmap![
            Label::from("canister_ranges") => LabeledTree::SubTree(flatmap![
                Label::from(subnet_id.get().to_vec()) => LabeledTree::SubTree(flatmap![
                    Label::from(CanisterId::from_u64(10).get().to_vec()) =>
                        LabeledTree::Leaf(vec![0xFF, 0xFF]),
                    Label::from(CanisterId::from_u64(100).get().to_vec()) =>
                        ranges_leaf(&[range(100, 200)]),
                ]),
            ]),
            Label::from("subnet") => LabeledTree::SubTree(flatmap![
                Label::from(subnet_id.get().to_vec()) => LabeledTree::SubTree(flatmap![
                    Label::from("public_key") => LabeledTree::Leaf(public_key.clone()),
                ]),
            ]),
        ]);

        assert_matches!(
            validate(
                &tree,
                subnet_id,
                &public_key,
                &state_ranges,
                CanisterRangesCheck::CanisterInTree(CanisterId::from_u64(150)),
            ),
            Ok(true),
            "checking canister 150 should only read the leaf keyed by 100 and ignore the \
             malformed leaf keyed by 10"
        );
        assert_matches!(
            validate(
                &tree,
                subnet_id,
                &public_key,
                &state_ranges,
                CanisterRangesCheck::CanisterInTree(CanisterId::from_u64(15)),
            ),
            Err(DelegationValidationError::MalformedCanisterRanges(_)),
            "checking canister 15 should read the malformed leaf keyed by 10 and fail with \
             MalformedCanisterRanges"
        );
    }

    /// `NoCheck` ignores the canister ranges entirely — even malformed ones — but the
    /// public key is still checked.
    #[rstest]
    #[case::matching_public_key(vec![1, 2, 3], true)]
    #[case::mismatching_public_key(vec![9, 9, 9], false)]
    fn no_check_ignores_ranges_but_still_checks_the_public_key(
        #[case] certified_public_key: Vec<u8>,
        #[case] expected_validity: bool,
    ) {
        let subnet_id = SUBNET_1;
        let expected_public_key = vec![1, 2, 3];
        // Both ranges locations carry garbage; NoCheck should never read them.
        let tree = LabeledTree::SubTree(flatmap![
            Label::from("canister_ranges") => LabeledTree::SubTree(flatmap![
                Label::from(subnet_id.get().to_vec()) => LabeledTree::SubTree(flatmap![
                    Label::from(CanisterId::from_u64(10).get().to_vec()) =>
                        LabeledTree::Leaf(vec![0xFF, 0xFF]),
                ]),
            ]),
            Label::from("subnet") => LabeledTree::SubTree(flatmap![
                Label::from(subnet_id.get().to_vec()) => LabeledTree::SubTree(flatmap![
                    Label::from("canister_ranges") => LabeledTree::Leaf(vec![0xFF, 0xFF]),
                    Label::from("public_key") => LabeledTree::Leaf(certified_public_key.clone()),
                ]),
            ]),
        ]);

        assert_matches!(
            validate(
                &tree,
                subnet_id,
                &expected_public_key,
                &[range(10, 20)],
                CanisterRangesCheck::NoCheck,
            ),
            Ok(is_valid) if is_valid == expected_validity,
            "NoCheck should ignore the (malformed) ranges and be decided solely by the \
             public key, which is {certified_public_key:?}"
        );
    }
}
