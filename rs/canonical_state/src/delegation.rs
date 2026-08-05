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
use ic_replicated_state::ReplicatedState;
use ic_types::{
    PrincipalId, SubnetId,
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

    let network_topology = &state.metadata.network_topology;
    let subnet_topology = network_topology
        .subnets_for_certification()
        .get(&subnet_id)
        .ok_or(DelegationValidationError::UnknownSubnet(subnet_id))?;

    // 1. The certified public key must match the one recorded in the state.
    let certified_public_key = match lookup_path(
        &tree,
        &[b"subnet", subnet_id.get_ref().as_slice(), b"public_key"],
    ) {
        Some(LabeledTree::Leaf(public_key)) => public_key,
        _ => {
            return Err(DelegationValidationError::UnexpectedTreeShape(format!(
                "missing /subnet/{subnet_id}/public_key leaf"
            )));
        }
    };
    if certified_public_key.as_slice() != subnet_topology.public_key.as_slice() {
        return Ok(false);
    }

    // 2. The certified canister ranges must match the ranges the state assigns
    //    to the subnet. Pruned delegations carry no ranges, so there is nothing
    //    left to compare once the public key matches.
    let Some(certified_ranges) = certified_canister_ranges(&tree, format, subnet_id)? else {
        return Ok(true);
    };

    let expected_ranges: Vec<(PrincipalId, PrincipalId)> = network_topology
        .routing_table_for_certification()
        .ranges(subnet_id)
        .iter()
        .map(|range| (range.start.get(), range.end.get()))
        .collect();

    Ok(certified_ranges == expected_ranges)
}

/// Extracts the canister ID ranges certified for `subnet_id` from the
/// delegation's certificate `tree`, according to `format`.
///
/// Returns `Ok(None)` for [`CertificateDelegationFormat::Pruned`] (the ranges
/// are absent, so there is nothing to compare), and `Ok(Some(ranges))`
/// otherwise.
fn certified_canister_ranges(
    tree: &LabeledTree<Vec<u8>>,
    format: CertificateDelegationFormat,
    subnet_id: SubnetId,
) -> Result<Option<Vec<(PrincipalId, PrincipalId)>>, DelegationValidationError> {
    let subnet_id_bytes = subnet_id.get_ref().as_slice();
    // Canister ranges are stored as self-describing CBOR of `(start, end)`
    // principal pairs (see `encoding::encode_subnet_canister_ranges`).
    let decode = |bytes: &[u8]| {
        serde_cbor::from_slice::<Vec<(PrincipalId, PrincipalId)>>(bytes)
            .map_err(|err| DelegationValidationError::MalformedCanisterRanges(err.to_string()))
    };

    match format {
        // A single leaf at /subnet/<subnet_id>/canister_ranges.
        CertificateDelegationFormat::Flat => {
            match lookup_path(tree, &[b"subnet", subnet_id_bytes, b"canister_ranges"]) {
                Some(LabeledTree::Leaf(bytes)) => Ok(Some(decode(bytes)?)),
                _ => Err(DelegationValidationError::UnexpectedTreeShape(format!(
                    "missing /subnet/{subnet_id}/canister_ranges leaf"
                ))),
            }
        }
        // Ranges split across the leaves of the /canister_ranges/<subnet_id> subtree.
        CertificateDelegationFormat::Tree => {
            match lookup_path(tree, &[b"canister_ranges", subnet_id_bytes]) {
                Some(LabeledTree::SubTree(children)) => {
                    let mut ranges = Vec::new();
                    for (_label, child) in children.iter() {
                        match child {
                            LabeledTree::Leaf(bytes) => ranges.extend(decode(bytes)?),
                            LabeledTree::SubTree(_) => {
                                return Err(DelegationValidationError::UnexpectedTreeShape(
                                    format!(
                                        "unexpected subtree under /canister_ranges/{subnet_id}"
                                    ),
                                ));
                            }
                        }
                    }
                    Ok(Some(ranges))
                }
                _ => Err(DelegationValidationError::UnexpectedTreeShape(format!(
                    "missing /canister_ranges/{subnet_id} subtree"
                ))),
            }
        }
        CertificateDelegationFormat::Pruned => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::{DelegationValidationError, is_delegation_valid_with_respect_to_state};
    use crate::encoding::encode_subnet_canister_ranges;
    use assert_matches::assert_matches;
    use ic_canonical_state_tree_hash_test_utils::build_witness_gen;
    use ic_crypto_tree_hash::{Label, LabeledTree, WitnessGenerator, flatmap};
    use ic_registry_routing_table::CanisterIdRange;
    use ic_registry_subnet_type::SubnetType;
    use ic_replicated_state::{
        ReplicatedState, SubnetTopology,
        metadata_state::testing::{NetworkTopologyTesting, SystemMetadataTesting},
    };
    use ic_test_utilities_types::ids::SUBNET_1;
    use ic_types::{
        CanisterId, PrincipalId, SubnetId,
        messages::{Blob, Certificate, CertificateDelegation, CertificateDelegationFormat},
    };
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
    /// subtree whose leaves hold the ranges split into two chunks (the `Tree`
    /// layout).
    fn tree_layout(
        subnet_id: SubnetId,
        public_key: &[u8],
        chunk_a: &[CanisterIdRange],
        chunk_b: &[CanisterIdRange],
    ) -> LabeledTree<Vec<u8>> {
        LabeledTree::SubTree(flatmap![
            Label::from("canister_ranges") => LabeledTree::SubTree(flatmap![
                Label::from(subnet_id.get().to_vec()) => LabeledTree::SubTree(flatmap![
                    Label::from(chunk_a[0].start.get().to_vec()) => ranges_leaf(chunk_a),
                    Label::from(chunk_b[0].start.get().to_vec()) => ranges_leaf(chunk_b),
                ]),
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

    #[test]
    fn flat_delegation_matching_public_key_and_ranges_is_valid() {
        let public_key = vec![1, 2, 3];
        let ranges = [range(10, 20), range(100, 200)];
        let state = state_with(SUBNET_1, public_key.clone(), &ranges);
        let delegation = delegation(SUBNET_1, &flat_tree(SUBNET_1, &public_key, &ranges));

        assert_matches!(
            is_delegation_valid_with_respect_to_state(
                &delegation,
                CertificateDelegationFormat::Flat,
                &state,
            ),
            Ok(true)
        );
    }

    #[test]
    fn tree_delegation_matching_public_key_and_ranges_is_valid() {
        let public_key = vec![1, 2, 3];
        // The state holds both ranges; the delegation splits them across two leaves.
        let state = state_with(
            SUBNET_1,
            public_key.clone(),
            &[range(10, 20), range(100, 200)],
        );
        let delegation = delegation(
            SUBNET_1,
            &tree_layout(SUBNET_1, &public_key, &[range(10, 20)], &[range(100, 200)]),
        );

        assert_matches!(
            is_delegation_valid_with_respect_to_state(
                &delegation,
                CertificateDelegationFormat::Tree,
                &state,
            ),
            Ok(true)
        );
    }

    #[test]
    fn pruned_delegation_ignores_ranges_and_only_checks_public_key() {
        let public_key = vec![1, 2, 3];
        // The state has ranges, but a pruned delegation carries none: they must
        // not be compared, so a matching public key is enough. The tree only
        // contains the public key.
        let state = state_with(SUBNET_1, public_key.clone(), &[range(10, 20)]);
        let delegation = delegation(SUBNET_1, &pruned_tree(SUBNET_1, &public_key));

        assert_matches!(
            is_delegation_valid_with_respect_to_state(
                &delegation,
                CertificateDelegationFormat::Pruned,
                &state,
            ),
            Ok(true)
        );
    }

    #[test]
    fn mismatching_public_key_is_invalid() {
        let ranges = [range(10, 20)];
        let state = state_with(SUBNET_1, vec![1, 2, 3], &ranges);
        // Same ranges, different public key.
        let delegation = delegation(SUBNET_1, &flat_tree(SUBNET_1, &[9, 9, 9], &ranges));

        assert_matches!(
            is_delegation_valid_with_respect_to_state(
                &delegation,
                CertificateDelegationFormat::Flat,
                &state,
            ),
            Ok(false)
        );
    }

    #[test]
    fn mismatching_canister_ranges_are_invalid() {
        let public_key = vec![1, 2, 3];
        let state = state_with(SUBNET_1, public_key.clone(), &[range(10, 20)]);
        // Same public key, but the delegation certifies a different range.
        let delegation = delegation(
            SUBNET_1,
            &flat_tree(SUBNET_1, &public_key, &[range(10, 999)]),
        );

        assert_matches!(
            is_delegation_valid_with_respect_to_state(
                &delegation,
                CertificateDelegationFormat::Flat,
                &state,
            ),
            Ok(false)
        );
    }

    #[test]
    fn unknown_subnet_is_an_error() {
        // The state does not know about SUBNET_1.
        let state = ReplicatedState::new(SUBNET_1, SubnetType::Application);
        let delegation = delegation(SUBNET_1, &flat_tree(SUBNET_1, &[1, 2, 3], &[range(10, 20)]));

        assert_matches!(
            is_delegation_valid_with_respect_to_state(
                &delegation,
                CertificateDelegationFormat::Flat,
                &state,
            ),
            Err(DelegationValidationError::UnknownSubnet(_))
        );
    }

    #[test]
    fn public_key_missing_from_delegation_is_an_error() {
        let state = state_with(SUBNET_1, vec![1, 2, 3], &[range(10, 20)]);
        // A tree that has canister ranges but no public_key leaf.
        let tree = LabeledTree::SubTree(flatmap![
            Label::from("subnet") => LabeledTree::SubTree(flatmap![
                Label::from(SUBNET_1.get().to_vec()) => LabeledTree::SubTree(flatmap![
                    Label::from("canister_ranges") => ranges_leaf(&[range(10, 20)]),
                ]),
            ]),
        ]);
        let delegation = delegation(SUBNET_1, &tree);

        assert_matches!(
            is_delegation_valid_with_respect_to_state(
                &delegation,
                CertificateDelegationFormat::Flat,
                &state,
            ),
            Err(DelegationValidationError::UnexpectedTreeShape(_))
        );
    }
}
