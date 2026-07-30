//! Phase-2 quick-upgrade types and the deterministic permit algorithm.
//!
//! During a Phase-2 rolling reboot, the replicated state ([`UpgradeState`])
//! tracks each node's latest committed GuestOS status and the set of outstanding
//! reboot permits. The block maker commits signed [`UpgradeStatus`] heartbeats
//! (collected from gossip) plus [`Permit`]s into each data block. Execution
//! applies them via [`UpgradeState::apply`]. The permit algorithm
//! ([`UpgradeState::pick_permits`]) is a pure function of the agreed state,
//! ensuring ≤ `f` concurrent reboots.
use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::{GuestOsVersion, Height, NodeId, ReplicaVersion};

/// The freshness window: a node whose latest committed status is older than
/// `W` rounds is treated as down (counts toward the `f`-budget).
pub const STATUS_FRESHNESS_WINDOW_FACTOR: u64 = 3;

/// A node's GuestOS status. Gossiped as a signed heartbeat and committed to
/// blocks by the block maker. Serves as both the version report and the
/// liveness signal (its `height` field, refreshed every K rounds).
///
/// (POC: signature omitted for simplicity; production would carry a
/// `BasicSignature<UpgradeStatus>` requiring crypto-team `SignatureDomain`
/// sign-off.)
#[derive(Clone, Eq, PartialEq, Hash, Debug, Deserialize, Serialize)]
pub struct UpgradeStatus {
    pub version: ReplicaVersion,
    pub node_id: NodeId,
    pub guestos_version: GuestOsVersion,
    pub height: Height,
}

/// A permit authorizing a node to reboot into a specific GuestOS version.
/// Issued by the block maker; retired on completion, leave, or stale target.
#[derive(Clone, Eq, PartialEq, Hash, Debug, Deserialize, Serialize)]
pub struct Permit {
    pub target_node: NodeId,
    pub target_version: ReplicaVersion,
}

/// The response to the `/_/upgrade_state` HTTP endpoint, polled by the
/// orchestrator during Phase 2 to learn whether this node holds a reboot
/// permit. Defined here (in `ic-types`) so both the HTTP server
/// (`ic-http-endpoints-public`) and the client (the orchestrator) share a
/// single type, mirroring how the CUP endpoint shares its wire types.
#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
pub struct UpgradeStateResponse {
    /// The GuestOS version the orchestrator should upgrade to, if any.
    /// `None` when no upgrade is in progress or this node is already on target.
    pub target_guestos_version: Option<ReplicaVersion>,
    /// Whether this node has a permit to reboot.
    pub has_permit: bool,
    /// The permit, if any.
    pub permit: Option<Permit>,
}

/// The upgrade section carried in a block's `BatchPayload`. Contains the
/// status delta (newer-than-state heartbeats collected from gossip) and the
/// block maker's chosen permits.
#[derive(Clone, Eq, PartialEq, Hash, Debug, Default, Deserialize, Serialize)]
pub struct UpgradePayload {
    pub statuses: Vec<UpgradeStatus>,
    pub permits: Vec<Permit>,
}

/// The agreed Phase-2 upgrade state, stored in `SystemMetadata` and advanced
/// deterministically by execution via [`UpgradeState::apply`].
#[derive(Clone, Eq, PartialEq, Debug, Default, Deserialize, Serialize)]
pub struct UpgradeState {
    /// Latest committed status per node: `node_id → (guestos_version, commit_height)`.
    pub latest_status: BTreeMap<NodeId, (GuestOsVersion, Height)>,
    /// Outstanding (un-retired) permits: `target_node → Permit`.
    pub issued_permits: BTreeMap<NodeId, Permit>,
}

/// The current subnet target GuestOS version, derived from the registry.
/// `None` when no upgrade is in progress (Phase 2 inactive).
pub type TargetVersion = Option<ReplicaVersion>;

impl UpgradeState {
    /// Apply a block's upgrade section to this state. This is the shared
    /// transition function used by BOTH execution (to maintain the accumulator)
    /// and the validator (to fold `past_payloads` across the certification gap).
    ///
    /// - `commit_height` is the height of the block being applied (used for
    ///   `last_commit_height` freshness tracking).
    /// - `current_target` is the registry-elected target version at this block
    ///   (used for stale-target permit retirement and completion detection).
    /// - `members` is the subnet membership at this block's registry version
    ///   (used for leave reconciliation).
    pub fn apply(
        &mut self,
        payload: &UpgradePayload,
        current_target: TargetVersion,
        members: &[NodeId],
    ) {
        let member_set: std::collections::BTreeSet<NodeId> = members.iter().copied().collect();

        // 1. Apply incoming statuses (update latest_status if newer).
        for status in &payload.statuses {
            self.latest_status
                .entry(status.node_id)
                .and_modify(|existing| {
                    if status.height > existing.1 {
                        *existing = (status.guestos_version.clone(), status.height);
                    }
                })
                .or_insert((status.guestos_version.clone(), status.height));
        }

        // 2. Retire stale-target permits (unconditional — target changed).
        //    Down nodes that lose their permit are picked up by `e` automatically.
        if let Some(target) = &current_target {
            self.issued_permits
                .retain(|_, permit| &permit.target_version != target);
        }

        // 3. Retire completed permits (node reported the permit's target version).
        self.issued_permits.retain(|node, permit| {
            match self.latest_status.get(node) {
                Some((version, _)) => version != &permit.target_version,
                None => true,
            }
        });

        // 4. Retire permits for nodes that left the membership.
        self.issued_permits
            .retain(|node, _| member_set.contains(node));

        // 5. Prune latest_status for departed members (housekeeping).
        self.latest_status
            .retain(|node, _| member_set.contains(node));

        // 6. Apply new permits from this block (within the f-budget, checked
        //    by the validator; here we just record them).
        for permit in &payload.permits {
            self.issued_permits
                .entry(permit.target_node)
                .or_insert(permit.clone());
        }
    }

    /// Compute the set of down nodes (`e`): members without a permit whose
    /// latest committed status is older than `W` rounds.
    ///
    /// `W = STATUS_FRESHNESS_WINDOW_FACTOR × N` where `N = members.len()`.
    /// A permitted node is never in `e` (it's counted via `issued_permits`).
    pub fn compute_down_set(&self, members: &[NodeId], current_height: Height) -> Vec<NodeId> {
        let n = members.len().max(1) as u64;
        let w = Height::from(STATUS_FRESHNESS_WINDOW_FACTOR * n);
        let threshold = Height::from(current_height.get().saturating_sub(w.get()));

        members
            .iter()
            .copied()
            .filter(|node| !self.issued_permits.contains_key(node))
            .filter(|node| {
                match self.latest_status.get(node) {
                    Some((_, commit_height)) => *commit_height < threshold,
                    None => true, // never reported → down
                }
            })
            .collect()
    }

    /// The number of "down slots" consumed: outstanding permits + down nodes.
    /// This must be ≤ `f` at all times.
    pub fn consumed(&self, members: &[NodeId], current_height: Height) -> usize {
        let down = self.compute_down_set(members, current_height);
        self.issued_permits.len() + down.len()
    }

    /// The fault tolerance: `f = ⌊(N−1)/3⌋`.
    pub fn faults_tolerated(num_members: usize) -> usize {
        (num_members.max(1) - 1) / 3
    }

    /// The permit-issuance algorithm. Returns the permits the block maker
    /// should issue this round to fill the budget, keeping `consumed ≤ f`.
    ///
    /// Eligible nodes: `outstanding − already_permitted − e`, where
    /// `outstanding = members − reported_done`.
    ///
    /// The block maker has discretion in WHICH eligible node to pick; this
    /// implementation picks by lowest NodeId (deterministic for the POC).
    /// The validator checks only the constraints (≤ budget, eligible), not
    /// the specific choice.
    pub fn pick_permits(
        &self,
        members: &[NodeId],
        current_height: Height,
        target: &ReplicaVersion,
    ) -> Vec<Permit> {
        let f = Self::faults_tolerated(members.len());
        let consumed = self.consumed(members, current_height);
        let budget = f.saturating_sub(consumed);
        if budget == 0 {
            return Vec::new();
        }

        let down: std::collections::BTreeSet<NodeId> =
            self.compute_down_set(members, current_height)
                .into_iter()
                .collect();

        // reported_done: nodes whose latest status matches target
        let reported_done: std::collections::BTreeSet<NodeId> = members
            .iter()
            .copied()
            .filter(|node| {
                self.latest_status
                    .get(node)
                    .map(|(version, _)| version == target)
                    .unwrap_or(false)
            })
            .collect();

        // outstanding = members − reported_done
        // eligible = outstanding − already_permitted − e
        let mut eligible: Vec<NodeId> = members
            .iter()
            .copied()
            .filter(|node| !reported_done.contains(node))
            .filter(|node| !self.issued_permits.contains_key(node))
            .filter(|node| !down.contains(node))
            .collect();
        eligible.sort();

        eligible
            .into_iter()
            .take(budget)
            .map(|node| Permit {
                target_node: node,
                target_version: target.clone(),
            })
            .collect()
    }

    /// Check whether a proposed set of permits satisfies the safety
    /// constraints (relaxed validation). Returns `Ok(())` if valid.
    ///
    /// Constraints:
    /// 1. `|prior_permits ∪ new_permits| + |e| ≤ f`
    /// 2. Each permitted node is `outstanding` (not `reported_done`) in the
    ///    prior state.
    pub fn validate_permits(
        &self,
        members: &[NodeId],
        current_height: Height,
        target: &ReplicaVersion,
        new_permits: &[Permit],
    ) -> Result<(), String> {
        let f = Self::faults_tolerated(members.len());
        let down_count = self.compute_down_set(members, current_height).len();

        // Each new permit must be for an outstanding (not done) node.
        let reported_done: std::collections::BTreeSet<NodeId> = members
            .iter()
            .copied()
            .filter(|node| {
                self.latest_status
                    .get(node)
                    .map(|(version, _)| version == target)
                    .unwrap_or(false)
            })
            .collect();

        for permit in new_permits {
            if reported_done.contains(&permit.target_node) {
                return Err(format!(
                    "permit for node {:?} which is already on target",
                    permit.target_node
                ));
            }
            if permit.target_version != *target {
                return Err(format!(
                    "permit target {:?} != current target {:?}",
                    permit.target_version, target
                ));
            }
        }

        // Budget: prior_permits + new_unique_permits + e ≤ f
        let mut all_permitted: std::collections::BTreeSet<NodeId> =
            self.issued_permits.keys().copied().collect();
        for permit in new_permits {
            all_permitted.insert(permit.target_node);
        }
        let total = all_permitted.len() + down_count;
        if total > f {
            return Err(format!(
                "budget exceeded: {} permitted + {} down = {} > f = {}",
                all_permitted.len(),
                down_count,
                total,
                f
            ));
        }
        Ok(())
    }

    /// Compute the status delta: statuses from the gossip pool that are newer
    /// than what's already in this (agreed) state. Used by the block maker
    /// to fill the block's upgrade section.
    pub fn compute_delta<'a>(&self, pool_statuses: &'a [UpgradeStatus]) -> Vec<&'a UpgradeStatus> {
        pool_statuses
            .iter()
            .filter(|s| {
                match self.latest_status.get(&s.node_id) {
                    Some((_, state_height)) => s.height > *state_height,
                    None => true,
                }
            })
            .collect()
    }

    /// Whether Phase 2 is active: the target exists and not all members are
    /// on the target version.
    pub fn is_phase2_active(&self, members: &[NodeId], target: TargetVersion) -> bool {
        let target = match target {
            Some(t) => t,
            None => return false,
        };
        !members.iter().all(|node| {
            self.latest_status
                .get(node)
                .map(|(version, _)| version == &target)
                .unwrap_or(false)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_base_types::PrincipalId;
    use std::str::FromStr;

    fn node(node_index: u64) -> NodeId {
        NodeId::from(PrincipalId::new_node_test_id(node_index))
    }

    fn guestos_v(guestos_version: &str) -> GuestOsVersion {
        GuestOsVersion::from_str(guestos_version).unwrap()
    }

    fn status(node_index: u64, guestos_version: &str, height: u64) -> UpgradeStatus {
        UpgradeStatus {
            version: ReplicaVersion::default(),
            node_id: node(node_index),
            guestos_version: guestos_v(guestos_version),
            height: Height::from(height),
        }
    }

    #[test]
    fn test_basic_permit_issuance() {
        let members = vec![node(1), node(2), node(3), node(4)]; // N=4, f=1
        let target = version("2.0");
        let mut state = UpgradeState::default();

        // All nodes report V1 at height 0.
        let payload = UpgradePayload {
            statuses: members
                .iter()
                .map(|member| UpgradeStatus {
                    version: ReplicaVersion::default(),
                    node_id: *member,
                    guestos_version: guestos_v("1.0"),
                    height: Height::from(0),
                })
                .collect(),
            permits: vec![],
        };
        state.apply(&payload, Some(target.clone()), &members);

        // Pick permits: budget = f - consumed = 1 - 0 = 1.
        let permits = state.pick_permits(&members, Height::from(0), &target);
        assert_eq!(permits.len(), 1);
        assert_eq!(permits[0].target_node, node(1)); // lowest NodeId
        assert_eq!(permits[0].target_version, target);
    }

    #[test]
    fn test_permit_completes_on_report() {
        let members = vec![node(1), node(2), node(3), node(4)]; // f=1
        let target = version("2.0");
        let mut state = UpgradeState::default();

        // Issue a permit for node 1.
        state.issued_permits.insert(
            node(1),
            Permit {
                target_node: node(1),
                target_version: target.clone(),
            },
        );

        // Node 1 reports V2 → permit should be retired.
        let payload = UpgradePayload {
            statuses: vec![status(1, "2.0", 10)],
            permits: vec![],
        };
        state.apply(&payload, Some(target.clone()), &members);
        assert!(state.issued_permits.is_empty());
    }

    #[test]
    fn test_down_node_counted_in_budget() {
        let members = vec![node(1), node(2), node(3), node(4)]; // f=1
        let target = version("2.0");
        let mut state = UpgradeState::default();

        // Nodes 1-3 report V1 at height 0; node 4 never reports.
        let payload = UpgradePayload {
            statuses: vec![status(1, "1.0", 0), status(2, "1.0", 0), status(3, "1.0", 0)],
            permits: vec![],
        };
        state.apply(&payload, Some(target), &members);

        // Node 4 is down (never reported). W = 3*4 = 12. At height 13, node 4 is stale.
        let consumed = state.consumed(&members, Height::from(13));
        assert_eq!(consumed, 1); // only node 4 is down
    }

    #[test]
    fn test_failed_reboot_permanently_occupies_slot() {
        let members = vec![node(1), node(2), node(3), node(4)]; // f=1
        let target = version("2.0");
        let mut state = UpgradeState::default();

        // Node 1 gets a permit and reboots but never reports (failed).
        state.issued_permits.insert(
            node(1),
            Permit {
                target_node: node(1),
                target_version: target.clone(),
            },
        );

        // At height 100, node 1 is still "permitted" (failed, never reported).
        // It should NOT be in e (it has a permit) → counted once.
        let down = state.compute_down_set(&members, Height::from(100));
        assert!(!down.contains(&node(1))); // not in e (has permit)
        assert_eq!(state.issued_permits.len(), 1); // permit not retired

        // consumed = 1 (permit) + 0 (no other down) = 1 ≤ f=1
        let consumed = state.consumed(&members, Height::from(100));
        assert_eq!(consumed, 1);
    }

    #[test]
    fn test_stale_target_unconditional_retirement() {
        let members = vec![node(1), node(2), node(3), node(4)]; // f=1
        let v2 = version("2.0");
        let v3 = version("3.0");
        let mut state = UpgradeState::default();

        // Issue a V2 permit for node 1.
        state.issued_permits.insert(
            node(1),
            Permit {
                target_node: node(1),
                target_version: v2.clone(),
            },
        );

        // Target changes to V3 → V2 permit retired unconditionally.
        let payload = UpgradePayload::default();
        state.apply(&payload, Some(v3.clone()), &members);
        assert!(state.issued_permits.is_empty()); // V2 permit retired
    }

    #[test]
    fn test_validate_permits_budget() {
        let members = vec![node(1), node(2), node(3), node(4)]; // f=1
        let target = version("2.0");
        let mut state = UpgradeState::default();

        // All report V1.
        let payload = UpgradePayload {
            statuses: members
                .iter()
                .map(|member| UpgradeStatus {
                    version: ReplicaVersion::default(),
                    node_id: *member,
                    guestos_version: guestos_v("1.0"),
                    height: Height::from(0),
                })
                .collect(),
            permits: vec![],
        };
        state.apply(&payload, Some(target.clone()), &members);

        // 1 permit is OK (budget = 1).
        let permits = vec![Permit {
            target_node: node(1),
            target_version: target.clone(),
        }];
        assert!(state
            .validate_permits(&members, Height::from(0), &target, &permits)
            .is_ok());

        // Apply it, then try 2 more — should fail (budget exhausted).
        state.apply(
            &UpgradePayload {
                statuses: vec![],
                permits: permits.clone(),
            },
            Some(target.clone()),
            &members,
        );
        let extra = vec![Permit {
            target_node: node(2),
            target_version: target.clone(),
        }];
        assert!(state
            .validate_permits(&members, Height::from(0), &target, &extra)
            .is_err());
    }

    #[test]
    fn test_delta_computation() {
        let mut state = UpgradeState::default();
        state
            .latest_status
            .insert(node(1), (version("1.0"), Height::from(5)));

        let pool = vec![
            status(1, "1.0", 10), // newer → included
            status(2, "2.0", 8),  // new node → included
        ];
        let delta = state.compute_delta(&pool);
        assert_eq!(delta.len(), 2);
    }
}
