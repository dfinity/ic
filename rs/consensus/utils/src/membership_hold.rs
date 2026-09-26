//! Holding a subnet membership change back while the nodes it adds sync state.
//!
//! A node added to a subnet learns of the change within seconds and starts to
//! state sync immediately, but under the plain schedule it is expected to
//! notarize roughly one DKG interval later. For a large state that is not enough
//! time, and if more than `f` of the new members are still syncing when the
//! handover happens, the subnet stalls.
//!
//! This module implements the rule that extends that transition phase: a
//! membership change may only enter the chain once it has been in the registry
//! for a given duration. Consensus derives subnet membership from the registry
//! version agreed in blocks, so refusing to raise that version past a fresh
//! membership change keeps the outgoing members in charge of consensus for
//! longer, giving the incoming ones time to finish syncing.
//!
//! Both inputs are agreed rather than observed locally:
//!
//! * the deadline is compared against the block's own `ValidationContext` time,
//!   and
//! * the time a registry version was created is the registry canister's own
//!   stamp — replicated NNS state, covered by the certified changelog — which
//!   [`RegistryClient::get_version_canister_timestamp`] reports only when it
//!   actually has it, never falling back to a local observation.
//!
//! So a block maker and every validator reach the same verdict, which is what
//! makes this enforceable rather than advisory.

use ic_interfaces_registry::RegistryClient;
use ic_registry_client_helpers::subnet::SubnetRegistry;
use ic_types::{NodeId, RegistryVersion, SubnetId, Time, registry::RegistryClientError};
use std::{collections::BTreeSet, time::Duration};

/// Why a registry version may not be adopted yet.
#[derive(Clone, Eq, PartialEq, Debug)]
pub enum MembershipHoldError {
    /// The registry could not be read. This is transient: the version is chain
    /// agreed, so every node can eventually read it, and a caller validating a
    /// block must defer rather than reject.
    RegistryClientError(RegistryClientError),
}

impl From<RegistryClientError> for MembershipHoldError {
    fn from(error: RegistryClientError) -> Self {
        Self::RegistryClientError(error)
    }
}

/// Returns the highest registry version in `membership_version..=latest` that a
/// block with time `block_time` may adopt.
///
/// A version may be adopted once it has been in the registry for `hold`, so this
/// walks down from `latest` and returns the first version that qualifies.
///
/// Checking a candidate's own timestamp also covers every membership change
/// below it, because the registry canister stamps each version as it applies it
/// with a canister clock that never goes backwards
/// (`RegistryCanister::apply_mutations`). So `timestamp(v) <= timestamp(w)`
/// whenever `v <= w`, and a candidate old enough to adopt cannot be carrying a
/// change that is not.
///
/// Only additions wait. A node being removed has nothing to sync, and holding a
/// removal back would keep a node the operator is retiring in the committee for
/// no benefit — so a change that only removes nodes is adopted immediately, and
/// a swap waits only on the node it adds.
///
/// A version the registry canister did not stamp predates this mechanism and is
/// therefore treated as long past. Waiting on it would mean waiting on a time
/// that different nodes disagree about, which is exactly what this rule must
/// not do.
///
/// `membership_version` itself always qualifies, so this always yields a
/// version. Note that an unrelated change landing above a held one is held with
/// it: registry versions form a single sequence, so there is no way to adopt a
/// later change without also adopting the membership change below it.
pub fn highest_adoptable_version(
    registry_client: &dyn RegistryClient,
    subnet_id: SubnetId,
    membership_version: RegistryVersion,
    latest: RegistryVersion,
    block_time: Time,
    hold: Duration,
) -> Result<RegistryVersion, MembershipHoldError> {
    if latest <= membership_version {
        return Ok(membership_version);
    }

    let members = subnet_members(registry_client, subnet_id, membership_version)?;

    for version in (membership_version.get()..=latest.get()).rev() {
        let version = RegistryVersion::from(version);
        let is_adoptable = is_adoptable(
            registry_client,
            subnet_id,
            &members,
            version,
            block_time,
            hold,
        )?;

        if is_adoptable {
            return Ok(version);
        }
    }

    Ok(membership_version)
}

/// Whether `candidate` may be adopted by a block at `block_time`, given the
/// `members` the subnet is currently counting on.
fn is_adoptable(
    registry_client: &dyn RegistryClient,
    subnet_id: SubnetId,
    members: &BTreeSet<NodeId>,
    candidate: RegistryVersion,
    block_time: Time,
    hold: Duration,
) -> Result<bool, MembershipHoldError> {
    let candidate_members = subnet_members(registry_client, subnet_id, candidate)?;
    let is_adding_nodes = candidate_members.difference(members).next().is_some();
    if !is_adding_nodes {
        return Ok(true);
    }

    let Some(applied_at) = registry_client.get_version_canister_timestamp(candidate) else {
        return Ok(true);
    };

    Ok(applied_at + hold <= block_time)
}

fn subnet_members(
    registry_client: &dyn RegistryClient,
    subnet_id: SubnetId,
    registry_version: RegistryVersion,
) -> Result<BTreeSet<NodeId>, MembershipHoldError> {
    Ok(registry_client
        .get_node_ids_on_subnet(subnet_id, registry_version)?
        .unwrap_or_default()
        .into_iter()
        .collect())
}

#[cfg(test)]
#[path = "membership_hold_tests.rs"]
mod tests;
