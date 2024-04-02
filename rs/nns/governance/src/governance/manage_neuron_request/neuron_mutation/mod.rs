use crate::{governance::Governance, neuron::types::Neuron, pb::v1::GovernanceError};
use async_trait::async_trait;
use ic_nns_common::pb::v1::NeuronId;
use std::{
    cmp::Ordering,
    collections::{btree_map::Entry, BTreeMap},
};

pub(crate) mod burn_fees_mutation;
pub(crate) mod merge_neuron_mutation;

/// A proxy type for applying mutations to governance state which allows for an alternate
/// implementation which simulates the changes without committing them.  This allows the same
/// logic to be tested and exposed as a "preview" of some action.
pub enum GovernanceMutationProxy<'a> {
    Committing(&'a mut Governance),
    Simulating(SimulatingGovernance<'a>),
}

impl GovernanceMutationProxy<'_> {
    /// Create a GovernanceMutationProxy::Committing instance  
    pub fn new_committing(gov: &mut Governance) -> GovernanceMutationProxy<'_> {
        GovernanceMutationProxy::Committing(gov)
    }

    /// Create a GovernanceMutationProxy::Simulating instance
    pub fn new_simulating(gov: &Governance) -> GovernanceMutationProxy<'_> {
        GovernanceMutationProxy::Simulating(SimulatingGovernance {
            real_gov: gov,
            neuron_map: Default::default(),
        })
    }

    /// Get the current time in seconds.
    pub fn now(&self) -> u64 {
        match self {
            GovernanceMutationProxy::Committing(real) => real.env.now(),
            GovernanceMutationProxy::Simulating(simulating) => simulating.real_gov.env.now(),
        }
    }

    /// Execute a function with a reference to a neuron, if it exists,
    /// returning the result or an error.
    pub fn with_neuron<R>(
        &self,
        neuron_id: &NeuronId,
        modify: impl FnOnce(&Neuron) -> R,
    ) -> Result<R, GovernanceError> {
        match self {
            GovernanceMutationProxy::Committing(real) => real.with_neuron(neuron_id, modify),
            GovernanceMutationProxy::Simulating(simulating) => {
                simulating.with_neuron(neuron_id, modify)
            }
        }
    }

    /// Execute a function with a mutable reference to a neuron, if it exists,
    /// returning the result or an error.
    pub fn with_neuron_mut<R>(
        &mut self,
        neuron_id: &NeuronId,
        modify: impl FnOnce(&mut Neuron) -> R,
    ) -> Result<R, GovernanceError> {
        match self {
            GovernanceMutationProxy::Committing(real) => real.with_neuron_mut(neuron_id, modify),
            GovernanceMutationProxy::Simulating(simulating) => {
                simulating.with_neuron_mut(neuron_id, modify)
            }
        }
    }

    /// Get the transaction_fee u8s
    pub fn transaction_fee(&self) -> u64 {
        match self {
            GovernanceMutationProxy::Committing(real) => real.transaction_fee(),
            GovernanceMutationProxy::Simulating(simulating) => {
                simulating.real_gov.transaction_fee()
            }
        }
    }
}

/// A struct representing a read-only reference to Governance along with accumulating changes, allowing
/// for complex simulations of state changes in Governance without committing.  
pub struct SimulatingGovernance<'a> {
    /// A reference to the real Governance object, to read data.
    real_gov: &'a Governance,
    /// A map keeping track of neurons that are edited
    neuron_map: BTreeMap<u64, Neuron>,
}

impl SimulatingGovernance<'_> {
    pub fn with_neuron<R>(
        &self,
        neuron_id: &NeuronId,
        modify: impl FnOnce(&Neuron) -> R,
    ) -> Result<R, GovernanceError> {
        let result = match self.neuron_map.get(&neuron_id.id) {
            Some(neuron) => modify(neuron),
            None => self.real_gov.neuron_store.with_neuron(neuron_id, modify)?,
        };
        Ok(result)
    }

    pub fn with_neuron_mut<R>(
        &mut self,
        neuron_id: &NeuronId,
        modify: impl FnOnce(&mut Neuron) -> R,
    ) -> Result<R, GovernanceError> {
        let neuron = match self.neuron_map.entry(neuron_id.id) {
            Entry::Occupied(o) => o.into_mut(),
            Entry::Vacant(entry) => entry.insert(
                self.real_gov
                    .neuron_store
                    .with_neuron(neuron_id, |n| n.clone())?,
            ),
        };

        Ok(modify(neuron))
    }
}

/// Apply a set of NeuronDeltas to GovernanceMutationProxy.
fn apply_neuron_deltas(
    gov_proxy: &mut GovernanceMutationProxy,
    deltas: &BTreeMap<NeuronId, NeuronDeltas>,
) -> Result<(), GovernanceError> {
    let now_seconds = gov_proxy.now();
    for (neuron_id, delta) in deltas {
        gov_proxy.with_neuron_mut(neuron_id, |neuron| {
            delta.apply(neuron, now_seconds);
        })?;
    }
    Ok(())
}

/// A trait representing an atomic mutation to apply to a Neuron, including external changes that
/// have to be made to keep everything in a consistent state.
///
/// Each individual inter-canister call should have its own set of internal changes, so that no more than one
/// inter-canister call is made without updating internal state to match.  Otherwise, a subsequent
/// failure could cause the canister to be in an inconsistent state.
///
/// An example of this is when burning fees, you have to first burn the ICP in the neuron account
/// (an external change), and then remove the amount burned from cached_neuron_stake_e8s
/// and neuron_fees_e8s (an internal change).
///
/// This trait is meant to represent a mutation that can be committed independently of any
/// other mutations, even if it is used in a sequence of mutations.
#[async_trait]
pub trait GovernanceNeuronMutation: Send + Sync {
    /// Calculate the Neuron deltas this mutation will make, which represents the difference between
    /// the current state of the neuron, and the future state of the neuron after the changes apply.
    fn calculate_neuron_deltas_to_apply(
        &self,
        gov: &GovernanceMutationProxy,
    ) -> Result<BTreeMap<NeuronId, NeuronDeltas>, GovernanceError>;

    /// Commit changes to other canisters.  This may mutate the deltas if there are pre operation changes
    /// and error checking code that may need to be executed.
    ///
    /// In order for changes to be atomic, this should 1) be applied along with internal_changes (which happens if you
    /// run apply_all_changes) and 2) only make a single async call.
    ///
    ///
    /// If apply_external_mutations modifies a neuron before an inter-canister call, it must have logic
    /// for rolling back that change if the external call fails, and must update the related NeuronDelta
    /// so that the change is not applied twice.
    async fn apply_external_mutation(
        &self,
        gov: &mut GovernanceMutationProxy,
        deltas: &mut BTreeMap<NeuronId, NeuronDeltas>,
    ) -> Result<(), GovernanceError>;

    /// Apply the changes that are calculated but skip external changes.  Typically this should
    /// only be done when using GovernanceMutationProxy::Simulating.
    fn apply_internal_mutations(
        &self,
        gov: &mut GovernanceMutationProxy,
    ) -> Result<(), GovernanceError> {
        let deltas = self.calculate_neuron_deltas_to_apply(gov)?;
        apply_neuron_deltas(gov, &deltas)
    }

    /// Apply all the changes, internal and external, and commit the result.
    async fn apply_all_mutations(
        &self,
        gov_proxy: &mut GovernanceMutationProxy,
    ) -> Result<(), GovernanceError> {
        let mut deltas = self.calculate_neuron_deltas_to_apply(gov_proxy)?;
        self.apply_external_mutation(gov_proxy, &mut deltas)
            .await
            .and_then(|_| apply_neuron_deltas(gov_proxy, &deltas))
    }
}

// A set of changes to be applied to neuron fields on a particular neuron
#[derive(Debug)]
pub struct NeuronDeltas {
    pub neuron_fees_e8s: i128,
    pub cached_neuron_stake_e8s: i128,
    pub aging_since_timestamp_seconds: i128,
    pub dissolve_delay: u32,
    pub maturity_e8s_equivalent: i128,
    pub staked_maturity_e8s_equivalent: i128,
}

impl NeuronDeltas {
    // Applies all changes to a neuron.
    fn apply(&self, neuron: &mut Neuron, now_seconds: u64) {
        neuron.increase_dissolve_delay(now_seconds, self.dissolve_delay);

        neuron.cached_neuron_stake_e8s = saturating_add_or_subtract_u64_i128(
            neuron.cached_neuron_stake_e8s,
            self.cached_neuron_stake_e8s,
        );

        neuron.neuron_fees_e8s =
            saturating_add_or_subtract_u64_i128(neuron.neuron_fees_e8s, self.neuron_fees_e8s);

        neuron.maturity_e8s_equivalent = saturating_add_or_subtract_u64_i128(
            neuron.maturity_e8s_equivalent,
            self.maturity_e8s_equivalent,
        );

        // Don't change None -> Some(0)
        if self.staked_maturity_e8s_equivalent != 0 {
            let staked_maturity_e8s_equivalent_original =
                neuron.staked_maturity_e8s_equivalent.unwrap_or_default();

            let staked_maturity_e8s_equivalent_new_value = saturating_add_or_subtract_u64_i128(
                staked_maturity_e8s_equivalent_original,
                self.staked_maturity_e8s_equivalent,
            );

            neuron.staked_maturity_e8s_equivalent = Some(staked_maturity_e8s_equivalent_new_value);
        }

        neuron.aging_since_timestamp_seconds = saturating_add_or_subtract_u64_i128(
            neuron.aging_since_timestamp_seconds,
            self.aging_since_timestamp_seconds,
        );
    }
}

/// Adds or subtracts a i128 to a u64, resulting in a u64.
fn saturating_add_or_subtract_u64_i128(initial_value: u64, delta: i128) -> u64 {
    match delta.cmp(&0) {
        Ordering::Less => initial_value.saturating_sub(delta.saturating_abs() as u64),
        Ordering::Equal => initial_value,
        Ordering::Greater => initial_value.saturating_add(delta as u64),
    }
}
