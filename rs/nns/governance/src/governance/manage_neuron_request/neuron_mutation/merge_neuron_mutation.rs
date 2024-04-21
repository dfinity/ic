use crate::{
    governance::{
        combine_aged_stakes,
        manage_neuron_request::neuron_mutation::{
            saturating_add_or_subtract_u64_i128, GovernanceMutationProxy, GovernanceNeuronMutation,
            NeuronDeltas,
        },
        neuron_subaccount,
    },
    pb::v1::{governance_error::ErrorType, GovernanceError},
};
use async_trait::async_trait;
use ic_nns_common::pb::v1::NeuronId;
use maplit::btreemap;
use std::{collections::BTreeMap, ops::Neg};

pub struct MergeNeuronMutation {
    source_neuron_id: NeuronId,
    target_neuron_id: NeuronId,
}

impl MergeNeuronMutation {
    pub fn new(source_neuron_id: NeuronId, target_neuron_id: NeuronId) -> Self {
        Self {
            source_neuron_id,
            target_neuron_id,
        }
    }
}

#[async_trait]
impl GovernanceNeuronMutation for MergeNeuronMutation {
    fn calculate_neuron_deltas_to_apply(
        &self,
        gov: &GovernanceMutationProxy,
    ) -> Result<BTreeMap<NeuronId, NeuronDeltas>, GovernanceError> {
        let source_neuron = gov.with_neuron(&self.source_neuron_id, |n| n.clone())?;
        let target_neuron = gov.with_neuron(&self.target_neuron_id, |n| n.clone())?;

        let transaction_fees_e8s = gov.transaction_fee();

        // ICP stake transfer
        let source_stake_e8s = source_neuron.minted_stake_e8s();
        let source_stake_less_transaction_fee_e8s =
            source_stake_e8s.saturating_sub(transaction_fees_e8s);

        // Aging Increase target Neuron
        let now = gov.now();
        let source_dissolve_delay = source_neuron.dissolve_delay_seconds(now);

        let target_dissolve_delay = target_neuron.dissolve_delay_seconds(now);

        let source_age_seconds = if source_neuron.is_dissolved(now) {
            // Do not credit age from dissolved neurons.
            0
        } else {
            source_neuron.age_seconds(now)
        };
        let target_age_seconds = if target_neuron.is_dissolved(now) {
            // Do not credit age from dissolved neurons.
            0
        } else {
            target_neuron.age_seconds(now)
        };
        let highest_dissolve_delay = std::cmp::max(target_dissolve_delay, source_dissolve_delay);
        let target_dissolve_delay_increase = highest_dissolve_delay
            .saturating_sub(target_dissolve_delay)
            .try_into()
            .map_err(|e| {
                GovernanceError::new_with_message(
                    ErrorType::PreconditionFailed,
                    format!(
                        "Difference for dissolve delays was greater than u32::MAX: {}",
                        e
                    ),
                )
            })?;

        let (_, new_age_seconds) = combine_aged_stakes(
            target_neuron.cached_neuron_stake_e8s,
            target_age_seconds,
            source_stake_less_transaction_fee_e8s,
            source_age_seconds,
        );

        // Maturity Transfer
        let source_maturity_to_transfer = source_neuron.maturity_e8s_equivalent;

        // Staked Maturity Transfer
        let source_staked_maturity_to_transfer = source_neuron
            .staked_maturity_e8s_equivalent
            .unwrap_or_default();

        let new_aging_since_timestamp_seconds = now.saturating_sub(new_age_seconds);
        let aging_timestamp_seconds_delta = (new_aging_since_timestamp_seconds as i128)
            .saturating_sub(target_neuron.aging_since_timestamp_seconds as i128);

        Ok(btreemap! {
        source_neuron.id() => NeuronDeltas {
            neuron_fees_e8s: 0,
            cached_neuron_stake_e8s: (if source_stake_less_transaction_fee_e8s > 0 {
                source_stake_e8s
            } else {
                0
            } as i128)
                .neg(),
            // Reset aging
            aging_since_timestamp_seconds: if source_stake_less_transaction_fee_e8s > 0 {
                now.saturating_sub(source_neuron.aging_since_timestamp_seconds) as i128
            } else {
                0
            },
            dissolve_delay: 0,
            maturity_e8s_equivalent: (source_maturity_to_transfer as i128).neg(),
            staked_maturity_e8s_equivalent: (source_staked_maturity_to_transfer as i128).neg(),
        },
        target_neuron.id() => NeuronDeltas {
            neuron_fees_e8s: 0,
            cached_neuron_stake_e8s: (source_stake_less_transaction_fee_e8s as i128),
            aging_since_timestamp_seconds: aging_timestamp_seconds_delta,
            dissolve_delay: target_dissolve_delay_increase,
            maturity_e8s_equivalent: (source_maturity_to_transfer as i128),
            staked_maturity_e8s_equivalent: (source_staked_maturity_to_transfer as i128),
        },})
    }

    async fn apply_external_mutation(
        &self,
        gov_proxy: &mut GovernanceMutationProxy,
        deltas: &mut BTreeMap<NeuronId, NeuronDeltas>,
    ) -> Result<(), GovernanceError> {
        let gov = match gov_proxy {
            GovernanceMutationProxy::Committing(g) => g,
            GovernanceMutationProxy::Simulating(_) => {
                panic!("Cannot run external operations without Governance")
            }
        };

        if deltas.len() != 2 {
            return Err(GovernanceError::new_with_message(
                ErrorType::PreconditionFailed,
                "Unable to apply MergeNeuronMutation because Deltas were not generated by this mutation.",
            ));
        }

        let Some(source_delta) = deltas.get(&self.source_neuron_id) else {
            return Err(GovernanceError::new_with_message(
                ErrorType::PreconditionFailed,
                "Unable to apply MergeNeuronMutation because Deltas were not generated by this mutation.",
            ));
        };
        let Some(target_delta) = deltas.get(&self.target_neuron_id) else {
            return Err(GovernanceError::new_with_message(
                ErrorType::PreconditionFailed,
                "Unable to apply MergeNeuronMutation because Deltas were not generated by this mutation.",
            ));
        };

        let source_stake_less_transaction_fee_e8s =
            target_delta.cached_neuron_stake_e8s.saturating_abs() as u64;

        let now = gov.env.now();

        if source_stake_less_transaction_fee_e8s > 0 {
            let transaction_fee_e8s = gov.transaction_fee();
            let to_subaccount = gov.with_neuron(&self.target_neuron_id, |target_neuron| {
                target_neuron.subaccount()
            })?;

            let from_subaccount = gov.with_neuron(&self.source_neuron_id, |source_neuron| {
                source_neuron.subaccount()
            })?;

            let original_delta_cached_neuron_stake_e8s = source_delta.cached_neuron_stake_e8s;
            let original_delta_aging_since_timestamp_seconds =
                source_delta.aging_since_timestamp_seconds;

            gov.with_neuron_mut(&self.source_neuron_id, |source_neuron_mut| {
                let source_delta_mut = deltas.get_mut(&self.source_neuron_id).unwrap();

                // We must zero out the source neuron's cached stake before
                // submitting the call to transfer_funds. If we do not do this,
                // there would be a window of opportunity -- from the moment the
                // stake is transferred but before the cached stake is updated --
                // when a proposal could be submitted and rejected on behalf of
                // the source neuron (since cached stake is high enough), but that
                // would be impossible to charge because the account had been
                // emptied. To guard against this, we preemptively set the stake
                // to zero, and set it back in case of transfer failure.
                //
                // Another important reason to set the cached stake to zero (net
                // fees) is so that the source neuron cannot use the stake that is
                // getting merged to vote or propose. Also, the source neuron
                // should not be able to increase stake while locked because we do
                // not allow the source to have pending proposals.
                source_neuron_mut.cached_neuron_stake_e8s = saturating_add_or_subtract_u64_i128(
                    source_neuron_mut.cached_neuron_stake_e8s,
                    source_delta_mut.cached_neuron_stake_e8s,
                );
                // Record that the delta was partially applied
                source_delta_mut.cached_neuron_stake_e8s = 0;

                // Reset source aging. In other words, if it was aging before, it
                // is still aging now, although the timer is reset to the time of
                // the merge -- but only if there is stake being transferred.
                // Since all fees have been burned (if they were greater in value
                // than the transaction fee) and since this neuron is not
                // currently participating in any proposal, it means the cached
                // stake is 0 and increasing the stake will not take advantage of
                // this age. However, it is consistent with the use of
                // aging_since_timestamp_seconds that we simply reset the age
                // here, since we do not change the dissolve state in any other
                // way.
                // let source_age_timestamp_seconds = source_neuron_mut.aging_since_timestamp_seconds;
                if source_neuron_mut.aging_since_timestamp_seconds != u64::MAX {
                    source_neuron_mut.aging_since_timestamp_seconds =
                        saturating_add_or_subtract_u64_i128(
                            source_neuron_mut.aging_since_timestamp_seconds,
                            source_delta_mut.aging_since_timestamp_seconds,
                        );
                    // Record that the delta was partially applied
                    source_delta_mut.aging_since_timestamp_seconds = 0;
                }
            })?;

            let _block_height: u64 = gov
                .ledger
                .transfer_funds(
                    source_stake_less_transaction_fee_e8s,
                    transaction_fee_e8s,
                    Some(from_subaccount),
                    neuron_subaccount(to_subaccount),
                    now,
                )
                .await
                .map_err(|err| {
                    gov.with_neuron_mut(&self.source_neuron_id, |source_neuron_mut| {
                        // Rollback changes (apply negative deltas)
                        source_neuron_mut.cached_neuron_stake_e8s =
                            saturating_add_or_subtract_u64_i128(
                                source_neuron_mut.cached_neuron_stake_e8s,
                                original_delta_cached_neuron_stake_e8s.saturating_neg(),
                            );
                        source_neuron_mut.aging_since_timestamp_seconds =
                            saturating_add_or_subtract_u64_i128(
                                source_neuron_mut.aging_since_timestamp_seconds,
                                original_delta_aging_since_timestamp_seconds.saturating_neg(),
                            );
                    })
                    .expect("Expected the source neuron to exist");

                    let source_delta_mut = deltas.get_mut(&self.source_neuron_id).unwrap();
                    // Restore the delta state of changes to be applied
                    source_delta_mut.cached_neuron_stake_e8s =
                        original_delta_cached_neuron_stake_e8s;
                    source_delta_mut.aging_since_timestamp_seconds =
                        original_delta_aging_since_timestamp_seconds;
                    err
                })?;
        }
        Ok(())
    }
}
