// TODO(NNS1-2819): remove after deployment
use crate::{
    governance::{Governance, LOG_PREFIX},
    pb::v1::governance::genesis_neuron_accounts::GenesisNeuronAccount,
};
#[cfg(target_arch = "wasm32")]
use dfn_core::println;
use ic_nns_common::pb::v1::NeuronId;
use icp_ledger::AccountIdentifier;

#[cfg(test)]
mod genesis_neuron_tests;

/// The maximum number of retries a GenesisNeuronAccount has to be tagged.
const MAXIMUM_RETRIES: u64 = 1;

impl Governance {
    /// Determines if Governance can tag genesis neurons.
    ///
    /// Conditions for true:
    /// 1. There is not a tagging operation in progress
    /// 2. There are still accounts that need to be tagged.
    ///
    /// Conditions for false:
    /// 1. There are no `genesis_neuron_accounts` in Governance state
    /// 2. All seed accounts have been tagged
    /// 3. The tagging process encountered a glitch and state is corrupted.
    pub fn some_genesis_neurons_are_untagged(&self) -> bool {
        if let Some(genesis_neuron_accounts) = &self.heap_data.genesis_neuron_accounts {
            // This is a quick check to determine if the last item in the vector has been
            // processed. If so, there is no need to search through all of the genesis_neuron_accounts
            // for the next account to tag.
            if let Some(last_genesis_neuron_account) =
                genesis_neuron_accounts.genesis_neuron_accounts.last()
            {
                if last_genesis_neuron_account
                    .tag_start_timestamp_seconds
                    .is_some()
                    && last_genesis_neuron_account
                        .tag_end_timestamp_seconds
                        .is_some()
                {
                    return false;
                }
            }

            for genesis_neuron_account in &genesis_neuron_accounts.genesis_neuron_accounts {
                let GenesisNeuronAccount {
                    account_ids: _,
                    tag_start_timestamp_seconds,
                    tag_end_timestamp_seconds,
                    error_count,
                    neuron_type: _,
                    amount_icp_e8s: _,
                    id,
                } = genesis_neuron_account;

                match (tag_start_timestamp_seconds, tag_end_timestamp_seconds) {
                    // Already tagged. Continue the search for the next genesis_neuron_account to tag
                    (Some(_), Some(_)) => continue,
                    // There is a tagging operation in progress. Wait for that to finish.
                    (Some(_), None) => return false,
                    // Found a genesis_account ready to be processed.
                    (None, None) => {
                        // If there has been >MAXIMUM_RETRIES errors skip this account.
                        if *error_count >= MAXIMUM_RETRIES {
                            continue;
                        }
                        return true;
                    }
                    // Glitch in the tagging process. Don't try to tag
                    // any new neurons until this has been resolved.
                    (None, Some(tag_end_timestamp_seconds)) => {
                        println!(
                            "{}Bug encountered with GenesisNeuronAccount={} when tagging GenesisAccountNeuron. \
                            tag_start_timestamp_seconds is None and tag_end_timestamp_seconds \
                            is {:?}. genesis_neuron_account = {:?}",
                            LOG_PREFIX, id, tag_end_timestamp_seconds, genesis_neuron_account,
                        );
                        return false;
                    }
                }
            }
        }

        false
    }

    pub fn tag_genesis_neurons(&mut self) {
        // Step 1: Find the next account that should be processed
        let now = self.env.now();

        let (id, neuron_type, account_ids, amount_icp_e8s) = {
            let untagged_genesis_neuron_account =
                match self.get_next_genesis_neuron_account_for_tagging_mut() {
                    Some(untagged_genesis_neuron_account) => untagged_genesis_neuron_account,
                    // This shouldn't occur due to `can_tag_genesis_neurons`
                    None => {
                        println!(
                            "{}No GenesisNeuronAccounts are ready to be tagged. This should not \
                            occur due to the `can_tag_genesis_neurons` check",
                            LOG_PREFIX
                        );
                        return;
                    }
                };

            // Set the tag_start_timestamp_seconds to the current time to indicate that a tagging process is underway.
            untagged_genesis_neuron_account.tag_start_timestamp_seconds = Some(now);
            (
                untagged_genesis_neuron_account.id,
                untagged_genesis_neuron_account.neuron_type,
                &untagged_genesis_neuron_account.account_ids.clone(),
                untagged_genesis_neuron_account.amount_icp_e8s,
            )
        };
        println!("{}Tagging GenesisNeuronAccount={}", LOG_PREFIX, id);

        let eligible_neuron_ids = match self
            .collect_eligible_genesis_neurons_ids_for_accounts(account_ids, amount_icp_e8s)
        {
            Ok(eligible_neuron_ids) => eligible_neuron_ids,
            Err(governance_error) => {
                let error_message = format!(
                    "GenesisNeuronAccount={} encountered an issue when collecting eligible neurons ids to tag. {}",
                    id, governance_error
                );
                self.handle_tagging_error(id, error_message);
                return;
            }
        };

        for neuron_id in &eligible_neuron_ids {
            if let Err(governance_error) =
                self.with_neuron_mut(neuron_id, |neuron| neuron.neuron_type = Some(neuron_type))
            {
                println!(
                    "{}NeuronId {:?} neuron_type could not be markeed as {:?}. Reason: {:?}",
                    LOG_PREFIX, neuron_id, neuron_type, governance_error,
                );
            }
        }

        let untagged_genesis_neuron_account = match self.get_genesis_neuron_account_mut(id) {
            Some(untagged_genesis_neuron_account) => untagged_genesis_neuron_account,
            None => {
                println!(
                    "{}GenesisNeuronAccount={} is missing. Cannot tag its neurons",
                    LOG_PREFIX, id
                );
                return;
            }
        };
        untagged_genesis_neuron_account.tag_end_timestamp_seconds = Some(now);
    }

    /// Get a mutable reference to the next available account for tagging, i.e. the
    /// first GenesisNeuronAccount with both `tag_start_timestamp_seconds` and `tag_end_timestamp_seconds`
    /// timestamps set to None. If a GenesisNeuronAccount is discovered with only one of those
    /// fields set, then the idempotency guarantees have been violated and this method
    /// returns None.
    fn get_next_genesis_neuron_account_for_tagging_mut(
        &mut self,
    ) -> Option<&mut GenesisNeuronAccount> {
        if let Some(genesis_neuron_account_ids) = &mut self.heap_data.genesis_neuron_accounts {
            for genesis_neuron_account in &mut genesis_neuron_account_ids.genesis_neuron_accounts {
                let GenesisNeuronAccount {
                    account_ids: _,
                    tag_start_timestamp_seconds,
                    tag_end_timestamp_seconds,
                    error_count,
                    neuron_type: _,
                    amount_icp_e8s: _,
                    id: _,
                } = genesis_neuron_account;

                match (tag_start_timestamp_seconds, tag_end_timestamp_seconds) {
                    // Continue the search for a GenesisNeuronAccount ready to be tagged.
                    (Some(_), Some(_)) => continue,
                    // If there was async, this would mean there is an account currently being processed
                    // This is currently not possible due to the synchronous nature of the tagging process.
                    // It would indicate an error, so we would stop the process.
                    (Some(_), None) => return None,
                    // There is an account ready to be processed
                    (None, None) => {
                        // If there has been >MAXIMUM_GET_ACCOUNT_RETRIES inter-canister
                        // call related errors skip this account.
                        if *error_count >= MAXIMUM_RETRIES {
                            continue;
                        }
                        return Some(genesis_neuron_account);
                    }
                    // This is an undefined state and a bug has occurred. Don't try to tag
                    // any new neurons
                    (None, Some(_)) => return None,
                }
            }
        }

        None
    }

    fn collect_eligible_genesis_neurons_ids_for_accounts(
        &self,
        account_ids: &[String],
        total_expected_icp_e8s_across_neurons: u64,
    ) -> Result<Vec<NeuronId>, String> {
        let mut neuron_ids = account_ids
            .iter()
            .filter_map(|account_id| {
                let account_id = AccountIdentifier::from_hex(account_id).unwrap();
                let maybe_neuron_id = self.neuron_store.get_neuron_id_for_account_id(&account_id);

                if maybe_neuron_id.is_none() {
                    println!(
                        "{}AccountId={} does not back an NNS Neuron. This account_id will not be used to collect \
                        eligible NeuronIds for tagging",
                        LOG_PREFIX, account_id
                    )
                }

                maybe_neuron_id
            })
            .collect::<Vec<_>>();

        // Sum the total_cached_stake_e8s (ignoring neuron fees) of the neuron ids..
        let total_cached_stake_e8s: u64 = neuron_ids
            .iter()
            .filter_map(|neuron_id| {
                self.with_neuron(neuron_id, |neuron| neuron.cached_neuron_stake_e8s)
                    .ok()
            })
            .sum();

        if total_cached_stake_e8s < total_expected_icp_e8s_across_neurons {
            let controlling_principal_id = self
                .neuron_store
                .with_neuron(neuron_ids.first().unwrap(), |neuron| {
                    neuron.controller.unwrap()
                })
                .unwrap();

            let controlled_neuron_ids = self.get_neuron_ids_by_principal(&controlling_principal_id);
            neuron_ids.extend(controlled_neuron_ids);
        }

        Ok(neuron_ids)
    }

    fn get_genesis_neuron_account_mut(&mut self, id: u64) -> Option<&mut GenesisNeuronAccount> {
        if let Some(genesis_neuron_account_ids) = &mut self.heap_data.genesis_neuron_accounts {
            for genesis_neuron_account in &mut genesis_neuron_account_ids.genesis_neuron_accounts {
                if genesis_neuron_account.id == id {
                    return Some(genesis_neuron_account);
                }
            }
        }

        None
    }

    /// Gets a mutable reference to the GenesisNeuronAccount of `id`, increments its error count, resets
    /// its timestamps, and prints and error message.
    fn handle_tagging_error(&mut self, id: u64, error_message: String) {
        let untagged_genesis_neuron_account = match self.get_genesis_neuron_account_mut(id) {
            Some(untagged_genesis_neuron_account) => untagged_genesis_neuron_account,
            None => {
                println!(
                    "{}GenesisNeuronAccount={} is missing. Cannot reset its tagging \
                    fields when handling the following error, {}",
                    LOG_PREFIX, id, error_message
                );
                return;
            }
        };

        untagged_genesis_neuron_account.tag_start_timestamp_seconds = None;
        untagged_genesis_neuron_account.tag_end_timestamp_seconds = None;
        untagged_genesis_neuron_account.error_count += 1;
        println!("{}{}", LOG_PREFIX, error_message);
    }
}
