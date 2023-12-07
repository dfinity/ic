use crate::{
    governance::{Governance, LOG_PREFIX, ONE_MONTH_SECONDS},
    pb::v1::{
        governance::seed_accounts::SeedAccount, governance_error::ErrorType, GovernanceError,
        NeuronType,
    },
};
use candid::{Decode, Encode};
#[cfg(target_arch = "wasm32")]
use dfn_core::println;
use ic_base_types::PrincipalId;
use ic_ledger_core::Tokens;
use ic_nns_common::pb::v1::NeuronId;
use ic_nns_constants::GENESIS_TOKEN_CANISTER_ID;
use std::collections::HashSet;

#[cfg(test)]
mod seed_accounts_tests;

/// The maximum number of retries a SeedAccount has to query the Genesis Token Canister.
const MAXIMUM_GET_ACCOUNT_RETRIES: u64 = 5;

/// The count of Neurons each genesis account received  
const SEED_NEURON_DISTRIBUTION_COUNT: f64 = 49.0;

impl Governance {
    /// Determines if Governance can tag seed neurons.
    ///
    /// Conditions for true:
    /// 1. There is not a tagging operation in progress
    /// 2. There are still accounts that need to be tagged.
    ///
    /// Conditions for false:
    /// 1. There are no seed accounts in Governance state
    /// 2. All seed accounts have been tagged
    /// 3. The tagging process encountered a glitch and state is corrupted.
    pub fn can_tag_seed_neurons(&self) -> bool {
        if let Some(seed_accounts) = &self.heap_data.seed_accounts {
            // This is a quick check to determine if the last item in the vector has been
            // processed. If so, there is no need to search through all of the seed_accounts
            // for the next account to tag.
            if let Some(last_seed_account) = seed_accounts.accounts.last() {
                if last_seed_account.tag_start_timestamp_seconds.is_some()
                    && last_seed_account.tag_end_timestamp_seconds.is_some()
                {
                    return false;
                }
            }

            for seed_account in &seed_accounts.accounts {
                let SeedAccount {
                    account_id,
                    tag_start_timestamp_seconds,
                    tag_end_timestamp_seconds,
                    error_count,
                    neuron_type: _,
                } = seed_account;

                match (tag_start_timestamp_seconds, tag_end_timestamp_seconds) {
                    // Already tagged. Continue the search for the next seed_account to tag
                    (Some(_), Some(_)) => continue,
                    // There is a tagging operation in progress. Wait for that to finish.
                    (Some(_), None) => return false,
                    // Found a seed_account ready to be processed.
                    (None, None) => {
                        // If there has been >MAXIMUM_GET_ACCOUNT_RETRIES inter-canister
                        // call related errors skip this account.
                        if *error_count >= MAXIMUM_GET_ACCOUNT_RETRIES {
                            continue;
                        }
                        return true;
                    }
                    // Glitch in the tagging process. Don't try to tag
                    // any new neurons until this has been resolved.
                    (None, Some(_)) => {
                        println!(
                            "{}Bug encountered with {} Account when tagging seed neurons. \
                            tag_start_timestamp_seconds is None and tag_end_timestamp_seconds \
                            is not. {:?}",
                            LOG_PREFIX, account_id, seed_account
                        );
                        return false;
                    }
                }
            }
        }

        false
    }

    /// Tag seed neuron based on response from GTC.
    pub async fn tag_seed_neurons(&mut self) {
        // Step 1: Find the next seed neuron to process
        let (account_id, neuron_type) = {
            let now = self.env.now();
            let untagged_seed_account = match self.get_next_seed_account_for_tagging() {
                Some(untagged_seed_account) => untagged_seed_account,
                // This shouldn't occur due to the `can_tag_seed_neurons`.
                None => return,
            };

            // Set the tag_start_timestamp_seconds to the current time before issuing the
            // async request to indicate that a tagging process is underway.
            untagged_seed_account.tag_start_timestamp_seconds = Some(now);
            (
                untagged_seed_account.account_id.clone(),
                untagged_seed_account.neuron_type,
            )
        };
        println!("{}Tagging SeedAccount {}", LOG_PREFIX, account_id);

        // Step 2: Issue the request to GTC.
        let get_account_result = self.get_gtc_account(&account_id).await;

        // Step 3: Process the response

        // Get the current time after the await
        let now = self.env.now();

        // Process the response. If the response failed for whatever reason, reset the
        // seed neuron's timestamps so it can retry.
        let account_state = match get_account_result {
            Ok(account_state) => account_state,
            Err(governance_error) => {
                let error_message = format!(
                    "SeedAccount {} encountered an issue when calling the GTC. {}",
                    account_id, governance_error
                );
                self.handle_tagging_error(&account_id, error_message);
                return;
            }
        };

        // Step 4: Collect all eligible NeuronIds to be marked
        let eligible_neuron_ids = match self.collect_eligible_genesis_neurons_ids_of_principal(
            &account_state,
            now,
            neuron_type,
        ) {
            Ok(eligible_neuron_ids) => eligible_neuron_ids,
            Err(governance_error) => {
                let error_message = format!(
                    "SeedAccount {} encountered an issue when collecting eligible neurons ids to tag. {}",
                    account_id, governance_error
                );
                self.handle_tagging_error(&account_id, error_message);
                return;
            }
        };

        // Step 5: Mark neuron's NeuronType field.
        for neuron_id in &eligible_neuron_ids {
            if let Err(governance_error) =
                self.with_neuron_mut(neuron_id, |neuron| neuron.neuron_type = Some(neuron_type))
            {
                println!(
                    "{}NeuronId {:?} could not be marked as . Reason: {:?}",
                    LOG_PREFIX, neuron_id, governance_error,
                );
            }
        }
        println!(
            "{}Tagged {} Neurons as `{:?}` for SeedAccount {}",
            LOG_PREFIX,
            eligible_neuron_ids.len(),
            NeuronType::try_from(neuron_type),
            account_id,
        );

        // Reacquire the same SeedAccount to satisfy the borrow checker
        let untagged_seed_account = match self.get_seed_account_mut(&account_id) {
            Some(untagged_seed_account) => untagged_seed_account,
            None => {
                println!(
                    "{}SeedAccount {} is missing. Cannot tag its neurons as seed neurons",
                    LOG_PREFIX, account_id
                );
                return;
            }
        };
        // Mark the end timestamp to indicate processing is done.
        untagged_seed_account.tag_end_timestamp_seconds = Some(now);
    }

    /// Get a mutable reference to the next available seed account for tagging, i.e. the
    /// first SeedAccount with both `tag_start_timestamp_seconds` and `tag_end_timestamp_seconds`
    /// timestamps set to None. If a SeedAccount is discovered with only one of those
    /// fields set, then the idempotency guarantees have been violated and this method
    /// returns None.
    fn get_next_seed_account_for_tagging(&mut self) -> Option<&mut SeedAccount> {
        if let Some(seed_accounts) = &mut self.heap_data.seed_accounts {
            for seed_account in &mut seed_accounts.accounts {
                let SeedAccount {
                    account_id: _,
                    tag_start_timestamp_seconds,
                    tag_end_timestamp_seconds,
                    error_count,
                    neuron_type: _,
                } = seed_account;

                match (tag_start_timestamp_seconds, tag_end_timestamp_seconds) {
                    // Continue the search for a SeedAccount ready to be tagged.
                    (Some(_), Some(_)) => continue,
                    // There is an account currently being processed
                    (Some(_), None) => return None,
                    // There is an account ready to be processed
                    (None, None) => {
                        // If there has been >MAXIMUM_GET_ACCOUNT_RETRIES inter-canister
                        // call related errors skip this account.
                        if *error_count >= MAXIMUM_GET_ACCOUNT_RETRIES {
                            continue;
                        }
                        return Some(seed_account);
                    }
                    // This is an undefined state and a bug has occurred. Don't try to tag
                    // any new neurons
                    (None, Some(_)) => return None,
                }
            }
        }

        None
    }

    /// Given an AccountId, return a mutable reference to the SeedAccount.
    // TODO: This code will only be run temporarily to tag seed neurons. Its performance
    // can be improved by using a HashMap, but the count of entries is 212, which has
    // equivalent performance to HashMap lookups.
    fn get_seed_account_mut(&mut self, account_id: &String) -> Option<&mut SeedAccount> {
        if let Some(seed_accounts) = &mut self.heap_data.seed_accounts {
            for seed_account in &mut seed_accounts.accounts {
                if &seed_account.account_id == account_id {
                    return Some(seed_account);
                }
            }
        }

        None
    }

    /// Gets a mutable reference to the SeedAccount of `account_id`, increments its error count, resets
    /// its timestamps, and prints and error message.
    fn handle_tagging_error(&mut self, account_id: &String, error_message: String) {
        let untagged_seed_account = match self.get_seed_account_mut(account_id) {
            Some(untagged_seed_account) => untagged_seed_account,
            None => {
                println!(
                    "{}SeedAccount {} is missing. Cannot reset its tagging \
                    fields when handling the following error, {}",
                    LOG_PREFIX, account_id, error_message
                );
                return;
            }
        };

        untagged_seed_account.tag_start_timestamp_seconds = None;
        untagged_seed_account.tag_end_timestamp_seconds = None;
        untagged_seed_account.error_count += 1;
        println!("{}{}", LOG_PREFIX, error_message);
    }

    /// Call the Genesis Token Canister's `get_account` API.
    async fn get_gtc_account(
        &mut self,
        account_id: &String,
    ) -> Result<AccountState, GovernanceError> {
        let request = Encode!(account_id).map_err(|err| {
            GovernanceError::new_with_message(
                ErrorType::External,
                format!(
                    "Cannot encode request type {} for 'get_account'. Error: {}",
                    account_id, err
                ),
            )
        })?;

        let gtc_response: Vec<u8> = self
            .env
            .call_canister_method(GENESIS_TOKEN_CANISTER_ID, "get_account", request)
            .await
            .map_err(|(code, msg)| {
                GovernanceError::new_with_message(
                    ErrorType::External,
                    format!(
                        "Error calling 'get_account': code: {:?}, message: {}",
                        code, msg
                    ),
                )
            })?;

        Decode!(&gtc_response, Result<AccountState, String>)
            .map_err(|err| {
                GovernanceError::new_with_message(
                    ErrorType::External,
                    format!(
                        "Cannot decode return type from 'get_account'. Error: {}",
                        err,
                    ),
                )
            })?
            .map_err(|msg| GovernanceError::new_with_message(ErrorType::External, msg))
    }

    /// Applies an algorithm to determine which Neurons are eligible to be tagged as a genesis
    /// neuron. The algorithm is roughly as follows:
    ///
    /// 1. Given an `AccountState`, read the amount of ICP Tokens (`icpts`) that was distributed to
    ///    this genesis account.
    /// 2. ECT schedules have been completed. If neuron_type is ECT, return only the NeuronIds in the
    ///    AccountState.
    /// 3. Calculate how many discrete months since genesis there have been (using `2629800` as a
    ///    proxy for month).
    /// 4. Seed investors had a vesting schedule of 49 neurons with dissolve delays from 0 to 48
    ///    months. Multiply each investors total ICP tokens by (months since genesis / 49 - 1) and
    ///    and this is the total minimum amount of ICP distributed across the the Genesis Neurons we
    ///    expect to see if there have been no splits.
    /// 5. Collect the total staked amount of all neuron ids that are in the `AccountState` and
    ///    compare it to the expected minimum. If the amount >= expected minimum, only tag those
    ///    neuron ids. If amount < expected minimum, some amount of neuron splitting has occurred,
    ///    and all neuron_ids owned by the `AccountState::authenticated_principal_id` should be
    ///    tagged.
    fn collect_eligible_genesis_neurons_ids_of_principal(
        &self,
        account_state: &AccountState,
        current_timestamp_seconds: u64,
        neuron_type: i32,
    ) -> Result<HashSet<NeuronId>, String> {
        // NeuronIds from the AccountState of a Genesis Account
        let mut neuron_ids: HashSet<NeuronId> =
            account_state.neuron_ids.clone().into_iter().collect();

        // ECT Neurons have had all funds distributed
        if neuron_type == NeuronType::Ect as i32 {
            return Ok(neuron_ids);
        }

        let total_distributed_neuron_icp = Tokens::from_tokens(account_state.icpts as u64)
            .map_err(|err| {
                format!(
                    "Unable to parse icpts({}) into Tokens format. Reason {}",
                    account_state.icpts, err
                )
            })?;

        let minimum_expected_staked_e8s = self.calculate_genesis_account_expected_stake_e8s(
            total_distributed_neuron_icp.get_e8s(),
            current_timestamp_seconds,
        );

        // Sum the total_cached_stake_e8s (ignoring neuron fees) of the neuron-ids that are
        // part of the AccountState.
        let total_cached_stake_e8s: u64 = neuron_ids
            .iter()
            .filter_map(|neuron_id| {
                self.with_neuron(neuron_id, |neuron| neuron.cached_neuron_stake_e8s)
                    .ok()
            })
            .sum();

        // If the total_cached_stake_e8s of the non-dissolved neurons is less than the expected
        // stake, some amount of splitting occurred, and all neurons controlled by the
        // authenticated_principal_id should be marked.
        if total_cached_stake_e8s < minimum_expected_staked_e8s {
            let controlling_principal_id = account_state.authenticated_principal_id.ok_or({
                "AccountState is missing authenticated_principal_id. \
                    Cannot search for other controlled neurons."
            })?;
            let controlled_neuron_ids = self.get_neuron_ids_by_principal(&controlling_principal_id);
            println!(
                "{}Total stake({}) lower than expected ({}). Splits detected. Marking {} additional neurons",
                LOG_PREFIX, total_cached_stake_e8s, minimum_expected_staked_e8s, controlled_neuron_ids.len(),
            );
            neuron_ids.extend(controlled_neuron_ids);
        }

        Ok(neuron_ids)
    }

    fn calculate_genesis_account_expected_stake_e8s(
        &self,
        total_distributed_neuron_icp_e8s: u64,
        current_timestamp_seconds: u64,
    ) -> u64 {
        // Calculate the amount of ICP that should be available in the set of neurons
        let genesis_timestamp_seconds = self.heap_data.genesis_timestamp_seconds;
        let seconds_since_genesis =
            current_timestamp_seconds.saturating_sub(genesis_timestamp_seconds);
        let months_since_genesis = seconds_since_genesis.saturating_div(ONE_MONTH_SECONDS);
        // We add 1 to  `months_since_genesis` since the dissolve delay of the 0th neuron is 0.
        // In other words, when current_timestamp_seconds == genesis_timestamp_seconds, 1/49th of
        // the funds are liquid. when current_timestamp_seconds == genesis_timestamp_seconds +
        // ONE_MONTH_SECONDS, 2/49th of the funds are liquid.
        let vested_neuron_ratio =
            (months_since_genesis + 1) as f64 / (SEED_NEURON_DISTRIBUTION_COUNT);
        // Neurons 1-48 received the floor(total/49) ICP e8s per neuron. The final neuron received
        // the remaining e8s, but this is irrelevant to the algorithm as we are well before needing
        // to include that in the calculation.
        let rounded_vested_icp_e8s =
            (total_distributed_neuron_icp_e8s as f64 * vested_neuron_ratio).floor() as u64;
        total_distributed_neuron_icp_e8s.saturating_sub(rounded_vested_icp_e8s)
    }
}

// ----------------- Copy of GTC Response structures -------------------------

/// The state of a GTC account
#[derive(candid::CandidType, candid::Deserialize, Debug, Default)]
pub struct AccountState {
    /// The neuron IDs of the neurons that exist in the Governance canister that
    /// were created on behalf of this account. These neurons, which initially
    /// have the GTC as the controller, can be claimed by the owner of this
    /// account, after which ownership of these neurons will be transferred from
    /// the GTC to the owner of this account.
    pub neuron_ids: Vec<NeuronId>,
    /// If `true`, the neurons in `neuron_ids` have been claimed by this account
    /// owner.
    pub has_claimed: bool,
    /// If `true`, the neurons in `neuron_ids` have been donated.
    pub has_donated: bool,
    /// If `true`, the neurons in `neuron_ids` have been forwarded.
    pub has_forwarded: bool,
    /// The `PrincipalId` that has been authenticated as the owner of this
    /// account.
    ///
    /// Both GTC methods `claim_neurons` and `donate_account` authenticate that
    /// the caller is the owner of this account, and either method may set this
    /// value.
    pub authenticated_principal_id: Option<PrincipalId>,
    /// The neurons that have been successfully transferred
    pub successfully_transferred_neurons: Vec<TransferredNeuron>,
    /// The neurons that failed to be transferred
    pub failed_transferred_neurons: Vec<TransferredNeuron>,
    /// The account is whitelisted for forwarding.
    pub is_whitelisted_for_forwarding: bool,
    /// The account value, in ICPTs. The sum of the stake of all neurons
    /// corresponding to `neuron_ids` must add up to `icpts`.
    pub icpts: u32,
}
#[derive(candid::CandidType, candid::Deserialize, Debug, Default)]
pub struct TransferredNeuron {
    /// The ID of the transferred neuron
    pub neuron_id: Option<NeuronId>,
    /// The UNIX timestamp (in seconds) at which the neuron was transferred
    pub timestamp_seconds: u64,
    /// The failure encountered when transferring the neuron, if any
    pub error: Option<String>,
}
