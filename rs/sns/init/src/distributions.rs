use crate::{
    SnsCanisterIds,
    pb::v1::{
        DeveloperDistribution, FractionalDeveloperVotingPower, NeuronDistribution,
        SwapDistribution, TreasuryDistribution,
    },
};
use ic_base_types::PrincipalId;
use ic_ledger_core::Tokens;
use ic_nervous_system_common::{
    ONE_MONTH_SECONDS,
    ledger::{
        compute_distribution_subaccount_bytes, compute_neuron_staking_subaccount,
        compute_neuron_staking_subaccount_bytes,
    },
};
use ic_sns_governance::{
    governance::TREASURY_SUBACCOUNT_NONCE,
    pb::v1::{NervousSystemParameters, Neuron, NeuronId, NeuronPermission, neuron::DissolveState},
};
use ic_sns_swap::swap::{NEURON_BASKET_MEMO_RANGE_START, SALE_NEURON_MEMO_RANGE_END};
use icrc_ledger_types::icrc1::account::Account;
use maplit::btreemap;
use std::collections::BTreeMap;

/// The static MEMO used when calculating the subaccount of future token swaps.
pub const SWAP_SUBACCOUNT_NONCE: u64 = 1;

/// The max number of DeveloperDistributions that can be specified in the SnsInitPayload.
pub const MAX_DEVELOPER_DISTRIBUTION_COUNT: usize = 100;

impl FractionalDeveloperVotingPower {
    /// Given the configuration of the different buckets, when provided the SnsCanisterIds calculate
    /// all the `AccountId`s of SNS Ledger accounts that will have tokens distributed at genesis.
    pub fn get_account_ids_and_tokens(
        &self,
        sns_canister_ids: &SnsCanisterIds,
    ) -> Result<BTreeMap<Account, Tokens>, String> {
        let mut accounts = BTreeMap::new();

        self.insert_developer_accounts(sns_canister_ids, &mut accounts)?;
        self.insert_treasury_accounts(sns_canister_ids, &mut accounts)?;
        self.insert_swap_accounts(sns_canister_ids, &mut accounts)?;

        Ok(accounts)
    }

    /// Given the configuration of the different buckets, create the neurons that will be available
    /// at genesis. These neurons will have reduced functionality until after the
    /// decentralization swap. Return a map of NeuronId to Neuron.
    pub fn get_initial_neurons(
        &self,
        parameters: &NervousSystemParameters,
    ) -> Result<BTreeMap<String, Neuron>, String> {
        let developer_neurons = &self.developer_distribution()?.developer_neurons;

        let swap = self.swap_distribution()?;

        // Multiplying this way will give the developer_voting_power_percentage_multiplier
        // as a percentage while also allowing use of checked_div.
        let developer_voting_power_percentage_multiplier = ((swap.initial_swap_amount_e8s as u128)
            * 100)
            .checked_div(swap.total_e8s as u128)
            .expect(
                "Underflow detected when calculating developer voting power percentage multiplier",
            ) as u64;

        let mut initial_neurons = btreemap! {};

        for developer_neuron_distribution in developer_neurons {
            let neuron = self.create_neuron(
                developer_neuron_distribution,
                developer_voting_power_percentage_multiplier,
                parameters,
            )?;

            initial_neurons.insert(neuron.id.as_ref().unwrap().to_string(), neuron);
        }

        Ok(initial_neurons)
    }

    /// Validate an instance of FractionalDeveloperVotingPower
    pub fn validate(
        &self,
        nervous_system_parameters: &NervousSystemParameters,
    ) -> Result<(), String> {
        let developer_distribution = self
            .developer_distribution
            .as_ref()
            .ok_or("Error: developer_distribution must be specified")?;

        self.treasury_distribution
            .as_ref()
            .ok_or("Error: treasury_distribution must be specified")?;

        let swap_distribution = self
            .swap_distribution
            .as_ref()
            .ok_or("Error: swap_distribution must be specified")?;

        self.validate_neurons(developer_distribution, nervous_system_parameters)?;

        if swap_distribution.initial_swap_amount_e8s == 0 {
            return Err(
                "Error: swap_distribution.initial_swap_amount_e8s must be greater than 0"
                    .to_string(),
            );
        }

        if swap_distribution.total_e8s < swap_distribution.initial_swap_amount_e8s {
            return Err("Error: swap_distribution.total_e8 must be greater than or equal to swap_distribution.initial_swap_amount_e8s".to_string());
        }

        let total_developer_e8s = match Self::get_total_distributions(&developer_distribution.developer_neurons) {
            Ok(total) => total,
            Err(_) => return Err("Error: The sum of all developer allocated tokens overflowed and is an invalid distribution".to_string()),
        };

        if total_developer_e8s > swap_distribution.total_e8s {
            return Err("Error: The sum of all developer allocated tokens must be less than or equal to swap_distribution.total_e8s".to_string());
        }

        Ok(())
    }

    /// Create a neuron available at genesis
    fn create_neuron(
        &self,
        neuron_distribution: &NeuronDistribution,
        voting_power_percentage_multiplier: u64,
        parameters: &NervousSystemParameters,
    ) -> Result<Neuron, String> {
        let (
            principal_id,
            stake_e8s,
            subaccount_memo,
            dissolve_delay_seconds,
            vesting_period_seconds,
        ) = (
            neuron_distribution.controller()?,
            neuron_distribution.stake_e8s,
            neuron_distribution.memo,
            neuron_distribution.dissolve_delay_seconds,
            neuron_distribution.vesting_period_seconds,
        );

        let subaccount = compute_neuron_staking_subaccount(principal_id, subaccount_memo);

        let permission = NeuronPermission {
            principal: Some(principal_id),
            permission_type: parameters
                .neuron_claimer_permissions
                .as_ref()
                .expect("NervousSystemParameters.neuron_claimer_permissions must be present")
                .permissions
                .clone(),
        };

        Ok(Neuron {
            id: Some(NeuronId {
                id: subaccount.to_vec(),
            }),
            permissions: vec![permission],
            cached_neuron_stake_e8s: stake_e8s,
            followees: btreemap! {},
            dissolve_state: Some(DissolveState::DissolveDelaySeconds(dissolve_delay_seconds)),
            voting_power_percentage_multiplier,
            vesting_period_seconds,
            ..Default::default()
        })
    }

    /// Validate the NeuronDistributions in the developer bucket.
    fn validate_neurons(
        &self,
        developer_distribution: &DeveloperDistribution,
        nervous_system_parameters: &NervousSystemParameters,
    ) -> Result<(), String> {
        let neuron_minimum_dissolve_delay_to_vote_seconds = nervous_system_parameters
            .neuron_minimum_dissolve_delay_to_vote_seconds
            .as_ref()
            .expect("Expected NervousSystemParameters.neuron_minimum_dissolve_delay_to_vote_seconds to be set");

        let max_dissolve_delay_seconds = nervous_system_parameters
            .max_dissolve_delay_seconds
            .as_ref()
            .expect("Expected NervousSystemParameters.max_dissolve_delay_seconds to be set");

        let missing_developer_principals_count = developer_distribution
            .developer_neurons
            .iter()
            .filter(|neuron_distribution| neuron_distribution.controller.is_none())
            .count();

        if missing_developer_principals_count != 0 {
            return Err(format!(
                "Error: {missing_developer_principals_count} developer_neurons are missing controllers"
            ));
        }

        let deduped_dev_neurons = developer_distribution
            .developer_neurons
            .iter()
            .map(|neuron_distribution| {
                (
                    (neuron_distribution.controller, neuron_distribution.memo),
                    neuron_distribution.stake_e8s,
                )
            })
            .collect::<BTreeMap<_, _>>();

        if deduped_dev_neurons.len() != developer_distribution.developer_neurons.len() {
            return Err(
                "Error: Neurons with the same controller and memo found in developer_neurons"
                    .to_string(),
            );
        }

        if deduped_dev_neurons.len() > MAX_DEVELOPER_DISTRIBUTION_COUNT {
            return Err(format!(
                "Error: The number of developer neurons must be less than {}. Current count is {}",
                MAX_DEVELOPER_DISTRIBUTION_COUNT,
                deduped_dev_neurons.len(),
            ));
        }

        for (controller, memo) in deduped_dev_neurons.keys() {
            if NEURON_BASKET_MEMO_RANGE_START <= *memo && *memo <= SALE_NEURON_MEMO_RANGE_END {
                return Err(format!(
                    "Error: Developer neuron with controller {} cannot have a memo in the range {} to {}",
                    controller.unwrap(),
                    NEURON_BASKET_MEMO_RANGE_START,
                    SALE_NEURON_MEMO_RANGE_END
                ));
            }
        }

        let configured_at_least_one_voting_neuron = developer_distribution
            .developer_neurons
            .iter()
            .any(|neuron_distribution| {
                neuron_distribution.dissolve_delay_seconds
                    >= *neuron_minimum_dissolve_delay_to_vote_seconds
            });

        if !configured_at_least_one_voting_neuron {
            return Err(format!(
                "Error: There needs to be at least one voting-eligible neuron configured. To be \
                 eligible to vote, a neuron must have dissolve_delay_seconds of at least {neuron_minimum_dissolve_delay_to_vote_seconds}"
            ));
        }

        let misconfigured_dissolve_delay_principals: Vec<PrincipalId> = developer_distribution
            .developer_neurons
            .iter()
            .filter(|neuron_distribution| {
                neuron_distribution.dissolve_delay_seconds > *max_dissolve_delay_seconds
            })
            .map(|neuron_distribution| neuron_distribution.controller.unwrap())
            .collect();

        if !misconfigured_dissolve_delay_principals.is_empty() {
            return Err(format!(
                "Error: The following PrincipalIds have a dissolve_delay_seconds configured greater than \
                 the allowed max_dissolve_delay_seconds ({max_dissolve_delay_seconds}): {misconfigured_dissolve_delay_principals:?}"
            ));
        }

        Ok(())
    }

    /// Calculate and insert the developer bucket accounts into the provided map.
    fn insert_developer_accounts(
        &self,
        sns_canister_ids: &SnsCanisterIds,
        accounts: &mut BTreeMap<Account, Tokens>,
    ) -> Result<(), String> {
        for neuron_distribution in &self.developer_distribution()?.developer_neurons {
            let principal_id = neuron_distribution.controller()?;

            let (account, tokens) = Self::get_neuron_account_id_and_tokens(
                &sns_canister_ids.governance,
                &principal_id,
                neuron_distribution.stake_e8s,
                neuron_distribution.memo,
            );
            accounts.insert(account, tokens);
        }
        Ok(())
    }

    /// Calculate and insert the treasury bucket account into the provided map.
    fn insert_treasury_accounts(
        &self,
        sns_canister_ids: &SnsCanisterIds,
        accounts: &mut BTreeMap<Account, Tokens>,
    ) -> Result<(), String> {
        let treasury = self.treasury_distribution()?;

        let (locked_treasury_distribution_account, locked_treasury_distribution) =
            Self::get_distribution_account_id_and_tokens(
                &sns_canister_ids.governance,
                TREASURY_SUBACCOUNT_NONCE,
                treasury.total_e8s,
            );
        accounts.insert(
            locked_treasury_distribution_account,
            locked_treasury_distribution,
        );

        Ok(())
    }

    /// Calculate and insert the swap bucket accounts into the provided map.
    fn insert_swap_accounts(
        &self,
        sns_canister_ids: &SnsCanisterIds,
        accounts: &mut BTreeMap<Account, Tokens>,
    ) -> Result<(), String> {
        let swap = self.swap_distribution()?;

        let swap_canister_account = Account {
            owner: sns_canister_ids.swap.0,
            subaccount: None,
        };
        let initial_swap_amount_tokens = Tokens::from_e8s(swap.initial_swap_amount_e8s);
        accounts.insert(swap_canister_account, initial_swap_amount_tokens);

        let future_swap_amount_e8s = swap.total_e8s - swap.initial_swap_amount_e8s;
        let (future_swap_distribution_account, future_swap_amount_tokens) =
            Self::get_distribution_account_id_and_tokens(
                &sns_canister_ids.governance,
                SWAP_SUBACCOUNT_NONCE,
                future_swap_amount_e8s,
            );
        accounts.insert(future_swap_distribution_account, future_swap_amount_tokens);

        Ok(())
    }

    /// Given a the PrincipalId of Governance, compute the AccountId and the number of tokens
    /// of a distribution account.
    pub fn get_distribution_account_id_and_tokens(
        governance_canister: &PrincipalId,
        distribution_account_nonce: u64,
        amount_e8s: u64,
    ) -> (Account, Tokens) {
        let subaccount =
            compute_distribution_subaccount_bytes(*governance_canister, distribution_account_nonce);
        let account = Account {
            owner: governance_canister.0,
            subaccount: Some(subaccount),
        };
        let tokens = Tokens::from_e8s(amount_e8s);

        (account, tokens)
    }

    /// Given a the PrincipalId of Governance, compute the AccountId and the number of tokens
    /// for a neuron.
    fn get_neuron_account_id_and_tokens(
        governance_canister: &PrincipalId,
        claimer: &PrincipalId,
        amount_e8s: u64,
        memo: u64,
    ) -> (Account, Tokens) {
        let subaccount = compute_neuron_staking_subaccount_bytes(*claimer, memo);
        let account = Account {
            owner: governance_canister.0,
            subaccount: Some(subaccount),
        };
        let tokens = Tokens::from_e8s(amount_e8s);

        (account, tokens)
    }

    /// Safely get the sum of all the e8 denominated neuron distributions. The maximum amount
    /// of tokens e8s must be less than or equal to u64::MAX.
    fn get_total_distributions(distributions: &Vec<NeuronDistribution>) -> Result<u64, String> {
        let mut distribution_total: u64 = 0;
        for distribution in distributions {
            distribution_total = match distribution_total.checked_add(distribution.stake_e8s) {
                Some(total) => total,
                None => {
                    return Err(
                        "The total distribution overflowed and is not a valid distribution"
                            .to_string(),
                    );
                }
            }
        }

        Ok(distribution_total)
    }

    fn developer_distribution(&self) -> Result<&DeveloperDistribution, String> {
        self.developer_distribution
            .as_ref()
            .ok_or_else(|| "Expected developer distribution to exist".to_string())
    }

    fn treasury_distribution(&self) -> Result<&TreasuryDistribution, String> {
        self.treasury_distribution
            .as_ref()
            .ok_or_else(|| "Expected treasury distribution to exist".to_string())
    }

    pub(crate) fn swap_distribution(&self) -> Result<&SwapDistribution, String> {
        self.swap_distribution
            .as_ref()
            .ok_or_else(|| "Expected swap distribution to exist".to_string())
    }

    /// This gives us some values that work for testing but would not be useful
    /// in a real world scenario. They are only meant to validate, not be sensible.
    pub fn with_valid_values_for_testing() -> Self {
        FractionalDeveloperVotingPower {
            developer_distribution: Some(DeveloperDistribution {
                developer_neurons: vec![NeuronDistribution::with_valid_values_for_testing()],
            }),
            treasury_distribution: Some(TreasuryDistribution {
                total_e8s: 500_000_000,
            }),
            swap_distribution: Some(SwapDistribution {
                total_e8s: 10_000_000_000,
                initial_swap_amount_e8s: 10_000_000_000,
            }),
        }
    }
}

impl NeuronDistribution {
    /// Internal helper method that provides a consistent error message.
    fn controller(&self) -> Result<PrincipalId, String> {
        self.controller
            .ok_or_else(|| "Expected controller to exist".to_string())
    }

    /// This gives us some values that work for testing but would not be useful
    /// in a real world scenario. They are only meant to validate, not be sensible.
    pub fn with_valid_values_for_testing() -> Self {
        NeuronDistribution {
            controller: Some(PrincipalId::new_user_test_id(1)),
            stake_e8s: 100_000_000,
            memo: 0,
            dissolve_delay_seconds: ONE_MONTH_SECONDS * 6,
            vesting_period_seconds: None,
        }
    }

    pub fn id(&self) -> NeuronId {
        let subaccount = compute_neuron_staking_subaccount(
            self.controller.expect("field `controller` not set"),
            self.memo,
        );
        NeuronId {
            id: subaccount.into(),
        }
    }
}

#[cfg(test)]
mod test {
    use crate::{
        SnsCanisterIds, Tokens,
        distributions::{MAX_DEVELOPER_DISTRIBUTION_COUNT, SWAP_SUBACCOUNT_NONCE},
        pb::v1::{
            DeveloperDistribution, FractionalDeveloperVotingPower, NeuronDistribution,
            SwapDistribution, TreasuryDistribution,
        },
    };
    use ic_base_types::{CanisterId, PrincipalId};
    use ic_ledger_core::tokens::CheckedAdd;
    use ic_nervous_system_common::{
        ONE_MONTH_SECONDS, ONE_YEAR_SECONDS,
        ledger::{compute_distribution_subaccount_bytes, compute_neuron_staking_subaccount_bytes},
    };
    use ic_nervous_system_common_test_keys::{
        TEST_NEURON_1_OWNER_PRINCIPAL, TEST_NEURON_2_OWNER_PRINCIPAL,
    };
    use ic_sns_governance::{
        governance::TREASURY_SUBACCOUNT_NONCE,
        pb::v1::{NervousSystemParameters, NeuronId, NeuronPermission, neuron::DissolveState},
    };
    use ic_sns_swap::swap::NEURON_BASKET_MEMO_RANGE_START;
    use icrc_ledger_types::icrc1::account::Account;
    use std::str::FromStr;

    fn create_canister_ids() -> SnsCanisterIds {
        SnsCanisterIds {
            governance: PrincipalId::from_str(&CanisterId::from_u64(1).to_string()).unwrap(),
            ledger: PrincipalId::from_str(&CanisterId::from_u64(2).to_string()).unwrap(),
            root: PrincipalId::from_str(&CanisterId::from_u64(3).to_string()).unwrap(),
            swap: PrincipalId::from_str(&CanisterId::from_u64(4).to_string()).unwrap(),
            index: PrincipalId::from_str(&CanisterId::from_u64(5).to_string()).unwrap(),
        }
    }

    fn get_distribution_account_identifier(
        canister: PrincipalId,
        principal_id: Option<PrincipalId>,
        nonce: Option<u64>,
    ) -> Account {
        let mut subaccount = None;
        if let Some(pid) = principal_id {
            subaccount = Some(compute_distribution_subaccount_bytes(
                pid,
                nonce.unwrap_or(0),
            ))
        }

        Account {
            owner: canister.0,
            subaccount,
        }
    }

    fn get_neuron_account_identifier(
        canister: PrincipalId,
        principal_id: Option<PrincipalId>,
        nonce: Option<u64>,
    ) -> Account {
        let mut subaccount = None;
        if let Some(pid) = principal_id {
            subaccount = Some(compute_neuron_staking_subaccount_bytes(
                pid,
                nonce.unwrap_or(0),
            ))
        }

        Account {
            owner: canister.0,
            subaccount,
        }
    }

    #[test]
    fn test_fractional_developer_voting_power_initial_ledger_accounts() {
        let neuron_stake = 200_000_000;
        let swap_total = 1_000_000_000;
        let swap_initial_round = 400_000_000;
        let treasury_total = 1_000_000_000;

        let initial_token_distribution = FractionalDeveloperVotingPower {
            developer_distribution: Some(DeveloperDistribution {
                developer_neurons: vec![
                    NeuronDistribution {
                        controller: Some(*TEST_NEURON_1_OWNER_PRINCIPAL),
                        stake_e8s: neuron_stake,
                        ..NeuronDistribution::with_valid_values_for_testing()
                    },
                    NeuronDistribution {
                        controller: Some(*TEST_NEURON_2_OWNER_PRINCIPAL),
                        stake_e8s: neuron_stake,
                        ..NeuronDistribution::with_valid_values_for_testing()
                    },
                ],
            }),
            treasury_distribution: Some(TreasuryDistribution {
                total_e8s: treasury_total,
            }),
            swap_distribution: Some(SwapDistribution {
                total_e8s: swap_total,
                initial_swap_amount_e8s: swap_initial_round,
            }),
        };

        let canister_ids = create_canister_ids();
        let initial_ledger_accounts = initial_token_distribution
            .get_account_ids_and_tokens(&canister_ids)
            .unwrap();

        let neuron_1_account = get_neuron_account_identifier(
            canister_ids.governance,
            Some(*TEST_NEURON_1_OWNER_PRINCIPAL),
            None,
        );
        let neuron_2_account = get_neuron_account_identifier(
            canister_ids.governance,
            Some(*TEST_NEURON_2_OWNER_PRINCIPAL),
            None,
        );

        let neuron_1_account_balance = initial_ledger_accounts.get(&neuron_1_account).unwrap();
        let neuron_2_account_balance = initial_ledger_accounts.get(&neuron_2_account).unwrap();

        assert_eq!(neuron_1_account_balance, &Tokens::from_e8s(neuron_stake));
        assert_eq!(neuron_2_account_balance, &Tokens::from_e8s(neuron_stake));

        // Verify swap related bucket
        let locked_swap_account = get_distribution_account_identifier(
            canister_ids.governance,
            Some(canister_ids.governance),
            Some(SWAP_SUBACCOUNT_NONCE),
        );
        let swap_canister_account = Account {
            owner: canister_ids.swap.0,
            subaccount: None,
        };

        let locked_swap_account_balance =
            initial_ledger_accounts.get(&locked_swap_account).unwrap();
        let swap_canister_account_balance =
            initial_ledger_accounts.get(&swap_canister_account).unwrap();

        assert_eq!(
            locked_swap_account_balance
                .checked_add(swap_canister_account_balance)
                .unwrap(),
            Tokens::from_e8s(
                initial_token_distribution
                    .swap_distribution
                    .unwrap()
                    .total_e8s
            )
        );

        // Verify treasury related bucket
        let locked_treasury_account = get_distribution_account_identifier(
            canister_ids.governance,
            Some(canister_ids.governance),
            Some(TREASURY_SUBACCOUNT_NONCE),
        );
        let locked_treasury_account_balance = initial_ledger_accounts
            .get(&locked_treasury_account)
            .unwrap();
        assert_eq!(
            *locked_treasury_account_balance,
            Tokens::from_e8s(treasury_total)
        );
    }

    #[test]
    fn test_initial_neurons() {
        // Different token values
        let developer_neuron_stake = 100_000_000;
        let swap_total = 1_000_000_000;
        let swap_initial_round = 400_000_000;
        let treasury_total = 1_000_000_000;

        // Different dissolve delays
        let neuron_1_dissolve_delay = 6 * ONE_MONTH_SECONDS;
        let neuron_2_dissolve_delay = ONE_YEAR_SECONDS;

        let neuron_2_vesting_period_seconds = Some(3 * ONE_YEAR_SECONDS);

        let initial_token_distribution = FractionalDeveloperVotingPower {
            developer_distribution: Some(DeveloperDistribution {
                developer_neurons: vec![
                    NeuronDistribution {
                        controller: Some(*TEST_NEURON_1_OWNER_PRINCIPAL),
                        stake_e8s: developer_neuron_stake,
                        dissolve_delay_seconds: neuron_1_dissolve_delay,
                        memo: 0,
                        vesting_period_seconds: None,
                    },
                    NeuronDistribution {
                        controller: Some(*TEST_NEURON_2_OWNER_PRINCIPAL),
                        stake_e8s: developer_neuron_stake,
                        dissolve_delay_seconds: neuron_2_dissolve_delay,
                        memo: 0,
                        vesting_period_seconds: neuron_2_vesting_period_seconds,
                    },
                ],
            }),
            treasury_distribution: Some(TreasuryDistribution {
                total_e8s: treasury_total,
            }),
            swap_distribution: Some(SwapDistribution {
                total_e8s: swap_total,
                initial_swap_amount_e8s: swap_initial_round,
            }),
        };

        let parameters = NervousSystemParameters::with_default_values();

        let initial_neurons = initial_token_distribution
            .get_initial_neurons(&parameters)
            .unwrap();

        let neuron_id_1 = NeuronId::from(compute_neuron_staking_subaccount_bytes(
            *TEST_NEURON_1_OWNER_PRINCIPAL,
            0,
        ));
        let neuron_id_2 = NeuronId::from(compute_neuron_staking_subaccount_bytes(
            *TEST_NEURON_2_OWNER_PRINCIPAL,
            0,
        ));

        // Validate they exist
        let neuron_1 = initial_neurons
            .get(&neuron_id_1.to_string())
            .expect("Expected neuron_id to exist");
        let neuron_2 = initial_neurons
            .get(&neuron_id_2.to_string())
            .expect("Expected neuron_id to exist");

        // That their stake is as configured
        assert_eq!(neuron_1.stake_e8s(), developer_neuron_stake);
        assert_eq!(neuron_2.stake_e8s(), developer_neuron_stake);

        // That the neurons have permissions to use them
        let mut expected_neuron_permission = NeuronPermission {
            principal: Some(*TEST_NEURON_1_OWNER_PRINCIPAL),
            permission_type: parameters
                .neuron_claimer_permissions
                .as_ref()
                .unwrap()
                .permissions
                .clone(),
        };

        assert_eq!(
            neuron_1.permissions,
            vec![expected_neuron_permission.clone()]
        );

        expected_neuron_permission.principal = Some(*TEST_NEURON_2_OWNER_PRINCIPAL);
        assert_eq!(
            neuron_2.permissions,
            vec![expected_neuron_permission.clone()]
        );

        assert_eq!(
            neuron_1.dissolve_state,
            Some(DissolveState::DissolveDelaySeconds(neuron_1_dissolve_delay))
        );
        assert_eq!(
            neuron_2.dissolve_state,
            Some(DissolveState::DissolveDelaySeconds(neuron_2_dissolve_delay))
        );

        // That they have the correct voting_power_percentage_multiplier. The developer neurons
        // (neuron_1, neuron_2) should have the voting_power_percentage_multiplier.
        let swap_ratio = swap_initial_round as f32 / swap_total as f32;
        let voting_power_percentage_multiplier = (swap_ratio * 100_f32) as u64;
        assert_eq!(
            neuron_1.voting_power_percentage_multiplier,
            voting_power_percentage_multiplier
        );
        assert_eq!(
            neuron_2.voting_power_percentage_multiplier,
            voting_power_percentage_multiplier
        );

        // That they have the expected vesting periods
        assert_eq!(neuron_1.vesting_period_seconds, None);
        assert_eq!(neuron_2.vesting_period_seconds, Some(3 * ONE_YEAR_SECONDS));
    }

    #[test]
    fn test_fractional_developer_voting_power_developer_validation() {
        // A basic valid FractionalDeveloperVotingPower
        let mut initial_token_distribution = FractionalDeveloperVotingPower {
            developer_distribution: Some(DeveloperDistribution {
                developer_neurons: vec![NeuronDistribution::with_valid_values_for_testing()],
            }),
            treasury_distribution: Some(TreasuryDistribution { total_e8s: 0 }),
            swap_distribution: Some(SwapDistribution {
                total_e8s: 1_000_000_000,
                initial_swap_amount_e8s: 100_000_000,
            }),
        };

        // A basic valid NervousSystemParameter
        let nervous_system_parameters = NervousSystemParameters::with_default_values();

        // Validate that the initial version is valid
        assert!(
            initial_token_distribution
                .validate(&nervous_system_parameters)
                .is_ok()
        );

        // The developer_distribution being absent should fail validation
        initial_token_distribution.developer_distribution = None;
        assert!(
            initial_token_distribution
                .validate(&nervous_system_parameters)
                .is_err()
        );

        // Check that returning to a default is valid
        initial_token_distribution.developer_distribution = Some(DeveloperDistribution {
            developer_neurons: vec![NeuronDistribution::with_valid_values_for_testing()],
        });
        assert!(
            initial_token_distribution
                .validate(&nervous_system_parameters)
                .is_ok()
        );

        // Duplicate principals + memo combos should fail validation
        initial_token_distribution.developer_distribution = Some(DeveloperDistribution {
            developer_neurons: vec![
                NeuronDistribution {
                    controller: Some(*TEST_NEURON_1_OWNER_PRINCIPAL),
                    memo: 0,
                    ..NeuronDistribution::with_valid_values_for_testing()
                },
                NeuronDistribution {
                    controller: Some(*TEST_NEURON_1_OWNER_PRINCIPAL),
                    memo: 0,
                    ..NeuronDistribution::with_valid_values_for_testing()
                },
            ],
        });
        assert!(
            initial_token_distribution
                .validate(&nervous_system_parameters)
                .is_err()
        );

        // Unique principals + memo combo should pass validation
        initial_token_distribution.developer_distribution = Some(DeveloperDistribution {
            developer_neurons: vec![
                NeuronDistribution {
                    controller: Some(*TEST_NEURON_1_OWNER_PRINCIPAL),
                    memo: 0,
                    ..NeuronDistribution::with_valid_values_for_testing()
                },
                NeuronDistribution {
                    controller: Some(*TEST_NEURON_1_OWNER_PRINCIPAL),
                    memo: 1,
                    ..NeuronDistribution::with_valid_values_for_testing()
                },
                NeuronDistribution {
                    controller: Some(*TEST_NEURON_2_OWNER_PRINCIPAL),
                    memo: 0,
                    ..NeuronDistribution::with_valid_values_for_testing()
                },
            ],
        });
        assert!(
            initial_token_distribution
                .validate(&nervous_system_parameters)
                .is_ok()
        );

        // The sum of the distributions MUST fit into a u64
        initial_token_distribution.developer_distribution = Some(DeveloperDistribution {
            developer_neurons: vec![
                NeuronDistribution {
                    controller: Some(*TEST_NEURON_1_OWNER_PRINCIPAL),
                    stake_e8s: u64::MAX,
                    ..NeuronDistribution::with_valid_values_for_testing()
                },
                NeuronDistribution {
                    controller: Some(*TEST_NEURON_2_OWNER_PRINCIPAL),
                    stake_e8s: u64::MAX,
                    ..NeuronDistribution::with_valid_values_for_testing()
                },
            ],
        });
        assert!(
            initial_token_distribution
                .validate(&nervous_system_parameters)
                .is_err()
        );

        // The sum of the distributions can equal the swap_distribution.total_e8s
        // which is set to 100 at the beginning of the test
        initial_token_distribution.developer_distribution = Some(DeveloperDistribution {
            developer_neurons: vec![
                NeuronDistribution {
                    controller: Some(*TEST_NEURON_1_OWNER_PRINCIPAL),
                    stake_e8s: 50,
                    ..NeuronDistribution::with_valid_values_for_testing()
                },
                NeuronDistribution {
                    controller: Some(*TEST_NEURON_2_OWNER_PRINCIPAL),
                    stake_e8s: 50,
                    ..NeuronDistribution::with_valid_values_for_testing()
                },
            ],
        });
        assert!(
            initial_token_distribution
                .validate(&nervous_system_parameters)
                .is_ok()
        );

        // The sum of the distributions being greater than swap_distribution.total_e8s should fail
        // validation
        initial_token_distribution.developer_distribution = Some(DeveloperDistribution {
            developer_neurons: vec![
                NeuronDistribution {
                    controller: Some(*TEST_NEURON_1_OWNER_PRINCIPAL),
                    stake_e8s: 500_000_000,
                    ..NeuronDistribution::with_valid_values_for_testing()
                },
                NeuronDistribution {
                    controller: Some(*TEST_NEURON_2_OWNER_PRINCIPAL),
                    stake_e8s: 500_000_001,
                    ..NeuronDistribution::with_valid_values_for_testing()
                },
            ],
        });
        assert!(
            initial_token_distribution
                .validate(&nervous_system_parameters)
                .is_err()
        );

        // Reset to a valid developer_distribution
        initial_token_distribution.developer_distribution = Some(DeveloperDistribution {
            developer_neurons: vec![NeuronDistribution {
                controller: Some(*TEST_NEURON_1_OWNER_PRINCIPAL),
                stake_e8s: 50,
                ..NeuronDistribution::with_valid_values_for_testing()
            }],
        });
        assert!(
            initial_token_distribution
                .validate(&nervous_system_parameters)
                .is_ok()
        );

        // There must be at least one neuron with the dissolve_delay greater than or equal to
        // neuron_minimum_dissolve_delay_to_vote_seconds.
        initial_token_distribution.developer_distribution = Some(DeveloperDistribution {
            developer_neurons: vec![NeuronDistribution {
                dissolve_delay_seconds: nervous_system_parameters
                    .neuron_minimum_dissolve_delay_to_vote_seconds
                    .as_ref()
                    .unwrap()
                    - 1,
                ..NeuronDistribution::with_valid_values_for_testing()
            }],
        });

        initial_token_distribution.developer_distribution = Some(DeveloperDistribution {
            developer_neurons: vec![NeuronDistribution::with_valid_values_for_testing()],
        });
        assert!(
            initial_token_distribution
                .validate(&nervous_system_parameters)
                .is_ok()
        );

        // Any neurons are configured with a dissolve_delay over the maximum should fail
        initial_token_distribution.developer_distribution = Some(DeveloperDistribution {
            developer_neurons: vec![NeuronDistribution {
                dissolve_delay_seconds: nervous_system_parameters
                    .max_dissolve_delay_seconds
                    .as_ref()
                    .unwrap()
                    + 1,
                ..NeuronDistribution::with_valid_values_for_testing()
            }],
        });

        initial_token_distribution.developer_distribution = Some(DeveloperDistribution {
            developer_neurons: vec![NeuronDistribution::with_valid_values_for_testing()],
        });
        assert!(
            initial_token_distribution
                .validate(&nervous_system_parameters)
                .is_ok()
        );

        // Exceeding the maximum count of developer neurons should fail
        let invalid_developer_neurons = (0..MAX_DEVELOPER_DISTRIBUTION_COUNT + 1)
            .map(|i| NeuronDistribution {
                controller: Some(*TEST_NEURON_1_OWNER_PRINCIPAL),
                memo: i as u64,
                ..NeuronDistribution::with_valid_values_for_testing()
            })
            .collect();
        initial_token_distribution.developer_distribution = Some(DeveloperDistribution {
            developer_neurons: invalid_developer_neurons,
        });
        assert!(
            initial_token_distribution
                .validate(&nervous_system_parameters)
                .is_err()
        );
    }

    #[test]
    fn test_fractional_developer_voting_power_treasury_validation() {
        // A basic valid FractionalDeveloperVotingPower
        let mut initial_token_distribution = FractionalDeveloperVotingPower {
            developer_distribution: Some(DeveloperDistribution {
                developer_neurons: vec![NeuronDistribution::with_valid_values_for_testing()],
            }),
            treasury_distribution: Some(TreasuryDistribution { total_e8s: 0 }),
            swap_distribution: Some(SwapDistribution {
                total_e8s: 1_000_000_000,
                initial_swap_amount_e8s: 100_000_000,
            }),
        };

        // A basic valid NervousSystemParameter
        let nervous_system_parameters = NervousSystemParameters::with_default_values();

        // Validate that the initial version is valid
        initial_token_distribution
            .validate(&nervous_system_parameters)
            .expect("");
        assert!(
            initial_token_distribution
                .validate(&nervous_system_parameters)
                .is_ok()
        );

        // The treasury_distribution being absent should fail validation
        initial_token_distribution.treasury_distribution = None;
        assert!(
            initial_token_distribution
                .validate(&nervous_system_parameters)
                .is_err()
        );

        // Check that returning to a default is valid
        initial_token_distribution.treasury_distribution =
            Some(TreasuryDistribution { total_e8s: 0 });
        assert!(
            initial_token_distribution
                .validate(&nervous_system_parameters)
                .is_ok()
        );

        // Check that the max value is valid
        initial_token_distribution.treasury_distribution = Some(TreasuryDistribution {
            total_e8s: u64::MAX,
        });
        assert!(
            initial_token_distribution
                .validate(&nervous_system_parameters)
                .is_ok()
        );
    }

    #[test]
    fn test_fractional_developer_voting_power_swap_validation() {
        // A basic valid FractionalDeveloperVotingPower
        let mut initial_token_distribution = FractionalDeveloperVotingPower {
            developer_distribution: Some(DeveloperDistribution {
                developer_neurons: vec![NeuronDistribution::with_valid_values_for_testing()],
            }),
            treasury_distribution: Some(TreasuryDistribution { total_e8s: 0 }),
            swap_distribution: Some(SwapDistribution {
                total_e8s: 1_000_000_000,
                initial_swap_amount_e8s: 100_000_000,
            }),
        };

        // A basic valid NervousSystemParameter
        let nervous_system_parameters = NervousSystemParameters::with_default_values();

        // Validate that the initial version is valid
        assert!(
            initial_token_distribution
                .validate(&nervous_system_parameters)
                .is_ok()
        );

        // The swap_distribution being absent should fail validation
        initial_token_distribution.swap_distribution = None;
        assert!(
            initial_token_distribution
                .validate(&nervous_system_parameters)
                .is_err()
        );

        // Check that returning to a default is valid
        initial_token_distribution.swap_distribution = Some(SwapDistribution {
            total_e8s: 1_000_000_000,
            initial_swap_amount_e8s: 100_000_000,
        });
        assert!(
            initial_token_distribution
                .validate(&nervous_system_parameters)
                .is_ok()
        );

        // initial_swap_amount_e8s must be greater than 0
        initial_token_distribution.swap_distribution = Some(SwapDistribution {
            initial_swap_amount_e8s: 0,
            total_e8s: 0,
        });
        assert!(
            initial_token_distribution
                .validate(&nervous_system_parameters)
                .is_err()
        );

        // initial_swap_amount_e8s cannot be greater than total_e8s
        initial_token_distribution.swap_distribution = Some(SwapDistribution {
            initial_swap_amount_e8s: 10,
            total_e8s: 5,
        });
        assert!(
            initial_token_distribution
                .validate(&nervous_system_parameters)
                .is_err()
        );
    }

    /// Test that validation fails if developer neurons are given memos in the incorrect range.
    #[test]
    fn test_fractional_developer_voting_power_memos() {
        let mut distribution1 = NeuronDistribution {
            controller: Some(PrincipalId::new_user_test_id(1)),
            stake_e8s: 100_000_000,
            memo: 0,
            dissolve_delay_seconds: ONE_MONTH_SECONDS * 6,
            vesting_period_seconds: None,
        };

        // A basic valid FractionalDeveloperVotingPower
        let mut initial_token_distribution = FractionalDeveloperVotingPower {
            developer_distribution: Some(DeveloperDistribution {
                developer_neurons: vec![distribution1.clone()],
            }),
            treasury_distribution: Some(TreasuryDistribution { total_e8s: 0 }),
            swap_distribution: Some(SwapDistribution {
                total_e8s: 1_000_000_000,
                initial_swap_amount_e8s: 100_000_000,
            }),
        };

        // A basic valid NervousSystemParameter
        let nervous_system_parameters = NervousSystemParameters::with_default_values();

        // Validate that the initial version is valid
        initial_token_distribution
            .validate(&nervous_system_parameters)
            .expect("initial_token_distribution is invalid");

        // A developer distribution with a memo in the Sale neuron memo range should fail validation
        distribution1.memo = NEURON_BASKET_MEMO_RANGE_START + 10;
        initial_token_distribution.developer_distribution = Some(DeveloperDistribution {
            developer_neurons: vec![distribution1.clone()],
        });

        assert_eq!(initial_token_distribution
            .validate(&nervous_system_parameters)
            .unwrap_err(), "Error: Developer neuron with controller 6fyp7-3ibaa-aaaaa-aaaap-4ai cannot have a memo in the range 1000000 to 10000000".to_string());

        // Reset the developer neuron memo
        distribution1.memo = 0;
        initial_token_distribution.developer_distribution = Some(DeveloperDistribution {
            developer_neurons: vec![distribution1],
        });
    }
}
