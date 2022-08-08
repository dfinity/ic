use crate::pb::v1::{
    DeveloperDistribution, FractionalDeveloperVotingPower, NeuronDistribution, SwapDistribution,
    TreasuryDistribution,
};
use crate::{AirdropDistribution, SnsCanisterIds};
use anyhow::anyhow;
use ic_base_types::PrincipalId;
use ic_icrc1::Account;
use ic_ledger_core::Tokens;
use ic_nervous_system_common::ledger::{
    compute_distribution_subaccount_bytes, compute_neuron_staking_subaccount,
    compute_neuron_staking_subaccount_bytes,
};
use ic_sns_governance::pb::v1::neuron::DissolveState;
use ic_sns_governance::pb::v1::{NervousSystemParameters, Neuron, NeuronId, NeuronPermission};
use maplit::btreemap;
use std::collections::{BTreeMap, HashMap};

/// The static MEMO used when calculating subaccounts of neurons available at genesis.
pub const DEFAULT_NEURON_STAKING_NONCE: u64 = 0;

/// The static MEMO used when calculating the SNS Treasury subaccount.
pub const TREASURY_SUBACCOUNT_NONCE: u64 = 0;

/// The static MEMO used when calculating the subaccount of future token swaps.
pub const SWAP_SUBACCOUNT_NONCE: u64 = 1;

impl FractionalDeveloperVotingPower {
    /// Given the configuration of the different buckets, when provided the SnsCanisterIds calculate
    /// all the `AccountId`s of SNS Ledger accounts that will have tokens distributed at genesis.
    pub fn get_account_ids_and_tokens(
        &self,
        sns_canister_ids: &SnsCanisterIds,
    ) -> anyhow::Result<HashMap<Account, Tokens>> {
        let mut accounts = HashMap::new();

        self.insert_developer_accounts(sns_canister_ids, &mut accounts)?;
        self.insert_treasury_accounts(sns_canister_ids, &mut accounts)?;
        self.insert_swap_accounts(sns_canister_ids, &mut accounts)?;
        self.insert_airdrop_accounts(sns_canister_ids, &mut accounts)?;

        Ok(accounts)
    }

    /// Given the configuration of the different buckets, create the neurons that will be available
    /// at genesis. These neurons will have reduced functionality until after the
    /// decentralization swap. Return a map of NeuronId to Neuron.
    pub fn get_initial_neurons(
        &self,
        parameters: &NervousSystemParameters,
    ) -> anyhow::Result<BTreeMap<String, Neuron>> {
        let developer_neurons = &self.developer_distribution()?.developer_neurons;
        let airdrop_neurons = &self.airdrop_distribution()?.airdrop_neurons;

        let swap = self.swap_distribution()?;
        // TODO NNS1-1465: Add the voting_power_multiplier as a field to neuron
        let _voting_power_multiplier = swap.initial_swap_amount_e8s as f64 / swap.total_e8s as f64;

        let mut initial_neurons = btreemap! {};

        for neuron_distribution in developer_neurons.iter().chain(airdrop_neurons.iter()) {
            let principal_id = neuron_distribution.controller()?;
            let stake_e8s = neuron_distribution.stake_e8s;

            let subaccount =
                compute_neuron_staking_subaccount(principal_id, DEFAULT_NEURON_STAKING_NONCE);

            let permission = NeuronPermission {
                principal: Some(principal_id),
                permission_type: parameters
                    .neuron_claimer_permissions
                    .as_ref()
                    .expect("NervousSystemParameters.neuron_claimer_permissions must be present")
                    .permissions
                    .clone(),
            };

            let default_followees = parameters
                .default_followees
                .as_ref()
                .expect("NervousSystemParameters.default_followees must be present")
                .followees
                .clone();

            let dissolve_delay_seconds = parameters
                .neuron_minimum_dissolve_delay_to_vote_seconds
                .expect("NervousSystemParameters.neuron_minimum_dissolve_delay_to_vote_seconds must be present");

            let neuron = Neuron {
                id: Some(NeuronId {
                    id: subaccount.to_vec(),
                }),
                permissions: vec![permission],
                cached_neuron_stake_e8s: stake_e8s,
                followees: default_followees,
                dissolve_state: Some(DissolveState::DissolveDelaySeconds(dissolve_delay_seconds)),
                ..Default::default()
            };

            initial_neurons.insert(neuron.id.as_ref().unwrap().to_string(), neuron);
        }

        Ok(initial_neurons)
    }

    /// Validate an instance of FractionalDeveloperVotingPower
    pub fn validate(&self) -> anyhow::Result<()> {
        let developer_distribution = self
            .developer_distribution
            .as_ref()
            .ok_or_else(|| anyhow!("Error: developer_distribution must be specified"))?;

        self.treasury_distribution
            .as_ref()
            .ok_or_else(|| anyhow!("Error: treasury_distribution must be specified"))?;

        let swap_distribution = self
            .swap_distribution
            .as_ref()
            .ok_or_else(|| anyhow!("Error: swap_distribution must be specified"))?;

        let airdrop_distribution = self
            .airdrop_distribution
            .as_ref()
            .ok_or_else(|| anyhow!("Error: airdrop_distribution must be specified"))?;

        self.validate_neurons(developer_distribution, airdrop_distribution)?;

        match Self::get_total_distributions(&airdrop_distribution.airdrop_neurons) {
            Ok(_) => (),
            Err(_) => return Err(anyhow!("Error: The sum of all airdrop allocated tokens overflowed and is an invalid distribution")),
        };

        if swap_distribution.initial_swap_amount_e8s == 0 {
            return Err(anyhow!(
                "Error: swap_distribution.initial_swap_amount_e8s must be greater than 0"
            ));
        }

        if swap_distribution.total_e8s < swap_distribution.initial_swap_amount_e8s {
            return Err(anyhow!("Error: swap_distribution.total_e8 must be greater than or equal to swap_distribution.initial_swap_amount_e8s"));
        }

        let total_developer_e8s = match Self::get_total_distributions(&developer_distribution.developer_neurons) {
            Ok(total) => total,
            Err(_) => return Err(anyhow!("Error: The sum of all developer allocated tokens overflowed and is an invalid distribution")),
        };

        if total_developer_e8s > swap_distribution.total_e8s {
            return Err(anyhow!("Error: The sum of all developer allocated tokens must be less than or equal to swap_distribution.total_e8s"));
        }

        Ok(())
    }

    /// Validate the NeuronDistributions in the Developer and Airdrop bucket
    fn validate_neurons(
        &self,
        developer_distribution: &DeveloperDistribution,
        airdrop_distribution: &AirdropDistribution,
    ) -> anyhow::Result<()> {
        let missing_developer_principals_count = developer_distribution
            .developer_neurons
            .iter()
            .filter(|neuron_distribution| neuron_distribution.controller.is_none())
            .count();

        if missing_developer_principals_count != 0 {
            return Err(anyhow!(
                "Error: {} developer_neurons are missing controllers",
                missing_developer_principals_count
            ));
        }

        let deduped_dev_neurons = developer_distribution
            .developer_neurons
            .iter()
            .map(|neuron_distribution| {
                (
                    neuron_distribution.controller,
                    neuron_distribution.stake_e8s,
                )
            })
            .collect::<BTreeMap<_, _>>();

        if deduped_dev_neurons.len() != developer_distribution.developer_neurons.len() {
            return Err(anyhow!(
                "Error: Duplicate controllers detected in developer_neurons"
            ));
        }

        let missing_airdrop_principals_count = airdrop_distribution
            .airdrop_neurons
            .iter()
            .filter(|neuron_distribution| neuron_distribution.controller.is_none())
            .count();

        if missing_airdrop_principals_count != 0 {
            return Err(anyhow!(
                "Error: {} airdrop_neurons are missing controllers",
                missing_airdrop_principals_count
            ));
        }

        let deduped_airdrop_neurons = airdrop_distribution
            .airdrop_neurons
            .iter()
            .map(|neuron_distribution| {
                (
                    neuron_distribution.controller,
                    neuron_distribution.stake_e8s,
                )
            })
            .collect::<BTreeMap<_, _>>();

        if deduped_airdrop_neurons.len() != airdrop_distribution.airdrop_neurons.len() {
            return Err(anyhow!(
                "Error: Duplicate controllers detected in developer_neurons"
            ));
        }

        let mut duplicated_neuron_principals = vec![];
        for developer_principal in deduped_dev_neurons.keys() {
            if deduped_airdrop_neurons.contains_key(developer_principal) {
                // Safe to unwrap due to the checks done above
                duplicated_neuron_principals.push(developer_principal.unwrap())
            }
        }

        if !duplicated_neuron_principals.is_empty() {
            return Err(anyhow!(
                "Error: The following controllers are present in AirdropDistribution \
                and DeveloperDistribution: {:?}",
                duplicated_neuron_principals
            ));
        }

        Ok(())
    }

    /// Calculate and insert the developer bucket accounts into the provided map.
    fn insert_developer_accounts(
        &self,
        sns_canister_ids: &SnsCanisterIds,
        accounts: &mut HashMap<Account, Tokens>,
    ) -> anyhow::Result<()> {
        for neuron_distribution in &self.developer_distribution()?.developer_neurons {
            let principal_id = neuron_distribution.controller()?;

            let (account, tokens) = Self::get_neuron_account_id_and_tokens(
                &sns_canister_ids.governance,
                &principal_id,
                neuron_distribution.stake_e8s,
            );
            accounts.insert(account, tokens);
        }
        Ok(())
    }

    /// Calculate and insert the treasury bucket account into the provided map.
    fn insert_treasury_accounts(
        &self,
        sns_canister_ids: &SnsCanisterIds,
        accounts: &mut HashMap<Account, Tokens>,
    ) -> anyhow::Result<()> {
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
        accounts: &mut HashMap<Account, Tokens>,
    ) -> anyhow::Result<()> {
        let swap = self.swap_distribution()?;

        let swap_canister_account = Account {
            of: sns_canister_ids.swap,
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

    /// Calculate and insert the airdrop bucket accounts into the provided map.
    fn insert_airdrop_accounts(
        &self,
        sns_canister_ids: &SnsCanisterIds,
        accounts: &mut HashMap<Account, Tokens>,
    ) -> anyhow::Result<()> {
        for neuron_distribution in &self.airdrop_distribution()?.airdrop_neurons {
            let principal_id = neuron_distribution.controller()?;

            let (account, tokens) = Self::get_neuron_account_id_and_tokens(
                &sns_canister_ids.governance,
                &principal_id,
                neuron_distribution.stake_e8s,
            );
            accounts.insert(account, tokens);
        }
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
            of: *governance_canister,
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
    ) -> (Account, Tokens) {
        let subaccount =
            compute_neuron_staking_subaccount_bytes(*claimer, DEFAULT_NEURON_STAKING_NONCE);
        let account = Account {
            of: *governance_canister,
            subaccount: Some(subaccount),
        };
        let tokens = Tokens::from_e8s(amount_e8s);

        (account, tokens)
    }

    /// Safely get the sum of all the e8 denominated neuron distributions. The maximum amount
    /// of tokens e8s must be less than or equal to u64::MAX.
    fn get_total_distributions(distributions: &Vec<NeuronDistribution>) -> anyhow::Result<u64> {
        let mut distribution_total: u64 = 0;
        for distribution in distributions {
            distribution_total = match distribution_total.checked_add(distribution.stake_e8s) {
                Some(total) => total,
                None => {
                    return Err(anyhow!(
                        "The total distribution overflowed and is not a valid distribution"
                    ))
                }
            }
        }

        Ok(distribution_total)
    }

    fn developer_distribution(&self) -> anyhow::Result<&DeveloperDistribution> {
        self.developer_distribution
            .as_ref()
            .ok_or_else(|| anyhow!("Expected developer distribution to exist"))
    }

    fn treasury_distribution(&self) -> anyhow::Result<&TreasuryDistribution> {
        self.treasury_distribution
            .as_ref()
            .ok_or_else(|| anyhow!("Expected treasury distribution to exist"))
    }

    fn swap_distribution(&self) -> anyhow::Result<&SwapDistribution> {
        self.swap_distribution
            .as_ref()
            .ok_or_else(|| anyhow!("Expected swap distribution to exist"))
    }

    fn airdrop_distribution(&self) -> anyhow::Result<&AirdropDistribution> {
        self.airdrop_distribution
            .as_ref()
            .ok_or_else(|| anyhow!("Expected airdrop distribution to exist"))
    }
}

impl NeuronDistribution {
    /// Internal helper method that provides a consistent error message.
    fn controller(&self) -> anyhow::Result<PrincipalId> {
        self.controller
            .ok_or_else(|| anyhow!("Expected controller to exist"))
    }
}

#[cfg(test)]
mod test {
    use crate::distributions::{
        DEFAULT_NEURON_STAKING_NONCE, SWAP_SUBACCOUNT_NONCE, TREASURY_SUBACCOUNT_NONCE,
    };
    use crate::pb::v1::{
        DeveloperDistribution, FractionalDeveloperVotingPower, NeuronDistribution,
        SwapDistribution, TreasuryDistribution,
    };
    use crate::{AirdropDistribution, SnsCanisterIds, Tokens};
    use ic_base_types::{CanisterId, PrincipalId};
    use ic_icrc1::Account;
    use ic_nervous_system_common::ledger::{
        compute_distribution_subaccount_bytes, compute_neuron_staking_subaccount_bytes,
    };
    use ic_nervous_system_common_test_keys::{
        TEST_NEURON_1_OWNER_PRINCIPAL, TEST_NEURON_2_OWNER_PRINCIPAL, TEST_NEURON_3_OWNER_PRINCIPAL,
    };
    use ic_sns_governance::pb::v1::neuron::DissolveState;
    use ic_sns_governance::pb::v1::{NervousSystemParameters, NeuronId, NeuronPermission};
    use std::str::FromStr;

    fn create_canister_ids() -> SnsCanisterIds {
        SnsCanisterIds {
            governance: PrincipalId::from_str(&CanisterId::from_u64(1).to_string()).unwrap(),
            ledger: PrincipalId::from_str(&CanisterId::from_u64(2).to_string()).unwrap(),
            root: PrincipalId::from_str(&CanisterId::from_u64(3).to_string()).unwrap(),
            swap: PrincipalId::from_str(&CanisterId::from_u64(4).to_string()).unwrap(),
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
            of: canister,
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
            of: canister,
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
                    },
                    NeuronDistribution {
                        controller: Some(*TEST_NEURON_2_OWNER_PRINCIPAL),
                        stake_e8s: neuron_stake,
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
            airdrop_distribution: Some(AirdropDistribution {
                airdrop_neurons: vec![NeuronDistribution {
                    controller: Some(*TEST_NEURON_3_OWNER_PRINCIPAL),
                    stake_e8s: neuron_stake,
                }],
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
        let neuron_3_account = get_neuron_account_identifier(
            canister_ids.governance,
            Some(*TEST_NEURON_3_OWNER_PRINCIPAL),
            None,
        );

        let neuron_1_account_balance = initial_ledger_accounts.get(&neuron_1_account).unwrap();
        let neuron_2_account_balance = initial_ledger_accounts.get(&neuron_2_account).unwrap();
        let neuron_3_account_balance = initial_ledger_accounts.get(&neuron_3_account).unwrap();

        assert_eq!(neuron_1_account_balance, &Tokens::from_e8s(neuron_stake));
        assert_eq!(neuron_2_account_balance, &Tokens::from_e8s(neuron_stake));
        assert_eq!(neuron_3_account_balance, &Tokens::from_e8s(neuron_stake));

        // Verify swap related bucket
        let locked_swap_account = get_distribution_account_identifier(
            canister_ids.governance,
            Some(canister_ids.governance),
            Some(SWAP_SUBACCOUNT_NONCE),
        );
        let swap_canister_account = Account {
            of: canister_ids.swap,
            subaccount: None,
        };

        let locked_swap_account_balance =
            initial_ledger_accounts.get(&locked_swap_account).unwrap();
        let swap_canister_account_balance =
            initial_ledger_accounts.get(&swap_canister_account).unwrap();

        assert_eq!(
            (*locked_swap_account_balance + *swap_canister_account_balance).unwrap(),
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
        let developer_neuron_stake = 100_000_000;
        let airdrop_neuron_stake = 50_000;
        let swap_total = 1_000_000_000;
        let swap_initial_round = 400_000_000;
        let treasury_total = 1_000_000_000;

        let initial_token_distribution = FractionalDeveloperVotingPower {
            developer_distribution: Some(DeveloperDistribution {
                developer_neurons: vec![
                    NeuronDistribution {
                        controller: Some(*TEST_NEURON_1_OWNER_PRINCIPAL),
                        stake_e8s: developer_neuron_stake,
                    },
                    NeuronDistribution {
                        controller: Some(*TEST_NEURON_2_OWNER_PRINCIPAL),
                        stake_e8s: developer_neuron_stake,
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
            airdrop_distribution: Some(AirdropDistribution {
                airdrop_neurons: vec![NeuronDistribution {
                    controller: Some(*TEST_NEURON_3_OWNER_PRINCIPAL),
                    stake_e8s: airdrop_neuron_stake,
                }],
            }),
        };

        let parameters = NervousSystemParameters::with_default_values();

        let initial_neurons = initial_token_distribution
            .get_initial_neurons(&parameters)
            .unwrap();

        let neuron_id_1 = NeuronId::from(compute_neuron_staking_subaccount_bytes(
            *TEST_NEURON_1_OWNER_PRINCIPAL,
            DEFAULT_NEURON_STAKING_NONCE,
        ));
        let neuron_id_2 = NeuronId::from(compute_neuron_staking_subaccount_bytes(
            *TEST_NEURON_2_OWNER_PRINCIPAL,
            DEFAULT_NEURON_STAKING_NONCE,
        ));
        let neuron_id_3 = NeuronId::from(compute_neuron_staking_subaccount_bytes(
            *TEST_NEURON_3_OWNER_PRINCIPAL,
            DEFAULT_NEURON_STAKING_NONCE,
        ));

        // Validate they exist
        let neuron_1 = initial_neurons
            .get(&neuron_id_1.to_string())
            .expect("Expected neuron_id to exist");
        let neuron_2 = initial_neurons
            .get(&neuron_id_2.to_string())
            .expect("Expected neuron_id to exist");
        let neuron_3 = initial_neurons
            .get(&neuron_id_3.to_string())
            .expect("Expected neuron_id to exist");

        // That their stake is as configured
        assert_eq!(neuron_1.stake_e8s(), developer_neuron_stake);
        assert_eq!(neuron_2.stake_e8s(), developer_neuron_stake);
        assert_eq!(neuron_3.stake_e8s(), airdrop_neuron_stake);

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

        expected_neuron_permission.principal = Some(*TEST_NEURON_3_OWNER_PRINCIPAL);
        assert_eq!(neuron_3.permissions, vec![expected_neuron_permission]);

        // That they have a dissolve delay
        let expected_dissolve_delay = DissolveState::DissolveDelaySeconds(
            parameters
                .neuron_minimum_dissolve_delay_to_vote_seconds
                .unwrap(),
        );

        assert_eq!(
            neuron_1.dissolve_state,
            Some(expected_dissolve_delay.clone())
        );
        assert_eq!(
            neuron_2.dissolve_state,
            Some(expected_dissolve_delay.clone())
        );
        assert_eq!(neuron_3.dissolve_state, Some(expected_dissolve_delay));
    }

    #[test]
    fn test_fractional_developer_voting_power_developer_validation() {
        // A basic valid FractionalDeveloperVotingPower
        let mut initial_token_distribution = FractionalDeveloperVotingPower {
            developer_distribution: Some(DeveloperDistribution {
                developer_neurons: Default::default(),
            }),
            treasury_distribution: Some(TreasuryDistribution { total_e8s: 0 }),
            swap_distribution: Some(SwapDistribution {
                total_e8s: 100,
                initial_swap_amount_e8s: 1,
            }),
            airdrop_distribution: Some(AirdropDistribution {
                airdrop_neurons: Default::default(),
            }),
        };
        // Validate that the initial version is valid
        assert!(initial_token_distribution.validate().is_ok());

        // The developer_distribution being absent should fail validation
        initial_token_distribution.developer_distribution = None;
        assert!(initial_token_distribution.validate().is_err());

        // Check that returning to a default is valid
        initial_token_distribution.developer_distribution = Some(DeveloperDistribution {
            developer_neurons: Default::default(),
        });
        assert!(initial_token_distribution.validate().is_ok());

        // Duplicate principals should fail validation
        initial_token_distribution.developer_distribution = Some(DeveloperDistribution {
            developer_neurons: vec![
                NeuronDistribution {
                    controller: Some(*TEST_NEURON_1_OWNER_PRINCIPAL),
                    stake_e8s: 1,
                },
                NeuronDistribution {
                    controller: Some(*TEST_NEURON_1_OWNER_PRINCIPAL),
                    stake_e8s: 1,
                },
            ],
        });
        assert!(initial_token_distribution.validate().is_err());

        // Unique principals should pass validation
        initial_token_distribution.developer_distribution = Some(DeveloperDistribution {
            developer_neurons: vec![
                NeuronDistribution {
                    controller: Some(*TEST_NEURON_1_OWNER_PRINCIPAL),
                    stake_e8s: 1,
                },
                NeuronDistribution {
                    controller: Some(*TEST_NEURON_2_OWNER_PRINCIPAL),
                    stake_e8s: 1,
                },
            ],
        });
        assert!(initial_token_distribution.validate().is_ok());

        // The sum of the distributions MUST fit into a u64
        initial_token_distribution.developer_distribution = Some(DeveloperDistribution {
            developer_neurons: vec![
                NeuronDistribution {
                    controller: Some(*TEST_NEURON_1_OWNER_PRINCIPAL),
                    stake_e8s: u64::MAX,
                },
                NeuronDistribution {
                    controller: Some(*TEST_NEURON_2_OWNER_PRINCIPAL),
                    stake_e8s: u64::MAX,
                },
            ],
        });
        assert!(initial_token_distribution.validate().is_err());

        // The sum of the distributions can equal the swap_distribution.total_e8s
        // which is set to 100 at the beginning of the test
        initial_token_distribution.developer_distribution = Some(DeveloperDistribution {
            developer_neurons: vec![
                NeuronDistribution {
                    controller: Some(*TEST_NEURON_1_OWNER_PRINCIPAL),
                    stake_e8s: 50,
                },
                NeuronDistribution {
                    controller: Some(*TEST_NEURON_2_OWNER_PRINCIPAL),
                    stake_e8s: 50,
                },
            ],
        });
        assert!(initial_token_distribution.validate().is_ok());

        // The sum of the distributions being greater than swap_distribution.total_e8s should fail
        // validation
        initial_token_distribution.developer_distribution = Some(DeveloperDistribution {
            developer_neurons: vec![
                NeuronDistribution {
                    controller: Some(*TEST_NEURON_1_OWNER_PRINCIPAL),
                    stake_e8s: 50,
                },
                NeuronDistribution {
                    controller: Some(*TEST_NEURON_2_OWNER_PRINCIPAL),
                    stake_e8s: 51,
                },
            ],
        });
        assert!(initial_token_distribution.validate().is_err());

        // Reset to a valid developer_distribution
        initial_token_distribution.developer_distribution = Some(DeveloperDistribution {
            developer_neurons: vec![NeuronDistribution {
                controller: Some(*TEST_NEURON_1_OWNER_PRINCIPAL),
                stake_e8s: 50,
            }],
        });
        assert!(initial_token_distribution.validate().is_ok());

        // Using the same controller in the AirdropDistribution and DeveloperDistribution should fail
        // validation
        initial_token_distribution.airdrop_distribution = Some(AirdropDistribution {
            airdrop_neurons: vec![NeuronDistribution {
                controller: Some(*TEST_NEURON_1_OWNER_PRINCIPAL),
                stake_e8s: 50,
            }],
        });
        assert!(initial_token_distribution.validate().is_err());

        initial_token_distribution.airdrop_distribution = Some(AirdropDistribution {
            airdrop_neurons: Default::default(),
        });
        assert!(initial_token_distribution.validate().is_ok());
    }

    #[test]
    fn test_fractional_developer_voting_power_treasury_validation() {
        // A basic valid FractionalDeveloperVotingPower
        let mut initial_token_distribution = FractionalDeveloperVotingPower {
            developer_distribution: Some(DeveloperDistribution {
                developer_neurons: Default::default(),
            }),
            treasury_distribution: Some(TreasuryDistribution { total_e8s: 0 }),
            swap_distribution: Some(SwapDistribution {
                total_e8s: 100,
                initial_swap_amount_e8s: 1,
            }),
            airdrop_distribution: Some(AirdropDistribution {
                airdrop_neurons: Default::default(),
            }),
        };
        // Validate that the initial version is valid
        assert!(initial_token_distribution.validate().is_ok());

        // The treasury_distribution being absent should fail validation
        initial_token_distribution.treasury_distribution = None;
        assert!(initial_token_distribution.validate().is_err());

        // Check that returning to a default is valid
        initial_token_distribution.treasury_distribution =
            Some(TreasuryDistribution { total_e8s: 0 });
        assert!(initial_token_distribution.validate().is_ok());

        // Check that the max value is valid
        initial_token_distribution.treasury_distribution = Some(TreasuryDistribution {
            total_e8s: u64::MAX,
        });
        assert!(initial_token_distribution.validate().is_ok());
    }

    #[test]
    fn test_fractional_developer_voting_power_swap_validation() {
        // A basic valid FractionalDeveloperVotingPower
        let mut initial_token_distribution = FractionalDeveloperVotingPower {
            developer_distribution: Some(DeveloperDistribution {
                developer_neurons: Default::default(),
            }),
            treasury_distribution: Some(TreasuryDistribution { total_e8s: 0 }),
            swap_distribution: Some(SwapDistribution {
                total_e8s: 100,
                initial_swap_amount_e8s: 1,
            }),
            airdrop_distribution: Some(AirdropDistribution {
                airdrop_neurons: Default::default(),
            }),
        };
        // Validate that the initial version is valid
        assert!(initial_token_distribution.validate().is_ok());

        // The swap_distribution being absent should fail validation
        initial_token_distribution.swap_distribution = None;
        assert!(initial_token_distribution.validate().is_err());

        // Check that returning to a default is valid
        initial_token_distribution.swap_distribution = Some(SwapDistribution {
            initial_swap_amount_e8s: 1,
            total_e8s: 1,
        });
        assert!(initial_token_distribution.validate().is_ok());

        // initial_swap_amount_e8s must be greater than 0
        initial_token_distribution.swap_distribution = Some(SwapDistribution {
            initial_swap_amount_e8s: 0,
            total_e8s: 0,
        });
        assert!(initial_token_distribution.validate().is_err());

        // initial_swap_amount_e8s cannot be greater than total_e8s
        initial_token_distribution.swap_distribution = Some(SwapDistribution {
            initial_swap_amount_e8s: 10,
            total_e8s: 5,
        });
        assert!(initial_token_distribution.validate().is_err());
    }

    #[test]
    fn test_fractional_developer_voting_power_airdrop_validation() {
        // A basic valid FractionalDeveloperVotingPower
        let mut initial_token_distribution = FractionalDeveloperVotingPower {
            developer_distribution: Some(DeveloperDistribution {
                developer_neurons: Default::default(),
            }),
            treasury_distribution: Some(TreasuryDistribution { total_e8s: 0 }),
            swap_distribution: Some(SwapDistribution {
                total_e8s: 100,
                initial_swap_amount_e8s: 1,
            }),
            airdrop_distribution: Some(AirdropDistribution {
                airdrop_neurons: Default::default(),
            }),
        };
        // Validate that the initial version is valid
        assert!(initial_token_distribution.validate().is_ok());

        // The airdrop_distribution being absent should fail validation
        initial_token_distribution.airdrop_distribution = None;
        assert!(initial_token_distribution.validate().is_err());

        // Check that returning to a default is valid
        initial_token_distribution.airdrop_distribution = Some(AirdropDistribution {
            airdrop_neurons: Default::default(),
        });
        assert!(initial_token_distribution.validate().is_ok());

        // Duplicate principals should fail validation
        initial_token_distribution.airdrop_distribution = Some(AirdropDistribution {
            airdrop_neurons: vec![
                NeuronDistribution {
                    controller: Some(*TEST_NEURON_1_OWNER_PRINCIPAL),
                    stake_e8s: 1,
                },
                NeuronDistribution {
                    controller: Some(*TEST_NEURON_1_OWNER_PRINCIPAL),
                    stake_e8s: 1,
                },
            ],
        });
        assert!(initial_token_distribution.validate().is_err());

        // Unique principals should pass validation
        initial_token_distribution.airdrop_distribution = Some(AirdropDistribution {
            airdrop_neurons: vec![
                NeuronDistribution {
                    controller: Some(*TEST_NEURON_1_OWNER_PRINCIPAL),
                    stake_e8s: 1,
                },
                NeuronDistribution {
                    controller: Some(*TEST_NEURON_2_OWNER_PRINCIPAL),
                    stake_e8s: 1,
                },
            ],
        });
        assert!(initial_token_distribution.validate().is_ok());

        // The sum of the distributions MUST fit into a u64
        initial_token_distribution.airdrop_distribution = Some(AirdropDistribution {
            airdrop_neurons: vec![
                NeuronDistribution {
                    controller: Some(*TEST_NEURON_1_OWNER_PRINCIPAL),
                    stake_e8s: u64::MAX,
                },
                NeuronDistribution {
                    controller: Some(*TEST_NEURON_2_OWNER_PRINCIPAL),
                    stake_e8s: u64::MAX,
                },
            ],
        });
        assert!(initial_token_distribution.validate().is_err());

        // Reset to a valid airdrop_distribution
        initial_token_distribution.airdrop_distribution = Some(AirdropDistribution {
            airdrop_neurons: vec![NeuronDistribution {
                controller: Some(*TEST_NEURON_1_OWNER_PRINCIPAL),
                stake_e8s: 50,
            }],
        });
        assert!(initial_token_distribution.validate().is_ok());

        // Using the same controller in the AirdropDistribution and DeveloperDistribution should fail
        // validation
        initial_token_distribution.developer_distribution = Some(DeveloperDistribution {
            developer_neurons: vec![NeuronDistribution {
                controller: Some(*TEST_NEURON_1_OWNER_PRINCIPAL),
                stake_e8s: 50,
            }],
        });
        assert!(initial_token_distribution.validate().is_err());
    }

    // TODO NNS1-1465: Add tests for fractional developer voting power
}
