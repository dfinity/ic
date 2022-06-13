use crate::{SnsCanisterIds, Tokens};
use ic_base_types::PrincipalId;
use ic_nervous_system_common::ledger::{
    compute_distribution_subaccount, compute_neuron_staking_subaccount,
};
use ic_nervous_system_common::{i2r, try_r2u64};
use ic_sns_governance::pb::v1::neuron::DissolveState;
use ic_sns_governance::pb::v1::{NervousSystemParameters, Neuron, NeuronPermission};
use ledger_canister::AccountIdentifier;
use num::rational::Ratio;
use num::BigInt;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::time::SystemTime;

/// The static MEMO used when calculating subaccounts of neurons available at genesis.
pub const DEFAULT_NEURON_STAKING_NONCE: u64 = 0;

/// The static MEMO used when calculating the SNS Treasury subaccount.
pub const TREASURY_SUBACCOUNT_NONCE: u64 = 0;

/// The static MEMO used when calculating the subaccount of future developer distributions.
pub const DEVELOPER_SUBACCOUNT_NONCE: u64 = 1;

/// The static MEMO used when calculating the subaccount of future token swaps.
pub const SWAP_SUBACCOUNT_NONCE: u64 = 2;

/// A `TokenDistribution` couples a bucket's total distribution, and distributions
/// of neurons created at genesis from that bucket's total distribution.
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct TokenDistribution {
    /// The total number of tokens denominated in e8s (1 token = 100,000,000 e8s)
    /// for a bucket at genesis. The stake of neurons created from this bucket
    /// will be pulled from `total_e8s`.
    pub total_e8s: u64,

    /// A map of `PrincipalId` to tokens denominated in e8s (1 token = 100,000,000 e8s)
    /// that represent Neurons and their stakes available at genesis. These neurons
    /// will have reduced functionality until the decentralization swap has completed.
    /// The ledger accounts containing the stake will be funded from `total_e8s`.
    pub distributions: HashMap<PrincipalId, u64>,
}

/// An `InitialTokenDistribution` structures the configuration of the SNS Ledger and SNS
/// Governance at genesis. Developers can allocate tokens to the different buckets needed
/// for a decentralization swap.
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct InitialTokenDistribution {
    /// The developer bucket distributes tokens to the original developers of the dapp.
    /// Each distribution will create a neuron in `PreInitializationSwap` mode controlled
    /// by the PrincipalId and with the provided stake. The tokens will be distributed
    /// to the neuron's subaccount in the SNS Ledger, and the amount will be funded by
    /// this bucket. The ratio between the bucket's `TokenDistribution::total_e8s` and
    /// the sum of each distribution's stake determines how many tokens are swapped in
    /// the first decentralization swap. This ratio will also determine how many
    /// neurons will be created for the developers in future swaps. Any undistributed
    /// tokens between swaps will remain in a subaccount of Governance until used to
    /// fund the developer neurons in the future.
    pub developers: TokenDistribution,

    /// The treasury bucket distributes tokens to the SNS's treasury account and creates neurons
    /// for the SNS community for use at genesis. Each distribution will create a one-time neuron
    /// in `PreInitializationSwap` mode controlled by the PrincipalId and with the provided stake.
    /// The tokens used to fund these one-time neurons comes from the treasury's total distribution.
    /// The remaining tokens will be distributed to a subaccount of Governance for use after the
    /// first decentralization swap.
    pub treasury: TokenDistribution,

    /// The total amount of tokens denominated in e8s (1 token = 100,000,000 e8s) used to fund
    /// the Swap Canister for the decentralization swap. These tokens will be distributed to the
    /// Swap Canister's main account on the SNS Ledger at genesis. The amount of these tokens
    /// used in each swap is determined by the ratio configured by the developers
    /// `TokenDistribution`. Any unused tokens will be distributed to a subaccount of Governance
    /// for use in future swaps. For example if the developers want 25% of their neurons issued for
    /// each during swap, only 25% of the swap bucket's total amount will be swapped
    /// via the Swap Canister. The rest will be in a protected subaccount of Governance for
    /// future swaps.
    pub swap: u64,
}

impl InitialTokenDistribution {
    /// Given the configuration of the different buckets, when provided the SnsCanisterIds calculate
    /// all the `AccountId`s of SNS Ledger accounts that will have tokens distributed at genesis.
    /// As there are ratios involved in determining how many tokens are distributed to which
    /// account, there is some tricky math with large numbers. This method makes use of
    /// `Ratio<BigInt>` to handle the rounding with precision, and to make sure every e8 is
    /// distributed.
    pub fn get_account_ids_and_tokens(
        &self,
        sns_canister_ids: &SnsCanisterIds,
    ) -> Result<HashMap<AccountIdentifier, Tokens>, String> {
        let developer_neuron_distribution =
            Self::get_total_distributions(&self.developers.distributions)?;
        let treasury_neuron_distribution =
            Self::get_total_distributions(&self.treasury.distributions)?;

        // The initial_swap_ratio determines how much of the swap distribution is put in
        // the Swap Canister, and how much is held in locked reserves. It is proportional to
        // the amount that the devs have allocated in neurons and their total distribution.
        //
        // As this is a ratio, use Ration<BigInt> to not lose precision when dividing.
        let initial_swap_ratio =
            i2r(developer_neuron_distribution) / i2r(self.developers.total_e8s);

        let mut accounts = HashMap::new();
        self.insert_developer_accounts(
            developer_neuron_distribution,
            sns_canister_ids,
            &mut accounts,
        );
        self.insert_treasury_accounts(
            treasury_neuron_distribution,
            sns_canister_ids,
            &mut accounts,
        );
        self.insert_swap_accounts(initial_swap_ratio, sns_canister_ids, &mut accounts)?;

        Ok(accounts)
    }

    /// Given the configuration of the different buckets, create the neurons that will be available
    /// at genesis. These neurons will have reduced functionality until after the
    /// decentralization swap. Return a map of NeuronId to Neuron.
    pub fn get_initial_neurons(
        &self,
        parameters: &NervousSystemParameters,
    ) -> BTreeMap<String, Neuron> {
        self.developers
            .distributions
            .iter()
            .chain(self.treasury.distributions.iter())
            .map(|(principal_id, stake_e8s)| {
                let subaccount =
                    compute_neuron_staking_subaccount(*principal_id, DEFAULT_NEURON_STAKING_NONCE);

                let permission = NeuronPermission {
                    principal: Some(*principal_id),
                    permission_type: parameters
                        .neuron_claimer_permissions
                        .as_ref()
                        .unwrap()
                        .permissions
                        .clone(),
                };

                // TODO Set to the genesis timestamp of the SNS
                let now = SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap()
                    .as_secs();

                let neuron = Neuron {
                    id: Some(subaccount.into()),
                    permissions: vec![permission],
                    cached_neuron_stake_e8s: *stake_e8s,
                    neuron_fees_e8s: 0,
                    created_timestamp_seconds: now,
                    aging_since_timestamp_seconds: now,
                    followees: Default::default(),
                    maturity_e8s_equivalent: 0,
                    dissolve_state: Some(DissolveState::DissolveDelaySeconds(
                        parameters
                            .neuron_minimum_dissolve_delay_to_vote_seconds
                            .expect(
                                "Expected neuron_minimum_dissolve_delay_to_vote_seconds to exist",
                            ),
                    )),
                };

                (neuron.id.as_ref().unwrap().to_string(), neuron)
            })
            .collect()
    }

    /// TODO NNS1-1464 : Enforce proper decentralization of distributions
    pub fn validate(&self) -> Result<(), String> {
        Ok(())
    }

    /// Calculate and insert the developer bucket accounts into the provided map.
    fn insert_developer_accounts(
        &self,
        developer_neuron_distribution: u64,
        sns_canister_ids: &SnsCanisterIds,
        accounts: &mut HashMap<AccountIdentifier, Tokens>,
    ) {
        // First deduct the distributions at genesis from the configured total_e8s. These funds
        // will be locked in a static subaccount of Governance until future decentralization swaps.
        let locked_developer_distribution =
            self.developers.total_e8s - developer_neuron_distribution;
        let (locked_developer_distribution_account, locked_developer_distribution) =
            Self::get_distribution_account_id_and_tokens(
                &sns_canister_ids.governance,
                DEVELOPER_SUBACCOUNT_NONCE,
                locked_developer_distribution,
            );
        accounts.insert(
            locked_developer_distribution_account,
            locked_developer_distribution,
        );

        for (principal_id, amount) in self.developers.distributions.iter() {
            let (account, tokens) = Self::get_neuron_account_id_and_tokens(
                &sns_canister_ids.governance,
                principal_id,
                *amount,
            );
            accounts.insert(account, tokens);
        }
    }

    /// Calculate and insert the treasury bucket accounts into the provided map.
    fn insert_treasury_accounts(
        &self,
        treasury_neuron_distributions: u64,
        sns_canister_ids: &SnsCanisterIds,
        accounts: &mut HashMap<AccountIdentifier, Tokens>,
    ) {
        let locked_treasury_distribution = self.treasury.total_e8s - treasury_neuron_distributions;
        let (locked_treasury_distribution_account, locked_treasury_distribution) =
            Self::get_distribution_account_id_and_tokens(
                &sns_canister_ids.governance,
                TREASURY_SUBACCOUNT_NONCE,
                locked_treasury_distribution,
            );
        accounts.insert(
            locked_treasury_distribution_account,
            locked_treasury_distribution,
        );

        for (principal_id, amount) in self.treasury.distributions.iter() {
            let (account, tokens) = Self::get_neuron_account_id_and_tokens(
                &sns_canister_ids.governance,
                principal_id,
                *amount,
            );
            accounts.insert(account, tokens);
        }
    }

    /// Calculate and insert the swap bucket accounts into the provided map.
    fn insert_swap_accounts(
        &self,
        initial_swap_ratio: Ratio<BigInt>,
        sns_canister_ids: &SnsCanisterIds,
        accounts: &mut HashMap<AccountIdentifier, Tokens>,
    ) -> Result<(), String> {
        // Multiply the total amount of allocated Swap distribution with the initial_swap_ratio to
        // determine how much of the distribution will be available to the token swap canister
        // at genesis.
        let initial_swap_amount_ratio: Ratio<BigInt> = i2r(self.swap) * initial_swap_ratio;
        // If the ratio produces a fractional, round down and convert back to a u64
        let initial_swap_amount = try_r2u64(&initial_swap_amount_ratio.floor()).map_err(|err| {
            format!(
                "Unable to convert initial swap tokens to an unsigned integer: {}",
                err
            )
        })?;

        let swap_canister_account = AccountIdentifier::new(sns_canister_ids.swap, None);
        let tokens = Tokens::from_e8s(initial_swap_amount);
        accounts.insert(swap_canister_account, tokens);

        let future_swap_amount = self.swap - initial_swap_amount;
        let (future_swap_distribution_account, future_swap_amount) =
            Self::get_distribution_account_id_and_tokens(
                &sns_canister_ids.governance,
                SWAP_SUBACCOUNT_NONCE,
                future_swap_amount,
            );
        accounts.insert(future_swap_distribution_account, future_swap_amount);

        Ok(())
    }

    /// Given a the PrincipalId of Governance, compute the AccountId and the number of tokens
    /// of a distribution account.
    pub fn get_distribution_account_id_and_tokens(
        governance_canister: &PrincipalId,
        distribution_account_nonce: u64,
        amount: u64,
    ) -> (AccountIdentifier, Tokens) {
        let subaccount =
            compute_distribution_subaccount(*governance_canister, distribution_account_nonce);
        let account = AccountIdentifier::new(*governance_canister, Some(subaccount));
        let tokens = Tokens::from_e8s(amount);

        (account, tokens)
    }

    /// Given a the PrincipalId of Governance, compute the AccountId and the number of tokens
    /// of a neuron.
    fn get_neuron_account_id_and_tokens(
        governance_canister: &PrincipalId,
        claimer: &PrincipalId,
        amount: u64,
    ) -> (AccountIdentifier, Tokens) {
        let subaccount = compute_neuron_staking_subaccount(*claimer, DEFAULT_NEURON_STAKING_NONCE);
        let account = AccountIdentifier::new(*governance_canister, Some(subaccount));
        let tokens = Tokens::from_e8s(amount);

        (account, tokens)
    }

    /// Safely get the sum of all the e8 denominated token distributions. The maximum amount
    /// of tokens e8s must be less than or equal to u64::MAX.
    fn get_total_distributions(distributions: &HashMap<PrincipalId, u64>) -> Result<u64, String> {
        let mut distribution_total: u64 = 0;
        for distribution in distributions.values() {
            distribution_total = match distribution_total.checked_add(*distribution) {
                Some(total) => total,
                None => {
                    return Err(
                        "The total distribution overflowed and is not a valid distribution"
                            .to_string(),
                    )
                }
            }
        }

        Ok(distribution_total)
    }
}

#[cfg(test)]
mod test {
    use crate::distributions::{
        TokenDistribution, DEFAULT_NEURON_STAKING_NONCE, DEVELOPER_SUBACCOUNT_NONCE,
        SWAP_SUBACCOUNT_NONCE, TREASURY_SUBACCOUNT_NONCE,
    };
    use crate::{InitialTokenDistribution, SnsCanisterIds, Tokens};
    use assert_approx_eq::assert_approx_eq;
    use ic_base_types::{CanisterId, PrincipalId};
    use ic_nervous_system_common::ledger::{
        compute_distribution_subaccount, compute_neuron_staking_subaccount,
    };
    use ic_nervous_system_common_test_keys::{
        TEST_NEURON_1_OWNER_PRINCIPAL, TEST_NEURON_2_OWNER_PRINCIPAL, TEST_NEURON_3_OWNER_PRINCIPAL,
    };
    use ic_sns_governance::pb::v1::neuron::DissolveState;
    use ic_sns_governance::pb::v1::{NervousSystemParameters, NeuronId, NeuronPermission};
    use ledger_canister::AccountIdentifier;
    use maplit::hashmap;
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
    ) -> AccountIdentifier {
        let mut subaccount = None;
        if let Some(pid) = principal_id {
            subaccount = Some(compute_distribution_subaccount(pid, nonce.unwrap_or(0)))
        }

        AccountIdentifier::new(canister, subaccount)
    }

    fn get_neuron_account_identifier(
        canister: PrincipalId,
        principal_id: Option<PrincipalId>,
        nonce: Option<u64>,
    ) -> AccountIdentifier {
        let mut subaccount = None;
        if let Some(pid) = principal_id {
            subaccount = Some(compute_neuron_staking_subaccount(pid, nonce.unwrap_or(0)))
        }

        AccountIdentifier::new(canister, subaccount)
    }

    #[test]
    fn test_initial_distributions() {
        let neuron_stake = 100_000_000;
        let dev_total = 600_000_000;
        let swap_total = 1_000_000_000;
        let treasury_total = 1_000_000_000;

        let initial_token_distribution = InitialTokenDistribution {
            developers: TokenDistribution {
                total_e8s: dev_total,
                distributions: hashmap! {
                    *TEST_NEURON_1_OWNER_PRINCIPAL => neuron_stake,
                    *TEST_NEURON_2_OWNER_PRINCIPAL => neuron_stake,
                },
            },
            treasury: TokenDistribution {
                total_e8s: treasury_total,
                distributions: hashmap! {
                    *TEST_NEURON_3_OWNER_PRINCIPAL => neuron_stake,
                },
            },
            swap: swap_total,
        };

        let canister_ids = create_canister_ids();
        let initial_accounts = initial_token_distribution
            .get_account_ids_and_tokens(&canister_ids)
            .unwrap();

        // Verify developer related bucket
        let locked_dev_account = get_distribution_account_identifier(
            canister_ids.governance,
            Some(canister_ids.governance),
            Some(DEVELOPER_SUBACCOUNT_NONCE),
        );

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

        let locked_dev_account_balance = initial_accounts.get(&locked_dev_account).unwrap();
        let neuron_1_account_balance = initial_accounts.get(&neuron_1_account).unwrap();
        let neuron_2_account_balance = initial_accounts.get(&neuron_2_account).unwrap();

        assert_eq!(neuron_1_account_balance, &Tokens::from_e8s(neuron_stake));
        assert_eq!(neuron_2_account_balance, &Tokens::from_e8s(neuron_stake));
        assert_eq!(
            ((*locked_dev_account_balance + *neuron_1_account_balance).unwrap()
                + *neuron_1_account_balance)
                .unwrap(),
            Tokens::from_e8s(dev_total)
        );

        // Verify swap related bucket
        let locked_swap_account = get_distribution_account_identifier(
            canister_ids.governance,
            Some(canister_ids.governance),
            Some(SWAP_SUBACCOUNT_NONCE),
        );
        let swap_canister_account = AccountIdentifier::new(canister_ids.swap, None);

        let locked_swap_account_balance = initial_accounts.get(&locked_swap_account).unwrap();
        let swap_canister_account_balance = initial_accounts.get(&swap_canister_account).unwrap();

        assert_eq!(
            (*locked_swap_account_balance + *swap_canister_account_balance).unwrap(),
            Tokens::from_e8s(initial_token_distribution.swap)
        );

        // Verify treasury related bucket
        let locked_treasury_account = get_distribution_account_identifier(
            canister_ids.governance,
            Some(canister_ids.governance),
            Some(TREASURY_SUBACCOUNT_NONCE),
        );
        let neuron_3_account = get_neuron_account_identifier(
            canister_ids.governance,
            Some(*TEST_NEURON_3_OWNER_PRINCIPAL),
            None,
        );
        let locked_treasury_account_balance =
            initial_accounts.get(&locked_treasury_account).unwrap();
        let neuron_3_account_balance = initial_accounts.get(&neuron_3_account).unwrap();

        assert_eq!(neuron_3_account_balance, &Tokens::from_e8s(neuron_stake));
        assert_eq!(
            (*locked_treasury_account_balance + *neuron_3_account_balance).unwrap(),
            Tokens::from_e8s(treasury_total)
        );
    }

    #[test]
    fn test_developer_and_swap_ratio() {
        // Choose initial values for the distributions. Choosing non-evenly-divisible numbers
        // like 1 / 6 developers will lead to fractional swaps for the swap canister which
        // this test is for.
        let neuron_stake = 100_000_000;
        let dev_total = 600_000_000;
        let swap_total = 1_000_000_000;
        let treasury_total = 0;

        let initial_token_distribution = InitialTokenDistribution {
            developers: TokenDistribution {
                total_e8s: dev_total,
                distributions: hashmap! {
                    *TEST_NEURON_1_OWNER_PRINCIPAL => neuron_stake,
                },
            },
            treasury: TokenDistribution {
                total_e8s: treasury_total,
                distributions: hashmap! {},
            },
            swap: swap_total,
        };

        let canister_ids = create_canister_ids();
        let initial_accounts = initial_token_distribution
            .get_account_ids_and_tokens(&canister_ids)
            .unwrap();

        // Calculate the swap accounts
        let locked_swap_account = get_distribution_account_identifier(
            canister_ids.governance,
            Some(canister_ids.governance),
            Some(SWAP_SUBACCOUNT_NONCE),
        );
        let swap_canister_account = AccountIdentifier::new(canister_ids.swap, None);

        // Get their initial balances
        let locked_swap_account_balance = initial_accounts.get(&locked_swap_account).unwrap();
        let swap_canister_account_balance = initial_accounts.get(&swap_canister_account).unwrap();

        // Calculate the swap ratio. This should be the same as the developer ratio.
        let swap_ratio = swap_canister_account_balance.get_e8s() as f64
            / locked_swap_account_balance.get_e8s() as f64;

        // Calculate the developer accounts
        let locked_dev_account = get_distribution_account_identifier(
            canister_ids.governance,
            Some(canister_ids.governance),
            Some(DEVELOPER_SUBACCOUNT_NONCE),
        );
        let neuron_1_account = get_neuron_account_identifier(
            canister_ids.governance,
            Some(*TEST_NEURON_1_OWNER_PRINCIPAL),
            None,
        );

        // Get their initial balances
        let locked_dev_account_balance = initial_accounts.get(&locked_dev_account).unwrap();
        let neuron_1_account_balance = initial_accounts.get(&neuron_1_account).unwrap();

        // Calculate the developer ratio. This should be the same as the swap ratio.
        let dev_ratio =
            neuron_1_account_balance.get_e8s() as f64 / locked_dev_account_balance.get_e8s() as f64;

        // Although this looks like the approx_eq is because of floating point division, it is in fact
        // because there could be a slight different in the ratio of these values. For instance,
        // if the initial_swap_ratio produces a fractional amount of tokens for the swap canister,
        // the formula will round down to the nearest integer (an 'e8' of a token) and subtract that
        // from the total, accounting for the extra e8. This assert_approx_eq! takes into account
        // these imperfect distribution ratios and allows this unit test to test this edge case.
        assert_approx_eq!(swap_ratio, dev_ratio, 1e-5f64);
    }

    #[test]
    fn test_initial_neurons() {
        let developer_neuron_stake = 100_000_000;
        let airdrop_neuron_stake = 50_000;
        let dev_total = 600_000_000;
        let swap_total = 1_000_000_000;
        let treasury_total = 1_000_000_000;

        let initial_token_distribution = InitialTokenDistribution {
            developers: TokenDistribution {
                total_e8s: dev_total,
                distributions: hashmap! {
                    *TEST_NEURON_1_OWNER_PRINCIPAL => developer_neuron_stake,
                    *TEST_NEURON_2_OWNER_PRINCIPAL => developer_neuron_stake,
                },
            },
            treasury: TokenDistribution {
                total_e8s: treasury_total,
                distributions: hashmap! {
                    *TEST_NEURON_3_OWNER_PRINCIPAL => airdrop_neuron_stake,
                },
            },
            swap: swap_total,
        };

        let parameters = NervousSystemParameters::with_default_values();

        let initial_neurons = initial_token_distribution.get_initial_neurons(&parameters);

        let neuron_id_1 = NeuronId::from(compute_neuron_staking_subaccount(
            *TEST_NEURON_1_OWNER_PRINCIPAL,
            DEFAULT_NEURON_STAKING_NONCE,
        ));
        let neuron_id_2 = NeuronId::from(compute_neuron_staking_subaccount(
            *TEST_NEURON_2_OWNER_PRINCIPAL,
            DEFAULT_NEURON_STAKING_NONCE,
        ));
        let neuron_id_3 = NeuronId::from(compute_neuron_staking_subaccount(
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
}
