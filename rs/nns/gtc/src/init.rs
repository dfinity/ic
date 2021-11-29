use crate::pb::v1::{AccountState, Gtc};
use ic_crypto_sha::Sha256;
use ic_nns_common::pb::v1::NeuronId;
use ic_nns_constants::GENESIS_TOKEN_CANISTER_ID;
use ic_nns_governance::pb::v1::neuron::DissolveState;
use ic_nns_governance::pb::v1::Neuron;
use ledger_canister::Tokens;
use rand::rngs::StdRng;
use rand_core::{RngCore, SeedableRng};
use std::collections::HashMap;
use std::time::SystemTime;

/// A few helper constants for durations.
const ONE_DAY_SECONDS: u64 = 24 * 60 * 60;
const ONE_YEAR_SECONDS: u64 = (4 * 365 + 1) * ONE_DAY_SECONDS / 4;
const ONE_MONTH_SECONDS: u64 = ONE_YEAR_SECONDS / 12;

// The age that GTC neurons will be created with
const GTC_NEURON_PRE_AGE_SECONDS: u64 = 18 * ONE_MONTH_SECONDS;

const INVESTOR_TYPE_SR: &str = "sr";
const INVESTOR_TYPE_ECT: &str = "ect";

impl From<&Vec<Neuron>> for AccountState {
    fn from(neurons: &Vec<Neuron>) -> AccountState {
        let neuron_ids = neurons
            .iter()
            .map(|neuron| neuron.id.clone().expect("GTC neuron missing ID"))
            .collect();

        let e8s = neurons
            .iter()
            .map(|neuron| neuron.cached_neuron_stake_e8s)
            .sum();

        let icpts = Tokens::from_e8s(e8s).get_tokens() as u32;

        AccountState {
            neuron_ids,
            icpts,
            ..Default::default()
        }
    }
}

#[derive(Default)]
pub struct GenesisTokenCanisterInitPayloadBuilder {
    pub gtc_neurons: HashMap<String, Vec<Neuron>>,
    pub total_alloc: u32,
    pub genesis_timestamp_seconds: u64,
    pub donate_account_recipient_neuron_id: Option<NeuronId>,
    pub forward_whitelisted_unclaimed_accounts_recipient_neuron_id: Option<NeuronId>,
    pub forward_unclaimed_accounts_whitelist: Vec<String>,
    pub sr_months_to_release: Option<u8>,
    pub ect_months_to_release: Option<u8>,
    pub rng: Option<StdRng>,
    pub aging_since_timestamp_seconds: u64,
}

impl GenesisTokenCanisterInitPayloadBuilder {
    pub fn new() -> Self {
        Self {
            aging_since_timestamp_seconds: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs()
                - GTC_NEURON_PRE_AGE_SECONDS,
            ..Default::default()
        }
    }

    /// Given a list of "Seed Round" accounts, create each account's neuron set
    /// and add a mapping from the account's address to these neurons in
    /// `gtc_neurons`
    pub fn add_sr_neurons(&mut self, sr_accounts: &[(&str, u32)]) {
        let sr_months_to_release = self
            .sr_months_to_release
            .expect("sr_months_to_release must be set");

        for (address, icpts) in sr_accounts.iter() {
            self.total_alloc += *icpts;
            let icpts = Tokens::from_tokens(*icpts as u64).unwrap();
            let sr_stakes = evenly_split_e8s(icpts.get_e8s(), sr_months_to_release);
            let aging_since_timestamp_seconds = self.aging_since_timestamp_seconds;
            let mut sr_neurons = make_neurons(
                address,
                INVESTOR_TYPE_SR,
                sr_stakes,
                self.get_rng(None),
                aging_since_timestamp_seconds,
            );
            let entry = self.gtc_neurons.entry(address.to_string()).or_default();
            entry.append(&mut sr_neurons);
        }
    }

    /// Given a list of "Early Contributor Tokenholder" accounts, create each
    /// account's neuron set and add a mapping from the account's address to
    /// these neurons in `gtc_neurons`
    pub fn add_ect_neurons(&mut self, ect_accounts: &[(&str, u32)]) {
        let ect_months_to_release = self
            .ect_months_to_release
            .expect("ect_months_to_release must be set");

        for (address, icpts) in ect_accounts.iter() {
            self.total_alloc += *icpts;
            let icpts = Tokens::from_tokens(*icpts as u64).unwrap();
            let ect_stakes = evenly_split_e8s(icpts.get_e8s(), ect_months_to_release);
            let aging_since_timestamp_seconds = self.aging_since_timestamp_seconds;
            let mut ect_neurons = make_neurons(
                address,
                INVESTOR_TYPE_ECT,
                ect_stakes,
                self.get_rng(None),
                aging_since_timestamp_seconds,
            );
            let entry = self.gtc_neurons.entry(address.to_string()).or_default();
            entry.append(&mut ect_neurons);
        }
    }

    pub fn add_forward_whitelist(&mut self, forward_whitelist: &[&str]) {
        for address in forward_whitelist {
            self.forward_unclaimed_accounts_whitelist
                .push(address.to_string());
        }
    }

    /// Return the set `StdRng`. If no `StdRng` has been set, create a new one,
    /// set it, and return it.
    fn get_rng(&mut self, optional_seed: Option<[u8; 32]>) -> &mut StdRng {
        if self.rng.is_none() {
            let seed = match optional_seed {
                Some(seed) => seed,
                None => {
                    let now_nanos = SystemTime::now()
                        .duration_since(SystemTime::UNIX_EPOCH)
                        .unwrap()
                        .as_nanos();

                    let mut seed = [0u8; 32];
                    seed[..16].copy_from_slice(&now_nanos.to_be_bytes());
                    seed[16..32].copy_from_slice(&now_nanos.to_be_bytes());
                    seed
                }
            };

            println!(
                "Seed used in generating GTC release schedule is: {:?}",
                &seed
            );

            let rng = StdRng::from_seed(seed);
            self.rng = Some(rng);
        }

        self.rng.as_mut().unwrap()
    }

    /// Return a list of all SR and ECT neurons that have been added
    pub fn get_gtc_neurons(&self) -> Vec<Neuron> {
        self.gtc_neurons.values().flatten().cloned().collect()
    }

    pub fn with_genesis_timestamp_seconds(&mut self, genesis_timestamp_seconds: u64) {
        self.genesis_timestamp_seconds = genesis_timestamp_seconds;
    }

    /// Convert `self` into a `Gtc`, which is used to initialize the GTC
    /// (canister)
    pub fn build(&mut self) -> Gtc {
        let accounts = self
            .gtc_neurons
            .iter()
            .map(|(address, neurons)| (address.clone(), AccountState::from(neurons)))
            .collect();

        Gtc {
            accounts,
            total_alloc: self.total_alloc,
            genesis_timestamp_seconds: self.genesis_timestamp_seconds,
            donate_account_recipient_neuron_id: self.donate_account_recipient_neuron_id.clone(),
            forward_whitelisted_unclaimed_accounts_recipient_neuron_id: self
                .forward_whitelisted_unclaimed_accounts_recipient_neuron_id
                .clone(),
            whitelisted_accounts_to_forward: self.forward_unclaimed_accounts_whitelist.clone(),
        }
    }
}

/// Return a list of neurons that contain the stakes given in `stakes` and
/// dissolve at monotonically increasing months.
///
/// The first neuron's dissolve delay will be set to 0, the following neurons
/// will dissolve at a random time in the month after the previous neuron.
fn make_neurons(
    address: &str,
    investor_type: &str,
    stakes: Vec<u64>,
    rng: &mut StdRng,
    aging_since_timestamp_seconds: u64,
) -> Vec<Neuron> {
    stakes
        .into_iter()
        .enumerate()
        .map(|(month_i, stake_e8s)| {
            let random_offset_within_one_month_seconds = rng.next_u64() % ONE_MONTH_SECONDS;
            let dissolve_delay_seconds = if month_i == 0 {
                0
            } else {
                ((month_i as u64) * ONE_MONTH_SECONDS) + random_offset_within_one_month_seconds
            };

            make_neuron(
                address,
                investor_type,
                stake_e8s,
                dissolve_delay_seconds,
                aging_since_timestamp_seconds,
            )
        })
        .collect()
}

/// Make a neuron with the fields that can be set initially, with the
/// expectation that the Governance canister will fill-in additional fields
/// (e.g. `created_timestamp_seconds`) when the neuron is claimed by the
/// associated GTC account owner in the future.
///
/// Arguments:
///
/// * `controller`: The controller of the to-be-created neuron
/// * `investor_type`: Either "sr" or "ect"
/// * `stake_e8s`: The stake (in "e8s") of the to-be-created neuron
/// * `dissolve_delay_seconds`: The dissolve delay of the to-be-created neuron
fn make_neuron(
    address: &str,
    investor_type: &str,
    stake_e8s: u64,
    dissolve_delay_seconds: u64,
    aging_since_timestamp_seconds: u64,
) -> Neuron {
    let subaccount = {
        let mut state = Sha256::new();
        state.write(b"gtc-neuron");
        state.write(address.as_bytes());
        state.write(investor_type.as_bytes());
        state.write(&dissolve_delay_seconds.to_be_bytes());
        state.finish()
    };

    Neuron {
        id: Some(NeuronId::from_subaccount(&subaccount)),
        account: subaccount.to_vec(),
        controller: Some(GENESIS_TOKEN_CANISTER_ID.get()),
        cached_neuron_stake_e8s: stake_e8s,
        dissolve_state: Some(DissolveState::DissolveDelaySeconds(dissolve_delay_seconds)),
        aging_since_timestamp_seconds,
        ..Default::default()
    }
}

/// Evenly split an amount of e8s across a number of buckets
fn evenly_split_e8s(e8s: u64, num_buckets: u8) -> Vec<u64> {
    (1..=num_buckets)
        .map(|bucket_i| {
            let mut e8s_i = e8s / (num_buckets as u64);
            if bucket_i == num_buckets {
                e8s_i += e8s % (num_buckets as u64);
            }
            e8s_i
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_evenly_split_e8s() {
        assert_eq!(evenly_split_e8s(3, 3), vec![1, 1, 1]);
        assert_eq!(evenly_split_e8s(50, 3), vec![16, 16, 18]);
        assert_eq!(evenly_split_e8s(1, 4), vec![0, 0, 0, 1]);
    }

    #[test]
    fn test_evenly_split_e8s_over_12_months() {
        let e8s = Tokens::from_tokens(1000).unwrap().get_e8s();
        let e8s1 = 8_333_333_333;
        let e8s2 = 8_333_333_337;

        let expected_stakes = vec![
            e8s1, e8s1, e8s1, e8s1, e8s1, e8s1, e8s1, e8s1, e8s1, e8s1, e8s1, e8s2,
        ];

        assert_eq!(evenly_split_e8s(e8s, 12), expected_stakes);
    }

    #[test]
    fn test_evenly_split_e8s_over_48_months() {
        let e8s = Tokens::from_tokens(1000).unwrap().get_e8s();
        let e8s1 = 2_083_333_333;
        let e8s2 = 2_083_333_349;

        let expected_stakes = vec![
            e8s1, e8s1, e8s1, e8s1, e8s1, e8s1, e8s1, e8s1, e8s1, e8s1, e8s1, e8s1, e8s1, e8s1,
            e8s1, e8s1, e8s1, e8s1, e8s1, e8s1, e8s1, e8s1, e8s1, e8s1, e8s1, e8s1, e8s1, e8s1,
            e8s1, e8s1, e8s1, e8s1, e8s1, e8s1, e8s1, e8s1, e8s1, e8s1, e8s1, e8s1, e8s1, e8s1,
            e8s1, e8s1, e8s1, e8s1, e8s1, e8s2,
        ];

        assert_eq!(evenly_split_e8s(e8s, 48), expected_stakes);
    }

    #[test]
    fn test_non_default_month_releases() {
        let sr_months_to_release = 25;
        let ect_months_to_release = 33;
        let sr_address = "sr_address";
        let ect_address = "ect_address";

        let mut payload_builder = GenesisTokenCanisterInitPayloadBuilder::new();
        payload_builder.sr_months_to_release = Some(sr_months_to_release);
        payload_builder.ect_months_to_release = Some(ect_months_to_release);
        payload_builder.add_sr_neurons(&[(sr_address, 12000)]);
        payload_builder.add_ect_neurons(&[(ect_address, 444555)]);

        assert_eq!(
            payload_builder.gtc_neurons.get(sr_address).unwrap().len(),
            sr_months_to_release as usize
        );
        assert_eq!(
            payload_builder.gtc_neurons.get(ect_address).unwrap().len(),
            ect_months_to_release as usize
        );
    }

    #[test]
    fn test_make_neurons() {
        let seed = [145u8; 32];
        let mut rng = StdRng::from_seed(seed);
        let stakes = vec![5000, 5000, 5000, 5000, 5000, 5000, 5000];
        let account_a_neurons = make_neurons("accountA", "sr", stakes.clone(), &mut rng, 12345678);
        let account_b_neurons = make_neurons("accountB", "sr", stakes.clone(), &mut rng, 87654321);

        // The first neuron (for each account) should have dissolve delay 0
        assert_eq!(
            account_a_neurons.get(0).unwrap().dissolve_delay_seconds(0),
            0
        );
        assert_eq!(
            account_b_neurons.get(0).unwrap().dissolve_delay_seconds(0),
            0
        );
        assert_eq!(
            account_a_neurons
                .get(0)
                .unwrap()
                .aging_since_timestamp_seconds,
            12345678
        );
        assert_eq!(
            account_b_neurons
                .get(0)
                .unwrap()
                .aging_since_timestamp_seconds,
            87654321
        );

        let mut exists_a_month_where_account_a_dissolved_first = false;
        let mut exists_a_month_where_account_b_dissolved_first = false;

        // From the 2nd neuron forward, the dissolve delay for each neuron
        // should be a random value within its "assigned" month, and neurons in
        // separate accounts should have different dissolve delays.
        // Furthermore, we assert that there exists a month where account A's
        // neurons dissolve before account B's, and a month where account B's
        // neurons dissolve before account A's.
        for n in 1..stakes.len() as u64 {
            let dissolve_delay_a = account_a_neurons
                .get(n as usize)
                .unwrap()
                .dissolve_delay_seconds(0);
            let dissolve_delay_b = account_b_neurons
                .get(n as usize)
                .unwrap()
                .dissolve_delay_seconds(0);

            assert!(n * ONE_MONTH_SECONDS < dissolve_delay_a);
            assert!(dissolve_delay_a < (n + 1) * ONE_MONTH_SECONDS);

            assert!(n * ONE_MONTH_SECONDS < dissolve_delay_b);
            assert!(dissolve_delay_b < (n + 1) * ONE_MONTH_SECONDS);

            assert_ne!(dissolve_delay_a, dissolve_delay_b);

            if dissolve_delay_a < dissolve_delay_b {
                exists_a_month_where_account_a_dissolved_first = true;
            }

            if dissolve_delay_b < dissolve_delay_a {
                exists_a_month_where_account_b_dissolved_first = true;
            }
        }

        assert!(exists_a_month_where_account_a_dissolved_first);
        assert!(exists_a_month_where_account_b_dissolved_first);
    }
}
