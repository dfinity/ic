#[cfg(not(target_arch = "wasm32"))]
use icp_ledger::Subaccount;
#[cfg(not(target_arch = "wasm32"))]
use rand::{RngCore, SeedableRng};
#[cfg(not(target_arch = "wasm32"))]
use rand_chacha::ChaCha20Rng;
#[cfg(not(target_arch = "wasm32"))]
use std::path::Path;

use ic_base_types::PrincipalId;
use ic_nns_common::types::NeuronId;
#[cfg(not(target_arch = "wasm32"))]
use ic_nns_governance_api::Visibility;
use ic_nns_governance_api::{
    Governance, NetworkEconomics, Neuron, XdrConversionRate as XdrConversionRatePb,
};

// To update or add more, add print statements to `with_test_neurons` to print
// the generated neuron IDs and copy the printed IDs here.
#[allow(dead_code)]
pub struct GovernanceCanisterInitPayloadBuilder {
    pub proto: Governance,
    voters_to_add_to_all_neurons: Vec<PrincipalId>,
    #[cfg(not(target_arch = "wasm32"))]
    rng: ChaCha20Rng,
}

#[allow(clippy::new_without_default)]
impl GovernanceCanisterInitPayloadBuilder {
    pub fn new() -> Self {
        Self {
            proto: Governance {
                economics: Some(NetworkEconomics::with_default_values()),
                wait_for_quiet_threshold_seconds: 60 * 60 * 24 * 4, // 4 days
                short_voting_period_seconds: 60 * 60 * 12,          // 12 hours
                neuron_management_voting_period_seconds: Some(60 * 60 * 48), // 48 hours
                xdr_conversion_rate: Some(XdrConversionRatePb::with_default_values()),
                ..Default::default()
            },
            voters_to_add_to_all_neurons: Vec::new(),
            #[cfg(not(target_arch = "wasm32"))]
            rng: ChaCha20Rng::seed_from_u64(0),
        }
    }

    // FIXME: This is temporary so that neurons retain their ids.
    // Moving forward we should only actually assign the ids to neurons
    // on the canister and should come up with a naming scheme to layout
    // the following graph on initialization that doesn't rely on ids.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn new_neuron_id(&mut self) -> NeuronId {
        let random_id = self.rng.next_u64();

        NeuronId(random_id)
    }

    #[cfg(target_arch = "wasm32")]
    pub fn new_neuron_id(&mut self) -> NeuronId {
        unimplemented!("Not implemented for wasm32");
    }

    pub fn get_balance(&self) -> u64 {
        self.proto
            .neurons
            .values()
            .map(|n| n.cached_neuron_stake_e8s)
            .sum()
    }

    pub fn with_governance_proto(&mut self, proto: Governance) -> &mut Self {
        // Save the neurons from the current proto, to account for the neurons
        // possibly already crated (say, for the GTC).
        let neurons = self.proto.neurons.clone();
        self.proto = proto;
        self.proto.neurons.extend(neurons);
        self
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub fn make_subaccount(&mut self) -> Subaccount {
        let mut bytes = [0u8; 32];
        self.rng.fill_bytes(&mut bytes);
        Subaccount(bytes)
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub fn with_test_neurons_impl(
        &mut self,
        maturity_equivalent_icp_e8s: Option<u64>,
        hotkeys: Vec<PrincipalId>,
    ) -> &mut Self {
        use ic_nns_common::pb::v1::NeuronId as NeuronIdProto;

        const TWELVE_MONTHS_SECONDS: u64 = 30 * 12 * 24 * 60 * 60;
        use ic_nervous_system_common_test_keys::{
            TEST_NEURON_1_ID, TEST_NEURON_1_OWNER_PRINCIPAL, TEST_NEURON_2_ID,
            TEST_NEURON_2_OWNER_PRINCIPAL, TEST_NEURON_3_ID, TEST_NEURON_3_OWNER_PRINCIPAL,
        };
        use ic_nns_governance_api::{Neuron, neuron::DissolveState};
        use std::time::SystemTime;

        // This assumption here is that with_current_time is used.
        // Alternatively, we could use u64::MAX, but u64::MAX is not as
        // realistic.
        let voting_power_refreshed_timestamp_seconds = Some(
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        );

        let mut neuron1 = {
            let neuron_id = NeuronIdProto::from(self.new_neuron_id());
            let subaccount = self.make_subaccount().into();
            Neuron {
                id: Some(neuron_id),
                controller: Some(*TEST_NEURON_1_OWNER_PRINCIPAL),
                // Use large values to avoid the possibility of collisions with other self-authenticating hotkeys
                hot_keys: hotkeys,
                dissolve_state: Some(DissolveState::DissolveDelaySeconds(TWELVE_MONTHS_SECONDS)),
                cached_neuron_stake_e8s: 1_000_000_000, /* invariant: part of
                                                         * TEST_NEURON_TOTAL_STAKE_E8S */
                account: subaccount,
                not_for_profit: true,
                voting_power_refreshed_timestamp_seconds,
                visibility: Some(Visibility::Public as i32),
                ..Default::default()
            }
        };
        assert_eq!(neuron1.id.as_ref().unwrap().id, TEST_NEURON_1_ID);

        if let Some(maturity_equivalent_icp_e8s) = maturity_equivalent_icp_e8s {
            neuron1.maturity_e8s_equivalent = maturity_equivalent_icp_e8s;
            neuron1.joined_community_fund_timestamp_seconds = Some(1);
            // Setting `auto_stake_maturity` makes simplifies testing, as maturity accumulated
            // over time does not need to be taken into account.
            neuron1.auto_stake_maturity = Some(true);
        }

        let neuron2 = {
            let neuron_id = NeuronIdProto::from(self.new_neuron_id());
            let subaccount = self.make_subaccount().into();
            Neuron {
                id: Some(neuron_id),
                controller: Some(*TEST_NEURON_2_OWNER_PRINCIPAL),
                dissolve_state: Some(DissolveState::DissolveDelaySeconds(TWELVE_MONTHS_SECONDS)),
                cached_neuron_stake_e8s: 100_000_000, /* invariant: part of
                                                       * TEST_NEURON_TOTAL_STAKE_E8S */
                created_timestamp_seconds: 1,
                aging_since_timestamp_seconds: 1,
                account: subaccount,
                not_for_profit: false,
                voting_power_refreshed_timestamp_seconds,
                visibility: Some(Visibility::Public as i32),
                ..Default::default()
            }
        };
        assert_eq!(neuron2.id.as_ref().unwrap().id, TEST_NEURON_2_ID);

        let neuron3 = {
            let neuron_id = NeuronIdProto::from(self.new_neuron_id());
            let subaccount = self.make_subaccount().into();
            Neuron {
                id: Some(neuron_id),
                controller: Some(*TEST_NEURON_3_OWNER_PRINCIPAL),
                dissolve_state: Some(DissolveState::DissolveDelaySeconds(TWELVE_MONTHS_SECONDS)),
                cached_neuron_stake_e8s: 10_000_000, /* invariant: part of
                                                      * TEST_NEURON_TOTAL_STAKE_E8S */
                created_timestamp_seconds: 10,
                aging_since_timestamp_seconds: 10,
                account: subaccount,
                not_for_profit: false,
                voting_power_refreshed_timestamp_seconds,
                visibility: Some(Visibility::Public as i32),
                ..Default::default()
            }
        };
        assert_eq!(neuron3.id.as_ref().unwrap().id, TEST_NEURON_3_ID);

        self.with_additional_neurons(vec![neuron1, neuron2, neuron3])
    }

    /// Initializes the governance canister with a few neurons to be used in tests.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn with_test_neurons(&mut self) -> &mut Self {
        self.with_test_neurons_impl(None, vec![])
    }

    /// Initializes the governance canister with a few neurons to be used in tests. One of
    /// the neurons will have `maturity_equivalent_icp_e8s` and had joined the Neurons' Fund.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn with_test_neurons_fund_neurons(
        &mut self,
        maturity_equivalent_icp_e8s: u64,
    ) -> &mut Self {
        self.with_test_neurons_impl(Some(maturity_equivalent_icp_e8s), vec![])
    }

    /// Initializes the governance canister with a few neurons to be used in tests. One of
    /// the neurons will have:
    /// - `hotkeys`
    /// - `maturity_equivalent_icp_e8s` worth of maturity
    /// - had joined the Neurons' Fund
    #[cfg(not(target_arch = "wasm32"))]
    pub fn with_test_neurons_fund_neurons_with_hotkeys(
        &mut self,
        hotkeys: Vec<PrincipalId>,
        maturity_equivalent_icp_e8s: u64,
    ) -> &mut Self {
        self.with_test_neurons_impl(Some(maturity_equivalent_icp_e8s), hotkeys)
    }

    /// Initializes the governance canister with the given neurons.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn with_additional_neurons(&mut self, neurons: Vec<Neuron>) -> &mut Self {
        for neuron in neurons {
            let id: u64 = neuron.id.as_ref().unwrap().id;
            assert_eq!(
                self.proto.neurons.insert(id, neuron),
                None,
                "There is more than one neuron with the same id ({id:?})."
            );
        }
        self
    }

    /// Initializes the governance canister with the given network economics.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn with_network_economics(&mut self, network_economics: NetworkEconomics) -> &mut Self {
        self.proto.economics = Some(network_economics);
        self
    }

    /// Initializes the governance canister with the given genesis timestamp.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn with_genesis_timestamp_seconds(&mut self, genesis_timestamp_seconds: u64) -> &mut Self {
        self.proto.genesis_timestamp_seconds = genesis_timestamp_seconds;
        self
    }

    /// Adds all the neurons from the specified CSV file.
    ///
    /// This obviously can only work when compiled to x86 so the wasm
    /// version doesn't include this method.
    ///
    /// An example is available at `rs/nns/governance/test/init.rs`.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn add_all_neurons_from_csv_file(&mut self, csv_file: &Path) -> &mut Self {
        use ic_nns_common::pb::v1::NeuronId as NeuronIdProto;

        use csv::ReaderBuilder;
        use ic_base_types::PrincipalId;
        use ic_nervous_system_common::ledger;
        use ic_nns_common::types::NeuronId;
        use ic_nns_governance_api::{
            Neuron, Topic,
            neuron::{DissolveState, Followees},
        };
        use std::str::FromStr;

        let mut reader = ReaderBuilder::new()
            .delimiter(b';')
            .from_path(csv_file)
            .unwrap_or_else(|_| panic!("error creating a csv reader at path: {csv_file:?}"));

        {
            let headers = reader.headers().expect("error reading CSV header row");
            let headers = headers
                .into_iter()
                .map(|f| f.parse::<String>().expect("couldn't read column header"))
                .collect::<Vec<String>>();

            assert_eq!(
                headers,
                vec![
                    "neuron_id",
                    "owner_id",
                    "created_ts_ns",
                    "dissolve_delay_s",
                    "staked_icpt",
                    "follows",
                    "not_for_profit",
                    "maturity_e8s_equivalent",
                ]
            );
        }

        for result in reader.records() {
            let record = result.expect("error reading CSV record");

            let id_field: &str = &record[0];
            let neuron_id = if id_field.is_empty() {
                self.new_neuron_id()
            } else {
                let id = id_field
                    .parse::<u64>()
                    .expect("couldn't read the neuron's id");
                NeuronId(id)
            };
            let principal_id = PrincipalId::from_str(&record[1]).unwrap();
            let creation_ts_ns = record[2]
                .parse::<u64>()
                .expect("couldn't read the neuron's creation time");
            let dissolve_delay_seconds = record[3]
                .parse::<u64>()
                .expect("couldn't read the neuron's dissolve delay");
            let staked_icpt = record[4]
                .parse::<u64>()
                .expect("couldn't read the neuron's staked icpt amount");
            let followees: Vec<NeuronIdProto> = record[5]
                .split_terminator(',')
                .map(|x| NeuronIdProto {
                    id: x.parse::<u64>().expect("could not parse followee"),
                })
                .collect();
            if followees.len() > 1 {
                println!("followees of {principal_id:?} : {followees:?}")
            }

            let neuron_id = NeuronIdProto::from(neuron_id);

            let not_for_profit = record[6]
                .parse::<bool>()
                .expect("couldn't read the neuron's not-for-profit flag");

            let memo = self.rng.next_u64();

            let maturity_e8s_equivalent = record[7]
                .parse::<u64>()
                .expect("could not parse maturity_e8s_equivalent");

            let kyc_verified = false;

            let neuron = Neuron {
                id: Some(neuron_id),
                account: ledger::compute_neuron_staking_subaccount(principal_id, memo).into(),
                controller: Some(principal_id),
                hot_keys: vec![principal_id],
                cached_neuron_stake_e8s: staked_icpt * 100_000_000, // to e8s
                created_timestamp_seconds: creation_ts_ns / (1_000_000_000), // to sec
                aging_since_timestamp_seconds: creation_ts_ns / (1_000_000_000), // to sec
                kyc_verified,
                maturity_e8s_equivalent,
                not_for_profit,
                dissolve_state: Some(DissolveState::DissolveDelaySeconds(dissolve_delay_seconds)),
                followees: [(Topic::Unspecified as i32, Followees { followees })]
                    .iter()
                    .cloned()
                    .collect(),
                visibility: Some(Visibility::Public as i32),
                ..Default::default()
            };

            assert_eq!(
                self.proto.neurons.insert(neuron_id.id, neuron),
                None,
                "There is more than one neuron with the same id"
            );
        }

        self
    }

    /// Add the neurons created for GTC accounts to Governance's collection
    /// of neurons
    pub fn add_gtc_neurons(&mut self, neurons: Vec<Neuron>) -> &mut Self {
        for neuron in neurons {
            let id = neuron.id.expect("GTC neuron missing ID").id;
            assert_eq!(
                self.proto.neurons.insert(id, neuron),
                None,
                "There is more than one neuron with the same id"
            );
        }

        self
    }

    pub fn build(&mut self) -> Governance {
        for neuron in self.proto.neurons.values_mut() {
            neuron
                .hot_keys
                .extend(self.voters_to_add_to_all_neurons.clone());
        }

        self.proto.clone()
    }
}
