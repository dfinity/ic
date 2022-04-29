#[cfg(target_arch = "x86_64")]
use crate::pb::v1::{neuron::DissolveState, neuron::Followees, Topic};
#[cfg(target_arch = "x86_64")]
use ledger_canister::Subaccount;
#[cfg(target_arch = "x86_64")]
use rand::rngs::StdRng;
#[cfg(target_arch = "x86_64")]
use rand_core::{RngCore, SeedableRng};
#[cfg(target_arch = "x86_64")]
use std::path::Path;

use crate::pb::v1::{Governance, NetworkEconomics, Neuron};
use ic_base_types::PrincipalId;
use ic_nns_common::types::NeuronId;

#[allow(dead_code)]
pub struct GovernanceCanisterInitPayloadBuilder {
    pub proto: Governance,
    voters_to_add_to_all_neurons: Vec<PrincipalId>,
    #[cfg(target_arch = "x86_64")]
    rng: StdRng,
}

#[allow(clippy::new_without_default)]
impl GovernanceCanisterInitPayloadBuilder {
    pub fn new() -> Self {
        Self {
            proto: Governance {
                economics: Some(NetworkEconomics::with_default_values()),
                wait_for_quiet_threshold_seconds: 60 * 60 * 24 * 4, // 4 days
                short_voting_period_seconds: 60 * 60 * 12,          // 12 hours
                ..Default::default()
            },
            voters_to_add_to_all_neurons: Vec::new(),
            #[cfg(target_arch = "x86_64")]
            rng: StdRng::seed_from_u64(0),
        }
    }

    // FIXME: This is temporary so that neurons retain their ids.
    // Moving forward we should only actually assign the ids to neurons
    // on the canister and should come up with a naming scheme to layout
    // the following graph on initialization that doesn't rely on ids.
    #[cfg(target_arch = "x86_64")]
    pub fn new_neuron_id(&mut self) -> NeuronId {
        let random_id = self.rng.next_u64();

        NeuronId(random_id)
    }

    #[cfg(not(target_arch = "x86_64"))]
    pub fn new_neuron_id(&mut self) -> NeuronId {
        unimplemented!("Not implemented for non-x86_64");
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

    #[cfg(target_arch = "x86_64")]
    pub fn make_subaccount(&mut self) -> Subaccount {
        let mut bytes = [0u8; 32];
        self.rng.fill_bytes(&mut bytes);
        Subaccount(bytes)
    }

    /// Initializes the governance canister with a few neurons to be used
    /// in tests.
    #[cfg(target_arch = "x86_64")]
    pub fn with_test_neurons(&mut self) -> &mut Self {
        use ic_nns_common::pb::v1::NeuronId as NeuronIdProto;

        const TWELVE_MONTHS_SECONDS: u64 = 30 * 12 * 24 * 60 * 60;
        use ic_nervous_system_common_test_keys::{
            TEST_NEURON_1_OWNER_PRINCIPAL, TEST_NEURON_2_OWNER_PRINCIPAL,
            TEST_NEURON_3_OWNER_PRINCIPAL,
        };
        let neuron_id = NeuronIdProto::from(self.new_neuron_id());
        let subaccount = self.make_subaccount().into();
        assert_eq!(
            self.proto.neurons.insert(
                neuron_id.id,
                Neuron {
                    id: Some(neuron_id),
                    controller: Some(*TEST_NEURON_1_OWNER_PRINCIPAL),
                    dissolve_state: Some(DissolveState::DissolveDelaySeconds(
                        TWELVE_MONTHS_SECONDS
                    )),
                    cached_neuron_stake_e8s: 1_000_000_000, /* invariant: part of
                                                             * TEST_NEURON_TOTAL_STAKE_E8S */
                    account: subaccount,
                    not_for_profit: true,
                    ..Default::default()
                }
            ),
            None,
            "There is more than one neuron with the same id."
        );
        let neuron_id = NeuronIdProto::from(self.new_neuron_id());
        let subaccount = self.make_subaccount().into();
        assert_eq!(
            self.proto.neurons.insert(
                neuron_id.id,
                Neuron {
                    id: Some(neuron_id),
                    controller: Some(*TEST_NEURON_2_OWNER_PRINCIPAL),
                    dissolve_state: Some(DissolveState::DissolveDelaySeconds(
                        TWELVE_MONTHS_SECONDS
                    )),
                    cached_neuron_stake_e8s: 100_000_000, /* invariant: part of
                                                           * TEST_NEURON_TOTAL_STAKE_E8S */
                    created_timestamp_seconds: 1,
                    aging_since_timestamp_seconds: 1,
                    account: subaccount,
                    not_for_profit: false,
                    ..Default::default()
                }
            ),
            None,
            "There is more than one neuron with the same id."
        );
        let neuron_id = NeuronIdProto::from(self.new_neuron_id());
        let subaccount = self.make_subaccount().into();
        assert_eq!(
            self.proto.neurons.insert(
                neuron_id.id,
                Neuron {
                    id: Some(neuron_id),
                    controller: Some(*TEST_NEURON_3_OWNER_PRINCIPAL),
                    dissolve_state: Some(DissolveState::DissolveDelaySeconds(
                        TWELVE_MONTHS_SECONDS
                    )),
                    cached_neuron_stake_e8s: 10_000_000, /* invariant: part of
                                                          * TEST_NEURON_TOTAL_STAKE_E8S */
                    created_timestamp_seconds: 10,
                    aging_since_timestamp_seconds: 10,
                    account: subaccount,
                    not_for_profit: false,
                    ..Default::default()
                }
            ),
            None,
            "There is more than one neuron with the same id."
        );
        self
    }

    /// Adds all the neurons from the specified CSV file.
    ///
    /// This obviously can only work when compiled to x86 so the wasm
    /// version doesn't include this method.
    ///
    /// An example is available at `rs/nns/governance/test/init.rs`.
    #[cfg(target_arch = "x86_64")]
    pub fn add_all_neurons_from_csv_file(&mut self, csv_file: &Path) -> &mut Self {
        use ic_nns_common::pb::v1::NeuronId as NeuronIdProto;

        use csv::ReaderBuilder;
        use std::str::FromStr;

        let mut reader = ReaderBuilder::new()
            .delimiter(b';')
            .from_path(csv_file)
            .unwrap_or_else(|_| panic!("error creating a csv reader at path: {:?}", csv_file));

        {
            let headers = reader.headers().expect("error reading CSV header row");
            let headers = headers
                .into_iter()
                .map(|f| f.parse::<String>().expect("couldn't read column header"))
                .collect::<Vec<String>>();

            if headers.len() == 7 {
                assert_eq!(
                    headers,
                    vec![
                        "neuron_id",
                        "owner_id",
                        "created_ts_ns",
                        "duration_to_dissolution_ns",
                        "staked_icpt",
                        "earnings",
                        "follows",
                    ]
                );
            } else {
                assert_eq!(
                    headers,
                    vec![
                        "neuron_id",
                        "owner_id",
                        "created_ts_ns",
                        "duration_to_dissolution_ns",
                        "staked_icpt",
                        "earnings",
                        "follows",
                        "not_for_profit"
                    ]
                );
            }
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
            let duration_to_dissolution_ns = record[3]
                .parse::<u64>()
                .expect("couldn't read the neuron's duration to dissolution time");
            let staked_icpt = record[4]
                .parse::<u64>()
                .expect("couldn't read the neuron's staked icpt amount");

            let followees: Vec<NeuronIdProto> = record[6]
                .split_terminator(',')
                .map(|x| NeuronIdProto {
                    id: x.parse::<u64>().expect("could not parse followee"),
                })
                .collect();
            if followees.len() > 1 {
                println!("followees of {:?} : {:?}", principal_id, followees)
            }

            let neuron_id = NeuronIdProto::from(neuron_id);

            let not_for_profit = if record.len() < 8 {
                false
            } else {
                record[7]
                    .parse::<bool>()
                    .expect("couldn't read the neuron's not-for-profit flag")
            };

            let neuron = Neuron {
                id: Some(neuron_id.clone()),
                account: self.make_subaccount().into(),
                controller: Some(principal_id),
                hot_keys: vec![principal_id],
                cached_neuron_stake_e8s: staked_icpt * 100_000_000, // to e8s
                created_timestamp_seconds: creation_ts_ns / (1_000_000_000), // to sec
                aging_since_timestamp_seconds: creation_ts_ns / (1_000_000_000), // to sec
                not_for_profit,
                dissolve_state: Some(DissolveState::DissolveDelaySeconds(
                    duration_to_dissolution_ns / (1_000_000_000),
                )), // to sec
                followees: [(Topic::Unspecified as i32, Followees { followees })]
                    .iter()
                    .cloned()
                    .collect(),
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
            let id = neuron.id.clone().expect("GTC neuron missing ID").id;
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
