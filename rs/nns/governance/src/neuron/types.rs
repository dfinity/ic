use crate::{
    neuron_store::NeuronStoreError,
    pb::v1::{
        abridged_neuron::DissolveState as AbridgedNeuronDissolveState,
        neuron::{DissolveState as NeuronDissolveState, Followees},
        AbridgedNeuron, BallotInfo, KnownNeuronData, Neuron as NeuronProto, NeuronStakeTransfer,
    },
};
use ic_base_types::PrincipalId;
use ic_nns_common::pb::v1::NeuronId;
use icp_ledger::Subaccount;
use std::collections::HashMap;

/// A neuron type internal to the governance crate. Currently, this type is identical to the
/// prost-generated Neuron type (except for derivations for prost). Gradually, this type will evolve
/// towards having all private fields while exposing methods for mutations, which allows it to hold
/// invariants.
#[derive(Clone, Debug, PartialEq)]
pub struct Neuron {
    /// The id of the neuron.
    id: NeuronId,
    /// The principal of the ICP ledger account where the locked ICP
    /// balance resides. This principal is indistinguishable from one
    /// identifying a public key pair, such that those browsing the ICP
    /// ledger cannot tell which balances belong to neurons.
    subaccount: Subaccount,
    /// The principal that actually controls the neuron. The principal
    /// must identify a public key pair, which acts as a “master key”,
    /// such that the corresponding secret key should be kept very
    /// secure. The principal may control many neurons.
    controller: PrincipalId,
    /// Keys that can be used to perform actions with limited privileges
    /// without exposing the secret key corresponding to the principal
    /// e.g. could be a WebAuthn key.
    pub hot_keys: Vec<PrincipalId>,
    /// The amount of staked ICP tokens, measured in fractions of 10E-8
    /// of an ICP.
    ///
    /// Cached record of the locked ICP balance on the ICP ledger.
    ///
    /// For neuron creation: has to contain some minimum amount. A
    /// spawned neuron with less stake cannot increase its dissolve
    /// delay.
    pub cached_neuron_stake_e8s: u64,
    /// The amount of ICP that this neuron has forfeited due to making
    /// proposals that were subsequently rejected or from using the
    /// 'manage neurons through proposals' functionality. Must be smaller
    /// than 'neuron_stake_e8s'. When a neuron is disbursed, these ICP
    /// will be burned.
    pub neuron_fees_e8s: u64,
    /// When the Neuron was created. A neuron can only vote on proposals
    /// submitted after its creation date.
    pub created_timestamp_seconds: u64,
    /// The timestamp, in seconds from the Unix epoch, corresponding to
    /// the time this neuron has started aging. This is either the
    /// creation time or the last time at which the neuron has stopped
    /// dissolving.
    ///
    /// This value is meaningless when the neuron is dissolving, since a
    /// dissolving neurons always has age zero. The canonical value of
    /// this field for a dissolving neuron is `u64::MAX`.
    pub aging_since_timestamp_seconds: u64,
    /// The timestamp, in seconds from the Unix epoch, at which this
    /// neuron should be spawned and its maturity converted to ICP
    /// according to <https://wiki.internetcomputer.org/wiki/Maturity_modulation.>
    pub spawn_at_timestamp_seconds: Option<u64>,
    /// Map `Topic` to followees. The key is represented by an integer as
    /// Protobuf does not support enum keys in maps.
    pub followees: HashMap<i32, Followees>,
    /// Information about how this neuron voted in the recent past. It
    /// only contains proposals that the neuron voted yes or no on.
    pub recent_ballots: Vec<BallotInfo>,
    /// `true` if this neuron has passed KYC, `false` otherwise
    pub kyc_verified: bool,
    /// The record of the transfer that was made to create this neuron.
    pub transfer: Option<NeuronStakeTransfer>,
    /// The accumulated unstaked maturity of the neuron, in "e8s equivalent".
    ///
    /// The unit is "e8s equivalent" to insist that, while this quantity is on
    /// the same scale as ICPs, maturity is not directly convertible to ICPs:
    /// conversion requires a minting event and the conversion rate is variable.
    pub maturity_e8s_equivalent: u64,
    /// The accumulated staked maturity of the neuron, in "e8s equivalent" (see
    /// "maturity_e8s_equivalent"). Staked maturity becomes regular maturity once
    /// the neuron is dissolved.
    ///
    /// Contrary to `maturity_e8s_equivalent` this maturity is staked and thus
    /// locked until the neuron is dissolved and contributes to voting power
    /// and rewards. Once the neuron is dissolved, this maturity will be "moved"
    /// to 'maturity_e8s_equivalent' and will be able to be spawned (with maturity
    /// modulation).
    pub staked_maturity_e8s_equivalent: Option<u64>,
    /// If set and true the maturity rewarded to this neuron for voting will be
    /// automatically staked and will contribute to the neuron's voting power.
    pub auto_stake_maturity: Option<bool>,
    /// Whether this neuron is "Not for profit", making it dissolvable
    /// by voting.
    pub not_for_profit: bool,
    /// If set, this neuron is a member of the Community Fund. This means that when
    /// a proposal to open an SNS token swap is executed, maturity from this neuron
    /// will be used to participate in the SNS token swap.
    pub joined_community_fund_timestamp_seconds: Option<u64>,
    /// If set, the neuron belongs to the "known neurons". It has been given a name and maybe a description.
    pub known_neuron_data: Option<KnownNeuronData>,
    /// The type of the Neuron. See \[NeuronType\] for a description
    /// of the different states.
    pub neuron_type: Option<i32>,
    /// At any time, at most one of `when_dissolved` and
    /// `dissolve_delay` are specified.
    ///
    /// `NotDissolving`. This is represented by `dissolve_delay` being
    /// set to a non zero value.
    ///
    /// `Dissolving`. This is represented by `when_dissolved` being
    /// set, and this value is in the future.
    ///
    /// `Dissolved`. All other states represent the dissolved
    /// state. That is, (a) `when_dissolved` is set and in the past,
    /// (b) `dissolve_delay` is set to zero, (c) neither value is set.
    ///
    /// Cf. \[Neuron::stop_dissolving\] and \[Neuron::start_dissolving\].
    pub dissolve_state: Option<NeuronDissolveState>,
}

impl Neuron {
    /// Returns the neuron's ID.
    pub fn id(&self) -> NeuronId {
        self.id
    }

    /// Returns the subaccount of the neuron.
    pub fn subaccount(&self) -> Subaccount {
        self.subaccount
    }

    /// Returns the principal that controls the neuron.
    pub fn controller(&self) -> PrincipalId {
        self.controller
    }

    /// Replace the controller of the neuron. Only GTC neurons can change their controller.
    pub fn set_controller(&mut self, new_controller: PrincipalId) {
        self.controller = new_controller;
    }
}

impl From<Neuron> for NeuronProto {
    fn from(neuron: Neuron) -> Self {
        NeuronProto {
            id: Some(neuron.id),
            account: neuron.subaccount.to_vec(),
            controller: Some(neuron.controller),
            hot_keys: neuron.hot_keys,
            cached_neuron_stake_e8s: neuron.cached_neuron_stake_e8s,
            neuron_fees_e8s: neuron.neuron_fees_e8s,
            created_timestamp_seconds: neuron.created_timestamp_seconds,
            aging_since_timestamp_seconds: neuron.aging_since_timestamp_seconds,
            spawn_at_timestamp_seconds: neuron.spawn_at_timestamp_seconds,
            followees: neuron.followees,
            recent_ballots: neuron.recent_ballots,
            kyc_verified: neuron.kyc_verified,
            transfer: neuron.transfer,
            maturity_e8s_equivalent: neuron.maturity_e8s_equivalent,
            staked_maturity_e8s_equivalent: neuron.staked_maturity_e8s_equivalent,
            auto_stake_maturity: neuron.auto_stake_maturity,
            not_for_profit: neuron.not_for_profit,
            joined_community_fund_timestamp_seconds: neuron.joined_community_fund_timestamp_seconds,
            known_neuron_data: neuron.known_neuron_data,
            neuron_type: neuron.neuron_type,
            dissolve_state: neuron.dissolve_state,
        }
    }
}

impl TryFrom<NeuronProto> for Neuron {
    type Error = String;

    fn try_from(proto: NeuronProto) -> Result<Self, Self::Error> {
        let id = proto.id.ok_or("Neuron ID is missing")?;

        Ok(Neuron {
            id,
            subaccount: Subaccount::try_from(proto.account.as_slice())
                .map_err(|_| "Invalid subaccount".to_string())?,
            controller: proto
                .controller
                .ok_or(format!("Controller is missing for neuron {}", id.id))?,
            hot_keys: proto.hot_keys,
            cached_neuron_stake_e8s: proto.cached_neuron_stake_e8s,
            neuron_fees_e8s: proto.neuron_fees_e8s,
            created_timestamp_seconds: proto.created_timestamp_seconds,
            aging_since_timestamp_seconds: proto.aging_since_timestamp_seconds,
            spawn_at_timestamp_seconds: proto.spawn_at_timestamp_seconds,
            followees: proto.followees,
            recent_ballots: proto.recent_ballots,
            kyc_verified: proto.kyc_verified,
            transfer: proto.transfer,
            maturity_e8s_equivalent: proto.maturity_e8s_equivalent,
            staked_maturity_e8s_equivalent: proto.staked_maturity_e8s_equivalent,
            auto_stake_maturity: proto.auto_stake_maturity,
            not_for_profit: proto.not_for_profit,
            joined_community_fund_timestamp_seconds: proto.joined_community_fund_timestamp_seconds,
            known_neuron_data: proto.known_neuron_data,
            neuron_type: proto.neuron_type,
            dissolve_state: proto.dissolve_state,
        })
    }
}

impl From<AbridgedNeuronDissolveState> for NeuronDissolveState {
    fn from(source: AbridgedNeuronDissolveState) -> Self {
        use AbridgedNeuronDissolveState as S;
        use NeuronDissolveState as D;
        match source {
            S::WhenDissolvedTimestampSeconds(timestamp) => {
                D::WhenDissolvedTimestampSeconds(timestamp)
            }
            S::DissolveDelaySeconds(delay) => D::DissolveDelaySeconds(delay),
        }
    }
}

impl From<NeuronDissolveState> for AbridgedNeuronDissolveState {
    fn from(source: NeuronDissolveState) -> Self {
        use AbridgedNeuronDissolveState as D;
        use NeuronDissolveState as S;
        match source {
            S::WhenDissolvedTimestampSeconds(timestamp) => {
                D::WhenDissolvedTimestampSeconds(timestamp)
            }
            S::DissolveDelaySeconds(delay) => D::DissolveDelaySeconds(delay),
        }
    }
}

/// Breaks out "fat" fields from a Neuron. This is equivalent to `NeuronProto` but for stable
/// storage.
///
/// Used like so:
///
///     let DecomposedNeuron {
///         main: abridged_neuron,
///
///         hot_keys,
///         recent_ballots,
///         followees,
///
///         known_neuron_data,
///         transfer,
///     } = DecomposedNeuron::from(full_neuron);
///
/// Of course, a similar effect can be achieved "manually" by calling std::mem::take on each of the
/// auxiliary fields, but that is error prone, because it is very easy to forget to take one of the
/// auxiliary fields. By sticking to this, such mistakes can be avoided.
///
/// Notice that full_neuron in the above example gets consumed. It is "replaced" with
/// abridged_neuron.
pub struct DecomposedNeuron {
    pub id: NeuronId,
    pub main: AbridgedNeuron,

    // Collections
    pub hot_keys: Vec<PrincipalId>,
    pub recent_ballots: Vec<BallotInfo>,
    pub followees: HashMap</* topic ID */ i32, Followees>,

    // Singletons
    pub known_neuron_data: Option<KnownNeuronData>,
    pub transfer: Option<NeuronStakeTransfer>,
}

impl TryFrom<Neuron> for DecomposedNeuron {
    type Error = NeuronStoreError;

    fn try_from(source: Neuron) -> Result<Self, NeuronStoreError> {
        let Neuron {
            id,
            subaccount,
            controller,
            hot_keys,
            cached_neuron_stake_e8s,
            neuron_fees_e8s,
            created_timestamp_seconds,
            aging_since_timestamp_seconds,
            spawn_at_timestamp_seconds,
            followees,
            recent_ballots,
            kyc_verified,
            transfer,
            maturity_e8s_equivalent,
            staked_maturity_e8s_equivalent,
            auto_stake_maturity,
            not_for_profit,
            joined_community_fund_timestamp_seconds,
            known_neuron_data,
            neuron_type,
            dissolve_state,
        } = source;

        let main = AbridgedNeuron {
            account: subaccount.to_vec(),
            controller: Some(controller),
            cached_neuron_stake_e8s,
            neuron_fees_e8s,
            created_timestamp_seconds,
            aging_since_timestamp_seconds,
            spawn_at_timestamp_seconds,
            kyc_verified,
            maturity_e8s_equivalent,
            staked_maturity_e8s_equivalent,
            auto_stake_maturity,
            not_for_profit,
            joined_community_fund_timestamp_seconds,
            neuron_type,
            dissolve_state: dissolve_state.map(AbridgedNeuronDissolveState::from),
        };

        Ok(Self {
            id,
            main,

            // Collections
            hot_keys,
            recent_ballots,
            followees,

            // Singletons
            known_neuron_data,
            transfer,
        })
    }
}

impl From<DecomposedNeuron> for Neuron {
    fn from(source: DecomposedNeuron) -> Self {
        let DecomposedNeuron {
            id,
            main,

            hot_keys,
            recent_ballots,
            followees,

            known_neuron_data,
            transfer,
        } = source;

        let AbridgedNeuron {
            account,
            controller,
            cached_neuron_stake_e8s,
            neuron_fees_e8s,
            created_timestamp_seconds,
            aging_since_timestamp_seconds,
            spawn_at_timestamp_seconds,
            kyc_verified,
            maturity_e8s_equivalent,
            staked_maturity_e8s_equivalent,
            auto_stake_maturity,
            not_for_profit,
            joined_community_fund_timestamp_seconds,
            neuron_type,
            dissolve_state,
        } = main;

        Neuron {
            id,
            subaccount: Subaccount::try_from(account.as_slice()).unwrap(),
            controller: controller.unwrap(),
            hot_keys,
            cached_neuron_stake_e8s,
            neuron_fees_e8s,
            created_timestamp_seconds,
            aging_since_timestamp_seconds,
            spawn_at_timestamp_seconds,
            followees,
            recent_ballots,
            kyc_verified,
            transfer,
            maturity_e8s_equivalent,
            staked_maturity_e8s_equivalent,
            auto_stake_maturity,
            not_for_profit,
            joined_community_fund_timestamp_seconds,
            known_neuron_data,
            neuron_type,
            dissolve_state: dissolve_state.map(NeuronDissolveState::from),
        }
    }
}

/// Builder of a neuron before it gets added into NeuronStore. This allows us to construct a neuron
/// with private fields. Only fields that are possible to be set at creation time are defined in the
/// builder.
#[derive(Clone, Debug, PartialEq)]
pub struct NeuronBuilder {
    // Required fields.
    id: NeuronId,
    subaccount: Subaccount,
    controller: PrincipalId,
    dissolve_state_and_age: DissolveStateAndAge,
    created_timestamp_seconds: u64,

    // Optional fields with reasonable defaults.
    cached_neuron_stake_e8s: u64,
    hot_keys: Vec<PrincipalId>,
    spawn_at_timestamp_seconds: Option<u64>,
    followees: HashMap<i32, Followees>,
    kyc_verified: bool,
    maturity_e8s_equivalent: u64,
    auto_stake_maturity: bool,
    not_for_profit: bool,
    joined_community_fund_timestamp_seconds: Option<u64>,
    neuron_type: Option<i32>,

    // Fields that don't exist when a neuron is first built. We allow them to be set in tests.
    #[cfg(test)]
    neuron_fees_e8s: u64,
    #[cfg(test)]
    recent_ballots: Vec<BallotInfo>,
    #[cfg(test)]
    transfer: Option<NeuronStakeTransfer>,
    #[cfg(test)]
    staked_maturity_e8s_equivalent: Option<u64>,
    #[cfg(test)]
    known_neuron_data: Option<KnownNeuronData>,
}

impl NeuronBuilder {
    pub fn new(
        id: NeuronId,
        subaccount: Subaccount,
        controller: PrincipalId,
        dissolve_state_and_age: DissolveStateAndAge,
        created_timestamp_seconds: u64,
    ) -> Self {
        NeuronBuilder {
            id,
            subaccount,
            controller,
            dissolve_state_and_age,
            created_timestamp_seconds,

            cached_neuron_stake_e8s: 0,
            hot_keys: Vec::new(),
            spawn_at_timestamp_seconds: None,
            followees: HashMap::new(),
            kyc_verified: false,
            maturity_e8s_equivalent: 0,
            auto_stake_maturity: false,
            not_for_profit: false,
            joined_community_fund_timestamp_seconds: None,
            neuron_type: None,

            #[cfg(test)]
            neuron_fees_e8s: 0,
            #[cfg(test)]
            recent_ballots: Vec::new(),
            #[cfg(test)]
            transfer: None,
            #[cfg(test)]
            staked_maturity_e8s_equivalent: None,
            #[cfg(test)]
            known_neuron_data: None,
        }
    }

    #[cfg(test)]
    pub fn with_subaccount(mut self, subaccount: Subaccount) -> Self {
        self.subaccount = subaccount;
        self
    }

    #[cfg(test)]
    pub fn with_controller(mut self, controller: PrincipalId) -> Self {
        self.controller = controller;
        self
    }

    #[cfg(test)]
    pub fn with_dissolve_state_and_age(
        mut self,
        dissolve_state_and_age: DissolveStateAndAge,
    ) -> Self {
        self.dissolve_state_and_age = dissolve_state_and_age;
        self
    }

    pub fn with_cached_neuron_stake_e8s(mut self, cached_neuron_stake_e8s: u64) -> Self {
        self.cached_neuron_stake_e8s = cached_neuron_stake_e8s;
        self
    }

    pub fn with_hot_keys(mut self, hot_keys: Vec<PrincipalId>) -> Self {
        self.hot_keys = hot_keys;
        self
    }

    pub fn with_spawn_at_timestamp_seconds(mut self, spawn_at_timestamp_seconds: u64) -> Self {
        self.spawn_at_timestamp_seconds = Some(spawn_at_timestamp_seconds);
        self
    }

    pub fn with_followees(mut self, followees: HashMap<i32, Followees>) -> Self {
        self.followees = followees;
        self
    }

    pub fn with_kyc_verified(mut self, kyc_verified: bool) -> Self {
        self.kyc_verified = kyc_verified;
        self
    }

    pub fn with_maturity_e8s_equivalent(mut self, maturity_e8s_equivalent: u64) -> Self {
        self.maturity_e8s_equivalent = maturity_e8s_equivalent;
        self
    }

    pub fn with_auto_stake_maturity(mut self, auto_stake_maturity: bool) -> Self {
        self.auto_stake_maturity = auto_stake_maturity;
        self
    }

    pub fn with_not_for_profit(mut self, not_for_profit: bool) -> Self {
        self.not_for_profit = not_for_profit;
        self
    }

    pub fn with_joined_community_fund_timestamp_seconds(
        mut self,
        joined_community_fund_timestamp_seconds: Option<u64>,
    ) -> Self {
        self.joined_community_fund_timestamp_seconds = joined_community_fund_timestamp_seconds;
        self
    }

    pub fn with_neuron_type(mut self, neuron_type: Option<i32>) -> Self {
        self.neuron_type = neuron_type;
        self
    }

    #[cfg(test)]
    pub fn with_neuron_fees_e8s(mut self, neuron_fees_e8s: u64) -> Self {
        self.neuron_fees_e8s = neuron_fees_e8s;
        self
    }

    #[cfg(test)]
    pub fn with_recent_ballots(mut self, recent_ballots: Vec<BallotInfo>) -> Self {
        self.recent_ballots = recent_ballots;
        self
    }

    #[cfg(test)]
    pub fn with_transfer(mut self, transfer: Option<NeuronStakeTransfer>) -> Self {
        self.transfer = transfer;
        self
    }

    #[cfg(test)]
    pub fn with_staked_maturity_e8s_equivalent(
        mut self,
        staked_maturity_e8s_equivalent: u64,
    ) -> Self {
        self.staked_maturity_e8s_equivalent = Some(staked_maturity_e8s_equivalent);
        self
    }

    #[cfg(test)]
    pub fn with_known_neuron_data(mut self, known_neuron_data: Option<KnownNeuronData>) -> Self {
        self.known_neuron_data = known_neuron_data;
        self
    }

    pub fn build(self) -> Neuron {
        let NeuronBuilder {
            id,
            subaccount,
            controller,
            hot_keys,
            cached_neuron_stake_e8s,
            created_timestamp_seconds,
            dissolve_state_and_age,
            spawn_at_timestamp_seconds,
            followees,
            kyc_verified,
            maturity_e8s_equivalent,
            auto_stake_maturity,
            not_for_profit,
            joined_community_fund_timestamp_seconds,
            neuron_type,
            #[cfg(test)]
            neuron_fees_e8s,
            #[cfg(test)]
            recent_ballots,
            #[cfg(test)]
            transfer,
            #[cfg(test)]
            staked_maturity_e8s_equivalent,
            #[cfg(test)]
            known_neuron_data,
        } = self;

        let StoredDissolvedStateAndAge {
            dissolve_state,
            aging_since_timestamp_seconds,
        } = StoredDissolvedStateAndAge::from(dissolve_state_and_age);
        let auto_stake_maturity = if auto_stake_maturity {
            Some(true)
        } else {
            None
        };

        // The below fields are always the default values for a new neuron.
        #[cfg(not(test))]
        let neuron_fees_e8s = 0;
        #[cfg(not(test))]
        let recent_ballots = Vec::new();
        #[cfg(not(test))]
        let transfer = None;
        #[cfg(not(test))]
        let staked_maturity_e8s_equivalent = None;
        #[cfg(not(test))]
        let known_neuron_data = None;

        Neuron {
            id,
            subaccount,
            controller,
            hot_keys,
            cached_neuron_stake_e8s,
            neuron_fees_e8s,
            created_timestamp_seconds,
            aging_since_timestamp_seconds,
            spawn_at_timestamp_seconds,
            followees,
            recent_ballots,
            kyc_verified,
            transfer,
            maturity_e8s_equivalent,
            staked_maturity_e8s_equivalent,
            auto_stake_maturity,
            not_for_profit,
            joined_community_fund_timestamp_seconds,
            known_neuron_data,
            neuron_type,
            dissolve_state,
        }
    }
}

/// An enum to represent different combinations of a neurons dissolve_state and
/// aging_since_timestamp_seconds. Currently, the back-and-forth conversions should make sure the
/// legacy states remain the same unless some operations performed on the neuron makes the state/age
/// changes. After we make sure all neuron mutations or creations must mutate states to valid ones
/// and the invalid states have been migrated to valid ones on the mainnet, we can panic in
/// conversion when invalid states are encountered. 2 of the legacy states
/// (LegacyDissolvingOrDissolved and LegacyDissolved) are the cases we already know to be existing
/// on the mainnet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DissolveStateAndAge {
    /// A non-dissolving neuron has a dissolve delay and an aging since timestamp.
    NotDissolving {
        dissolve_delay_seconds: u64,
        aging_since_timestamp_seconds: u64,
    },
    /// A dissolving or dissolved neuron has a dissolved timestamp and no aging since timestamp.
    DissolvingOrDissolved {
        when_dissolved_timestamp_seconds: u64,
    },
    /// We used to allow neurons to have age when they were dissolving or dissolved. This should be
    /// mapped to DissolvingOrDissolved { when_dissolved_timestamp_seconds } and its aging singe
    /// timestamp removed.
    LegacyDissolvingOrDissolved {
        when_dissolved_timestamp_seconds: u64,
        aging_since_timestamp_seconds: u64,
    },
    /// When claiming a neuron, the dissolve delay is set to 0 while the neuron is considered
    /// dissolved. Its aging_since_timestamp_seconds is set to the neuron was claimed. This state
    /// should be mapped to DissolvingOrDissolved { when_dissolved_timestamp_seconds:
    /// aging_since_timestamp_seconds }.
    LegacyDissolved { aging_since_timestamp_seconds: u64 },

    /// The dissolve state is None, which should have never existed, but we keep the current
    /// behavior of considering it as a dissolved neuron.
    LegacyNoneDissolveState { aging_since_timestamp_seconds: u64 },
}

/// An intermediate struct to represent a neuron's dissolve state and age on the storage layer.
#[derive(Clone, Debug, PartialEq)]
pub(super) struct StoredDissolvedStateAndAge {
    pub dissolve_state: Option<NeuronDissolveState>,
    pub aging_since_timestamp_seconds: u64,
}

impl From<DissolveStateAndAge> for StoredDissolvedStateAndAge {
    fn from(dissolve_state_and_age: DissolveStateAndAge) -> Self {
        match dissolve_state_and_age {
            DissolveStateAndAge::NotDissolving {
                dissolve_delay_seconds,
                aging_since_timestamp_seconds,
            } => StoredDissolvedStateAndAge {
                dissolve_state: Some(NeuronDissolveState::DissolveDelaySeconds(
                    dissolve_delay_seconds,
                )),
                aging_since_timestamp_seconds,
            },
            DissolveStateAndAge::DissolvingOrDissolved {
                when_dissolved_timestamp_seconds,
            } => StoredDissolvedStateAndAge {
                dissolve_state: Some(NeuronDissolveState::WhenDissolvedTimestampSeconds(
                    when_dissolved_timestamp_seconds,
                )),
                aging_since_timestamp_seconds: u64::MAX,
            },
            DissolveStateAndAge::LegacyDissolvingOrDissolved {
                when_dissolved_timestamp_seconds,
                aging_since_timestamp_seconds,
            } => StoredDissolvedStateAndAge {
                dissolve_state: Some(NeuronDissolveState::WhenDissolvedTimestampSeconds(
                    when_dissolved_timestamp_seconds,
                )),
                aging_since_timestamp_seconds,
            },
            DissolveStateAndAge::LegacyDissolved {
                aging_since_timestamp_seconds,
            } => StoredDissolvedStateAndAge {
                dissolve_state: Some(NeuronDissolveState::DissolveDelaySeconds(0)),
                aging_since_timestamp_seconds,
            },
            DissolveStateAndAge::LegacyNoneDissolveState {
                aging_since_timestamp_seconds,
            } => StoredDissolvedStateAndAge {
                dissolve_state: None,
                aging_since_timestamp_seconds,
            },
        }
    }
}

impl From<StoredDissolvedStateAndAge> for DissolveStateAndAge {
    fn from(stored: StoredDissolvedStateAndAge) -> Self {
        match (stored.dissolve_state, stored.aging_since_timestamp_seconds) {
            (None, aging_since_timestamp_seconds) => DissolveStateAndAge::LegacyNoneDissolveState {
                aging_since_timestamp_seconds,
            },
            (Some(NeuronDissolveState::DissolveDelaySeconds(0)), aging_since_timestamp_seconds) => {
                DissolveStateAndAge::LegacyDissolved {
                    aging_since_timestamp_seconds,
                }
            }
            (
                Some(NeuronDissolveState::DissolveDelaySeconds(dissolve_delay_seconds)),
                // TODO(NNS1-2951): have a stricter guarantee about the aging_since_timestamp_seconds.
                aging_since_timestamp_seconds,
            ) => DissolveStateAndAge::NotDissolving {
                dissolve_delay_seconds,
                aging_since_timestamp_seconds,
            },
            (
                Some(NeuronDissolveState::WhenDissolvedTimestampSeconds(
                    when_dissolved_timestamp_seconds,
                )),
                u64::MAX,
            ) => DissolveStateAndAge::DissolvingOrDissolved {
                when_dissolved_timestamp_seconds,
            },
            (
                Some(NeuronDissolveState::WhenDissolvedTimestampSeconds(
                    when_dissolved_timestamp_seconds,
                )),
                aging_since_timestamp_seconds,
            ) => DissolveStateAndAge::LegacyDissolvingOrDissolved {
                when_dissolved_timestamp_seconds,
                aging_since_timestamp_seconds,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use ic_stable_structures::Storable;
    use prost::Message;

    #[test]
    fn test_dissolve_state_and_age_conversion() {
        let test_cases = vec![
            (
                DissolveStateAndAge::NotDissolving {
                    dissolve_delay_seconds: 100,
                    aging_since_timestamp_seconds: 200,
                },
                StoredDissolvedStateAndAge {
                    dissolve_state: Some(NeuronDissolveState::DissolveDelaySeconds(100)),
                    aging_since_timestamp_seconds: 200,
                },
            ),
            // TODO(NNS1-2951): have a more strict guarantee about the
            // aging_since_timestamp_seconds. This case is theoretically possible, while we should
            // never have such a neuron. The aging_since_timestamp_seconds should be in the past.
            (
                DissolveStateAndAge::NotDissolving {
                    dissolve_delay_seconds: 100,
                    aging_since_timestamp_seconds: u64::MAX,
                },
                StoredDissolvedStateAndAge {
                    dissolve_state: Some(NeuronDissolveState::DissolveDelaySeconds(100)),
                    aging_since_timestamp_seconds: u64::MAX,
                },
            ),
            (
                DissolveStateAndAge::DissolvingOrDissolved {
                    when_dissolved_timestamp_seconds: 300,
                },
                StoredDissolvedStateAndAge {
                    dissolve_state: Some(NeuronDissolveState::WhenDissolvedTimestampSeconds(300)),
                    aging_since_timestamp_seconds: u64::MAX,
                },
            ),
            (
                DissolveStateAndAge::LegacyDissolvingOrDissolved {
                    when_dissolved_timestamp_seconds: 400,
                    aging_since_timestamp_seconds: 500,
                },
                StoredDissolvedStateAndAge {
                    dissolve_state: Some(NeuronDissolveState::WhenDissolvedTimestampSeconds(400)),
                    aging_since_timestamp_seconds: 500,
                },
            ),
            (
                DissolveStateAndAge::LegacyDissolved {
                    aging_since_timestamp_seconds: 600,
                },
                StoredDissolvedStateAndAge {
                    dissolve_state: Some(NeuronDissolveState::DissolveDelaySeconds(0)),
                    aging_since_timestamp_seconds: 600,
                },
            ),
            (
                DissolveStateAndAge::LegacyNoneDissolveState {
                    aging_since_timestamp_seconds: 700,
                },
                StoredDissolvedStateAndAge {
                    dissolve_state: None,
                    aging_since_timestamp_seconds: 700,
                },
            ),
        ];

        for (dissolve_state_and_age, stored_dissolved_state_and_age) in test_cases {
            assert_eq!(
                StoredDissolvedStateAndAge::from(dissolve_state_and_age.clone()),
                stored_dissolved_state_and_age.clone()
            );
            assert_eq!(
                DissolveStateAndAge::from(stored_dissolved_state_and_age),
                dissolve_state_and_age
            );
        }
    }

    #[test]
    fn test_abridged_neuron_size() {
        // All VARINT encoded fields (e.g. int32, uint64, ..., as opposed to fixed32/fixed64) have
        // larger serialized size for larger numbers (10 bytes for u64::MAX as uint64, while 1 byte for
        // 0u64). Therefore, we make the numbers below as large as possible even though they aren't
        // realistic.
        let abridged_neuron = AbridgedNeuron {
            account: vec![u8::MAX; 32],
            controller: Some(PrincipalId::new(
                PrincipalId::MAX_LENGTH_IN_BYTES,
                [u8::MAX; PrincipalId::MAX_LENGTH_IN_BYTES],
            )),
            cached_neuron_stake_e8s: u64::MAX,
            neuron_fees_e8s: u64::MAX,
            created_timestamp_seconds: u64::MAX,
            aging_since_timestamp_seconds: u64::MAX,
            spawn_at_timestamp_seconds: Some(u64::MAX),
            kyc_verified: true,
            maturity_e8s_equivalent: u64::MAX,
            staked_maturity_e8s_equivalent: Some(u64::MAX),
            auto_stake_maturity: Some(true),
            not_for_profit: true,
            joined_community_fund_timestamp_seconds: Some(u64::MAX),
            neuron_type: Some(i32::MAX),
            dissolve_state: Some(AbridgedNeuronDissolveState::WhenDissolvedTimestampSeconds(
                u64::MAX,
            )),
        };

        assert!(abridged_neuron.encoded_len() as u32 <= AbridgedNeuron::BOUND.max_size());
        // This size can be updated. This assertion is created so that we are aware of the available
        // headroom.
        assert_eq!(abridged_neuron.encoded_len(), 184);
    }
}
