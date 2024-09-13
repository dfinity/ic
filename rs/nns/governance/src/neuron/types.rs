use crate::{
    governance::{
        LOG_PREFIX, MAX_DISSOLVE_DELAY_SECONDS, MAX_NEURON_AGE_FOR_AGE_BONUS,
        MAX_NEURON_RECENT_BALLOTS, MAX_NUM_HOT_KEYS_PER_NEURON,
    },
    is_private_neuron_enforcement_enabled,
    neuron::{combine_aged_stakes, dissolve_state_and_age::DissolveStateAndAge, neuron_stake_e8s},
    neuron_store::NeuronStoreError,
    pb::v1::{
        abridged_neuron::DissolveState as AbridgedNeuronDissolveState,
        governance_error::ErrorType,
        manage_neuron::{configure::Operation, Configure},
        neuron::{DissolveState as NeuronDissolveState, Followees},
        AbridgedNeuron, Ballot, BallotInfo, GovernanceError, KnownNeuronData,
        Neuron as NeuronProto, NeuronInfo, NeuronStakeTransfer, NeuronState, NeuronType, Topic,
        Visibility, Vote,
    },
};
#[cfg(target_arch = "wasm32")]
use dfn_core::println;
use ic_base_types::PrincipalId;
use ic_nervous_system_common::ONE_DAY_SECONDS;
use ic_nns_common::pb::v1::{NeuronId, ProposalId};
use icp_ledger::Subaccount;
use std::collections::{BTreeSet, HashMap};

/// A neuron type internal to the governance crate. Currently, this type is identical to the
/// prost-generated Neuron type (except for derivations for prost). Gradually, this type will evolve
/// towards having all private fields while exposing methods for mutations, which allows it to hold
/// invariants.
#[derive(Clone, PartialEq, Debug)]
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
    /// The dissolve state and age of the neuron.
    dissolve_state_and_age: DissolveStateAndAge,
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
    /// How much unprivileged principals (i.e. is neither controller, nor
    /// hotkey) can see about this neuron.
    visibility: Option<Visibility>,
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

    /// Returns an enum representing the dissolve state and age of a neuron.
    pub fn dissolve_state_and_age(&self) -> DissolveStateAndAge {
        self.dissolve_state_and_age
    }

    /// When we turn on enforcement of private neurons, this will only return
    /// Public or Private, not None. When that happens, we should define another
    /// Visibility that does NOT have Unspecified.
    pub fn visibility(&self) -> Option<Visibility> {
        if self.known_neuron_data.is_some() {
            return Some(Visibility::Public);
        }

        self.visibility
    }

    /// Sets a neuron's dissolve state and age.
    pub fn set_dissolve_state_and_age(&mut self, dissolve_state_and_age: DissolveStateAndAge) {
        self.dissolve_state_and_age = dissolve_state_and_age;
    }

    // --- Utility methods on neurons: mostly not for public consumption.

    /// Returns the state the neuron would be in a time
    /// `now_seconds`. See [NeuronState] for details.
    pub fn state(&self, now_seconds: u64) -> NeuronState {
        if self.spawn_at_timestamp_seconds.is_some() {
            return NeuronState::Spawning;
        }
        self.dissolve_state_and_age().current_state(now_seconds)
    }

    /// Returns true if and only if `principal` is equal to the
    /// controller of this neuron.
    pub(crate) fn is_controlled_by(&self, principal: &PrincipalId) -> bool {
        self.controller() == *principal
    }

    /// Returns true if and only if `principal` is authorized to
    /// perform non-privileged operations, like vote and follow,
    /// on behalf of this neuron, i.e., if `principal` is either the
    /// controller or one of the authorized hot keys.
    pub(crate) fn is_authorized_to_vote(&self, principal: &PrincipalId) -> bool {
        self.is_hotkey_or_controller(principal)
    }

    /// Returns true if and only if `principal` is authorized to
    /// call simulate_manage_neuron requests on this neuron
    pub(crate) fn is_authorized_to_simulate_manage_neuron(&self, principal: &PrincipalId) -> bool {
        self.is_hotkey_or_controller(principal)
    }

    /// Returns true if and only if `principal` is either the controller or a hotkey
    fn is_hotkey_or_controller(&self, principal: &PrincipalId) -> bool {
        self.is_controlled_by(principal) || self.hot_keys.contains(principal)
    }

    // Returns all principal ids with special permissions..
    pub fn principal_ids_with_special_permissions(&self) -> Vec<PrincipalId> {
        let mut principal_ids: Vec<_> = self.hot_keys.clone();
        principal_ids.push(self.controller());
        // The number of entries is bounded so Vec->HashSet->Vec won't have a clear advantage. Also,
        // although the order isn't needed by this method and expected use cases, having a stable
        // ordering (instead of being determined by hash) is usually good for debugging.
        principal_ids.sort();
        principal_ids.dedup();
        principal_ids
    }

    pub fn topic_followee_pairs(&self) -> BTreeSet<(Topic, NeuronId)> {
        self.followees
            .iter()
            .filter_map(|(topic, followees)| {
                let topic = match Topic::try_from(*topic).ok() {
                    Some(topic) => topic,
                    None => {
                        println!(
                            "{} Invalid topic {:?} in neuron {:?}",
                            LOG_PREFIX,
                            topic,
                            self.id()
                        );
                        return None;
                    }
                };
                Some((topic, followees))
            })
            .flat_map(|(topic, followees)| {
                followees
                    .followees
                    .iter()
                    .map(move |followee| (topic, *followee))
            })
            .collect()
    }

    /// Returns whether self is a member of Neurons Fund.
    pub(crate) fn is_a_neurons_fund_member(&self) -> bool {
        self.joined_community_fund_timestamp_seconds
            .unwrap_or_default()
            > 0
    }

    /// Return the voting power of this neuron.
    ///
    /// The voting power is the stake of the neuron modified by a
    /// bonus of up to 100% depending on the dissolve delay, with
    /// the maximum bonus of 100% received at an 8 year dissolve
    /// delay. The voting power is further modified by the age of
    /// the neuron giving up to 25% bonus after four years.
    pub fn voting_power(&self, now_seconds: u64) -> u64 {
        // We compute the stake adjustments in u128.
        let stake = self.stake_e8s() as u128;
        // Dissolve delay is capped to eight years, but we cap it
        // again here to make sure, e.g., if this changes in the
        // future.
        let d = std::cmp::min(
            self.dissolve_delay_seconds(now_seconds),
            MAX_DISSOLVE_DELAY_SECONDS,
        ) as u128;
        // 'd_stake' is the stake with bonus for dissolve delay.
        let d_stake = stake + ((stake * d) / (MAX_DISSOLVE_DELAY_SECONDS as u128));
        // Sanity check.
        assert!(d_stake <= 2 * stake);
        // The voting power is also a function of the age of the
        // neuron, giving a bonus of up to 25% at the four year mark.
        let a = std::cmp::min(self.age_seconds(now_seconds), MAX_NEURON_AGE_FOR_AGE_BONUS) as u128;
        let ad_stake = d_stake + ((d_stake * a) / (4 * MAX_NEURON_AGE_FOR_AGE_BONUS as u128));
        // Final stake 'ad_stake' is at most 5/4 of the 'd_stake'.
        assert!(ad_stake <= (5 * d_stake) / 4);
        // The final voting power is the stake adjusted by both age
        // and dissolve delay. If the stake is is greater than
        // u64::MAX divided by 2.5, the voting power may actually not
        // fit in a u64.
        std::cmp::min(ad_stake, u64::MAX as u128) as u64
    }

    /// Given the specified `ballots`: determine how this neuron would
    /// vote on a proposal of `topic` based on which neurons this
    /// neuron follows on this topic (or on the default topic if this
    /// neuron doesn't specify any followees for `topic`).
    pub(crate) fn would_follow_ballots(
        &self,
        topic: Topic,
        ballots: &HashMap<u64, Ballot>,
    ) -> Vote {
        // Compute the list of followees for this topic. If no
        // following is specified for the topic, use the followees
        // from the 'Unspecified' topic.
        if let Some(followees) = self
            .followees
            .get(&(topic as i32))
            .or_else(|| self.followees.get(&(Topic::Unspecified as i32)))
            // extract plain vector from 'Followees' proto
            .map(|x| &x.followees)
        {
            // If, for some reason, a list of followees is specified
            // but empty (this is not normal), don't vote 'no', as
            // would be the natural result of the algorithm below, but
            // instead don't cast a vote.
            if followees.is_empty() {
                return Vote::Unspecified;
            }
            let mut yes: usize = 0;
            let mut no: usize = 0;
            for f in followees.iter() {
                if let Some(f_vote) = ballots.get(&f.id) {
                    if f_vote.vote == (Vote::Yes as i32) {
                        yes += 1;
                    } else if f_vote.vote == (Vote::No as i32) {
                        no += 1;
                    }
                }
            }
            if 2 * yes > followees.len() {
                return Vote::Yes;
            }
            if 2 * no >= followees.len() {
                return Vote::No;
            }
        }
        // No followees specified.
        Vote::Unspecified
    }

    /// Returns the list of followees on the manage neuron topic for
    /// this neuron.
    pub(crate) fn neuron_managers(&self) -> Vec<NeuronId> {
        self.followees
            .get(&(Topic::NeuronManagement as i32))
            .map(|x| x.followees.clone())
            .unwrap_or_default()
    }

    /// Register that this neuron has cast a ballot for a
    /// proposal. Don't include votes on "real time" topics (such as
    /// setting the ICP/SDR exchange rate).
    pub(crate) fn register_recent_ballot(
        &mut self,
        topic: Topic,
        proposal_id: &ProposalId,
        vote: Vote,
    ) {
        // Ignore votes on topics for which no public voting history
        // is required.
        if topic == Topic::ExchangeRate {
            return;
        }
        let ballot_info = BallotInfo {
            proposal_id: Some(*proposal_id),
            vote: vote as i32,
        };
        // We would really like to have a circular buffer here. As
        // we're dealing with a simple vector, we insert at the
        // beginning and remove at the end once we have reached
        // the maximum number of votes to keep track of.
        self.recent_ballots.insert(0, ballot_info);
        // Pop and discard elements from the end until we reach
        // the maximum allowed length of the vector.
        while self.recent_ballots.len() > MAX_NEURON_RECENT_BALLOTS {
            self.recent_ballots.pop();
        }
    }

    pub(crate) fn ready_to_unstake_maturity(&self, now_seconds: u64) -> bool {
        self.state(now_seconds) == NeuronState::Dissolved
            && self.staked_maturity_e8s_equivalent.unwrap_or(0) > 0
    }

    pub(crate) fn unstake_maturity(&mut self, now_seconds: u64) {
        if self.ready_to_unstake_maturity(now_seconds) {
            self.maturity_e8s_equivalent = self
                .maturity_e8s_equivalent
                .saturating_add(self.staked_maturity_e8s_equivalent.unwrap_or(0));

            self.staked_maturity_e8s_equivalent = None;
        }
    }

    // See the relevant protobuf for a high-level description of
    // these operations

    /// If this method is called on a non-dissolving neuron, it remains
    /// non-dissolving. If it is called on dissolving neuron, it remains
    /// dissolving.
    ///
    /// If it is called on a dissolved neuron, it becomes non-dissolving and
    /// its 'age' is reset to start counting from when it last entered
    /// the dissolved state, when applicable (that is, the Dissolved state
    /// was reached through explicit dissolution) --- or from `now` when not
    /// applicable (e.g., newly created neuron with zero dissolve delay).
    pub(crate) fn increase_dissolve_delay(
        &mut self,
        now_seconds: u64,
        additional_dissolve_delay_seconds: u32,
    ) {
        let new_dissolve_state_and_age = self
            .dissolve_state_and_age()
            .increase_dissolve_delay(now_seconds, additional_dissolve_delay_seconds);
        self.set_dissolve_state_and_age(new_dissolve_state_and_age);
    }

    /// Join the Internet Computer's Neurons' Fund. If this neuron is
    /// already a member of the Neurons' Fund, an error is returned.
    fn join_community_fund(&mut self, now_seconds: u64) -> Result<(), GovernanceError> {
        if self.joined_community_fund_timestamp_seconds.unwrap_or(0) == 0 {
            self.joined_community_fund_timestamp_seconds = Some(now_seconds);
            Ok(())
        } else {
            // Already joined...
            Err(GovernanceError::new(ErrorType::AlreadyJoinedCommunityFund))
        }
    }

    /// Leave the Internet Computer's Neurons' Fund. If this neuron is not a
    /// member of the Neurons' Fund, an error will be returned.
    fn leave_community_fund(&mut self) -> Result<(), GovernanceError> {
        if self.joined_community_fund_timestamp_seconds.unwrap_or(0) != 0 {
            self.joined_community_fund_timestamp_seconds = None;
            Ok(())
        } else {
            Err(GovernanceError::new(ErrorType::NotInTheCommunityFund))
        }
    }

    /// If this neuron is not dissolving, start dissolving it.
    ///
    /// If the neuron is dissolving or dissolved, an error is returned.
    fn start_dissolving(&mut self, now_seconds: u64) -> Result<(), GovernanceError> {
        let dissolve_state_and_age = self.dissolve_state_and_age();
        if let DissolveStateAndAge::NotDissolving { .. } = dissolve_state_and_age {
            let new_disolved_dissolve_state_and_age =
                dissolve_state_and_age.start_dissolving(now_seconds);
            self.set_dissolve_state_and_age(new_disolved_dissolve_state_and_age);
            Ok(())
        } else {
            Err(GovernanceError::new(ErrorType::RequiresNotDissolving))
        }
    }

    /// If this neuron is dissolving, set it to not dissolving.
    ///
    /// If the neuron is not dissolving, an error is returned.
    fn stop_dissolving(&mut self, now_seconds: u64) -> Result<(), GovernanceError> {
        let dissolve_state_and_age = self.dissolve_state_and_age();
        let new_disolved_dissolve_state_and_age =
            dissolve_state_and_age.stop_dissolving(now_seconds);
        if new_disolved_dissolve_state_and_age == dissolve_state_and_age {
            Err(GovernanceError::new(ErrorType::RequiresDissolving))
        } else {
            self.set_dissolve_state_and_age(new_disolved_dissolve_state_and_age);
            Ok(())
        }
    }

    /// Preconditions:
    /// - key to add is not already present in 'hot_keys'
    /// - the key to add is well-formed
    /// - there are not already too many hot keys for this neuron.
    fn add_hot_key(&mut self, new_hot_key: &PrincipalId) -> Result<(), GovernanceError> {
        // Make sure that the same hot key is not added twice.
        for key in &self.hot_keys {
            if *key == *new_hot_key {
                return Err(GovernanceError::new_with_message(
                    ErrorType::HotKey,
                    "Hot key duplicated.",
                ));
            }
        }
        // Allow at most 10 hot keys per neuron.
        if self.hot_keys.len() >= MAX_NUM_HOT_KEYS_PER_NEURON {
            return Err(GovernanceError::new_with_message(
                ErrorType::ResourceExhausted,
                "Reached the maximum number of hotkeys.",
            ));
        }
        self.hot_keys.push(*new_hot_key);
        Ok(())
    }

    /// Precondition: key to remove is present in 'hot_keys'
    fn remove_hot_key(&mut self, hot_key_to_remove: &PrincipalId) -> Result<(), GovernanceError> {
        if let Some(index) = self.hot_keys.iter().position(|x| *x == *hot_key_to_remove) {
            self.hot_keys.swap_remove(index);
            Ok(())
        } else {
            // Hot key to remove was not found.
            Err(GovernanceError::new_with_message(
                ErrorType::NotFound,
                "Remove failed: Hot key not found.",
            ))
        }
    }

    /// Err is returned is in the following cases:
    ///
    ///     1. visibility is invalid.
    ///
    ///     2. This neuron is known.
    fn set_visibility(&mut self, visibility: Option<i32>) -> Result<(), GovernanceError> {
        // Reject visibility == None;
        let Some(visibility) = visibility else {
            return Err(GovernanceError::new_with_message(
                ErrorType::InvalidCommand,
                "Visibility was not specified.".to_string(),
            ));
        };

        // Known neurons are not allowed to set their visibility.
        if self.known_neuron_data.is_some() {
            return Err(GovernanceError::new_with_message(
                ErrorType::PreconditionFailed,
                "Setting the visibility of known neurons is not allowed \
                 (they are always public).",
            ));
        }

        // Convert from i32 to enum.
        let visibility = Visibility::try_from(visibility).map_err(|err| {
            GovernanceError::new_with_message(
                ErrorType::InvalidCommand,
                format!("{} is an invalid visibility: {:?}", visibility, err),
            )
        })?;

        // Reject unspecified.
        match visibility {
            Visibility::Unspecified => {
                return Err(GovernanceError::new_with_message(
                    ErrorType::InvalidCommand,
                    "A neuron's visibility cannot be set to unspecified.".to_string(),
                ))
            }
            Visibility::Public | Visibility::Private => (),
        }

        // Everything looks good.
        self.visibility = Some(visibility);
        Ok(())
    }

    // --- Public interface of a neuron.

    /// Return the age of this neuron.
    ///
    /// A dissolving neuron has age zero.
    ///
    /// Technically, each neuron has an internal `aging_since`
    /// field that is set to the current time when a neuron is
    /// created in a non-dissolving state and reset when a neuron is
    /// not dissolving again after a call to `stop_dissolve`. While a
    /// neuron is dissolving, `aging_since` is a value in the far
    /// future, effectively making its age zero.
    pub fn age_seconds(&self, now_seconds: u64) -> u64 {
        self.dissolve_state_and_age().age_seconds(now_seconds)
    }

    /// Returns the dissolve delay of this neuron. For a non-dissolving
    /// neuron, this is just the recorded dissolve delay; for a
    /// dissolving neuron, this is the the time left (from
    /// `now_seconds`) until the neuron becomes dissolved; for a
    /// dissolved neuron, this function returns zero.
    pub fn dissolve_delay_seconds(&self, now_seconds: u64) -> u64 {
        self.dissolve_state_and_age()
            .dissolve_delay_seconds(now_seconds)
    }

    pub fn is_dissolved(&self, now_seconds: u64) -> bool {
        self.dissolve_delay_seconds(now_seconds) == 0
    }

    fn is_authorized_to_configure_or_err(
        &self,
        caller: &PrincipalId,
        configure: &Operation,
    ) -> Result<(), GovernanceError> {
        use Operation::{JoinCommunityFund, LeaveCommunityFund};

        match configure {
            // The controller and hotkeys are allowed to change Neuron Fund membership.
            JoinCommunityFund(_) | LeaveCommunityFund(_) => {
                if self.is_hotkey_or_controller(caller) {
                    Ok(())
                } else {
                    Err(GovernanceError::new_with_message(
                        ErrorType::NotAuthorized,
                        format!(
                            "Caller '{:?}' must be the controller or hotkey of the neuron to join or leave the neuron fund.",
                            caller,
                        ),
                    ))
                }
            }
            Operation::RemoveHotKey(remove_hot_key) => {
                let caller_asking_to_remove_self = remove_hot_key
                    .hot_key_to_remove
                    .as_ref()
                    .map(|hk| hk == caller)
                    .unwrap_or_default();

                if self.is_controlled_by(caller)
                    || (self.is_hotkey_or_controller(caller) && caller_asking_to_remove_self)
                {
                    Ok(())
                } else {
                    Err(GovernanceError::new_with_message(
                        ErrorType::NotAuthorized,
                        format!(
                            "Caller '{:?}' must be the controller or the hot key that is being removed from the neuron.",
                            caller,
                        ),
                    ))
                }
            }

            // Only the controller is allowed to perform other configure operations.
            _ => {
                if self.is_controlled_by(caller) {
                    Ok(())
                } else {
                    Err(GovernanceError::new_with_message(
                        ErrorType::NotAuthorized,
                        format!(
                            "Caller '{:?}' must be the controller of the neuron to perform this operation:\n{:#?}",
                            caller,
                            configure,
                        ),
                    ))
                }
            }
        }
    }

    /// Apply the specified neuron configuration operation on this neuron.
    ///
    /// See [Configure] for details.
    pub fn configure(
        &mut self,
        caller: &PrincipalId,
        now_seconds: u64,
        cmd: &Configure,
    ) -> Result<(), GovernanceError> {
        let op = &cmd.operation.as_ref().ok_or_else(|| {
            GovernanceError::new_with_message(
                ErrorType::InvalidCommand,
                "Configure must have an operation.",
            )
        })?;

        self.is_authorized_to_configure_or_err(caller, op)?;

        match op {
            Operation::IncreaseDissolveDelay(d) => {
                if d.additional_dissolve_delay_seconds == 0 {
                    return Err(GovernanceError::new_with_message(
                        ErrorType::InvalidCommand,
                        "Additional delay is 0.",
                    ));
                }
                self.increase_dissolve_delay(now_seconds, d.additional_dissolve_delay_seconds);
                Ok(())
            }
            Operation::SetDissolveTimestamp(d) => {
                if now_seconds > d.dissolve_timestamp_seconds {
                    return Err(GovernanceError::new_with_message(
                        ErrorType::InvalidCommand,
                        "The dissolve delay must be set to a future time.",
                    ));
                }
                let desired_dd = d.dissolve_timestamp_seconds - now_seconds;
                let current_dd = self.dissolve_delay_seconds(now_seconds);

                if current_dd > desired_dd {
                    return Err(GovernanceError::new_with_message(
                        ErrorType::InvalidCommand,
                        "Can't set a dissolve delay that is smaller than the current dissolve delay."
                    ));
                }

                let dd_diff = desired_dd - current_dd;
                if dd_diff == 0 {
                    return Err(GovernanceError::new_with_message(
                        ErrorType::InvalidCommand,
                        "Additional delay is 0.",
                    ));
                }
                self.increase_dissolve_delay(
                    now_seconds,
                    dd_diff.try_into().map_err(|_| {
                        GovernanceError::new_with_message(
                            ErrorType::InvalidCommand,
                            "Can't convert u64 dissolve delay into u32.",
                        )
                    })?,
                );
                Ok(())
            }
            Operation::StartDissolving(_) => self.start_dissolving(now_seconds),
            Operation::StopDissolving(_) => self.stop_dissolving(now_seconds),
            Operation::AddHotKey(k) => {
                let hot_key = k.new_hot_key.as_ref().ok_or_else(|| {
                    GovernanceError::new_with_message(
                    ErrorType::InvalidCommand,
                    "Operation AddHotKey requires the hot key to add to be specified in the input",
                )
                })?;
                self.add_hot_key(hot_key)
            }
            Operation::RemoveHotKey(k) => {
                let hot_key = k.hot_key_to_remove.as_ref().ok_or_else(|| GovernanceError::new_with_message(
                    ErrorType::InvalidCommand,
                    "Operation RemoveHotKey requires the hot key to remove to be specified in the input",
                ))?;
                self.remove_hot_key(hot_key)
            }
            Operation::JoinCommunityFund(_) => self.join_community_fund(now_seconds),
            Operation::LeaveCommunityFund(_) => self.leave_community_fund(),
            Operation::ChangeAutoStakeMaturity(change) => {
                if change.requested_setting_for_auto_stake_maturity {
                    self.auto_stake_maturity = Some(true);
                } else {
                    self.auto_stake_maturity = None;
                }
                Ok(())
            }
            Operation::SetVisibility(set_visibility) => {
                self.set_visibility(set_visibility.visibility)
            }
        }
    }

    /// Get the 'public' information associated with this neuron.
    pub fn get_neuron_info(&self, now_seconds: u64, requester: PrincipalId) -> NeuronInfo {
        let mut recent_ballots = vec![];
        let mut joined_community_fund_timestamp_seconds = None;

        let show_full = !is_private_neuron_enforcement_enabled()
            || self.visibility() == Some(Visibility::Public)
            || self.is_hotkey_or_controller(&requester);
        if show_full {
            recent_ballots.append(&mut self.recent_ballots.clone());
            joined_community_fund_timestamp_seconds = self.joined_community_fund_timestamp_seconds;
        }

        let visibility = if !is_private_neuron_enforcement_enabled() {
            None
        } else if self.known_neuron_data.is_some() {
            Some(Visibility::Public as i32)
        } else {
            Some(self.visibility.unwrap_or(Visibility::Private) as i32)
        };

        NeuronInfo {
            retrieved_at_timestamp_seconds: now_seconds,
            state: self.state(now_seconds) as i32,
            age_seconds: self.age_seconds(now_seconds),
            dissolve_delay_seconds: self.dissolve_delay_seconds(now_seconds),
            recent_ballots,
            voting_power: self.voting_power(now_seconds),
            created_timestamp_seconds: self.created_timestamp_seconds,
            stake_e8s: self.minted_stake_e8s(),
            joined_community_fund_timestamp_seconds,
            known_neuron_data: self.known_neuron_data.clone(),
            neuron_type: self.neuron_type,
            visibility,
        }
    }

    /// Return the current 'stake' of this Neuron in number of 10^-8 ICPs.
    /// (That is, if the stake is 1 ICP, this function will return 10^8).
    ///
    /// The stake can be decreased by making proposals that are
    /// subsequently rejected, and increased by transferring funds
    /// to the account of this neuron and then refreshing the stake, or
    /// by accumulating staked maturity.
    pub fn stake_e8s(&self) -> u64 {
        neuron_stake_e8s(
            self.cached_neuron_stake_e8s,
            self.neuron_fees_e8s,
            self.staked_maturity_e8s_equivalent,
        )
    }

    /// Returns the current `minted` stake of the neuron, i.e. the ICP backing the
    /// neuron, minus the fees. This does not count staked maturity.
    pub fn minted_stake_e8s(&self) -> u64 {
        self.cached_neuron_stake_e8s
            .saturating_sub(self.neuron_fees_e8s)
    }

    /// Set the cached stake of this neuron to `updated_stake_e8s` and adjust
    /// this neuron's age to be the weighted average of the priorly cached
    /// and the added stakes. For example, if neuron N had staked 10 ICP aging
    /// since 3 years and 5 ICP has been added, then
    /// `N.update_stake_adjust_age(15 ICP)` will result in N staking 15 ICP aged
    /// at (10 ICP * 3 years) / (10 ICP + 5 ICP) = 2 years.
    ///
    /// Only a non-dissolving neuron has a non-zero age. The age of all other
    /// neurons (i.e., dissolving and dissolved) is represented as
    /// `aging_since_timestamp_seconds == u64::MAX`. This method maintains
    /// that invariant.
    pub fn update_stake_adjust_age(&mut self, updated_stake_e8s: u64, now: u64) {
        // If the updated stake is less than the original stake, preserve the
        // age and distribute it over the new amount. This should not happen
        // in practice, so this code exists merely as a defensive fallback.
        //
        // TODO(NNS1-954) Consider whether update_stake_adjust_age (and other
        // similar methods) should use a neurons effective stake rather than
        // the cached stake.
        if updated_stake_e8s < self.cached_neuron_stake_e8s {
            println!(
                "{}Reducing neuron {:?} stake via update_stake_adjust_age: {} -> {}",
                LOG_PREFIX,
                self.id(),
                self.cached_neuron_stake_e8s,
                updated_stake_e8s
            );
            self.cached_neuron_stake_e8s = updated_stake_e8s;
        } else {
            // If one looks at "stake * age" as describing an area, the goal
            // at this point is to increase the stake while keeping the area
            // constant. This means decreasing the age in proportion to the
            // additional stake, which is the purpose of combine_aged_stakes.
            let (new_stake_e8s, new_age_seconds) = combine_aged_stakes(
                self.cached_neuron_stake_e8s,
                self.age_seconds(now),
                updated_stake_e8s.saturating_sub(self.cached_neuron_stake_e8s),
                0,
            );
            // A consequence of the math above is that the 'new_stake_e8s' is
            // always the same as the 'updated_stake_e8s'. We use
            // 'combine_aged_stakes' here to make sure the age is
            // appropriately pro-rated to accommodate the new stake.
            assert!(new_stake_e8s == updated_stake_e8s);
            self.cached_neuron_stake_e8s = new_stake_e8s;

            let new_aging_since_timestamp_seconds = now.saturating_sub(new_age_seconds);
            let new_disolved_dissolve_state_and_age = self
                .dissolve_state_and_age()
                .adjust_age(new_aging_since_timestamp_seconds);
            self.set_dissolve_state_and_age(new_disolved_dissolve_state_and_age);
        }
    }

    /// An inactive neuron is supposed to end up living in stable memory.
    ///
    /// The exact criteria is subject to change. Currently, all of the following must hold:
    ///
    ///     1. Not seed or ect: NeuronType is not NeuronType::Seed or NeuronType::Ect
    ///     2. Not funded: No stake, and no (unstaked) maturity.
    ///     3. Dissolved sufficiently "long ago": Precisely, dissolved as of now - 2 weeks.
    ///     4. Member of the Neuron's Fund.
    ///
    ///
    /// Remarks about condition 2:
    ///
    /// A. Notice that under these criteria, a Neuron CAN INDEED become inactive merely by the passage
    /// of time. This is unfortunate, but not catastrophic. As long as "most" inactive Neurons are
    /// in stable memory, and nothing is relying on "if a Neuron is inactive, then it is in stable
    /// memory", then we have achieved our goal: save heap space.
    ///
    /// B. This is why this method has the `now` parameter.
    pub fn is_inactive(&self, now: u64) -> bool {
        // Require condition 1.
        if self.is_seed_neuron() || self.is_ect_neuron() {
            return false;
        }

        // Require condition 2.
        if self.is_funded() {
            return false;
        }

        // Require condition 3.

        // 3.1: Interpret dissolve_state field.
        let dissolved_at_timestamp_seconds = match self.dissolved_at_timestamp_seconds() {
            // None -> not dissolving -> will be dissolved in the future -> not dissolved now ->
            // certainly was not dissolved sufficiently "long" ago!
            None => {
                return false;
            }
            Some(ok) => ok,
        };

        // 3.2: Now, we know when self is "dissolved" (could be in the past, present, or future).
        // Thus, we can evaluate whether that happened sufficiently long ago.
        let max_dissolved_at_timestamp_seconds_to_be_inactive = now - 2 * 7 * ONE_DAY_SECONDS;
        if dissolved_at_timestamp_seconds > max_dissolved_at_timestamp_seconds_to_be_inactive {
            return false;
        }

        // Finally, require condition 4: Member of the Neuron's Fund.
        if self.is_a_neurons_fund_member() {
            return false;
        }

        // All requirements have been met.
        true
    }

    pub fn is_seed_neuron(&self) -> bool {
        self.neuron_type == Some(NeuronType::Seed as i32)
    }

    pub fn is_ect_neuron(&self) -> bool {
        self.neuron_type == Some(NeuronType::Ect as i32)
    }

    pub fn is_genesis_neuron(&self) -> bool {
        self.is_ect_neuron() || self.is_seed_neuron()
    }

    pub fn is_funded(&self) -> bool {
        let amount_e8s = self.stake_e8s() + self.maturity_e8s_equivalent;
        amount_e8s > 0
    }

    /// If not dissolving, returns None. Otherwise, returns Some Unix timestamp (seconds) when the
    /// Neuron is dissolved (could be in the past, present, or future).
    ///
    /// Note that when self.dissolve_state == DissolveDelaySeconds(0), even though the Neuron is
    /// dissolved, we do not know when that happened. This tends to happen when Neurons are first
    /// created. In those cases, we could have set dissolve_state to
    /// WhenDissolvedTimestampSeconds(now()), but we didn't. This could be changed for new Neurons,
    /// but there is no intention to do that (yet).
    pub fn dissolved_at_timestamp_seconds(&self) -> Option<u64> {
        self.dissolve_state_and_age()
            .dissolved_at_timestamp_seconds()
    }

    pub fn subtract_staked_maturity(&mut self, amount_e8s: u64) {
        let new_staked_maturity_e8s = self
            .staked_maturity_e8s_equivalent
            .unwrap_or(0)
            .saturating_sub(amount_e8s);
        self.staked_maturity_e8s_equivalent = if new_staked_maturity_e8s == 0 {
            None
        } else {
            Some(new_staked_maturity_e8s)
        };
    }

    pub fn add_staked_maturity(&mut self, amount_e8s: u64) {
        let new_staked_maturity_e8s = self
            .staked_maturity_e8s_equivalent
            .unwrap_or(0)
            .saturating_add(amount_e8s);
        self.staked_maturity_e8s_equivalent = if new_staked_maturity_e8s == 0 {
            None
        } else {
            Some(new_staked_maturity_e8s)
        };
    }
}

impl From<Neuron> for NeuronProto {
    fn from(neuron: Neuron) -> Self {
        let Neuron {
            id,
            subaccount,
            controller,
            dissolve_state_and_age,
            hot_keys,
            cached_neuron_stake_e8s,
            neuron_fees_e8s,
            created_timestamp_seconds,
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
            visibility,
        } = neuron;

        let id = Some(id);
        let controller = Some(controller);
        let account = subaccount.to_vec();
        let StoredDissolveStateAndAge {
            dissolve_state,
            aging_since_timestamp_seconds,
        } = StoredDissolveStateAndAge::from(dissolve_state_and_age);
        let visibility = visibility.map(|visibility| visibility as i32);

        NeuronProto {
            id,
            account,
            controller,
            dissolve_state,
            aging_since_timestamp_seconds,
            hot_keys,
            cached_neuron_stake_e8s,
            neuron_fees_e8s,
            created_timestamp_seconds,
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
            visibility,
        }
    }
}

impl TryFrom<NeuronProto> for Neuron {
    type Error = String;

    fn try_from(proto: NeuronProto) -> Result<Self, Self::Error> {
        let NeuronProto {
            id,
            account,
            controller,
            dissolve_state,
            aging_since_timestamp_seconds,
            hot_keys,
            cached_neuron_stake_e8s,
            neuron_fees_e8s,
            created_timestamp_seconds,
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
            visibility,
        } = proto;

        let id = id.ok_or("Neuron ID is missing")?;
        let subaccount = Subaccount::try_from(account.as_slice())
            .map_err(|_| "Invalid subaccount".to_string())?;
        let controller = controller.ok_or(format!("Controller is missing for neuron {}", id.id))?;
        let dissolve_state_and_age = DissolveStateAndAge::try_from(StoredDissolveStateAndAge {
            dissolve_state,
            aging_since_timestamp_seconds,
        })?;
        let visibility = match visibility {
            None => None,
            Some(visibility) => Some(Visibility::try_from(visibility).map_err(|err| {
                format!(
                    "Failed to interpret visibility of neuron {:?}: {:?}",
                    id, err,
                )
            })?),
        };

        Ok(Neuron {
            id,
            subaccount,
            controller,
            dissolve_state_and_age,
            hot_keys,
            cached_neuron_stake_e8s,
            neuron_fees_e8s,
            created_timestamp_seconds,
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
            visibility,
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
            dissolve_state_and_age,
            hot_keys,
            cached_neuron_stake_e8s,
            neuron_fees_e8s,
            created_timestamp_seconds,
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
            visibility,
        } = source;

        let account = subaccount.to_vec();
        let controller = Some(controller);
        let StoredDissolveStateAndAge {
            dissolve_state,
            aging_since_timestamp_seconds,
        } = StoredDissolveStateAndAge::from(dissolve_state_and_age);
        let dissolve_state = dissolve_state.map(AbridgedNeuronDissolveState::from);
        let visibility = visibility.map(|visibility| visibility as i32);

        let main = AbridgedNeuron {
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
            visibility,
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
            visibility,
        } = main;

        let subaccount =
            Subaccount::try_from(account.as_slice()).expect("Neuron account is missing");
        let controller = controller.expect("Neuron controller is missing");
        let dissolve_state_and_age = DissolveStateAndAge::try_from(StoredDissolveStateAndAge {
            dissolve_state: dissolve_state.map(NeuronDissolveState::from),
            aging_since_timestamp_seconds,
        })
        .expect("Neuron dissolve state and age is invalid");
        let visibility = visibility.and_then(|visibility| Visibility::try_from(visibility).ok());

        Neuron {
            id,
            subaccount,
            controller,
            dissolve_state_and_age,
            hot_keys,
            cached_neuron_stake_e8s,
            neuron_fees_e8s,
            created_timestamp_seconds,
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
            visibility,
        }
    }
}

/// Builder of a neuron before it gets added into NeuronStore. This allows us to construct a neuron
/// with private fields. Only fields that are possible to be set at creation time are defined in the
/// builder.
#[derive(Clone, PartialEq, Debug)]
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
    visibility: Option<Visibility>,

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
            visibility: None,

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

    #[cfg(test)] // To satisfy clippy. Feel free to use in production code.
    pub fn with_visibility(mut self, visibility: Option<Visibility>) -> Self {
        self.visibility = visibility;
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
            visibility,
        } = self;

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
            dissolve_state_and_age,
            hot_keys,
            cached_neuron_stake_e8s,
            neuron_fees_e8s,
            created_timestamp_seconds,
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
            visibility,
        }
    }
}

/// An intermediate struct to represent a neuron's dissolve state and age on the storage layer.
#[derive(Clone, PartialEq, Debug)]
pub(crate) struct StoredDissolveStateAndAge {
    pub dissolve_state: Option<NeuronDissolveState>,
    pub aging_since_timestamp_seconds: u64,
}

impl From<DissolveStateAndAge> for StoredDissolveStateAndAge {
    fn from(dissolve_state_and_age: DissolveStateAndAge) -> Self {
        match dissolve_state_and_age {
            DissolveStateAndAge::NotDissolving {
                dissolve_delay_seconds,
                aging_since_timestamp_seconds,
            } => StoredDissolveStateAndAge {
                dissolve_state: Some(NeuronDissolveState::DissolveDelaySeconds(
                    dissolve_delay_seconds,
                )),
                aging_since_timestamp_seconds,
            },
            DissolveStateAndAge::DissolvingOrDissolved {
                when_dissolved_timestamp_seconds,
            } => StoredDissolveStateAndAge {
                dissolve_state: Some(NeuronDissolveState::WhenDissolvedTimestampSeconds(
                    when_dissolved_timestamp_seconds,
                )),
                aging_since_timestamp_seconds: u64::MAX,
            },
        }
    }
}

impl TryFrom<StoredDissolveStateAndAge> for DissolveStateAndAge {
    type Error = String;

    fn try_from(stored: StoredDissolveStateAndAge) -> Result<Self, Self::Error> {
        let StoredDissolveStateAndAge {
            dissolve_state,
            aging_since_timestamp_seconds,
        } = stored;

        let Some(dissolve_state) = dissolve_state else {
            return Err("Dissolve state is missing".to_string());
        };

        match dissolve_state {
            NeuronDissolveState::DissolveDelaySeconds(dissolve_delay_seconds) => {
                if dissolve_delay_seconds > 0 {
                    Ok(DissolveStateAndAge::NotDissolving {
                        dissolve_delay_seconds,
                        aging_since_timestamp_seconds,
                    })
                } else {
                    Err("Dissolve delay must be greater than 0".to_string())
                }
            }
            NeuronDissolveState::WhenDissolvedTimestampSeconds(
                when_dissolved_timestamp_seconds,
            ) => {
                if aging_since_timestamp_seconds == u64::MAX {
                    Ok(DissolveStateAndAge::DissolvingOrDissolved {
                        when_dissolved_timestamp_seconds,
                    })
                } else {
                    Err("Aging since timestamp must be u64::MAX for dissolving or dissolved neurons".to_string())
                }
            }
        }
    }
}

#[cfg(test)]
mod tests;
