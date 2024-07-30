use crate::{
    pb::v1::{
        governance_error::ErrorType, manage_neuron, neuron::DissolveState, proposal::Action,
        Ballot, Empty, GovernanceError, Neuron, NeuronId, NeuronPermission, NeuronPermissionList,
        NeuronPermissionType, Vote,
    },
    types::function_id_to_proposal_criticality,
};
use ic_base_types::PrincipalId;
use ic_sns_governance_proposal_criticality::ProposalCriticality;
use icrc_ledger_types::icrc1::account::Subaccount;
use std::{
    cmp::Ordering,
    collections::{BTreeMap, HashSet},
    convert::{TryFrom, TryInto},
    fmt::{Display, Formatter},
    iter::FromIterator,
    str::FromStr,
};

/// The maximum number of neurons returned by the method `list_neurons`.
pub const MAX_LIST_NEURONS_RESULTS: u32 = 100;

/// The default voting_power_percentage_multiplier applied to a neuron.
pub const DEFAULT_VOTING_POWER_PERCENTAGE_MULTIPLIER: u64 = 100;

/// The state of a neuron
#[derive(Debug, PartialEq, Eq)]
pub enum NeuronState {
    /// In this state, the neuron is not dissolving and has a specific
    /// `dissolve_delay` that is larger than zero.
    NotDissolving,
    /// In this state, the neuron's dissolve clock is running down with
    /// the passage of time. The neuron has a defined
    /// `when_dissolved_timestamp` that specifies at what time (in the
    /// future) it will be dissolved.
    Dissolving,
    /// In this state, the neuron is dissolved and can be disbursed.
    /// This captures all the remaining cases. In particular a neuron
    /// is dissolved if its `when_dissolved_timestamp` is in the past
    /// or when its `dissolve_delay` is zero.
    Dissolved,
}
/// The status of an invocation of `remove_permission`.
#[derive(Debug, PartialEq, Eq)]
pub enum RemovePermissionsStatus {
    /// This status indicates all PermissionTypes for a PrincipalId
    /// were removed from a neuron's permission list and therefore
    /// the PrincipalId was removed as well.
    AllPermissionTypesRemoved,
    /// This status indicates that only some PermissionTypes for a
    /// PrincipalId were removed from a neuron's permission list
    /// and therefore the PrincipalId was not removed.
    SomePermissionTypesRemoved,
}

impl Neuron {
    pub const PERMISSIONS_RELATED_TO_VOTING: &'static [NeuronPermissionType] = &[
        NeuronPermissionType::Vote,
        NeuronPermissionType::SubmitProposal,
        NeuronPermissionType::ManageVotingPermission,
    ];

    pub const PERMISSIONS_FOR_NEURONS_FUND_NNS_NEURON_CONTROLLER:
        &'static [NeuronPermissionType] = &[
        NeuronPermissionType::ManageVotingPermission,
        NeuronPermissionType::SubmitProposal,
        NeuronPermissionType::Vote,
    ];

    pub const PERMISSIONS_FOR_NEURONS_FUND_NNS_NEURON_HOTKEY: &'static [NeuronPermissionType] = &[
        NeuronPermissionType::SubmitProposal,
        NeuronPermissionType::Vote,
    ];

    // Utility methods on neurons.

    /// Returns the neuron's state.
    pub fn state(&self, now_seconds: u64) -> NeuronState {
        match self.dissolve_state {
            Some(DissolveState::DissolveDelaySeconds(d)) => {
                if d > 0 {
                    NeuronState::NotDissolving
                } else {
                    NeuronState::Dissolved
                }
            }
            Some(DissolveState::WhenDissolvedTimestampSeconds(ts)) => {
                if ts > now_seconds {
                    NeuronState::Dissolving
                } else {
                    NeuronState::Dissolved
                }
            }
            None => NeuronState::Dissolved,
        }
    }

    /// Checks whether a given principal has the permission to perform a certain action on
    /// the neuron.
    pub(crate) fn check_authorized(
        &self,
        principal: &PrincipalId,
        permission: NeuronPermissionType,
    ) -> Result<(), GovernanceError> {
        if !self.is_authorized(principal, permission) {
            return Err(GovernanceError::new_with_message(
                ErrorType::NotAuthorized,
                format!(
                    "Caller '{:?}' is not authorized to perform action: '{:?}' on neuron '{}'.",
                    principal,
                    permission,
                    self.id.as_ref().expect("Neuron must have a NeuronId"),
                ),
            ));
        }

        Ok(())
    }

    /// Returns true if the principalId has the permission to act on this neuron (i.e., self).
    pub(crate) fn is_authorized(
        &self,
        principal: &PrincipalId,
        permission: NeuronPermissionType,
    ) -> bool {
        let found_neuron_permission = self
            .permissions
            .iter()
            .find(|neuron_permission| neuron_permission.principal == Some(*principal));

        if let Some(p) = found_neuron_permission {
            return p.permission_type.contains(&(permission as i32));
        }

        false
    }

    /// Returns Ok if the caller has ManagePrincipals, or if the caller has
    /// ManageVotingPermission and the permissions to change relate to voting.
    pub(crate) fn check_principal_authorized_to_change_permissions(
        &self,
        caller: &PrincipalId,
        permissions_to_change: NeuronPermissionList,
    ) -> Result<(), GovernanceError> {
        // If the permissions to change are exclusively voting related,
        // ManagePrincipals or ManageVotingPermission is sufficient.
        // Otherwise, only ManagePrincipals is sufficient.
        let sufficient_permissions = if permissions_to_change.is_exclusively_voting_related() {
            vec![
                NeuronPermissionType::ManagePrincipals,
                NeuronPermissionType::ManageVotingPermission,
            ]
        } else {
            vec![NeuronPermissionType::ManagePrincipals]
        };

        // The caller is authorized if they have any of the sufficient permissions
        let caller_authorized = sufficient_permissions
            .iter()
            .any(|sufficient_permission| self.is_authorized(caller, *sufficient_permission));

        if caller_authorized {
            Ok(())
        } else {
            let caller_permissions = self.permissions_for_principal(caller);
            Err(GovernanceError::new_with_message(ErrorType::NotAuthorized,
            format!(
                "Caller '{caller:?}' is not authorized to modify permissions {permissions_to_change} for neuron '{}' as it does not have any of {sufficient_permissions:?}. (Caller's permissions are {caller_permissions})",
                self.id.as_ref().expect("Neuron must have a NeuronId"),
            )))
        }
    }

    /// Returns the voting power of the neuron.
    ///
    /// The voting power is computed as
    /// the neuron's stake * a dissolve delay bonus * an age bonus * voting power multiplier.
    /// - The dissolve delay bonus depends on the neuron's dissolve delay and is in the range
    ///   of 0%, for 0 dissolve delay, up to max_dissolve_delay_bonus_percentage, for a neuron
    ///   with max_dissolve_delay_seconds.
    /// - The age bonus depends on the neuron's age and is in the range of 0%, for 0 age, up
    ///   to max_age_bonus_percentage, for a neuron with max_neuron_age_for_age_bonus.
    /// - The voting power multiplier depends on the neuron.voting_power_percentage_multiplier,
    ///   and is applied against the total voting power of the neuron. It is represented
    ///   as a percent in the range of 0 and 100 where 0 will result in 0 voting power,
    ///   and 100 will result in unadjusted voting power.
    ///
    /// max_dissolve_delay_seconds and max_neuron_age_for_age_bonus are defined in
    /// the nervous system parameters.
    pub fn voting_power(
        &self,
        now_seconds: u64,
        max_dissolve_delay_seconds: u64,
        max_neuron_age_for_age_bonus: u64,
        max_dissolve_delay_bonus_percentage: u64,
        max_age_bonus_percentage: u64,
    ) -> u64 {
        // We compute the stake adjustments in u128.
        let stake = self.voting_power_stake_e8s() as u128;
        // Dissolve delay is capped to max_dissolve_delay_seconds, but we cap it
        // again here to make sure, e.g., if this changes in the future.
        let d = std::cmp::min(
            self.dissolve_delay_seconds(now_seconds),
            max_dissolve_delay_seconds,
        ) as u128;
        // 'd_stake' is the stake with bonus for dissolve delay.
        let d_stake = stake
            + if max_dissolve_delay_seconds > 0 {
                (stake * d * max_dissolve_delay_bonus_percentage as u128)
                    / (100 * max_dissolve_delay_seconds as u128)
            } else {
                0
            };
        // Sanity check.
        assert!(d_stake <= stake + (stake * (max_dissolve_delay_bonus_percentage as u128) / 100));
        // The voting power is also a function of the age of the
        // neuron, giving a bonus of up to max_age_bonus_percentage at max_neuron_age_for_age_bonus.
        let a = std::cmp::min(self.age_seconds(now_seconds), max_neuron_age_for_age_bonus) as u128;
        let ad_stake = d_stake
            + if max_neuron_age_for_age_bonus > 0 {
                (d_stake * a * max_age_bonus_percentage as u128)
                    / (100 * max_neuron_age_for_age_bonus as u128)
            } else {
                0
            };
        // Final stake 'ad_stake' has is not more than max_age_bonus_percentage above 'd_stake'.
        assert!(ad_stake <= d_stake + (d_stake * (max_age_bonus_percentage as u128) / 100));

        // Convert the multiplier to u128. The voting_power_percentage_multiplier represents
        // a percent and will always be within the range 0 to 100.
        let v = self.voting_power_percentage_multiplier as u128;

        // Apply the multiplier to 'ad_stake' and divide by 100 to have the same effect as
        // multiplying by a percent.
        let vad_stake = ad_stake
            .checked_mul(v)
            .expect("Overflow detected when calculating voting power")
            .checked_div(100)
            .expect("Underflow detected when calculating voting power");

        // The final voting power is the stake adjusted by both age,
        // dissolve delay, and voting power multiplier. If the stake is is greater than
        // u64::MAX divided by 2.5, the voting power may actually not
        // fit in a u64.
        std::cmp::min(vad_stake, u64::MAX as u128) as u64
    }

    /// Given the specified `ballots`, determine how the neuron would
    /// vote on a proposal of `action` based on which neurons this
    /// neuron follows on this action (or on the default action if this
    /// neuron doesn't specify any followees for `action`).
    pub(crate) fn would_follow_ballots(
        &self,
        function_id: u64,
        ballots: &BTreeMap<String, Ballot>,
    ) -> Vote {
        // Step 1: Who are the relevant followees?

        let empty = vec![];
        let get_followee_neuron_ids = |function_id| -> &Vec<NeuronId> {
            self.followees
                .get(&function_id)
                .map(|followees_message| &followees_message.followees)
                // If there was no Followees object, then result is empty Vec. Therefore, we treat
                // None the same as Some(Followees { followees: vec![] }).
                .unwrap_or(&empty)
        };

        let mut followee_neuron_ids = get_followee_neuron_ids(function_id);

        // If the function is not critical, and this Neuron does not have followees specifically for
        // the function, then fall back to the "catch-all" following.
        if followee_neuron_ids.is_empty() {
            use ProposalCriticality::{Critical, Normal};
            match function_id_to_proposal_criticality(function_id) {
                Normal => {
                    let fallback_pseudo_function_id = u64::from(&Action::Unspecified(Empty {}));
                    followee_neuron_ids = get_followee_neuron_ids(fallback_pseudo_function_id);
                }
                Critical => (),
            }
        }

        // This is needed to avoid returning No in Step 3 due to no followees.
        if followee_neuron_ids.is_empty() {
            return Vote::Unspecified;
        }

        // Step 2: Count followee votes.
        let mut yes: usize = 0;
        let mut no: usize = 0;
        for followee_neuron_id in followee_neuron_ids {
            let followee_vote = match ballots.get(&followee_neuron_id.to_string()) {
                Some(ballot) => ballot.vote,
                None => {
                    // We are following someone who doesn't even have an empty
                    // ballot. Maybe this followee should be removed?
                    continue;
                }
            };

            if followee_vote == Vote::Yes as i32 {
                yes += 1;
            } else if followee_vote == Vote::No as i32 {
                no += 1;
            }
        }

        // Step 3: Use vote counts to decide which Vote option to return.

        // If a majority of followees voted Yes, return Yes.
        if 2 * yes > followee_neuron_ids.len() {
            return Vote::Yes;
        }
        // If a majority for Yes can never be achieved, return No.
        if 2 * no >= followee_neuron_ids.len() {
            return Vote::No;
        }
        // Otherwise, we are still open to going either way.
        Vote::Unspecified
    }

    // See the relevant SNS' governance's protobuf for a high-level description
    // of the following operations

    /// If this method is called on a non-dissolving neuron, it remains
    /// non-dissolving. If it is called on dissolving neuron, it remains
    /// dissolving.
    ///
    /// If it is called on a dissolved neuron, it becomes non-dissolving and
    /// its 'age' is reset to start counting from when it last entered
    /// the dissolved state, when applicable (that is, the Dissolved state
    /// was reached through explicit dissolution) --- or from `now` when not
    /// applicable (e.g., newly created neuron with zero dissolve delay).
    fn increase_dissolve_delay(
        &mut self,
        now_seconds: u64,
        additional_dissolve_delay_seconds: u32,
        max_dissolve_delay_seconds: u64,
    ) -> Result<(), GovernanceError> {
        let additional_delay = additional_dissolve_delay_seconds as u64;
        if additional_delay == 0 {
            return Err(GovernanceError::new_with_message(
                ErrorType::InvalidCommand,
                "Additional delay is 0.",
            ));
        }

        match self.dissolve_state {
            Some(DissolveState::DissolveDelaySeconds(delay)) => {
                let new_delay = std::cmp::min(
                    delay.saturating_add(additional_delay),
                    max_dissolve_delay_seconds,
                );
                // Note that if delay == 0, this neuron was
                // dissolved and it now becomes non-dissolving.
                self.dissolve_state = Some(DissolveState::DissolveDelaySeconds(new_delay));
                if delay == 0 {
                    // We transition from `Dissolved` to `NotDissolving`: reset age.
                    self.aging_since_timestamp_seconds = now_seconds;
                }
                Ok(())
            }
            Some(DissolveState::WhenDissolvedTimestampSeconds(ts)) => {
                if ts > now_seconds {
                    let delay = ts - now_seconds;
                    let new_delay = std::cmp::min(
                        delay.saturating_add(additional_delay),
                        max_dissolve_delay_seconds,
                    );
                    let new_ts = now_seconds + new_delay;
                    // Sanity check:
                    // if additional_delay == 0, then
                    // new_delay == delay == ts - now_seconds, whence
                    // new_ts == now_seconds + ts - now_seconds == ts
                    self.dissolve_state =
                        Some(DissolveState::WhenDissolvedTimestampSeconds(new_ts));
                    // The neuron was and remains `Dissolving`:
                    // its effective neuron age should already be
                    // zero by having an `aging_since` timestamp
                    // in the far future. Reset it just in case.
                    self.aging_since_timestamp_seconds = u64::MAX;
                    Ok(())
                } else {
                    // ts <= now_seconds
                    // This neuron is dissolved. Set it to non-dissolving.
                    let new_delay = std::cmp::min(additional_delay, max_dissolve_delay_seconds);
                    self.dissolve_state = Some(DissolveState::DissolveDelaySeconds(new_delay));
                    // We transition from `Dissolved` to `NotDissolving`: reset age.
                    self.aging_since_timestamp_seconds = now_seconds;
                    Ok(())
                }
            }
            None => {
                // This neuron is dissolved. Set it to non-dissolving.
                let new_delay = std::cmp::min(additional_delay, max_dissolve_delay_seconds);
                self.dissolve_state = Some(DissolveState::DissolveDelaySeconds(new_delay));
                // We transition from `Dissolved` to `NotDissolving`: reset age.
                self.aging_since_timestamp_seconds = now_seconds;
                Ok(())
            }
        }
    }

    /// If the neuron is not dissolving, starts dissolving it.
    ///
    /// If the neuron is dissolving or dissolved, an error is returned.
    fn start_dissolving(&mut self, now_seconds: u64) -> Result<(), GovernanceError> {
        if let Some(DissolveState::DissolveDelaySeconds(delay)) = self.dissolve_state {
            // Neuron is not dissolving.
            if delay > 0 {
                self.dissolve_state = Some(DissolveState::WhenDissolvedTimestampSeconds(
                    delay + now_seconds,
                ));
                // When we start dissolving, we set the neuron age to
                // zero, and it stays zero until we stop
                // dissolving. This is represented by setting the
                // 'aging since' to its maximum possible value, which
                // will remain in the future until approximately
                // 292,277,026,596 AD.
                self.aging_since_timestamp_seconds = u64::MAX;
                Ok(())
            } else {
                // Already dissolved - cannot start dissolving.
                Err(GovernanceError::new(ErrorType::RequiresNotDissolving))
            }
        } else {
            // Already dissolving or dissolved - cannot start dissolving.
            Err(GovernanceError::new(ErrorType::RequiresNotDissolving))
        }
    }

    /// If the neuron is dissolving, sets it to not dissolving.
    ///
    /// If the neuron is not dissolving, an error is returned.
    fn stop_dissolving(&mut self, now_seconds: u64) -> Result<(), GovernanceError> {
        if let Some(DissolveState::WhenDissolvedTimestampSeconds(ts)) = self.dissolve_state {
            if ts > now_seconds {
                // As the dissolve time is in the future, the neuron is dissolving. Pause dissolving.
                self.dissolve_state = Some(DissolveState::DissolveDelaySeconds(ts - now_seconds));
                self.aging_since_timestamp_seconds = now_seconds;
                Ok(())
            } else {
                // Already dissolved - cannot stop dissolving.
                Err(GovernanceError::new(ErrorType::RequiresDissolving))
            }
        } else {
            // Already not dissolving or dissolved - cannot stop dissolving..
            Err(GovernanceError::new(ErrorType::RequiresDissolving))
        }
    }

    /// Returns the neuron's age.
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
        now_seconds.saturating_sub(self.aging_since_timestamp_seconds)
    }

    /// Returns the neuron's dissolve delay. For a non-dissolving
    /// neuron, this is just the recorded dissolve delay; for a
    /// dissolving neuron, this is the the time left (from
    /// `now_seconds`) until the neuron becomes dissolved; for a
    /// dissolved neuron, this function returns zero.
    pub fn dissolve_delay_seconds(&self, now_seconds: u64) -> u64 {
        match self.dissolve_state {
            Some(DissolveState::DissolveDelaySeconds(d)) => d,
            Some(DissolveState::WhenDissolvedTimestampSeconds(ts)) => {
                ts.saturating_sub(now_seconds)
            }
            None => 0,
        }
    }

    /// Apply the specified neuron configuration operation on this neuron.
    ///
    /// See [manage_neuron::Configure] for details.
    pub fn configure(
        &mut self,
        now_seconds: u64,
        cmd: &manage_neuron::Configure,
        max_dissolve_delay_seconds: u64,
    ) -> Result<(), GovernanceError> {
        let op = &cmd.operation.as_ref().ok_or_else(|| {
            GovernanceError::new_with_message(
                ErrorType::InvalidCommand,
                "Configure must have an operation.",
            )
        })?;

        match op {
            manage_neuron::configure::Operation::IncreaseDissolveDelay(d) => self
                .increase_dissolve_delay(
                    now_seconds,
                    d.additional_dissolve_delay_seconds,
                    max_dissolve_delay_seconds,
                ),
            manage_neuron::configure::Operation::SetDissolveTimestamp(d) => {
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
                self.increase_dissolve_delay(
                    now_seconds,
                    dd_diff.try_into().map_err(|_| {
                        GovernanceError::new_with_message(
                            ErrorType::InvalidCommand,
                            "Can't convert u64 dissolve delay into u32.",
                        )
                    })?,
                    max_dissolve_delay_seconds,
                )
            }
            manage_neuron::configure::Operation::StartDissolving(_) => {
                self.start_dissolving(now_seconds)
            }
            manage_neuron::configure::Operation::StopDissolving(_) => {
                self.stop_dissolving(now_seconds)
            }
            manage_neuron::configure::Operation::ChangeAutoStakeMaturity(change) => {
                if change.requested_setting_for_auto_stake_maturity {
                    self.auto_stake_maturity = Some(true);
                } else {
                    self.auto_stake_maturity = None;
                }
                Ok(())
            }
        }
    }

    /// Returns the neuron's effective 'stake' in number of 10^-8 governance
    /// tokens. (That is, if the stake is 1 governance token, this function
    /// will return 10^8).
    // TODO verify correctness of comment.
    /// The neuron's effective stake is the difference between the neuron's
    /// cached stake and the fees that the neuron owes.
    /// The stake can be decreased by making proposals that are
    /// subsequently rejected, and increased by previously submitted proposals
    /// that are adopted (then the fees are returned and not owed anymore) or
    /// by transferring funds to the neuron's account and then refreshing the stake.
    pub fn stake_e8s(&self) -> u64 {
        self.cached_neuron_stake_e8s
            .saturating_sub(self.neuron_fees_e8s)
    }

    /// Returns the current stake of this Neuron as used as an input
    /// for the voting power calculation.
    ///
    /// It it is determined as the sum of staked tokens and staked maturity
    /// minus fees occurred for rejected proposals made by this neuron.
    fn voting_power_stake_e8s(&self) -> u64 {
        self.cached_neuron_stake_e8s
            .saturating_sub(self.neuron_fees_e8s)
            .saturating_add(self.staked_maturity_e8s_equivalent.unwrap_or(0))
    }

    /// Updates the stake of this neuron to `new_stake` and adjust this neuron's
    /// age accordingly
    pub fn update_stake(&mut self, new_stake_e8s: u64, now: u64) {
        // If this neuron has an age and its stake is being increased, adjust the
        // neuron's age
        if self.aging_since_timestamp_seconds < now && self.cached_neuron_stake_e8s <= new_stake_e8s
        {
            let old_stake = self.cached_neuron_stake_e8s as u128;
            let old_age = now.saturating_sub(self.aging_since_timestamp_seconds) as u128;
            let new_age = (old_age * old_stake) / (new_stake_e8s as u128);

            // new_age * new_stake = old_age * old_stake -
            // (old_stake * old_age) % new_stake. That is, age is
            // adjusted in proportion to the stake, but due to the
            // discrete nature of u64 numbers, some resolution is
            // lost due to the division above. This means the age
            // bonus is derived from a constant times age times
            // stake, minus up to new_stake - 1 each time the
            // neuron is refreshed. Only if old_age * old_stake is
            // a multiple of new_stake does the age remain
            // constant after the refresh operation. However, in
            // the end, the most that can be lost due to rounding
            // from the actual age, is always less 1 second, so
            // this is not a problem.
            self.aging_since_timestamp_seconds = now.saturating_sub(new_age as u64);
            // Note that if new_stake == old_stake, then
            // new_age == old_age, and
            // now - new_age =
            // now-(now-neuron.aging_since_timestamp_seconds)
            // = neuron.aging_since_timestamp_seconds.
        }

        self.cached_neuron_stake_e8s = new_stake_e8s;
    }

    /// Returns a neuron's subaccount or an error if there is none (a neuron
    /// should always have a subaccount).
    pub fn subaccount(&self) -> Result<Subaccount, GovernanceError> {
        if let Some(nid) = &self.id {
            nid.subaccount()
        } else {
            Err(GovernanceError::new_with_message(
                ErrorType::NotFound,
                "Neuron must have a subaccount",
            ))
        }
    }

    /// Adds a given permission to a principalId's `NeuronPermission` for this neuron. If
    /// no permissions exist for this principal, add a new `NeuronPermission`.
    pub fn add_permissions_for_principal(
        &mut self,
        principal_id: PrincipalId,
        permissions_to_add: Vec<i32>,
    ) {
        // Initialize the structure (a set for deduplication of user input) with the new permissions
        // for eventual union with the existing permissions if they exist
        let mut new_permission_type: HashSet<i32> = HashSet::from_iter(permissions_to_add);

        // Try to find the existing NeuronPermission for the given PrincipalId
        let existing_permission = self
            .permissions
            .iter_mut()
            .find(|p| p.principal == Some(principal_id));

        // If the NeuronPermission exists, update the HashSet with the existing permissions to
        // deduplicate with the permissions from the user input
        if let Some(p) = existing_permission {
            for permission in &p.permission_type {
                new_permission_type.insert(*permission);
            }

            // Replace the current Vector with a Vector built from the HashSet
            p.permission_type = Vec::from_iter(new_permission_type);
        // If the NeuronPermission doesn't exist, create a new one with the deduplicated user input
        } else {
            self.permissions.push(NeuronPermission {
                principal: Some(principal_id),
                permission_type: Vec::from_iter(new_permission_type),
            })
        }
    }

    /// Removes a given permissions from a principalId's `NeuronPermission` for this neuron.
    /// Returns an enum indicating if a `NeuronPermission' is removed due to all of the
    /// principalId's PermissionTypes being removed.
    pub fn remove_permissions_for_principal(
        &mut self,
        principal_id: PrincipalId,
        permission_types_to_remove: Vec<i32>,
    ) -> Result<RemovePermissionsStatus, GovernanceError> {
        // Get the position as it will reduce search time in the future.
        let existing_permission_position = self
            .permissions
            .iter()
            .position(|p| p.principal == Some(principal_id))
            .ok_or_else(|| {
                GovernanceError::new_with_message(
                    ErrorType::AccessControlList,
                    format!(
                        "PrincipalId {} does not have any permissions in Neuron {}",
                        principal_id,
                        self.id.as_ref().expect("Neuron must have a NeuronId")
                    ),
                )
            })?;

        let existing_permission = self
            .permissions
            .get_mut(existing_permission_position)
            .expect("Expected permission to exist");

        // Initialize a structure to efficiently remove provided permission_types from
        // existing permission_types.
        let mut remaining_permission_types: HashSet<i32> =
            HashSet::from_iter(existing_permission.permission_type.iter().cloned());

        // Initialize a structure to track if permission_types were present in the existing NeuronPermission
        let mut missing_permissions = HashSet::new();
        for permission_type in &permission_types_to_remove {
            let permission_type_is_present = remaining_permission_types.remove(permission_type);
            if !permission_type_is_present {
                missing_permissions.insert(NeuronPermissionType::try_from(*permission_type).ok());
            }
        }

        if !missing_permissions.is_empty() {
            return Err(GovernanceError::new_with_message(
                ErrorType::AccessControlList,
                format!(
                    "PrincipalId {} was missing permissions {:?} when removing {:?}",
                    principal_id, missing_permissions, permission_types_to_remove
                ),
            ));
        }

        // If there are no remaining permissions after removing the requested permissions, remove
        // the NeuronPermission entry from the neuron.
        if remaining_permission_types.is_empty() {
            self.permissions.swap_remove(existing_permission_position);
            return Ok(RemovePermissionsStatus::AllPermissionTypesRemoved);
        // If not, update the existing permission with what is left in the remaining permissions.
        } else {
            existing_permission.permission_type = Vec::from_iter(remaining_permission_types);
        }

        Ok(RemovePermissionsStatus::SomePermissionTypesRemoved)
    }

    /// Returns true if this neuron is vesting, false otherwise
    pub fn is_vesting(&self, now: u64) -> bool {
        self.vesting_period_seconds
            .map(|vesting_period_seconds| {
                self.created_timestamp_seconds + vesting_period_seconds >= now
            })
            .unwrap_or_default()
    }

    // Returns the permissions that a given principal has for this neuron.
    pub fn permissions_for_principal(&self, principal: &PrincipalId) -> NeuronPermissionList {
        NeuronPermissionList {
            permissions: self
                .permissions
                .iter()
                .filter(|permission| permission.principal == Some(*principal))
                .flat_map(|permissions| &permissions.permission_type)
                .cloned()
                .collect(),
        }
    }

    /// "NF neurons" are defined as neurons where the NNS governance canister
    /// has the the `ManagePrincipals` permission and is the only principal that
    /// does.
    pub fn is_neurons_fund_controlled(&self) -> bool {
        let principals_with_manage_principals_permission = self
            .permissions
            .iter()
            .filter_map(|p| {
                let manage_principals_present = p.permission_type.iter().any(|permission| {
                    NeuronPermissionType::try_from(*permission).ok()
                        == Some(NeuronPermissionType::ManagePrincipals)
                });
                if manage_principals_present {
                    p.principal
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();

        principals_with_manage_principals_permission
            == vec![PrincipalId::from(ic_nns_constants::GOVERNANCE_CANISTER_ID)]
    }
}

/// A neuron's ID that is defined as the neuron's subaccount on the ledger canister.
impl NeuronId {
    pub fn subaccount(&self) -> Result<Subaccount, GovernanceError> {
        match Subaccount::try_from(self.id.as_slice()) {
            Ok(subaccount) => Ok(subaccount),
            Err(e) => Err(GovernanceError::new_with_message(
                ErrorType::InvalidNeuronId,
                format!("Could not convert NeuronId to Subaccount {}", e),
            )),
        }
    }

    /// A test method to help generate NeuronId's where the subaccount does not matter.
    /// This should only be used in tests.
    pub fn new_test_neuron_id(id: u64) -> NeuronId {
        let mut subaccount = [0; std::mem::size_of::<Subaccount>()];
        let id = &id.to_be_bytes();
        subaccount[0] = id.len().try_into().unwrap();
        subaccount[1..1 + id.len()].copy_from_slice(id);
        NeuronId::from(subaccount)
    }

    pub fn test_neuron_ids<const N: usize>() -> [NeuronId; N] {
        core::array::from_fn(|i| NeuronId::new_test_neuron_id(10 + i as u64))
    }
}

impl From<Subaccount> for NeuronId {
    fn from(subaccount: Subaccount) -> Self {
        NeuronId {
            id: subaccount.to_vec(),
        }
    }
}

impl FromStr for NeuronId {
    type Err = GovernanceError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match hex::decode(s) {
            Ok(id) => Ok(NeuronId { id }),
            Err(e) => Err(GovernanceError::new_with_message(
                ErrorType::InvalidNeuronId,
                format!("Could not convert {} to NeuronId", e),
            )),
        }
    }
}

impl Display for NeuronId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(&self.id))
    }
}

impl Ord for NeuronId {
    fn cmp(&self, other: &Self) -> Ordering {
        self.id.cmp(&other.id)
    }
}

impl PartialOrd for NeuronId {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[cfg(test)]
mod tests;
