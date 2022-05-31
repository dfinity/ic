use crate::pb::v1::governance_error::ErrorType;
use crate::pb::v1::neuron::DissolveState;
use crate::pb::v1::proposal::Action;
use crate::pb::v1::{
    manage_neuron, Ballot, Empty, GovernanceError, Neuron, NeuronId, NeuronPermission,
    NeuronPermissionType, Vote,
};
use ic_base_types::PrincipalId;
use ledger_canister::Subaccount;
use std::cmp::Ordering;
use std::collections::{BTreeMap, HashSet};
use std::convert::{TryFrom, TryInto};
use std::fmt::{Display, Formatter};
use std::iter::FromIterator;
use std::str::FromStr;

/// The maximum number of neurons returned by the method `list_neurons`.
pub const MAX_LIST_NEURONS_RESULTS: u32 = 100;

/// The state of a neuron
#[derive(Debug, PartialEq)]
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
#[derive(Debug, PartialEq)]
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

    /// Returns the voting power of the neuron.
    ///
    /// The voting power is computed as
    /// the neuron's stake * a dissolve delay bonus * an age bonus.
    /// The dissolve delay bonus depends on the neuron's dissolve delay and is in the range
    /// of 0%, for 0 dissolve delay, up to 100%, for a neuron with max_dissolve_delay_seconds.
    /// The age bonus depends on the neuron's age and is in the range of 0%, for 0 age, up
    /// to 25%, for a neuron with max_neuron_age_for_age_bonus.
    /// max_dissolve_delay_seconds and max_neuron_age_for_age_bonus are defined in
    /// the nervous system parameters.
    pub fn voting_power(
        &self,
        now_seconds: u64,
        max_dissolve_delay_seconds: u64,
        max_neuron_age_for_age_bonus: u64,
    ) -> u64 {
        // We compute the stake adjustments in u128.
        let stake = self.stake_e8s() as u128;
        // Dissolve delay is capped to max_dissolve_delay_seconds, but we cap it
        // again here to make sure, e.g., if this changes in the future.
        let d = std::cmp::min(
            self.dissolve_delay_seconds(now_seconds),
            max_dissolve_delay_seconds,
        ) as u128;
        // 'd_stake' is the stake with bonus for dissolve delay.
        let d_stake = stake + ((stake * d) / (max_dissolve_delay_seconds as u128));
        // Sanity check.
        assert!(d_stake <= 2 * stake);
        // The voting power is also a function of the age of the
        // neuron, giving a bonus of up to 25% at max_neuron_age_for_age_bonus.
        let a = std::cmp::min(self.age_seconds(now_seconds), max_neuron_age_for_age_bonus) as u128;
        let ad_stake = d_stake + ((d_stake * a) / (4 * max_neuron_age_for_age_bonus as u128));
        // Final stake 'ad_stake' is at most 5/4 of the 'd_stake'.
        assert!(ad_stake <= (5 * d_stake) / 4);
        // The final voting power is the stake adjusted by both age
        // and dissolve delay. If the stake is is greater than
        // u64::MAX divided by 2.5, the voting power may actually not
        // fit in a u64.
        std::cmp::min(ad_stake, u64::MAX as u128) as u64
    }

    /// Given the specified `ballots`, determine how the neuron would
    /// vote on a proposal of `action` based on which neurons this
    /// neuron follows on this action (or on the default action if this
    /// neuron doesn't specify any followees for `action`).
    pub(crate) fn would_follow_ballots(
        &self,
        action: u64,
        ballots: &BTreeMap<String, Ballot>,
    ) -> Vote {
        // Compute the list of followees for this action. If no
        // following is specified for the action, use the followees
        // from the 'Unspecified' action.
        let unspecified_key = u64::from(&Action::Unspecified(Empty {}));
        if let Some(followees) = self
            .followees
            .get(&(action))
            .or_else(|| self.followees.get(&unspecified_key))
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
                if let Some(f_vote) = ballots.get(&f.to_string()) {
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
                    //
                    // We set the age to ts as, at this point in
                    // time, the neuron exited the dissolving
                    // state and entered the dissolved state.
                    //
                    // This way of setting the age of neuron
                    // transitioning from dissolved to non-dissolving
                    // creates an incentive to increase the
                    // dissolve delay of a dissolved neuron
                    // instead of dissolving it.
                    self.aging_since_timestamp_seconds = ts;
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

        self.cached_neuron_stake_e8s = new_stake_e8s as u64;
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
                    ErrorType::ErrorAccessControlList,
                    format!(
                        "PrincipalId {} does not have any permissions in Neuron {}",
                        principal_id,
                        self.id.as_ref().expect("Neuron must have a NeuronId")
                    ),
                )
            })?;

        let mut existing_permission = self
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
                missing_permissions.insert(NeuronPermissionType::from_i32(*permission_type));
            }
        }

        if !missing_permissions.is_empty() {
            return Err(GovernanceError::new_with_message(
                ErrorType::ErrorAccessControlList,
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
