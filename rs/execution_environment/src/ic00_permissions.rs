use ic_error_types::{ErrorCode, UserError};
use ic_management_canister_types_private::Method as Ic00Method;
use ic_replicated_state::ReplicatedState;
use ic_types::messages::CanisterCall;
use ic_types::{CanisterId, SubnetId};
use ic_types_cycles::CanisterCyclesCostSchedule;

/// Keeps track of when an IC00 method is allowed to be executed.
#[derive(Eq, PartialEq)]
pub struct Ic00MethodPermissions {
    method: Ic00Method,

    /// Call initiated by a remote subnet.
    allow_remote_subnet_sender: bool,
    /// Call initiated only by the NNS subnet.
    allow_only_nns_subnet_sender: bool,
    /// Call initiated by a sender on a subnet with a "free" cost schedule.
    ///
    /// Such senders are not charged the message transmission fee and cannot
    /// attach cycles, so methods that perform (otherwise caller-funded) work on
    /// their behalf without a cycles fee (e.g. `fetch_canister_logs`) disallow
    /// them to avoid doing that work entirely for free.
    allow_free_cost_schedule_sender: bool,
    /// Due to the substantial complexity of this call, it must be counted toward the round limit.
    counts_toward_round_limit: bool,
    /// As this call modifies the canister state (changes to the cycles balance are ignored here),
    /// it must not be executed on an aborted canister.
    /// The only exception is `update_settings` to enable changing an aborted canister's compute allocation.
    does_not_run_on_aborted_canister: bool,
    /// The call installs a new canister code.
    installs_code: bool,
}

impl Ic00MethodPermissions {
    pub fn new(method: Ic00Method) -> Self {
        match method {
            Ic00Method::UpdateSettings => Self {
                method,
                allow_remote_subnet_sender: true,
                allow_only_nns_subnet_sender: false,
                allow_free_cost_schedule_sender: true,
                counts_toward_round_limit: true,
                does_not_run_on_aborted_canister: false,
                installs_code: false,
            },
            Ic00Method::CanisterStatus
            | Ic00Method::CanisterInfo
            | Ic00Method::CanisterMetadata
            // NOTE: `ListCanisters` does consume round instructions, but it has
            // no effective canister ID and therefore never reaches
            // `can_be_executed` (see `can_execute_subnet_msg` in `scheduler.rs`),
            // so `counts_toward_round_limit` is not consulted for it. Its
            // round-instruction deferral is handled by a dedicated special case
            // in `can_execute_subnet_msg` instead.
            | Ic00Method::ListCanisters
            | Ic00Method::DepositCycles
            | Ic00Method::ECDSAPublicKey
            | Ic00Method::SignWithECDSA
            | Ic00Method::SchnorrPublicKey
            | Ic00Method::SignWithSchnorr
            | Ic00Method::VetKdPublicKey
            | Ic00Method::VetKdDeriveKey
            | Ic00Method::BitcoinGetBalance
            | Ic00Method::BitcoinGetUtxos
            | Ic00Method::BitcoinGetBlockHeaders
            | Ic00Method::BitcoinSendTransaction
            | Ic00Method::BitcoinGetCurrentFeePercentiles
            | Ic00Method::BitcoinSendTransactionInternal
            | Ic00Method::BitcoinGetSuccessors
            | Ic00Method::NodeMetricsHistory
            | Ic00Method::SubnetInfo
            | Ic00Method::ProvisionalCreateCanisterWithCycles
            | Ic00Method::ProvisionalTopUpCanister
            | Ic00Method::StoredChunks
            | Ic00Method::ListCanisterSnapshots
            | Ic00Method::CanisterMetrics => Self {
                method,
                allow_remote_subnet_sender: true,
                allow_only_nns_subnet_sender: false,
                allow_free_cost_schedule_sender: true,
                counts_toward_round_limit: false,
                does_not_run_on_aborted_canister: false,
                installs_code: false,
            },
            // `fetch_canister_logs` charges no cycles fee; its cost is covered by
            // the message transmission and per-message execution fees the caller
            // pays. On a subnet with a "free" cost schedule the caller pays none of
            // those, so it would get the read work for free — hence it must not be
            // allowed to call it.
            Ic00Method::FetchCanisterLogs => Self {
                method,
                allow_remote_subnet_sender: true,
                allow_only_nns_subnet_sender: false,
                allow_free_cost_schedule_sender: false,
                counts_toward_round_limit: true,
                does_not_run_on_aborted_canister: false,
                installs_code: false,
            },
            Ic00Method::ReadCanisterSnapshotMetadata | Ic00Method::ReadCanisterSnapshotData => {
                Self {
                    method,
                    allow_remote_subnet_sender: true,
                    allow_only_nns_subnet_sender: false,
                    allow_free_cost_schedule_sender: true,
                    counts_toward_round_limit: true,
                    does_not_run_on_aborted_canister: false,
                    installs_code: false,
                }
            }
            Ic00Method::UploadChunk
            | Ic00Method::TakeCanisterSnapshot
            | Ic00Method::LoadCanisterSnapshot
            | Ic00Method::UploadCanisterSnapshotMetadata
            | Ic00Method::UploadCanisterSnapshotData => Self {
                method,
                allow_remote_subnet_sender: true,
                allow_only_nns_subnet_sender: false,
                allow_free_cost_schedule_sender: true,
                counts_toward_round_limit: true,
                does_not_run_on_aborted_canister: true,
                installs_code: false,
            },
            Ic00Method::StartCanister
            | Ic00Method::StopCanister
            | Ic00Method::UninstallCode
            | Ic00Method::ClearChunkStore
            | Ic00Method::DeleteCanisterSnapshot
            | Ic00Method::DeleteCanister => Self {
                method,
                allow_remote_subnet_sender: true,
                allow_only_nns_subnet_sender: false,
                allow_free_cost_schedule_sender: true,
                counts_toward_round_limit: false,
                does_not_run_on_aborted_canister: true,
                installs_code: false,
            },
            Ic00Method::CreateCanister
            | Ic00Method::HttpRequest
            | Ic00Method::FlexibleHttpRequest
            | Ic00Method::RawRand => Self {
                method,
                allow_remote_subnet_sender: false,
                allow_only_nns_subnet_sender: false,
                allow_free_cost_schedule_sender: true,
                counts_toward_round_limit: false,
                does_not_run_on_aborted_canister: false,
                installs_code: false,
            },
            Ic00Method::InstallCode | Ic00Method::InstallChunkedCode => Self {
                method,
                allow_remote_subnet_sender: true,
                allow_only_nns_subnet_sender: false,
                allow_free_cost_schedule_sender: true,
                counts_toward_round_limit: true,
                does_not_run_on_aborted_canister: true,
                // Only one install code message allowed at a time.
                installs_code: true,
            },
            Ic00Method::SetupInitialDKG | Ic00Method::ReshareChainKey => Self {
                method,
                allow_remote_subnet_sender: true,
                allow_only_nns_subnet_sender: true,
                allow_free_cost_schedule_sender: true,
                counts_toward_round_limit: false,
                does_not_run_on_aborted_canister: false,
                installs_code: false,
            },
            // Renaming a canister can only be called by NNS.
            Ic00Method::RenameCanister => Self {
                method,
                allow_remote_subnet_sender: true,
                allow_only_nns_subnet_sender: true,
                allow_free_cost_schedule_sender: true,
                counts_toward_round_limit: false,
                does_not_run_on_aborted_canister: true,
                installs_code: false,
            },
        }
    }

    /// Verifies all the rules defined for a management method.
    pub fn verify(&self, msg: &CanisterCall, state: &ReplicatedState) -> Result<(), UserError> {
        match msg {
            CanisterCall::Ingress(_) => Ok(()),
            CanisterCall::Request(msg) => match state.find_subnet_id(msg.sender().into()) {
                Ok(sender_subnet_id) => {
                    self.verify_caller_is_remote_subnet(sender_subnet_id, state)?;
                    self.verify_caller_is_nns_subnet(msg.sender(), sender_subnet_id, state)?;
                    self.verify_caller_is_not_on_free_cost_schedule(sender_subnet_id, state)?;
                    Ok(())
                }
                Err(err) => Err(err),
            },
        }
    }

    /// Checks if the caller is allowed to be on a remote subnet.
    fn verify_caller_is_remote_subnet(
        &self,
        sender_subnet_id: SubnetId,
        state: &ReplicatedState,
    ) -> Result<(), UserError> {
        if self.allow_remote_subnet_sender {
            return Ok(());
        }

        if sender_subnet_id == state.metadata.network_topology.nns_subnet_id
            || sender_subnet_id == state.metadata.own_subnet_id
        {
            Ok(())
        } else {
            Err(UserError::new(
                ErrorCode::CanisterContractViolation,
                format!(
                    "Incorrect sender subnet id: {sender_subnet_id}. Sender should be on the same subnet or on the NNS subnet."
                ),
            ))
        }
    }

    /// Checks if the NNS is the only subnet allowed to call the management method.
    fn verify_caller_is_nns_subnet(
        &self,
        sender_id: CanisterId,
        sender_subnet_id: SubnetId,
        state: &ReplicatedState,
    ) -> Result<(), UserError> {
        if !self.allow_only_nns_subnet_sender {
            return Ok(());
        }
        if sender_subnet_id != state.metadata.network_topology.nns_subnet_id {
            return Err(UserError::new(
                ErrorCode::CanisterContractViolation,
                format!(
                    "{} is called by {}. It can only be called by NNS.",
                    self.method, sender_id
                ),
            ));
        }
        Ok(())
    }

    /// Checks that the caller is on a subnet known to be on a normal (i.e. not
    /// "free") cost schedule, for methods that disallow free-schedule senders.
    ///
    /// A missing topology entry for the sender's subnet is treated as a failure
    /// too: we cannot confirm the sender is charged for the call, so we reject
    /// rather than risk doing the work for free.
    fn verify_caller_is_not_on_free_cost_schedule(
        &self,
        sender_subnet_id: SubnetId,
        state: &ReplicatedState,
    ) -> Result<(), UserError> {
        if self.allow_free_cost_schedule_sender {
            return Ok(());
        }
        if state
            .metadata
            .network_topology
            .get_cost_schedule(&sender_subnet_id)
            != Some(CanisterCyclesCostSchedule::Normal)
        {
            return Err(UserError::new(
                ErrorCode::CanisterContractViolation,
                format!(
                    "{} can only be called by a canister on a subnet with a normal cost schedule.",
                    self.method
                ),
            ));
        }
        Ok(())
    }

    pub(crate) fn can_be_executed(
        &self,
        instructions_reached: bool,
        ongoing_long_install_code: bool,
        effective_canister_is_aborted: bool,
    ) -> bool {
        !(self.counts_toward_round_limit && instructions_reached
            || self.does_not_run_on_aborted_canister && effective_canister_is_aborted
            || self.installs_code && ongoing_long_install_code)
    }

    pub fn counts_toward_round_limit(&self) -> bool {
        self.counts_toward_round_limit
    }
}
