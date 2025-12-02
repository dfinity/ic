use ic_error_types::{ErrorCode, UserError};
use ic_management_canister_types_private::Method as Ic00Method;
use ic_replicated_state::ReplicatedState;
use ic_types::messages::CanisterCall;
use ic_types::{CanisterId, SubnetId};

/// Keeps track of when an IC00 method is allowed to be executed.
#[derive(Eq, PartialEq)]
pub(crate) struct Ic00MethodPermissions {
    method: Ic00Method,

    /// Call initiated by a remote subnet.
    allow_remote_subnet_sender: bool,
    /// Call initiated only by the NNS subnet.
    allow_only_nns_subnet_sender: bool,
    /// Due to the substantial complexity of this call, it must be counted toward the round limit.
    counts_toward_round_limit: bool,
    /// As this call modifies the canister state, it must not be executed on an aborted canister.
    does_not_run_on_aborted_canister: bool,
    /// The call installs a new canister code.
    installs_code: bool,
}

impl Ic00MethodPermissions {
    pub fn new(method: Ic00Method) -> Self {
        match method {
            Ic00Method::CanisterStatus
            | Ic00Method::CanisterInfo
            | Ic00Method::CanisterMetadata
            | Ic00Method::DepositCycles
            | Ic00Method::ECDSAPublicKey
            | Ic00Method::SignWithECDSA
            | Ic00Method::StartCanister
            | Ic00Method::UninstallCode
            | Ic00Method::UpdateSettings
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
            | Ic00Method::ClearChunkStore
            | Ic00Method::ListCanisterSnapshots
            | Ic00Method::DeleteCanisterSnapshot
            | Ic00Method::ReadCanisterSnapshotMetadata
            | Ic00Method::ReadCanisterSnapshotData
            | Ic00Method::UploadCanisterSnapshotMetadata
            | Ic00Method::UploadCanisterSnapshotData => Self {
                method,
                allow_remote_subnet_sender: true,
                allow_only_nns_subnet_sender: false,
                counts_toward_round_limit: false,
                does_not_run_on_aborted_canister: false,
                installs_code: false,
            },
            Ic00Method::CreateCanister | Ic00Method::HttpRequest | Ic00Method::RawRand => Self {
                method,
                allow_remote_subnet_sender: false,
                allow_only_nns_subnet_sender: false,
                counts_toward_round_limit: false,
                does_not_run_on_aborted_canister: false,
                installs_code: false,
            },
            Ic00Method::DeleteCanister | Ic00Method::StopCanister => Self {
                method,
                allow_remote_subnet_sender: true,
                allow_only_nns_subnet_sender: false,
                counts_toward_round_limit: false,
                // Deleting an aborted canister requires to stop it first.
                // Stopping an aborted canister does not generate a reply.
                does_not_run_on_aborted_canister: true,
                installs_code: false,
            },
            Ic00Method::InstallCode | Ic00Method::InstallChunkedCode => Self {
                method,
                allow_remote_subnet_sender: true,
                allow_only_nns_subnet_sender: false,
                counts_toward_round_limit: true,
                does_not_run_on_aborted_canister: true,
                // Only one install code message allowed at a time.
                installs_code: true,
            },
            Ic00Method::SetupInitialDKG
            | Ic00Method::ReshareChainKey
            | Ic00Method::RenameCanister => Self {
                method,
                allow_remote_subnet_sender: true,
                allow_only_nns_subnet_sender: true,
                counts_toward_round_limit: false,
                does_not_run_on_aborted_canister: false,
                installs_code: false,
            },
            Ic00Method::FetchCanisterLogs => Self {
                method,
                // `FetchCanisterLogs` disallows inter-canister calls by default.
                // A feature flag can enable them, so permissions are preset here,
                // while the actual handling is done elsewhere.
                allow_remote_subnet_sender: true,
                allow_only_nns_subnet_sender: false,
                counts_toward_round_limit: true,
                does_not_run_on_aborted_canister: true,
                installs_code: false,
            },
            Ic00Method::UploadChunk | Ic00Method::TakeCanisterSnapshot => Self {
                method,
                allow_remote_subnet_sender: true,
                allow_only_nns_subnet_sender: false,
                counts_toward_round_limit: true,
                does_not_run_on_aborted_canister: false,
                installs_code: false,
            },
            Ic00Method::LoadCanisterSnapshot => Self {
                method,
                allow_remote_subnet_sender: true,
                allow_only_nns_subnet_sender: false,
                // Loading a snapshot is similar to the install code.
                counts_toward_round_limit: true,
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
}
