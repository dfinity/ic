use ic_error_types::{ErrorCode, UserError};
use ic_management_canister_types::Method as Ic00Method;
use ic_replicated_state::ReplicatedState;
use ic_types::messages::CanisterCall;
use ic_types::{CanisterId, SubnetId};

/// Keeps track of when an IC00 method is allowed to be executed.
#[derive(PartialEq, Eq)]
pub(crate) struct Ic00MethodPermissions {
    method: Ic00Method,

    /// Call initiated by a remote subnet.
    allow_remote_subnet_sender: bool,
    /// Call initiated only by the NNS subnet.
    allow_only_nns_subnet_sender: bool,
}

impl Ic00MethodPermissions {
    pub fn new(method: Ic00Method) -> Self {
        match method {
            Ic00Method::SignWithECDSA => Self {
                method,
                allow_remote_subnet_sender: true,
                allow_only_nns_subnet_sender: false,
            },
            Ic00Method::CanisterStatus => Self {
                method,
                allow_remote_subnet_sender: true,
                allow_only_nns_subnet_sender: false,
            },
            Ic00Method::CanisterInfo => Self {
                method,
                allow_remote_subnet_sender: true,
                allow_only_nns_subnet_sender: false,
            },
            Ic00Method::CreateCanister => Self {
                method,
                allow_remote_subnet_sender: false,
                allow_only_nns_subnet_sender: false,
            },
            Ic00Method::DeleteCanister => Self {
                method,
                allow_remote_subnet_sender: true,
                allow_only_nns_subnet_sender: false,
            },
            Ic00Method::DepositCycles => Self {
                method,
                allow_remote_subnet_sender: true,
                allow_only_nns_subnet_sender: false,
            },
            Ic00Method::HttpRequest => Self {
                method,
                allow_remote_subnet_sender: false,
                allow_only_nns_subnet_sender: false,
            },
            Ic00Method::ECDSAPublicKey => Self {
                method,
                allow_remote_subnet_sender: true,
                allow_only_nns_subnet_sender: false,
            },
            Ic00Method::InstallCode => Self {
                method,
                allow_remote_subnet_sender: true,
                allow_only_nns_subnet_sender: false,
            },
            Ic00Method::InstallChunkedCode => Self {
                method,
                allow_remote_subnet_sender: true,
                allow_only_nns_subnet_sender: false,
            },
            Ic00Method::RawRand => Self {
                method,
                allow_remote_subnet_sender: false,
                allow_only_nns_subnet_sender: false,
            },
            Ic00Method::SetupInitialDKG => Self {
                method,
                allow_remote_subnet_sender: true,
                allow_only_nns_subnet_sender: true,
            },
            Ic00Method::StartCanister => Self {
                method,
                allow_remote_subnet_sender: true,
                allow_only_nns_subnet_sender: false,
            },
            Ic00Method::StopCanister => Self {
                method,
                allow_remote_subnet_sender: true,
                allow_only_nns_subnet_sender: false,
            },
            Ic00Method::UninstallCode => Self {
                method,
                allow_remote_subnet_sender: true,
                allow_only_nns_subnet_sender: false,
            },
            Ic00Method::UpdateSettings => Self {
                method,
                allow_remote_subnet_sender: true,
                allow_only_nns_subnet_sender: false,
            },
            Ic00Method::ComputeInitialIDkgDealings => Self {
                method,
                allow_remote_subnet_sender: true,
                allow_only_nns_subnet_sender: true,
            },
            Ic00Method::SchnorrPublicKey => Self {
                method,
                allow_remote_subnet_sender: true,
                allow_only_nns_subnet_sender: false,
            },
            Ic00Method::SignWithSchnorr => Self {
                method,
                allow_remote_subnet_sender: true,
                allow_only_nns_subnet_sender: false,
            },
            Ic00Method::BitcoinGetBalance => Self {
                method,
                allow_remote_subnet_sender: true,
                allow_only_nns_subnet_sender: false,
            },
            Ic00Method::BitcoinGetUtxos => Self {
                method,
                allow_remote_subnet_sender: true,
                allow_only_nns_subnet_sender: false,
            },
            Ic00Method::BitcoinGetBlockHeaders => Self {
                method,
                allow_remote_subnet_sender: true,
                allow_only_nns_subnet_sender: false,
            },
            Ic00Method::BitcoinSendTransaction => Self {
                method,
                allow_remote_subnet_sender: true,
                allow_only_nns_subnet_sender: false,
            },
            Ic00Method::BitcoinGetCurrentFeePercentiles => Self {
                method,
                allow_remote_subnet_sender: true,
                allow_only_nns_subnet_sender: false,
            },
            Ic00Method::BitcoinSendTransactionInternal => Self {
                method,
                allow_remote_subnet_sender: true,
                allow_only_nns_subnet_sender: false,
            },
            Ic00Method::BitcoinGetSuccessors => Self {
                method,
                allow_remote_subnet_sender: true,
                allow_only_nns_subnet_sender: false,
            },
            Ic00Method::NodeMetricsHistory => Self {
                method,
                allow_remote_subnet_sender: true,
                allow_only_nns_subnet_sender: false,
            },
            Ic00Method::FetchCanisterLogs => Self {
                method,
                // `FetchCanisterLogs` method is only allowed for messages sent by users,
                // all inter-canister call permissions are irrelevant and therefore set to false.
                allow_remote_subnet_sender: false,
                allow_only_nns_subnet_sender: false,
            },
            Ic00Method::ProvisionalCreateCanisterWithCycles => Self {
                method,
                allow_remote_subnet_sender: true,
                allow_only_nns_subnet_sender: false,
            },
            Ic00Method::ProvisionalTopUpCanister => Self {
                method,
                allow_remote_subnet_sender: true,
                allow_only_nns_subnet_sender: false,
            },
            Ic00Method::UploadChunk | Ic00Method::StoredChunks | Ic00Method::ClearChunkStore => {
                Self {
                    method,
                    allow_remote_subnet_sender: true,
                    allow_only_nns_subnet_sender: false,
                }
            }
            Ic00Method::TakeCanisterSnapshot
            | Ic00Method::LoadCanisterSnapshot
            | Ic00Method::ListCanisterSnapshots
            | Ic00Method::DeleteCanisterSnapshot => Self {
                method,
                allow_remote_subnet_sender: true,
                allow_only_nns_subnet_sender: false,
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
                format!("Incorrect sender subnet id: {sender_subnet_id}. Sender should be on the same subnet or on the NNS subnet."),
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
}
