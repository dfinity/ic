use ic_error_types::{ErrorCode, UserError};
use ic_ic00_types::Method as Ic00Method;
use ic_replicated_state::ReplicatedState;
use ic_types::messages::Request;

/// Keeps track of when an IC00 method is allowed to be executed.
#[derive(PartialEq, Eq)]
pub(crate) struct Ic00MethodPermissions {
    /// Call initiated by a remote subnet.
    allow_remote_subnet_sender: bool,
}

impl Ic00MethodPermissions {
    pub fn new(method_type: Ic00Method) -> Self {
        match method_type {
            Ic00Method::SignWithECDSA => Self {
                allow_remote_subnet_sender: true,
            },
            Ic00Method::CanisterStatus => Self {
                allow_remote_subnet_sender: true,
            },
            Ic00Method::CanisterInfo => Self {
                allow_remote_subnet_sender: true,
            },
            Ic00Method::CreateCanister => Self {
                allow_remote_subnet_sender: false,
            },
            Ic00Method::DeleteCanister => Self {
                allow_remote_subnet_sender: true,
            },
            Ic00Method::DepositCycles => Self {
                allow_remote_subnet_sender: true,
            },
            Ic00Method::HttpRequest => Self {
                allow_remote_subnet_sender: false,
            },
            Ic00Method::ECDSAPublicKey => Self {
                allow_remote_subnet_sender: true,
            },
            Ic00Method::InstallCode => Self {
                allow_remote_subnet_sender: true,
            },
            Ic00Method::RawRand => Self {
                allow_remote_subnet_sender: false,
            },
            Ic00Method::SetController => Self {
                allow_remote_subnet_sender: true,
            },
            Ic00Method::SetupInitialDKG => Self {
                allow_remote_subnet_sender: true,
            },
            Ic00Method::StartCanister => Self {
                allow_remote_subnet_sender: true,
            },
            Ic00Method::StopCanister => Self {
                allow_remote_subnet_sender: true,
            },
            Ic00Method::UninstallCode => Self {
                allow_remote_subnet_sender: true,
            },
            Ic00Method::UpdateSettings => Self {
                allow_remote_subnet_sender: true,
            },
            Ic00Method::ComputeInitialEcdsaDealings => Self {
                allow_remote_subnet_sender: true,
            },
            Ic00Method::BitcoinGetBalance => Self {
                allow_remote_subnet_sender: true,
            },
            Ic00Method::BitcoinGetUtxos => Self {
                allow_remote_subnet_sender: true,
            },
            Ic00Method::BitcoinSendTransaction => Self {
                allow_remote_subnet_sender: true,
            },
            Ic00Method::BitcoinGetCurrentFeePercentiles => Self {
                allow_remote_subnet_sender: true,
            },
            Ic00Method::BitcoinSendTransactionInternal => Self {
                allow_remote_subnet_sender: true,
            },
            Ic00Method::BitcoinGetSuccessors => Self {
                allow_remote_subnet_sender: true,
            },
            Ic00Method::ProvisionalCreateCanisterWithCycles => Self {
                allow_remote_subnet_sender: true,
            },
            Ic00Method::ProvisionalTopUpCanister => Self {
                allow_remote_subnet_sender: true,
            },
        }
    }

    /// Checks if the caller is allowed to be on a remote subnet.
    pub fn verify_sender_id(
        &self,
        msg: &Request,
        state: &ReplicatedState,
    ) -> Result<(), UserError> {
        if self.allow_remote_subnet_sender {
            return Ok(());
        }

        match state.find_subnet_id(msg.sender().get()) {
            Ok(sender_subnet_id) => {
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
            Err(err) => Err(err),
        }
    }
}
