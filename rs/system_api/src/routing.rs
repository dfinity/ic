use std::str::FromStr;

use candid::Decode;
use ic_base_types::{CanisterId, SubnetId};
use ic_ic00_types::{
    CanisterIdRecord, InstallCodeArgs, Method as Ic00Method, Payload, ProvisionalTopUpCanisterArgs,
    SetControllerArgs, UpdateSettingsArgs,
};
use ic_replicated_state::NetworkTopology;

pub(super) enum ResolveDestinationError {
    CandidError(candid::Error),
    MethodNotFound(String),
    SubnetNotFound(CanisterId, Ic00Method),
}

impl From<candid::Error> for ResolveDestinationError {
    fn from(err: candid::Error) -> Self {
        ResolveDestinationError::CandidError(err)
    }
}

/// Inspect the method name and payload of a request to ic:00 to figure out to
/// which subnet it should be sent to.
pub(super) fn resolve_destination(
    network_topology: &NetworkTopology,
    method_name: &str,
    payload: &[u8],
    own_subnet: SubnetId,
) -> Result<SubnetId, ResolveDestinationError> {
    // Figure out the destination subnet based on the method and the payload.
    let method = Ic00Method::from_str(method_name);
    match method {
        Ok(Ic00Method::CreateCanister)
        | Ok(Ic00Method::RawRand)
        | Ok(Ic00Method::ProvisionalCreateCanisterWithCycles)
        | Ok(Ic00Method::ECDSAPublicKey)
        | Ok(Ic00Method::SignWithECDSA)
        | Ok(Ic00Method::HttpRequest) => Ok(own_subnet),
        // This message needs to be routed to the NNS subnet.  We assume that
        // this message can only be sent by canisters on the NNS subnet hence
        // returning `own_subnet` here is fine.
        //
        // It might be cleaner to pipe in the actual NNS subnet id to this
        // function and return that instead.
        Ok(Ic00Method::SetupInitialDKG) => Ok(own_subnet),
        Ok(Ic00Method::UpdateSettings) => {
            // Find the destination canister from the payload.
            let args = Decode!(payload, UpdateSettingsArgs)?;
            let canister_id = args.get_canister_id();
            network_topology
                .routing_table
                .route(canister_id.get())
                .ok_or({
                    ResolveDestinationError::SubnetNotFound(canister_id, Ic00Method::UpdateSettings)
                })
        }
        Ok(Ic00Method::InstallCode) => {
            // Find the destination canister from the payload.
            let args = Decode!(payload, InstallCodeArgs)?;
            let canister_id = args.get_canister_id();
            network_topology
                .routing_table
                .route(canister_id.get())
                .ok_or({
                    ResolveDestinationError::SubnetNotFound(canister_id, Ic00Method::InstallCode)
                })
        }
        Ok(Ic00Method::SetController) => {
            let args = Decode!(payload, SetControllerArgs)?;
            let canister_id = args.get_canister_id();
            network_topology
                .routing_table
                .route(canister_id.get())
                .ok_or({
                    ResolveDestinationError::SubnetNotFound(canister_id, Ic00Method::SetController)
                })
        }
        Ok(Ic00Method::CanisterStatus)
        | Ok(Ic00Method::StartCanister)
        | Ok(Ic00Method::StopCanister)
        | Ok(Ic00Method::DeleteCanister)
        | Ok(Ic00Method::UninstallCode)
        | Ok(Ic00Method::DepositCycles) => {
            let args = Decode!(payload, CanisterIdRecord)?;
            let canister_id = args.get_canister_id();
            network_topology
                .routing_table
                .route(canister_id.get())
                .ok_or_else(|| {
                    ResolveDestinationError::SubnetNotFound(canister_id, method.unwrap())
                })
        }
        Ok(Ic00Method::ProvisionalTopUpCanister) => {
            let args = ProvisionalTopUpCanisterArgs::decode(payload)?;
            let canister_id = args.get_canister_id();
            network_topology
                .routing_table
                .route(canister_id.get())
                .ok_or({
                    ResolveDestinationError::SubnetNotFound(
                        canister_id,
                        Ic00Method::ProvisionalTopUpCanister,
                    )
                })
        }
        Ok(Ic00Method::BitcoinTestnetGetBalance)
        | Ok(Ic00Method::BitcoinTestnetGetUtxos)
        | Ok(Ic00Method::BitcoinTestnetSendTransaction) => {
            // TODO(EXC-939): Route requests to the appropriate subnet.
            // For now, we return our own subnet ID.
            Ok(own_subnet)
        }
        Err(_) => Err(ResolveDestinationError::MethodNotFound(
            method_name.to_string(),
        )),
    }
}
