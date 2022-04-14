use std::str::FromStr;

use candid::Decode;
use ic_base_types::{CanisterId, SubnetId};
use ic_ic00_types::{
    CanisterIdRecord, ComputeInitialEcdsaDealingsArgs, ECDSAPublicKeyArgs, InstallCodeArgs,
    Method as Ic00Method, Payload, ProvisionalTopUpCanisterArgs, SetControllerArgs,
    SignWithECDSAArgs, UpdateSettingsArgs,
};
use ic_replicated_state::NetworkTopology;

#[derive(Debug)]
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
        Ok(Ic00Method::ECDSAPublicKey) => {
            let key_id = Decode!(payload, ECDSAPublicKeyArgs)?.key_id;
            route_ecdsa_message(&key_id, network_topology)
        }
        Ok(Ic00Method::SignWithECDSA) => {
            let key_id = Decode!(payload, SignWithECDSAArgs)?.key_id;
            route_ecdsa_message(&key_id, network_topology)
        }
        Ok(Ic00Method::ComputeInitialEcdsaDealings) => {
            let key_id = Decode!(payload, ComputeInitialEcdsaDealingsArgs)?.key_id;
            route_ecdsa_message(&key_id, network_topology)
        }
        Err(_) => Err(ResolveDestinationError::MethodNotFound(
            method_name.to_string(),
        )),
    }
}

fn route_ecdsa_message(
    key_id: &str,
    network_topology: &NetworkTopology,
) -> Result<SubnetId, ResolveDestinationError> {
    if let Some(subnet_id) = network_topology.ecdsa_subnets(key_id).get(0) {
        Ok(*subnet_id)
    } else {
        Err(ResolveDestinationError::MethodNotFound(format!(
            "requested key: {}, existing keys: {:?}",
            key_id, network_topology.ecdsa_keys
        )))
    }
}

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use candid::Encode;
    use ic_base_types::RegistryVersion;
    use ic_ic00_types::{ComputeInitialEcdsaDealingsArgs, SignWithECDSAArgs};
    use ic_test_utilities::types::ids::{node_test_id, subnet_test_id};
    use maplit::btreemap;

    use super::*;

    const KEY_ID: &str = "some_key";

    fn network_with_ecdsa_on_subnet_0() -> NetworkTopology {
        let subnet_id = subnet_test_id(0);
        NetworkTopology {
            ecdsa_keys: btreemap! {
                KEY_ID.to_string() => vec![subnet_id],
            },
            ..NetworkTopology::default()
        }
    }

    fn network_without_ecdsa_subnet() -> NetworkTopology {
        NetworkTopology::default()
    }

    fn compute_initial_ecdsa_dealings_req() -> Vec<u8> {
        let args = ComputeInitialEcdsaDealingsArgs::new(
            KEY_ID.to_string(),
            vec![node_test_id(0)].into_iter().collect(),
            RegistryVersion::from(100),
        );
        Encode!(&args).unwrap()
    }

    fn ecdsa_sign_req() -> Vec<u8> {
        let args = SignWithECDSAArgs {
            message_hash: vec![1; 32],
            derivation_path: vec![vec![0; 10]],
            key_id: KEY_ID.to_string(),
        };
        Encode!(&args).unwrap()
    }

    #[test]
    fn resolve_compute_initial_ecdsa_dealings() {
        assert_eq!(
            resolve_destination(
                &network_with_ecdsa_on_subnet_0(),
                &Ic00Method::ComputeInitialEcdsaDealings.to_string(),
                &compute_initial_ecdsa_dealings_req(),
                subnet_test_id(1),
            )
            .unwrap(),
            subnet_test_id(0)
        )
    }

    #[test]
    fn resolve_compute_initial_ecdsa_dealings_error() {
        assert_matches!(
            resolve_destination(
                &network_without_ecdsa_subnet(),
                &Ic00Method::ComputeInitialEcdsaDealings.to_string(),
                &compute_initial_ecdsa_dealings_req(),
                subnet_test_id(1),
            )
            .unwrap_err(),
            ResolveDestinationError::MethodNotFound(err) => assert_eq!(
                err,
                format!("requested key: {}, existing keys: {{}}", KEY_ID)
            )
        )
    }

    #[test]
    fn resolve_ecdsa_sign() {
        assert_eq!(
            resolve_destination(
                &network_with_ecdsa_on_subnet_0(),
                &Ic00Method::SignWithECDSA.to_string(),
                &ecdsa_sign_req(),
                subnet_test_id(1),
            )
            .unwrap(),
            subnet_test_id(0)
        )
    }

    #[test]
    fn resolve_ecdsa_sign_error() {
        assert_matches!(resolve_destination(
            &network_without_ecdsa_subnet(),
            &Ic00Method::SignWithECDSA.to_string(),
            &ecdsa_sign_req(),
            subnet_test_id(1),
        )
        .unwrap_err(),
        ResolveDestinationError::MethodNotFound(err) => assert_eq!(
                err,
                format!("requested key: {}, existing keys: {{}}", KEY_ID)
            )
        )
    }
}
