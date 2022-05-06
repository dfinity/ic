use std::str::FromStr;

use candid::Decode;
use ic_base_types::{CanisterId, SubnetId};
use ic_ic00_types::{
    CanisterIdRecord, ComputeInitialEcdsaDealingsArgs, ECDSAPublicKeyArgs, EcdsaKeyId,
    InstallCodeArgs, Method as Ic00Method, Payload, ProvisionalTopUpCanisterArgs,
    SetControllerArgs, SignWithECDSAArgs, UpdateSettingsArgs,
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
        Ok(Ic00Method::BitcoinGetBalance)
        | Ok(Ic00Method::BitcoinGetUtxos)
        | Ok(Ic00Method::BitcoinSendTransaction)
        | Ok(Ic00Method::BitcoinGetCurrentFees) => {
            // TODO(EXC-939): Route requests to the appropriate subnet.
            // For now, we return our own subnet ID.
            Ok(own_subnet)
        }
        Ok(Ic00Method::ECDSAPublicKey) => {
            let key_id = Decode!(payload, ECDSAPublicKeyArgs)?.key_id;
            route_ecdsa_message(&key_id, network_topology, &None)
        }
        Ok(Ic00Method::SignWithECDSA) => {
            let key_id = Decode!(payload, SignWithECDSAArgs)?.key_id;
            route_ecdsa_message(&key_id, network_topology, &None)
        }
        Ok(Ic00Method::ComputeInitialEcdsaDealings) => {
            let args = Decode!(payload, ComputeInitialEcdsaDealingsArgs)?;
            route_ecdsa_message(&args.key_id, network_topology, &args.subnet_id)
        }
        Err(_) => Err(ResolveDestinationError::MethodNotFound(
            method_name.to_string(),
        )),
    }
}

/// Routes to the `requested_subnet` if it holds the key (and fails if that
/// subnet doesn't hold the key).  If a `requested_subnet` is not provided,
/// route to the first subnet enabled to sign with the given key.
fn route_ecdsa_message(
    key_id: &EcdsaKeyId,
    network_topology: &NetworkTopology,
    requested_subnet: &Option<SubnetId>,
) -> Result<SubnetId, ResolveDestinationError> {
    match requested_subnet {
        Some(subnet_id) => match network_topology.subnets.get(subnet_id) {
            None => Err(ResolveDestinationError::MethodNotFound(format!(
                "requested ECDSA key {} from unknown subnet {}",
                key_id, subnet_id
            ))),
            Some(subnet_topology) => {
                if subnet_topology.ecdsa_keys_held.contains(key_id) {
                    Ok(*subnet_id)
                } else {
                    Err(ResolveDestinationError::MethodNotFound(format!(
                        "requested ECDSA key {} on subnet {}, subnet has keys: {:?}",
                        key_id, subnet_id, subnet_topology.ecdsa_keys_held
                    )))
                }
            }
        },
        None => {
            if let Some(subnet_id) = network_topology.ecdsa_subnets(key_id).get(0) {
                Ok(*subnet_id)
            } else {
                Err(ResolveDestinationError::MethodNotFound(format!(
                    "requested ECDSA key: {}, existing keys: {:?}",
                    key_id, network_topology.ecdsa_keys
                )))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use candid::Encode;
    use ic_base_types::RegistryVersion;
    use ic_ic00_types::{
        ComputeInitialEcdsaDealingsArgs, EcdsaCurve, EcdsaKeyId, SignWithECDSAArgs,
    };
    use ic_replicated_state::SubnetTopology;
    use ic_test_utilities::types::ids::{node_test_id, subnet_test_id};
    use maplit::btreemap;

    use super::*;

    fn key_id() -> EcdsaKeyId {
        EcdsaKeyId {
            curve: EcdsaCurve::Secp256k1,
            name: "some_key".to_string(),
        }
    }

    /// Two subnets have the ECDSA key, but only one of the subnets is enabled
    /// to sign with it.
    fn network_with_ecdsa_subnets() -> NetworkTopology {
        let subnet_id0 = subnet_test_id(0);
        NetworkTopology {
            ecdsa_keys: btreemap! {
                key_id() => vec![subnet_id0],
            },
            subnets: btreemap! {
                subnet_id0 => SubnetTopology {
                    ecdsa_keys_held: vec![key_id()].into_iter().collect(),
                    ..SubnetTopology::default()
                },
                subnet_test_id(1) => SubnetTopology {
                    ecdsa_keys_held: vec![key_id()].into_iter().collect(),
                    ..SubnetTopology::default()
                },
                subnet_test_id(2) => SubnetTopology::default(),
            },
            ..NetworkTopology::default()
        }
    }

    fn network_without_ecdsa_subnet() -> NetworkTopology {
        NetworkTopology::default()
    }

    fn compute_initial_ecdsa_dealings_req(subnet_id: Option<SubnetId>) -> Vec<u8> {
        let args = ComputeInitialEcdsaDealingsArgs::new(
            key_id(),
            subnet_id,
            vec![node_test_id(0)].into_iter().collect(),
            RegistryVersion::from(100),
        );
        Encode!(&args).unwrap()
    }

    fn ecdsa_sign_req() -> Vec<u8> {
        let args = SignWithECDSAArgs {
            message_hash: vec![1; 32],
            derivation_path: vec![vec![0; 10]],
            key_id: key_id(),
        };
        Encode!(&args).unwrap()
    }

    #[test]
    fn resolve_compute_initial_ecdsa_dealings() {
        assert_eq!(
            resolve_destination(
                &network_with_ecdsa_subnets(),
                &Ic00Method::ComputeInitialEcdsaDealings.to_string(),
                &compute_initial_ecdsa_dealings_req(None),
                subnet_test_id(2),
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
                &compute_initial_ecdsa_dealings_req(None),
                subnet_test_id(2),
            )
            .unwrap_err(),
            ResolveDestinationError::MethodNotFound(err) => assert_eq!(
                err,
                format!("requested ECDSA key: {}, existing keys: {{}}", key_id())
            )
        )
    }

    #[test]
    fn resolve_compute_initial_ecdsa_dealings_with_subnet() {
        assert_eq!(
            resolve_destination(
                &network_with_ecdsa_subnets(),
                &Ic00Method::ComputeInitialEcdsaDealings.to_string(),
                &compute_initial_ecdsa_dealings_req(Some(subnet_test_id(1))),
                subnet_test_id(2),
            )
            .unwrap(),
            subnet_test_id(1)
        )
    }

    #[test]
    fn resolve_compute_initial_ecdsa_dealings_wrong_subnet_error() {
        assert_matches!(
                resolve_destination(
                    &network_with_ecdsa_subnets(),
                    &Ic00Method::ComputeInitialEcdsaDealings.to_string(),
                    // Subnet 2 doesn't have the requested key.
                    &compute_initial_ecdsa_dealings_req(Some(subnet_test_id(2))),
                    subnet_test_id(2),
                )
                .unwrap_err(),
                ResolveDestinationError::MethodNotFound(err) => assert_eq!(
                    err,
                    format!("requested ECDSA key {} on subnet {}, subnet has keys: {{}}",
                        key_id(),
                        subnet_test_id(2),
                )
            )
        )
    }

    #[test]
    fn resolve_compute_initial_ecdsa_dealings_subnet_not_found_error() {
        assert_matches!(
                resolve_destination(
                    &network_with_ecdsa_subnets(),
                    &Ic00Method::ComputeInitialEcdsaDealings.to_string(),
                    // Subnet 3 doesn't exist
                    &compute_initial_ecdsa_dealings_req(Some(subnet_test_id(3))),
                    subnet_test_id(2),
                )
                .unwrap_err(),
                ResolveDestinationError::MethodNotFound(err) => assert_eq!(
                    err,
                    format!("requested ECDSA key {} from unknown subnet {}",
                        key_id(),
                        subnet_test_id(3),
                )
            )
        )
    }

    #[test]
    fn resolve_ecdsa_sign() {
        assert_eq!(
            resolve_destination(
                &network_with_ecdsa_subnets(),
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
                format!("requested ECDSA key: {}, existing keys: {{}}", key_id())
            )
        )
    }
}
