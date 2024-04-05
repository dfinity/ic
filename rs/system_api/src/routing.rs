use std::str::FromStr;
use std::{collections::BTreeSet, fmt::Write};

use ic_base_types::{CanisterId, PrincipalId, SubnetId};
use ic_btc_interface::NetworkInRequest as BitcoinNetwork;
use ic_error_types::UserError;
use ic_management_canister_types::{
    BitcoinGetBalanceArgs, BitcoinGetCurrentFeePercentilesArgs, BitcoinGetUtxosArgs,
    BitcoinSendTransactionArgs, CanisterIdRecord, CanisterInfoRequest, ClearChunkStoreArgs,
    ComputeInitialEcdsaDealingsArgs, ECDSAPublicKeyArgs, EcdsaKeyId, InstallChunkedCodeArgs,
    InstallCodeArgsV2, Method as Ic00Method, NodeMetricsHistoryArgs, Payload,
    ProvisionalTopUpCanisterArgs, SignWithECDSAArgs, StoredChunksArgs, UninstallCodeArgs,
    UpdateSettingsArgs, UploadChunkArgs,
};
use ic_replicated_state::NetworkTopology;

#[derive(Debug)]
#[allow(dead_code)]
// The fields are only read by the `Debug` implementation.
// The `dead_code` lint ignores `Debug` impls, see: https://github.com/rust-lang/rust/issues/88900.
pub(super) enum ResolveDestinationError {
    UserError(UserError),
    MethodNotFound(String),
    SubnetNotFound(CanisterId, Ic00Method),
    AlreadyResolved(PrincipalId),
    EcdsaKeyError(String),
}

impl From<UserError> for ResolveDestinationError {
    fn from(err: UserError) -> Self {
        ResolveDestinationError::UserError(err)
    }
}

/// Inspect the method name and payload of a request to ic:00 to figure out to
/// which subnet it should be sent to.
pub(super) fn resolve_destination(
    network_topology: &NetworkTopology,
    method_name: &str,
    payload: &[u8],
    own_subnet: SubnetId,
) -> Result<PrincipalId, ResolveDestinationError> {
    // Figure out the destination subnet based on the method and the payload.
    let method = Ic00Method::from_str(method_name);
    match method {
        Ok(Ic00Method::CreateCanister)
        | Ok(Ic00Method::RawRand)
        | Ok(Ic00Method::ProvisionalCreateCanisterWithCycles)
        | Ok(Ic00Method::HttpRequest)
        | Ok(Ic00Method::BitcoinSendTransactionInternal)
        | Ok(Ic00Method::BitcoinGetSuccessors) => Ok(own_subnet.get()),
        // This message needs to be routed to the NNS subnet.  We assume that
        // this message can only be sent by canisters on the NNS subnet hence
        // returning `own_subnet` here is fine.
        //
        // It might be cleaner to pipe in the actual NNS subnet id to this
        // function and return that instead.
        Ok(Ic00Method::SetupInitialDKG) => Ok(own_subnet.get()),
        Ok(Ic00Method::UpdateSettings) => {
            // Find the destination canister from the payload.
            let args = UpdateSettingsArgs::decode(payload)?;
            let canister_id = args.get_canister_id();

            network_topology
                .routing_table
                .route(canister_id.get())
                .map(|subnet_id| subnet_id.get())
                .ok_or({
                    ResolveDestinationError::SubnetNotFound(canister_id, Ic00Method::UpdateSettings)
                })
        }
        Ok(Ic00Method::InstallCode) => {
            // Find the destination canister from the payload.
            let args = InstallCodeArgsV2::decode(payload)?;
            let canister_id = args.get_canister_id();
            network_topology
                .routing_table
                .route(canister_id.get())
                .map(|subnet_id| subnet_id.get())
                .ok_or({
                    ResolveDestinationError::SubnetNotFound(canister_id, Ic00Method::InstallCode)
                })
        }
        Ok(Ic00Method::InstallChunkedCode) => {
            // Find the destination canister from the payload.
            let args = InstallChunkedCodeArgs::decode(payload)?;
            let canister_id = args.target_canister_id();
            network_topology
                .routing_table
                .route(canister_id.get())
                .map(|subnet_id| subnet_id.get())
                .ok_or({
                    ResolveDestinationError::SubnetNotFound(canister_id, Ic00Method::InstallCode)
                })
        }
        Ok(Ic00Method::CanisterStatus)
        | Ok(Ic00Method::StartCanister)
        | Ok(Ic00Method::StopCanister)
        | Ok(Ic00Method::DeleteCanister)
        | Ok(Ic00Method::DepositCycles) => {
            let args = CanisterIdRecord::decode(payload)?;
            let canister_id = args.get_canister_id();
            network_topology
                .routing_table
                .route(canister_id.get())
                .map(|subnet_id| subnet_id.get())
                .ok_or_else(|| {
                    ResolveDestinationError::SubnetNotFound(canister_id, method.unwrap())
                })
        }
        Ok(Ic00Method::CanisterInfo) => {
            let args = CanisterInfoRequest::decode(payload)?;
            let canister_id = args.canister_id();
            network_topology
                .routing_table
                .route(canister_id.get())
                .map(|subnet_id| subnet_id.get())
                .ok_or_else(|| {
                    ResolveDestinationError::SubnetNotFound(canister_id, method.unwrap())
                })
        }
        Ok(Ic00Method::UninstallCode) => {
            let args = UninstallCodeArgs::decode(payload)?;
            let canister_id = args.get_canister_id();
            network_topology
                .routing_table
                .route(canister_id.get())
                .map(|subnet_id| subnet_id.get())
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
                .map(|subnet_id| subnet_id.get())
                .ok_or({
                    ResolveDestinationError::SubnetNotFound(
                        canister_id,
                        Ic00Method::ProvisionalTopUpCanister,
                    )
                })
        }
        Ok(Ic00Method::BitcoinGetBalance) => {
            let args = BitcoinGetBalanceArgs::decode(payload)?;
            Ok(route_bitcoin_message(
                args.network,
                network_topology,
                own_subnet,
            ))
        }
        Ok(Ic00Method::BitcoinGetUtxos) => {
            let args = BitcoinGetUtxosArgs::decode(payload)?;
            Ok(route_bitcoin_message(
                args.network,
                network_topology,
                own_subnet,
            ))
        }
        Ok(Ic00Method::BitcoinSendTransaction) => {
            let args = BitcoinSendTransactionArgs::decode(payload)?;

            Ok(route_bitcoin_message(
                args.network,
                network_topology,
                own_subnet,
            ))
        }
        Ok(Ic00Method::BitcoinGetCurrentFeePercentiles) => {
            let args = BitcoinGetCurrentFeePercentilesArgs::decode(payload)?;
            Ok(route_bitcoin_message(
                args.network,
                network_topology,
                own_subnet,
            ))
        }
        Ok(Ic00Method::NodeMetricsHistory) => {
            Ok(NodeMetricsHistoryArgs::decode(payload)?.subnet_id)
        }
        Ok(Ic00Method::FetchCanisterLogs) => {
            // TODO(IC-272).
            Err(ResolveDestinationError::UserError(UserError::new(
                ic_error_types::ErrorCode::CanisterRejectedMessage,
                format!(
                    "{} API is not yet implemented",
                    Ic00Method::FetchCanisterLogs
                ),
            )))
        }
        Ok(Ic00Method::ECDSAPublicKey) => {
            let key_id = ECDSAPublicKeyArgs::decode(payload)?.key_id;
            route_ecdsa_message(
                &key_id,
                network_topology,
                &None,
                EcdsaSubnetKind::OnlyHoldsKey,
            )
        }
        Ok(Ic00Method::SignWithECDSA) => {
            let key_id = SignWithECDSAArgs::decode(payload)?.key_id;
            route_ecdsa_message(
                &key_id,
                network_topology,
                &None,
                EcdsaSubnetKind::HoldsAndSignWithKey,
            )
        }
        Ok(Ic00Method::ComputeInitialEcdsaDealings) => {
            let args = ComputeInitialEcdsaDealingsArgs::decode(payload)?;
            route_ecdsa_message(
                &args.key_id,
                network_topology,
                &Some(args.subnet_id),
                EcdsaSubnetKind::OnlyHoldsKey,
            )
        }
        Ok(Ic00Method::UploadChunk) => {
            let args = UploadChunkArgs::decode(payload)?;
            let canister_id = args.get_canister_id();
            network_topology
                .routing_table
                .route(canister_id.get())
                .map(|subnet_id| subnet_id.get())
                .ok_or({
                    ResolveDestinationError::SubnetNotFound(canister_id, Ic00Method::UploadChunk)
                })
        }
        Ok(Ic00Method::ClearChunkStore) => {
            let args = ClearChunkStoreArgs::decode(payload)?;
            let canister_id = args.get_canister_id();
            network_topology
                .routing_table
                .route(canister_id.get())
                .map(|subnet_id| subnet_id.get())
                .ok_or({
                    ResolveDestinationError::SubnetNotFound(
                        canister_id,
                        Ic00Method::ClearChunkStore,
                    )
                })
        }
        Ok(Ic00Method::StoredChunks) => {
            let args = StoredChunksArgs::decode(payload)?;
            let canister_id = args.get_canister_id();
            network_topology
                .routing_table
                .route(canister_id.get())
                .map(|subnet_id| subnet_id.get())
                .ok_or({
                    ResolveDestinationError::SubnetNotFound(canister_id, Ic00Method::StoredChunks)
                })
        }
        Ok(Ic00Method::DeleteChunks) => Err(ResolveDestinationError::UserError(UserError::new(
            ic_error_types::ErrorCode::CanisterRejectedMessage,
            "Delete chunks API is not yet implemented",
        ))),
        Ok(Ic00Method::TakeCanisterSnapshot)
        | Ok(Ic00Method::LoadCanisterSnapshot)
        | Ok(Ic00Method::ListCanisterSnapshots)
        | Ok(Ic00Method::DeleteCanisterSnapshot) => {
            Err(ResolveDestinationError::UserError(UserError::new(
                ic_error_types::ErrorCode::CanisterRejectedMessage,
                "Snapshotting API is not yet implemented",
            )))
        }
        Err(_) => Err(ResolveDestinationError::MethodNotFound(
            method_name.to_string(),
        )),
    }
}

enum EcdsaSubnetKind {
    OnlyHoldsKey,
    HoldsAndSignWithKey,
}

/// Routes to the `requested_subnet` if it holds the key (and fails if that
/// subnet doesn't hold the key).  If a `requested_subnet` is not provided,
/// route to the first subnet enabled to sign with the given key.
fn route_ecdsa_message(
    key_id: &EcdsaKeyId,
    network_topology: &NetworkTopology,
    requested_subnet: &Option<SubnetId>,
    signing_must_be_enabled: EcdsaSubnetKind,
) -> Result<PrincipalId, ResolveDestinationError> {
    fn format_keys<'a>(mut found_keys: impl Iterator<Item = &'a EcdsaKeyId>) -> String {
        let mut keys = "[".to_string();
        if let Some(key) = found_keys.next() {
            write!(keys, "{}", key).unwrap();
        }
        for key in found_keys {
            write!(keys, ", {}", key).unwrap();
        }
        keys.push(']');
        keys
    }

    match requested_subnet {
        Some(subnet_id) => match network_topology.subnets.get(subnet_id) {
            None => Err(ResolveDestinationError::EcdsaKeyError(format!(
                "Requested ECDSA key {} from unknown subnet {}",
                key_id, subnet_id
            ))),
            Some(subnet_topology) => {
                if subnet_topology.ecdsa_keys_held.contains(key_id) {
                    match signing_must_be_enabled {
                        EcdsaSubnetKind::HoldsAndSignWithKey => {
                            if network_topology
                                .ecdsa_signing_subnets(key_id)
                                .contains(subnet_id)
                            {
                                Ok((*subnet_id).get())
                            } else {
                                Err(ResolveDestinationError::EcdsaKeyError(format!(
                                    "Subnet {} is not enabled to sign with ECDSA key {}",
                                    subnet_id, key_id,
                                )))
                            }
                        }
                        EcdsaSubnetKind::OnlyHoldsKey => Ok((*subnet_id).get()),
                    }
                } else {
                    Err(ResolveDestinationError::EcdsaKeyError(format!(
                        "Requested ECDSA key {} on subnet {}, subnet has keys: {}",
                        key_id,
                        subnet_id,
                        format_keys(subnet_topology.ecdsa_keys_held.iter())
                    )))
                }
            }
        },
        None => {
            // If some subnet is enabled to sign for the key we can immediately return it.
            if let Some(subnet_id) = network_topology.ecdsa_signing_subnets(key_id).first() {
                return Ok((*subnet_id).get());
            }
            // Otherwise either return an error, or look through all subnets to
            // find one with the key if signing isn't required.
            match signing_must_be_enabled {
                EcdsaSubnetKind::HoldsAndSignWithKey => {
                    let keys = format_keys(network_topology.ecdsa_signing_subnets.keys());
                    Err(ResolveDestinationError::EcdsaKeyError(format!(
                        "Requested ECDSA key: {}, existing keys with signing enabled: {}",
                        key_id, keys
                    )))
                }
                EcdsaSubnetKind::OnlyHoldsKey => {
                    let mut keys = BTreeSet::new();
                    for (subnet_id, topology) in &network_topology.subnets {
                        if topology.ecdsa_keys_held.contains(key_id) {
                            return Ok((*subnet_id).get());
                        }
                        keys.extend(topology.ecdsa_keys_held.iter().cloned());
                    }
                    let keys = format_keys(keys.iter());
                    Err(ResolveDestinationError::EcdsaKeyError(format!(
                        "Requested ECDSA key: {}, existing keys: {}",
                        key_id, keys
                    )))
                }
            }
        }
    }
}

fn route_bitcoin_message(
    network: BitcoinNetwork,
    network_topology: &NetworkTopology,
    own_subnet: SubnetId,
) -> PrincipalId {
    match network {
        // Route to the bitcoin canister if it exists, otherwise route to own subnet.
        // NOTE: Local deployments can run regtest mode for testing, and that routes to the
        // same canister ID as the bitcoin testnet.
        BitcoinNetwork::Testnet
        | BitcoinNetwork::testnet
        | BitcoinNetwork::Regtest
        | BitcoinNetwork::regtest => network_topology
            .bitcoin_testnet_canister_id
            .unwrap_or_else(|| CanisterId::from(own_subnet))
            .get(),
        BitcoinNetwork::Mainnet | BitcoinNetwork::mainnet => network_topology
            .bitcoin_mainnet_canister_id
            .unwrap_or_else(|| CanisterId::from(own_subnet))
            .get(),
    }
}

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use candid::Encode;
    use ic_base_types::RegistryVersion;
    use ic_management_canister_types::{
        ComputeInitialEcdsaDealingsArgs, DerivationPath, EcdsaCurve, EcdsaKeyId, SignWithECDSAArgs,
    };
    use ic_replicated_state::SubnetTopology;
    use ic_test_utilities_types::ids::{canister_test_id, node_test_id, subnet_test_id};
    use maplit::btreemap;
    use serde_bytes::ByteBuf;

    use super::*;

    fn key_id1() -> EcdsaKeyId {
        EcdsaKeyId {
            curve: EcdsaCurve::Secp256k1,
            name: "some_key".to_string(),
        }
    }

    fn key_id2() -> EcdsaKeyId {
        EcdsaKeyId {
            curve: EcdsaCurve::Secp256k1,
            name: "other_key".to_string(),
        }
    }

    /// Two subnets have key_id1, but only one of the subnets is enabled
    /// to sign with it.
    /// Only one subnet has key_id2, and it isn't enabled to sign with it.
    fn network_with_ecdsa_subnets() -> NetworkTopology {
        let subnet_id0 = subnet_test_id(0);
        NetworkTopology {
            // Only subnet 0 can sign with the first key.
            ecdsa_signing_subnets: btreemap! {
                key_id1() => vec![subnet_id0],
            },
            subnets: btreemap! {
                // Subnet 0 holds both keys
                subnet_id0 => SubnetTopology {
                    ecdsa_keys_held: vec![key_id1(), key_id2()].into_iter().collect(),
                    ..SubnetTopology::default()
                },
                // Subnet 1 holds only the first key.
                subnet_test_id(1) => SubnetTopology {
                    ecdsa_keys_held: vec![key_id1()].into_iter().collect(),
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

    fn compute_initial_ecdsa_dealings_req(key_id: EcdsaKeyId, subnet_id: SubnetId) -> Vec<u8> {
        let args = ComputeInitialEcdsaDealingsArgs::new(
            key_id,
            subnet_id,
            vec![node_test_id(0)].into_iter().collect(),
            RegistryVersion::from(100),
        );
        Encode!(&args).unwrap()
    }

    fn ecdsa_sign_req(key_id: EcdsaKeyId) -> Vec<u8> {
        let args = SignWithECDSAArgs {
            message_hash: [1; 32],
            derivation_path: DerivationPath::new(vec![ByteBuf::from(vec![0; 10])]),
            key_id,
        };
        Encode!(&args).unwrap()
    }

    fn public_key_req(key_id: EcdsaKeyId) -> Vec<u8> {
        let args = ECDSAPublicKeyArgs {
            canister_id: Some(canister_test_id(1)),
            derivation_path: DerivationPath::new(vec![ByteBuf::from(vec![0; 10])]),
            key_id,
        };
        Encode!(&args).unwrap()
    }

    #[test]
    fn resolve_compute_initial_ecdsa_dealings() {
        assert_eq!(
            resolve_destination(
                &network_with_ecdsa_subnets(),
                &Ic00Method::ComputeInitialEcdsaDealings.to_string(),
                &compute_initial_ecdsa_dealings_req(key_id1(), subnet_test_id(1)),
                subnet_test_id(2),
            )
            .unwrap(),
            PrincipalId::new_subnet_test_id(1)
        )
    }

    #[test]
    fn resolve_compute_initial_ecdsa_dealings_key_not_held_error() {
        assert_matches!(
            resolve_destination(
                &network_with_ecdsa_subnets(),
                &Ic00Method::ComputeInitialEcdsaDealings.to_string(),
                &compute_initial_ecdsa_dealings_req(key_id1(), subnet_test_id(2)),
                subnet_test_id(2),
            )
            .unwrap_err(),
            ResolveDestinationError::EcdsaKeyError(err) => assert_eq!(
                err,
                format!("Requested ECDSA key {} on subnet {}, subnet has keys: []", key_id1(), subnet_test_id(2))
            )
        )
    }

    #[test]
    fn resolve_compute_initial_ecdsa_dealings_unknown_subnet_error() {
        assert_matches!(
            resolve_destination(
                &network_with_ecdsa_subnets(),
                &Ic00Method::ComputeInitialEcdsaDealings.to_string(),
                &compute_initial_ecdsa_dealings_req(key_id1(), subnet_test_id(3)),
                subnet_test_id(2),
            )
            .unwrap_err(),
            ResolveDestinationError::EcdsaKeyError(err) => assert_eq!(
                err,
                format!("Requested ECDSA key {} from unknown subnet {}", key_id1(), subnet_test_id(3))
            )
        )
    }

    #[test]
    fn resolve_compute_initial_ecdsa_dealings_wrong_subnet_error() {
        assert_matches!(
                resolve_destination(
                    &network_with_ecdsa_subnets(),
                    &Ic00Method::ComputeInitialEcdsaDealings.to_string(),
                    // Subnet 2 doesn't have the requested key.
                    &compute_initial_ecdsa_dealings_req(key_id1(), subnet_test_id(2)),
                    subnet_test_id(2),
                )
                .unwrap_err(),
                ResolveDestinationError::EcdsaKeyError(err) => assert_eq!(
                    err,
                    format!("Requested ECDSA key {} on subnet {}, subnet has keys: []",
                        key_id1(),
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
                    &compute_initial_ecdsa_dealings_req(key_id1(), subnet_test_id(3)),
                    subnet_test_id(2),
                )
                .unwrap_err(),
                ResolveDestinationError::EcdsaKeyError(err) => assert_eq!(
                    err,
                    format!("Requested ECDSA key {} from unknown subnet {}",
                        key_id1(),
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
                &ecdsa_sign_req(key_id1()),
                subnet_test_id(1),
            )
            .unwrap(),
            PrincipalId::new_subnet_test_id(0)
        )
    }

    #[test]
    fn resolve_ecdsa_sign_error() {
        assert_matches!(resolve_destination(
            &network_without_ecdsa_subnet(),
            &Ic00Method::SignWithECDSA.to_string(),
            &ecdsa_sign_req(key_id1()),
            subnet_test_id(1),
        )
        .unwrap_err(),
        ResolveDestinationError::EcdsaKeyError(err) => assert_eq!(
                err,
                format!("Requested ECDSA key: {}, existing keys with signing enabled: []", key_id1())
            )
        )
    }

    #[test]
    fn resolve_ecdsa_public_key_works_without_signing_enabled() {
        assert_eq!(
            resolve_destination(
                &network_with_ecdsa_subnets(),
                &Ic00Method::ECDSAPublicKey.to_string(),
                &public_key_req(key_id2()),
                subnet_test_id(1),
            )
            .unwrap(),
            PrincipalId::new_subnet_test_id(0)
        )
    }

    #[test]
    fn resolve_ecdsa_initial_dealings_works_without_signing_enabled() {
        assert_eq!(
            resolve_destination(
                &network_with_ecdsa_subnets(),
                &Ic00Method::ComputeInitialEcdsaDealings.to_string(),
                &compute_initial_ecdsa_dealings_req(key_id2(), subnet_test_id(0)),
                subnet_test_id(1),
            )
            .unwrap(),
            PrincipalId::new_subnet_test_id(0)
        )
    }

    #[test]
    fn route_ecdsa_message_subnet_can_sign() {
        // subnet_test_id(0) is enabled to sign with key_id1()
        assert_eq!(
            route_ecdsa_message(
                &key_id1(),
                &network_with_ecdsa_subnets(),
                &Some(subnet_test_id(0)),
                EcdsaSubnetKind::HoldsAndSignWithKey
            )
            .unwrap(),
            subnet_test_id(0).get()
        );
    }

    #[test]
    fn route_ecdsa_message_subnet_cannot_sign() {
        // subnet_test_id(1) is not enabled to sign with key_id1()
        let key_id = key_id1();
        let subnet_id = subnet_test_id(1);
        match route_ecdsa_message(
            &key_id,
            &network_with_ecdsa_subnets(),
            &Some(subnet_id),
            EcdsaSubnetKind::HoldsAndSignWithKey,
        ) {
            Err(ResolveDestinationError::EcdsaKeyError(msg)) => assert_eq!(
                msg,
                format!(
                    "Subnet {} is not enabled to sign with ECDSA key {}",
                    subnet_id, key_id,
                )
            ),
            _ => panic!("Unexpected result."),
        };
    }
}
