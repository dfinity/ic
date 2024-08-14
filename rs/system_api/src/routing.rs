use std::collections::BTreeSet;
use std::str::FromStr;

use ic_base_types::{CanisterId, PrincipalId, SubnetId};
use ic_btc_interface::NetworkInRequest as BitcoinNetwork;
use ic_error_types::UserError;
use ic_management_canister_types::{
    BitcoinGetBalanceArgs, BitcoinGetBlockHeadersArgs, BitcoinGetCurrentFeePercentilesArgs,
    BitcoinGetUtxosArgs, BitcoinSendTransactionArgs, CanisterIdRecord, CanisterInfoRequest,
    ClearChunkStoreArgs, ComputeInitialIDkgDealingsArgs, DeleteCanisterSnapshotArgs,
    ECDSAPublicKeyArgs, InstallChunkedCodeArgs, InstallCodeArgsV2, ListCanisterSnapshotArgs,
    LoadCanisterSnapshotArgs, MasterPublicKeyId, Method as Ic00Method, NodeMetricsHistoryArgs,
    Payload, ProvisionalTopUpCanisterArgs, SchnorrPublicKeyArgs, SignWithECDSAArgs,
    SignWithSchnorrArgs, StoredChunksArgs, TakeCanisterSnapshotArgs, UninstallCodeArgs,
    UpdateSettingsArgs, UploadChunkArgs,
};
use ic_replicated_state::NetworkTopology;
use itertools::Itertools;

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
    IDkgKeyError(String),
}

impl From<UserError> for ResolveDestinationError {
    fn from(err: UserError) -> Self {
        ResolveDestinationError::UserError(err)
    }
}

/// Finds out the destination subnet based on the canister ID.
fn route_canister_id(
    canister_id: CanisterId,
    method: Ic00Method,
    network_topology: &NetworkTopology,
) -> Result<PrincipalId, ResolveDestinationError> {
    network_topology
        .routing_table
        .route(canister_id.get())
        .map(|subnet_id| subnet_id.get())
        .ok_or(ResolveDestinationError::SubnetNotFound(canister_id, method))
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

            route_canister_id(canister_id, Ic00Method::UpdateSettings, network_topology)
        }
        Ok(Ic00Method::InstallCode) => {
            // Find the destination canister from the payload.
            let args = InstallCodeArgsV2::decode(payload)?;
            let canister_id = args.get_canister_id();
            route_canister_id(canister_id, Ic00Method::InstallCode, network_topology)
        }
        Ok(Ic00Method::InstallChunkedCode) => {
            // Find the destination canister from the payload.
            let args = InstallChunkedCodeArgs::decode(payload)?;
            let canister_id = args.target_canister_id();
            route_canister_id(
                canister_id,
                Ic00Method::InstallChunkedCode,
                network_topology,
            )
        }
        Ok(Ic00Method::CanisterStatus)
        | Ok(Ic00Method::StartCanister)
        | Ok(Ic00Method::StopCanister)
        | Ok(Ic00Method::DeleteCanister)
        | Ok(Ic00Method::DepositCycles) => {
            let args = CanisterIdRecord::decode(payload)?;
            let canister_id = args.get_canister_id();
            route_canister_id(canister_id, Ic00Method::DepositCycles, network_topology)
        }
        Ok(Ic00Method::CanisterInfo) => {
            let args = CanisterInfoRequest::decode(payload)?;
            let canister_id = args.canister_id();
            route_canister_id(canister_id, Ic00Method::CanisterInfo, network_topology)
        }
        Ok(Ic00Method::UninstallCode) => {
            let args = UninstallCodeArgs::decode(payload)?;
            let canister_id = args.get_canister_id();
            route_canister_id(canister_id, Ic00Method::UninstallCode, network_topology)
        }
        Ok(Ic00Method::ProvisionalTopUpCanister) => {
            let args = ProvisionalTopUpCanisterArgs::decode(payload)?;
            let canister_id = args.get_canister_id();
            route_canister_id(
                canister_id,
                Ic00Method::ProvisionalTopUpCanister,
                network_topology,
            )
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
        Ok(Ic00Method::BitcoinGetBlockHeaders) => {
            let args = BitcoinGetBlockHeadersArgs::decode(payload)?;
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
            Err(ResolveDestinationError::UserError(UserError::new(
                ic_error_types::ErrorCode::CanisterRejectedMessage,
                format!(
                    "{} API is only accessible to end users in non-replicated mode",
                    Ic00Method::FetchCanisterLogs
                ),
            )))
        }
        Ok(Ic00Method::ECDSAPublicKey) => {
            let key_id = ECDSAPublicKeyArgs::decode(payload)?.key_id;
            route_idkg_message(
                &MasterPublicKeyId::Ecdsa(key_id),
                network_topology,
                &None,
                IDkgSubnetKind::OnlyHoldsKey,
            )
        }
        Ok(Ic00Method::SignWithECDSA) => {
            let key_id = SignWithECDSAArgs::decode(payload)?.key_id;
            route_idkg_message(
                &MasterPublicKeyId::Ecdsa(key_id),
                network_topology,
                &None,
                IDkgSubnetKind::HoldsAndSignWithKey,
            )
        }
        Ok(Ic00Method::ComputeInitialIDkgDealings) => {
            let args = ComputeInitialIDkgDealingsArgs::decode(payload)?;
            route_idkg_message(
                &args.key_id,
                network_topology,
                &Some(args.subnet_id),
                IDkgSubnetKind::OnlyHoldsKey,
            )
        }
        Ok(Ic00Method::SchnorrPublicKey) => {
            let args = SchnorrPublicKeyArgs::decode(payload)?;
            route_idkg_message(
                &MasterPublicKeyId::Schnorr(args.key_id),
                network_topology,
                &None,
                IDkgSubnetKind::OnlyHoldsKey,
            )
        }
        Ok(Ic00Method::SignWithSchnorr) => {
            let args = SignWithSchnorrArgs::decode(payload)?;
            route_idkg_message(
                &MasterPublicKeyId::Schnorr(args.key_id),
                network_topology,
                &None,
                IDkgSubnetKind::HoldsAndSignWithKey,
            )
        }
        Ok(Ic00Method::UploadChunk) => {
            let args = UploadChunkArgs::decode(payload)?;
            let canister_id = args.get_canister_id();
            route_canister_id(canister_id, Ic00Method::UploadChunk, network_topology)
        }
        Ok(Ic00Method::ClearChunkStore) => {
            let args = ClearChunkStoreArgs::decode(payload)?;
            let canister_id = args.get_canister_id();
            route_canister_id(canister_id, Ic00Method::ClearChunkStore, network_topology)
        }
        Ok(Ic00Method::StoredChunks) => {
            let args = StoredChunksArgs::decode(payload)?;
            let canister_id = args.get_canister_id();
            route_canister_id(canister_id, Ic00Method::StoredChunks, network_topology)
        }
        Ok(Ic00Method::TakeCanisterSnapshot) => {
            let args = TakeCanisterSnapshotArgs::decode(payload)?;
            let canister_id = args.get_canister_id();
            route_canister_id(
                canister_id,
                Ic00Method::TakeCanisterSnapshot,
                network_topology,
            )
        }
        Ok(Ic00Method::LoadCanisterSnapshot) => {
            let args = LoadCanisterSnapshotArgs::decode(payload)?;
            let canister_id = args.get_canister_id();
            route_canister_id(
                canister_id,
                Ic00Method::LoadCanisterSnapshot,
                network_topology,
            )
        }
        Ok(Ic00Method::ListCanisterSnapshots) => {
            let args = ListCanisterSnapshotArgs::decode(payload)?;
            let canister_id = args.get_canister_id();
            route_canister_id(
                canister_id,
                Ic00Method::ListCanisterSnapshots,
                network_topology,
            )
        }
        Ok(Ic00Method::DeleteCanisterSnapshot) => {
            let args = DeleteCanisterSnapshotArgs::decode(payload)?;
            let canister_id = args.get_canister_id();
            route_canister_id(
                canister_id,
                Ic00Method::DeleteCanisterSnapshot,
                network_topology,
            )
        }
        Err(_) => Err(ResolveDestinationError::MethodNotFound(
            method_name.to_string(),
        )),
    }
}
enum IDkgSubnetKind {
    OnlyHoldsKey,
    HoldsAndSignWithKey,
}

/// Routes to the `requested_subnet` if it holds the key (and fails if that
/// subnet doesn't hold the key).  If a `requested_subnet` is not provided,
/// route to the first subnet enabled to sign with the given key.
fn route_idkg_message(
    key_id: &MasterPublicKeyId,
    network_topology: &NetworkTopology,
    requested_subnet: &Option<SubnetId>,
    idkg_subnet_kind: IDkgSubnetKind,
) -> Result<PrincipalId, ResolveDestinationError> {
    /// Formats a list of keys and returns them in a sorted order.
    fn format_keys<'a>(keys: impl Iterator<Item = &'a MasterPublicKeyId>) -> String {
        format!("[{}]", keys.map(ToString::to_string).sorted().join(", "))
    }

    match requested_subnet {
        Some(subnet_id) => match network_topology.subnets.get(subnet_id) {
            None => Err(ResolveDestinationError::IDkgKeyError(format!(
                "Requested threshold key {} from unknown subnet {}",
                key_id, subnet_id
            ))),
            Some(subnet_topology) => {
                if subnet_topology.idkg_keys_held.contains(key_id) {
                    match idkg_subnet_kind {
                        IDkgSubnetKind::HoldsAndSignWithKey => {
                            if network_topology
                                .idkg_signing_subnets(key_id)
                                .contains(subnet_id)
                            {
                                Ok((*subnet_id).get())
                            } else {
                                Err(ResolveDestinationError::IDkgKeyError(format!(
                                    "Subnet {} is not enabled to sign with threshold key {}",
                                    subnet_id, key_id,
                                )))
                            }
                        }
                        IDkgSubnetKind::OnlyHoldsKey => Ok((*subnet_id).get()),
                    }
                } else {
                    Err(ResolveDestinationError::IDkgKeyError(format!(
                        "Requested unknown threshold key {} on subnet {}, subnet has keys: {}",
                        key_id,
                        subnet_id,
                        format_keys(subnet_topology.idkg_keys_held.iter())
                    )))
                }
            }
        },
        None => {
            // If some subnet is enabled to sign for the key we can immediately return it.
            if let Some(subnet_id) = network_topology.idkg_signing_subnets(key_id).first() {
                return Ok((*subnet_id).get());
            }
            // Otherwise either return an error, or look through all subnets to
            // find one with the key if signing isn't required.
            match idkg_subnet_kind {
                IDkgSubnetKind::HoldsAndSignWithKey => {
                    let keys = format_keys(network_topology.idkg_signing_subnets.keys());
                    Err(ResolveDestinationError::IDkgKeyError(format!(
                        "Requested unknown or signing disabled threshold key: {}, existing keys with signing enabled: {}",
                        key_id, keys
                    )))
                }
                IDkgSubnetKind::OnlyHoldsKey => {
                    let mut keys = BTreeSet::new();
                    for (subnet_id, topology) in &network_topology.subnets {
                        if topology.idkg_keys_held.contains(key_id) {
                            return Ok((*subnet_id).get());
                        }
                        keys.extend(topology.idkg_keys_held.iter().cloned());
                    }
                    let keys = format_keys(keys.iter());
                    Err(ResolveDestinationError::IDkgKeyError(format!(
                        "Requested unknown threshold key: {}, existing keys: {}",
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
        DerivationPath, EcdsaCurve, EcdsaKeyId, SchnorrAlgorithm, SchnorrKeyId, SignWithECDSAArgs,
    };
    use ic_replicated_state::SubnetTopology;
    use ic_test_utilities_types::ids::{canister_test_id, node_test_id, subnet_test_id};
    use maplit::btreemap;
    use serde_bytes::ByteBuf;

    use super::*;

    fn _ecdsa_key_id(name: &'static str) -> EcdsaKeyId {
        EcdsaKeyId {
            curve: EcdsaCurve::Secp256k1,
            name: name.to_string(),
        }
    }

    fn _schnorr_key_id(name: &'static str) -> SchnorrKeyId {
        SchnorrKeyId {
            algorithm: SchnorrAlgorithm::Ed25519,
            name: name.to_string(),
        }
    }

    fn ecdsa_key_id1() -> EcdsaKeyId {
        _ecdsa_key_id("key_id1")
    }

    fn ecdsa_key_id2() -> EcdsaKeyId {
        _ecdsa_key_id("key_id2")
    }

    fn ecdsa_key_id3() -> EcdsaKeyId {
        _ecdsa_key_id("key_id3")
    }

    fn idkg_ecdsa_key_id1() -> MasterPublicKeyId {
        MasterPublicKeyId::Ecdsa(ecdsa_key_id1())
    }

    fn idkg_ecdsa_key_id2() -> MasterPublicKeyId {
        MasterPublicKeyId::Ecdsa(ecdsa_key_id2())
    }

    fn idkg_ecdsa_key_id3() -> MasterPublicKeyId {
        MasterPublicKeyId::Ecdsa(ecdsa_key_id3())
    }

    fn schnorr_key_id1() -> SchnorrKeyId {
        _schnorr_key_id("key_id1")
    }

    fn schnorr_key_id2() -> SchnorrKeyId {
        _schnorr_key_id("key_id2")
    }

    fn schnorr_key_id3() -> SchnorrKeyId {
        _schnorr_key_id("key_id3")
    }

    fn idkg_schnorr_key_id1() -> MasterPublicKeyId {
        MasterPublicKeyId::Schnorr(schnorr_key_id1())
    }

    fn idkg_schnorr_key_id2() -> MasterPublicKeyId {
        MasterPublicKeyId::Schnorr(schnorr_key_id2())
    }

    fn idkg_schnorr_key_id3() -> MasterPublicKeyId {
        MasterPublicKeyId::Schnorr(schnorr_key_id3())
    }

    /// Two subnets have key_id1, but only one of the subnets is enabled to sign with it.
    /// Only one subnet has key_id2, and it isn't enabled to sign with it.
    fn network_with_idkg_subnets(
        key_id1: MasterPublicKeyId,
        key_id2: MasterPublicKeyId,
    ) -> NetworkTopology {
        let subnet_id0 = subnet_test_id(0);
        NetworkTopology {
            // Only subnet 0 can sign with the first key.
            idkg_signing_subnets: btreemap! {
                key_id1.clone() => vec![subnet_id0],
            },
            subnets: btreemap! {
                // Subnet 0 holds both keys
                subnet_id0 => SubnetTopology {
                    idkg_keys_held: vec![key_id1.clone(), key_id2].into_iter().collect(),
                    ..SubnetTopology::default()
                },
                // Subnet 1 holds only the first key.
                subnet_test_id(1) => SubnetTopology {
                    idkg_keys_held: vec![key_id1].into_iter().collect(),
                    ..SubnetTopology::default()
                },
                subnet_test_id(2) => SubnetTopology::default(),
            },
            ..NetworkTopology::default()
        }
    }

    fn network_with_ecdsa_subnets() -> NetworkTopology {
        network_with_idkg_subnets(idkg_ecdsa_key_id1(), idkg_ecdsa_key_id2())
    }

    fn network_with_schnorr_subnets() -> NetworkTopology {
        network_with_idkg_subnets(idkg_schnorr_key_id1(), idkg_schnorr_key_id2())
    }

    fn network_without_idkg_subnets() -> NetworkTopology {
        NetworkTopology::default()
    }

    fn compute_initial_idkg_dealings_request(
        key_id: MasterPublicKeyId,
        subnet_id: SubnetId,
    ) -> Vec<u8> {
        let args = ComputeInitialIDkgDealingsArgs::new(
            key_id,
            subnet_id,
            vec![node_test_id(0)].into_iter().collect(),
            RegistryVersion::from(100),
        );
        Encode!(&args).unwrap()
    }

    fn ecdsa_sign_request(key_id: EcdsaKeyId) -> Vec<u8> {
        let args = SignWithECDSAArgs {
            message_hash: [1; 32],
            derivation_path: DerivationPath::new(vec![ByteBuf::from(vec![0; 10])]),
            key_id,
        };
        Encode!(&args).unwrap()
    }

    fn schnorr_sign_request(key_id: SchnorrKeyId) -> Vec<u8> {
        let args = SignWithSchnorrArgs {
            message: vec![1; 32],
            derivation_path: DerivationPath::new(vec![ByteBuf::from(vec![0; 10])]),
            key_id,
        };
        Encode!(&args).unwrap()
    }

    fn ecdsa_public_key_request(key_id: EcdsaKeyId) -> Vec<u8> {
        let args = ECDSAPublicKeyArgs {
            canister_id: Some(canister_test_id(1)),
            derivation_path: DerivationPath::new(vec![ByteBuf::from(vec![0; 10])]),
            key_id,
        };
        Encode!(&args).unwrap()
    }

    fn schnorr_public_key_request(key_id: SchnorrKeyId) -> Vec<u8> {
        let args = SchnorrPublicKeyArgs {
            canister_id: Some(canister_test_id(1)),
            derivation_path: DerivationPath::new(vec![ByteBuf::from(vec![0; 10])]),
            key_id,
        };
        Encode!(&args).unwrap()
    }

    #[test]
    fn resolve_compute_initial_idkg_dealings() {
        for (network_topology, key_id) in [
            (network_with_ecdsa_subnets(), idkg_ecdsa_key_id1()),
            (network_with_schnorr_subnets(), idkg_schnorr_key_id1()),
        ] {
            assert_eq!(
                resolve_destination(
                    &network_topology,
                    &Ic00Method::ComputeInitialIDkgDealings.to_string(),
                    &compute_initial_idkg_dealings_request(key_id.clone(), subnet_test_id(1)),
                    subnet_test_id(2),
                )
                .unwrap(),
                PrincipalId::new_subnet_test_id(1)
            );
        }
    }

    #[test]
    fn resolve_compute_initial_idkg_dealings_key_not_held_error() {
        for (network_topology, key_id) in [
            (network_with_ecdsa_subnets(), idkg_ecdsa_key_id1()),
            (network_with_schnorr_subnets(), idkg_schnorr_key_id1()),
        ] {
            assert_matches!(
                resolve_destination(
                    &network_topology,
                    &Ic00Method::ComputeInitialIDkgDealings.to_string(),
                    &compute_initial_idkg_dealings_request(key_id.clone(), subnet_test_id(2)),
                    subnet_test_id(2),
                )
                .unwrap_err(),
                ResolveDestinationError::IDkgKeyError(err) => assert_eq!(
                    err,
                    format!(
                        "Requested unknown threshold key {} on subnet {}, subnet has keys: []",
                        key_id,
                        subnet_test_id(2),
                    )
                )
            );
        }
    }

    #[test]
    fn resolve_compute_initial_idkg_dealings_unknown_subnet_error() {
        for (network_topology, key_id) in [
            (network_with_ecdsa_subnets(), idkg_ecdsa_key_id1()),
            (network_with_schnorr_subnets(), idkg_schnorr_key_id1()),
        ] {
            assert_matches!(
                resolve_destination(
                    &network_topology,
                    &Ic00Method::ComputeInitialIDkgDealings.to_string(),
                    &compute_initial_idkg_dealings_request(key_id.clone(), subnet_test_id(3)),
                    subnet_test_id(2),
                )
                .unwrap_err(),
                ResolveDestinationError::IDkgKeyError(err) => assert_eq!(
                    err,
                    format!(
                        "Requested threshold key {} from unknown subnet {}",
                        key_id,
                        subnet_test_id(3),
                    )
                )
            );
        }
    }

    #[test]
    fn resolve_compute_initial_idkg_dealings_wrong_subnet_error() {
        for (network_topology, key_id) in [
            (network_with_ecdsa_subnets(), idkg_ecdsa_key_id1()),
            (network_with_schnorr_subnets(), idkg_schnorr_key_id1()),
        ] {
            assert_matches!(
                    resolve_destination(
                        &network_topology,
                        &Ic00Method::ComputeInitialIDkgDealings.to_string(),
                        // Subnet 2 doesn't have the requested key.
                        &compute_initial_idkg_dealings_request(key_id.clone(), subnet_test_id(2)),
                        subnet_test_id(2),
                    )
                    .unwrap_err(),
                    ResolveDestinationError::IDkgKeyError(err) => assert_eq!(
                        err,
                        format!(
                            "Requested unknown threshold key {} on subnet {}, subnet has keys: []",
                            key_id,
                            subnet_test_id(2),
                    )
                )
            );
        }
    }

    #[test]
    fn resolve_compute_initial_idkg_dealings_subnet_not_found_error() {
        for (network_topology, key_id) in [
            (network_with_ecdsa_subnets(), idkg_ecdsa_key_id1()),
            (network_with_schnorr_subnets(), idkg_schnorr_key_id1()),
        ] {
            assert_matches!(
                resolve_destination(
                    &network_topology,
                    &Ic00Method::ComputeInitialIDkgDealings.to_string(),
                    // Subnet 3 doesn't exist
                    &compute_initial_idkg_dealings_request(key_id.clone(), subnet_test_id(3)),
                    subnet_test_id(2),
                )
                .unwrap_err(),
                ResolveDestinationError::IDkgKeyError(err) => assert_eq!(
                    err,
                    format!(
                        "Requested threshold key {} from unknown subnet {}",
                        key_id,
                        subnet_test_id(3),
                    )
                )
            );
        }
    }

    #[test]
    fn resolve_idkg_sign() {
        for (network_topology, method, payload) in [
            (
                network_with_ecdsa_subnets(),
                Ic00Method::SignWithECDSA,
                ecdsa_sign_request(ecdsa_key_id1()),
            ),
            (
                network_with_schnorr_subnets(),
                Ic00Method::SignWithSchnorr,
                schnorr_sign_request(schnorr_key_id1()),
            ),
        ] {
            assert_eq!(
                resolve_destination(
                    &network_topology,
                    &method.to_string(),
                    &payload,
                    subnet_test_id(1),
                )
                .unwrap(),
                PrincipalId::new_subnet_test_id(0)
            );
        }
    }

    #[test]
    fn resolve_idkg_sign_error() {
        for (method, payload, idkg_key_id) in [
            (
                Ic00Method::SignWithECDSA,
                ecdsa_sign_request(ecdsa_key_id1()),
                idkg_ecdsa_key_id1(),
            ),
            (
                Ic00Method::SignWithSchnorr,
                schnorr_sign_request(schnorr_key_id1()),
                idkg_schnorr_key_id1(),
            ),
        ] {
            assert_matches!(resolve_destination(
                &network_without_idkg_subnets(),
                &method.to_string(),
                &payload,
                subnet_test_id(1),
            )
            .unwrap_err(),
            ResolveDestinationError::IDkgKeyError(err) => assert_eq!(
                    err,
                    format!(
                        "Requested unknown or signing disabled threshold key: {}, existing keys with signing enabled: []",
                        idkg_key_id,
                    )
                )
            )
        }
    }

    #[test]
    fn resolve_idkg_public_key_works_without_signing_enabled() {
        for (network_topology, method, payload) in [
            (
                network_with_ecdsa_subnets(),
                Ic00Method::ECDSAPublicKey,
                ecdsa_public_key_request(ecdsa_key_id2()),
            ),
            (
                network_with_schnorr_subnets(),
                Ic00Method::SchnorrPublicKey,
                schnorr_public_key_request(schnorr_key_id2()),
            ),
        ] {
            assert_eq!(
                resolve_destination(
                    &network_topology,
                    &method.to_string(),
                    &payload,
                    subnet_test_id(1),
                )
                .unwrap(),
                PrincipalId::new_subnet_test_id(0)
            );
        }
    }

    #[test]
    fn resolve_idkg_initial_dealings_works_without_signing_enabled() {
        for (network_topology, key_id) in [
            (network_with_ecdsa_subnets(), idkg_ecdsa_key_id2()),
            (network_with_schnorr_subnets(), idkg_schnorr_key_id2()),
        ] {
            assert_eq!(
                resolve_destination(
                    &network_topology,
                    &Ic00Method::ComputeInitialIDkgDealings.to_string(),
                    &compute_initial_idkg_dealings_request(key_id, subnet_test_id(0)),
                    subnet_test_id(1),
                )
                .unwrap(),
                PrincipalId::new_subnet_test_id(0)
            );
        }
    }

    #[test]
    fn route_idkg_message_subnet_can_sign() {
        // subnet_test_id(0) is enabled to sign with idkg_X_key_id1().
        for (key_id, network_topology) in [
            (idkg_ecdsa_key_id1(), network_with_ecdsa_subnets()),
            (idkg_schnorr_key_id1(), network_with_schnorr_subnets()),
        ] {
            assert_eq!(
                route_idkg_message(
                    &key_id,
                    &network_topology,
                    &Some(subnet_test_id(0)),
                    IDkgSubnetKind::HoldsAndSignWithKey
                )
                .unwrap(),
                subnet_test_id(0).get()
            );
        }
    }

    #[test]
    fn route_idkg_message_subnet_cannot_sign() {
        // subnet_test_id(1) is not enabled to sign with idkg_X_key_id1().
        for (key_id, network_topology) in [
            (idkg_ecdsa_key_id1(), network_with_ecdsa_subnets()),
            (idkg_schnorr_key_id1(), network_with_schnorr_subnets()),
        ] {
            let subnet_id = subnet_test_id(1);
            match route_idkg_message(
                &key_id,
                &network_topology,
                &Some(subnet_id),
                IDkgSubnetKind::HoldsAndSignWithKey,
            ) {
                Err(ResolveDestinationError::IDkgKeyError(msg)) => assert_eq!(
                    msg,
                    format!(
                        "Subnet {} is not enabled to sign with threshold key {}",
                        subnet_id, key_id,
                    )
                ),
                _ => panic!("Unexpected result."),
            };
        }
    }

    #[test]
    fn route_idkg_message_subnet_cannot_sign_unknown_subnet() {
        for (key_id, network_topology) in [
            (idkg_ecdsa_key_id1(), network_with_ecdsa_subnets()),
            (idkg_schnorr_key_id1(), network_with_schnorr_subnets()),
        ] {
            let unknown_subnet_id = subnet_test_id(3);
            match route_idkg_message(
                &key_id,
                &network_topology,
                &Some(unknown_subnet_id),
                IDkgSubnetKind::HoldsAndSignWithKey,
            ) {
                Err(ResolveDestinationError::IDkgKeyError(msg)) => assert_eq!(
                    msg,
                    format!(
                        "Requested threshold key {key_id} from unknown subnet {unknown_subnet_id}",
                    )
                ),
                _ => panic!("Unexpected result."),
            };
        }
    }

    #[test]
    fn route_idkg_message_subnet_cannot_sign_unknown_key() {
        for (key_id, network_topology) in [
            (idkg_ecdsa_key_id1(), network_with_ecdsa_subnets()),
            (idkg_schnorr_key_id1(), network_with_schnorr_subnets()),
        ] {
            let subnet_id = subnet_test_id(2);
            match route_idkg_message(
                &key_id,
                &network_topology,
                &Some(subnet_id),
                IDkgSubnetKind::HoldsAndSignWithKey,
            ) {
                Err(ResolveDestinationError::IDkgKeyError(msg)) => assert_eq!(
                    msg,
                    format!("Requested unknown threshold key {key_id} on subnet {subnet_id}, subnet has keys: []",)
                ),
                _ => panic!("Unexpected result."),
            };
        }
    }

    #[test]
    fn route_idkg_message_subnet_cannot_sign_no_requested_subnet_unknown_key() {
        for (known_key_id, unknown_key_id, network_topology) in [
            (
                idkg_ecdsa_key_id1(),
                idkg_ecdsa_key_id3(),
                network_with_ecdsa_subnets(),
            ),
            (
                idkg_schnorr_key_id1(),
                idkg_schnorr_key_id3(),
                network_with_schnorr_subnets(),
            ),
        ] {
            match route_idkg_message(
                &unknown_key_id,
                &network_topology,
                &None,
                IDkgSubnetKind::HoldsAndSignWithKey,
            ) {
                Err(ResolveDestinationError::IDkgKeyError(msg)) => assert_eq!(
                    msg,
                    format!(
                        "Requested unknown or signing disabled threshold key: {unknown_key_id}, existing keys with signing enabled: [{known_key_id}]",
                    )
                ),
                _ => panic!("Unexpected result."),
            };
        }
    }

    #[test]
    fn route_idkg_message_subnet_cannot_sign_no_required_signing_unknown_key() {
        for (key_id1, key_id2, unknown_key_id, network_topology) in [
            (
                idkg_ecdsa_key_id1(),
                idkg_ecdsa_key_id2(),
                idkg_ecdsa_key_id3(),
                network_with_ecdsa_subnets(),
            ),
            (
                idkg_schnorr_key_id1(),
                idkg_schnorr_key_id2(),
                idkg_schnorr_key_id3(),
                network_with_schnorr_subnets(),
            ),
        ] {
            match route_idkg_message(
                &unknown_key_id,
                &network_topology,
                &None,
                IDkgSubnetKind::OnlyHoldsKey,
            ) {
                Err(ResolveDestinationError::IDkgKeyError(msg)) => assert_eq!(
                    msg,
                    format!(
                        "Requested unknown threshold key: {unknown_key_id}, existing keys: [{key_id1}, {key_id2}]",
                    )
                ),
                _ => panic!("Unexpected result."),
            };
        }
    }
}
