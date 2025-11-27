use std::collections::BTreeSet;
use std::str::FromStr;

use ic_base_types::{CanisterId, PrincipalId, SubnetId};
use ic_btc_interface::NetworkInRequest as BitcoinNetwork;
use ic_error_types::UserError;
use ic_logger::{ReplicaLogger, info};
use ic_management_canister_types_private::{
    BitcoinGetBalanceArgs, BitcoinGetBlockHeadersArgs, BitcoinGetCurrentFeePercentilesArgs,
    BitcoinGetUtxosArgs, BitcoinSendTransactionArgs, CanisterIdRecord, CanisterInfoRequest,
    CanisterMetadataRequest, ClearChunkStoreArgs, DeleteCanisterSnapshotArgs, ECDSAPublicKeyArgs,
    FetchCanisterLogsRequest, InstallChunkedCodeArgs, InstallCodeArgsV2, ListCanisterSnapshotArgs,
    LoadCanisterSnapshotArgs, MasterPublicKeyId, Method as Ic00Method, NodeMetricsHistoryArgs,
    Payload, ProvisionalTopUpCanisterArgs, ReadCanisterSnapshotDataArgs,
    ReadCanisterSnapshotMetadataArgs, RenameCanisterArgs, ReshareChainKeyArgs,
    SchnorrPublicKeyArgs, SignWithECDSAArgs, SignWithSchnorrArgs, StoredChunksArgs, SubnetInfoArgs,
    TakeCanisterSnapshotArgs, UninstallCodeArgs, UpdateSettingsArgs,
    UploadCanisterSnapshotDataArgs, UploadCanisterSnapshotMetadataArgs, UploadChunkArgs,
    VetKdDeriveKeyArgs, VetKdPublicKeyArgs,
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
    ChainKeyError(String),
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
    caller: CanisterId,
    is_composite_query: bool,
    logger: &ReplicaLogger,
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
        Ok(Ic00Method::CanisterMetadata) => {
            let args = CanisterMetadataRequest::decode(payload)?;
            let canister_id = args.canister_id();
            route_canister_id(canister_id, Ic00Method::CanisterMetadata, network_topology)
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
                caller,
                method_name,
                logger,
            ))
        }
        Ok(Ic00Method::BitcoinGetUtxos) => {
            let args = BitcoinGetUtxosArgs::decode(payload)?;
            Ok(route_bitcoin_message(
                args.network,
                network_topology,
                own_subnet,
                caller,
                method_name,
                logger,
            ))
        }
        Ok(Ic00Method::BitcoinGetBlockHeaders) => {
            let args = BitcoinGetBlockHeadersArgs::decode(payload)?;
            Ok(route_bitcoin_message(
                args.network,
                network_topology,
                own_subnet,
                caller,
                method_name,
                logger,
            ))
        }
        Ok(Ic00Method::BitcoinSendTransaction) => {
            let args = BitcoinSendTransactionArgs::decode(payload)?;

            Ok(route_bitcoin_message(
                args.network,
                network_topology,
                own_subnet,
                caller,
                method_name,
                logger,
            ))
        }
        Ok(Ic00Method::BitcoinGetCurrentFeePercentiles) => {
            let args = BitcoinGetCurrentFeePercentilesArgs::decode(payload)?;
            Ok(route_bitcoin_message(
                args.network,
                network_topology,
                own_subnet,
                caller,
                method_name,
                logger,
            ))
        }
        Ok(Ic00Method::NodeMetricsHistory) => {
            Ok(NodeMetricsHistoryArgs::decode(payload)?.subnet_id)
        }
        Ok(Ic00Method::SubnetInfo) => Ok(SubnetInfoArgs::decode(payload)?.subnet_id),
        Ok(Ic00Method::FetchCanisterLogs) => {
            if is_composite_query {
                Err(ResolveDestinationError::UserError(UserError::new(
                    ic_error_types::ErrorCode::CanisterRejectedMessage,
                    format!(
                        "{} API cannot be called from a composite query",
                        Ic00Method::FetchCanisterLogs
                    ),
                )))
            } else {
                let canister_id = FetchCanisterLogsRequest::decode(payload)?.get_canister_id();
                route_canister_id(canister_id, Ic00Method::FetchCanisterLogs, network_topology)
            }
        }
        Ok(Ic00Method::ECDSAPublicKey) => {
            let key_id = ECDSAPublicKeyArgs::decode(payload)?.key_id;
            route_chain_key_message(
                &MasterPublicKeyId::Ecdsa(key_id),
                network_topology,
                &None,
                ChainKeySubnetKind::OnlyHoldsKey,
            )
        }
        Ok(Ic00Method::SignWithECDSA) => {
            let key_id = SignWithECDSAArgs::decode(payload)?.key_id;
            route_chain_key_message(
                &MasterPublicKeyId::Ecdsa(key_id),
                network_topology,
                &None,
                ChainKeySubnetKind::HoldsEnabledKey,
            )
        }
        Ok(Ic00Method::ReshareChainKey) => {
            let args = ReshareChainKeyArgs::decode(payload)?;
            route_chain_key_message(
                &args.key_id,
                network_topology,
                &Some(args.subnet_id),
                ChainKeySubnetKind::OnlyHoldsKey,
            )
        }
        Ok(Ic00Method::SchnorrPublicKey) => {
            let args = SchnorrPublicKeyArgs::decode(payload)?;
            route_chain_key_message(
                &MasterPublicKeyId::Schnorr(args.key_id),
                network_topology,
                &None,
                ChainKeySubnetKind::OnlyHoldsKey,
            )
        }
        Ok(Ic00Method::SignWithSchnorr) => {
            let args = SignWithSchnorrArgs::decode(payload)?;
            route_chain_key_message(
                &MasterPublicKeyId::Schnorr(args.key_id),
                network_topology,
                &None,
                ChainKeySubnetKind::HoldsEnabledKey,
            )
        }
        Ok(Ic00Method::VetKdPublicKey) => {
            let args = VetKdPublicKeyArgs::decode(payload)?;
            route_chain_key_message(
                &MasterPublicKeyId::VetKd(args.key_id),
                network_topology,
                &None,
                ChainKeySubnetKind::OnlyHoldsKey,
            )
        }
        Ok(Ic00Method::VetKdDeriveKey) => {
            let args = VetKdDeriveKeyArgs::decode(payload)?;
            route_chain_key_message(
                &MasterPublicKeyId::VetKd(args.key_id),
                network_topology,
                &None,
                ChainKeySubnetKind::HoldsEnabledKey,
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
        Ok(Ic00Method::ReadCanisterSnapshotMetadata) => {
            let args = ReadCanisterSnapshotMetadataArgs::decode(payload)?;
            let canister_id = args.get_canister_id();
            route_canister_id(
                canister_id,
                Ic00Method::ReadCanisterSnapshotMetadata,
                network_topology,
            )
        }
        Ok(Ic00Method::ReadCanisterSnapshotData) => {
            let args = ReadCanisterSnapshotDataArgs::decode(payload)?;
            let canister_id = args.get_canister_id();
            route_canister_id(
                canister_id,
                Ic00Method::ReadCanisterSnapshotData,
                network_topology,
            )
        }
        Ok(Ic00Method::UploadCanisterSnapshotMetadata) => {
            let args = UploadCanisterSnapshotMetadataArgs::decode(payload)?;
            let canister_id = args.get_canister_id();
            route_canister_id(
                canister_id,
                Ic00Method::UploadCanisterSnapshotMetadata,
                network_topology,
            )
        }
        Ok(Ic00Method::UploadCanisterSnapshotData) => {
            let args = UploadCanisterSnapshotDataArgs::decode(payload)?;
            let canister_id = args.get_canister_id();
            route_canister_id(
                canister_id,
                Ic00Method::UploadCanisterSnapshotData,
                network_topology,
            )
        }
        Ok(Ic00Method::RenameCanister) => {
            let args = RenameCanisterArgs::decode(payload)?;
            let canister_id = args.get_canister_id();
            route_canister_id(canister_id, Ic00Method::RenameCanister, network_topology)
        }
        Err(_) => Err(ResolveDestinationError::MethodNotFound(
            method_name.to_string(),
        )),
    }
}

enum ChainKeySubnetKind {
    OnlyHoldsKey,
    HoldsEnabledKey,
}

/// Routes to the `requested_subnet` if it holds the key (and fails if that
/// subnet doesn't hold the key).  If a `requested_subnet` is not provided,
/// route to the first subnet that has the given key enabled.
fn route_chain_key_message(
    key_id: &MasterPublicKeyId,
    network_topology: &NetworkTopology,
    requested_subnet: &Option<SubnetId>,
    chain_key_subnet_kind: ChainKeySubnetKind,
) -> Result<PrincipalId, ResolveDestinationError> {
    /// Formats a list of keys and returns them in a sorted order.
    fn format_keys<'a>(keys: impl Iterator<Item = &'a MasterPublicKeyId>) -> String {
        format!("[{}]", keys.map(ToString::to_string).sorted().join(", "))
    }

    match requested_subnet {
        Some(subnet_id) => match network_topology.subnets.get(subnet_id) {
            None => Err(ResolveDestinationError::ChainKeyError(format!(
                "Requested threshold key {key_id} from unknown subnet {subnet_id}"
            ))),
            Some(subnet_topology) => {
                if subnet_topology.chain_keys_held.contains(key_id) {
                    match chain_key_subnet_kind {
                        ChainKeySubnetKind::HoldsEnabledKey => {
                            if network_topology
                                .chain_key_enabled_subnets(key_id)
                                .contains(subnet_id)
                            {
                                Ok((*subnet_id).get())
                            } else {
                                Err(ResolveDestinationError::ChainKeyError(format!(
                                    "Subnet {subnet_id} is not enabled to use threshold key {key_id}",
                                )))
                            }
                        }
                        ChainKeySubnetKind::OnlyHoldsKey => Ok((*subnet_id).get()),
                    }
                } else {
                    Err(ResolveDestinationError::ChainKeyError(format!(
                        "Requested unknown threshold key {} on subnet {}, subnet has keys: {}",
                        key_id,
                        subnet_id,
                        format_keys(subnet_topology.chain_keys_held.iter())
                    )))
                }
            }
        },
        None => {
            // If some subnet is enabled to use the key we can immediately return it.
            if let Some(subnet_id) = network_topology.chain_key_enabled_subnets(key_id).first() {
                return Ok((*subnet_id).get());
            }
            // Otherwise either return an error, or look through all subnets to
            // find one holding the key if it being enabled isn't required.
            match chain_key_subnet_kind {
                ChainKeySubnetKind::HoldsEnabledKey => {
                    let keys = format_keys(network_topology.chain_key_enabled_subnets.keys());
                    Err(ResolveDestinationError::ChainKeyError(format!(
                        "Requested unknown or disabled threshold key: {key_id}, existing enabled keys: {keys}"
                    )))
                }
                ChainKeySubnetKind::OnlyHoldsKey => {
                    let mut keys = BTreeSet::new();
                    for (subnet_id, topology) in &network_topology.subnets {
                        if topology.chain_keys_held.contains(key_id) {
                            return Ok((*subnet_id).get());
                        }
                        keys.extend(topology.chain_keys_held.iter().cloned());
                    }
                    let keys = format_keys(keys.iter());
                    Err(ResolveDestinationError::ChainKeyError(format!(
                        "Requested unknown threshold key: {key_id}, existing keys: {keys}"
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
    caller: CanisterId,
    method_name: &str,
    logger: &ReplicaLogger,
) -> PrincipalId {
    info!(
        logger,
        "Canister {} called Bitcoin method {} with network: {:?} directly on the management canister",
        caller,
        method_name,
        network
    );
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
    use ic_logger::no_op_logger;
    use ic_management_canister_types_private::{
        DerivationPath, EcdsaCurve, EcdsaKeyId, SchnorrAlgorithm, SchnorrKeyId, SignWithECDSAArgs,
        VetKdCurve, VetKdKeyId,
    };
    use ic_replicated_state::SubnetTopology;
    use ic_test_utilities_types::ids::{canister_test_id, node_test_id, subnet_test_id};
    use maplit::btreemap;
    use serde_bytes::ByteBuf;

    use super::*;

    fn ecdsa_key_id(i: u8) -> EcdsaKeyId {
        EcdsaKeyId {
            curve: EcdsaCurve::Secp256k1,
            name: format!("key_id{i}"),
        }
    }

    fn schnorr_key_id(i: u8) -> SchnorrKeyId {
        SchnorrKeyId {
            algorithm: SchnorrAlgorithm::Ed25519,
            name: format!("key_id{i}"),
        }
    }

    fn vetkd_key_id(i: u8) -> VetKdKeyId {
        VetKdKeyId {
            curve: VetKdCurve::Bls12_381_G2,
            name: format!("key_id{i}"),
        }
    }

    fn ecdsa_master_key_id(i: u8) -> MasterPublicKeyId {
        MasterPublicKeyId::Ecdsa(ecdsa_key_id(i))
    }

    fn schnorr_master_key_id(i: u8) -> MasterPublicKeyId {
        MasterPublicKeyId::Schnorr(schnorr_key_id(i))
    }

    fn vetkd_master_key_id(i: u8) -> MasterPublicKeyId {
        MasterPublicKeyId::VetKd(vetkd_key_id(i))
    }

    /// Two subnets have key_id1, but only one of the subnets is enabled to use it.
    /// Only one subnet has key_id2, and it isn't enabled to use it.
    fn network_with_chain_key_subnets(
        key_id1: MasterPublicKeyId,
        key_id2: MasterPublicKeyId,
    ) -> NetworkTopology {
        let subnet_id0 = subnet_test_id(0);
        NetworkTopology {
            // The first key is enabled only on subnet 0.
            chain_key_enabled_subnets: btreemap! {
                key_id1.clone() => vec![subnet_id0],
            },
            subnets: btreemap! {
                // Subnet 0 holds both keys
                subnet_id0 => SubnetTopology {
                    chain_keys_held: vec![key_id1.clone(), key_id2].into_iter().collect(),
                    ..SubnetTopology::default()
                },
                // Subnet 1 holds only the first key.
                subnet_test_id(1) => SubnetTopology {
                    chain_keys_held: vec![key_id1].into_iter().collect(),
                    ..SubnetTopology::default()
                },
                subnet_test_id(2) => SubnetTopology::default(),
            },
            ..NetworkTopology::default()
        }
    }

    fn network_with_ecdsa_subnets() -> NetworkTopology {
        network_with_chain_key_subnets(ecdsa_master_key_id(1), ecdsa_master_key_id(2))
    }

    fn network_with_schnorr_subnets() -> NetworkTopology {
        network_with_chain_key_subnets(schnorr_master_key_id(1), schnorr_master_key_id(2))
    }

    fn network_with_vetkd_subnets() -> NetworkTopology {
        network_with_chain_key_subnets(vetkd_master_key_id(1), vetkd_master_key_id(2))
    }

    fn network_without_chain_key_subnets() -> NetworkTopology {
        NetworkTopology::default()
    }

    fn reshare_chain_key_request(key_id: MasterPublicKeyId, subnet_id: SubnetId) -> Vec<u8> {
        let args = ReshareChainKeyArgs::new(
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
            aux: None,
        };
        Encode!(&args).unwrap()
    }

    fn vetkd_derive_key_request(key_id: VetKdKeyId) -> Vec<u8> {
        let args = VetKdDeriveKeyArgs {
            key_id,
            context: vec![0; 10],
            input: vec![1; 32],
            transport_public_key: [1; 48],
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

    fn vetkd_public_key_request(key_id: VetKdKeyId) -> Vec<u8> {
        let args = VetKdPublicKeyArgs {
            canister_id: Some(canister_test_id(1)),
            context: vec![0; 10],
            key_id,
        };
        Encode!(&args).unwrap()
    }

    #[test]
    fn resolve_reshare_chain_key() {
        let logger = no_op_logger();
        for (network_topology, key_id) in [
            (network_with_ecdsa_subnets(), ecdsa_master_key_id(1)),
            (network_with_schnorr_subnets(), schnorr_master_key_id(1)),
            (network_with_vetkd_subnets(), vetkd_master_key_id(1)),
        ] {
            assert_eq!(
                resolve_destination(
                    &network_topology,
                    &Ic00Method::ReshareChainKey.to_string(),
                    &reshare_chain_key_request(key_id.clone(), subnet_test_id(1)),
                    subnet_test_id(2),
                    canister_test_id(1),
                    false,
                    &logger,
                )
                .unwrap(),
                PrincipalId::new_subnet_test_id(1)
            );
        }
    }

    #[test]
    fn resolve_reshare_chain_key_key_not_held_error() {
        let logger = no_op_logger();
        for (network_topology, key_id) in [
            (network_with_ecdsa_subnets(), ecdsa_master_key_id(1)),
            (network_with_schnorr_subnets(), schnorr_master_key_id(1)),
            (network_with_vetkd_subnets(), vetkd_master_key_id(1)),
        ] {
            assert_matches!(
                resolve_destination(
                    &network_topology,
                    &Ic00Method::ReshareChainKey.to_string(),
                    &reshare_chain_key_request(key_id.clone(), subnet_test_id(2)),
                    subnet_test_id(2),
                    canister_test_id(1),
                    false,
                    &logger,
                )
                .unwrap_err(),
                ResolveDestinationError::ChainKeyError(err) => assert_eq!(
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
    fn resolve_reshare_chain_key_unknown_subnet_error() {
        let logger = no_op_logger();
        for (network_topology, key_id) in [
            (network_with_ecdsa_subnets(), ecdsa_master_key_id(1)),
            (network_with_schnorr_subnets(), schnorr_master_key_id(1)),
            (network_with_vetkd_subnets(), vetkd_master_key_id(1)),
        ] {
            assert_matches!(
                resolve_destination(
                    &network_topology,
                    &Ic00Method::ReshareChainKey.to_string(),
                    &reshare_chain_key_request(key_id.clone(), subnet_test_id(3)),
                    subnet_test_id(2),
                    canister_test_id(1),
                    false,
                    &logger,
                )
                .unwrap_err(),
                ResolveDestinationError::ChainKeyError(err) => assert_eq!(
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
    fn resolve_reshare_chain_key_wrong_subnet_error() {
        let logger = no_op_logger();
        for (network_topology, key_id) in [
            (network_with_ecdsa_subnets(), ecdsa_master_key_id(1)),
            (network_with_schnorr_subnets(), schnorr_master_key_id(1)),
            (network_with_vetkd_subnets(), vetkd_master_key_id(1)),
        ] {
            assert_matches!(
                    resolve_destination(
                        &network_topology,
                        &Ic00Method::ReshareChainKey.to_string(),
                        // Subnet 2 doesn't have the requested key.
                        &reshare_chain_key_request(key_id.clone(), subnet_test_id(2)),
                        subnet_test_id(2),
                        canister_test_id(1),
                        false,
                        &logger,
                    )
                    .unwrap_err(),
                    ResolveDestinationError::ChainKeyError(err) => assert_eq!(
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
    fn resolve_reshare_chain_key_subnet_not_found_error() {
        let logger = no_op_logger();
        for (network_topology, key_id) in [
            (network_with_ecdsa_subnets(), ecdsa_master_key_id(1)),
            (network_with_schnorr_subnets(), schnorr_master_key_id(1)),
            (network_with_vetkd_subnets(), vetkd_master_key_id(1)),
        ] {
            assert_matches!(
                resolve_destination(
                    &network_topology,
                    &Ic00Method::ReshareChainKey.to_string(),
                    // Subnet 3 doesn't exist
                    &reshare_chain_key_request(key_id.clone(), subnet_test_id(3)),
                    subnet_test_id(2),
                    canister_test_id(1),
                    false,
                    &logger,
                )
                .unwrap_err(),
                ResolveDestinationError::ChainKeyError(err) => assert_eq!(
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
    fn resolve_chain_key_request() {
        let logger = no_op_logger();
        for (network_topology, method, payload) in [
            (
                network_with_ecdsa_subnets(),
                Ic00Method::SignWithECDSA,
                ecdsa_sign_request(ecdsa_key_id(1)),
            ),
            (
                network_with_schnorr_subnets(),
                Ic00Method::SignWithSchnorr,
                schnorr_sign_request(schnorr_key_id(1)),
            ),
            (
                network_with_vetkd_subnets(),
                Ic00Method::VetKdDeriveKey,
                vetkd_derive_key_request(vetkd_key_id(1)),
            ),
        ] {
            assert_eq!(
                resolve_destination(
                    &network_topology,
                    &method.to_string(),
                    &payload,
                    subnet_test_id(1),
                    canister_test_id(1),
                    false,
                    &logger,
                )
                .unwrap(),
                PrincipalId::new_subnet_test_id(0)
            );
        }
    }

    #[test]
    fn resolve_chain_key_request_error() {
        let logger = no_op_logger();
        for (method, payload, master_key_id) in [
            (
                Ic00Method::SignWithECDSA,
                ecdsa_sign_request(ecdsa_key_id(1)),
                ecdsa_master_key_id(1),
            ),
            (
                Ic00Method::SignWithSchnorr,
                schnorr_sign_request(schnorr_key_id(1)),
                schnorr_master_key_id(1),
            ),
            (
                Ic00Method::VetKdDeriveKey,
                vetkd_derive_key_request(vetkd_key_id(1)),
                vetkd_master_key_id(1),
            ),
        ] {
            assert_matches!(resolve_destination(
                &network_without_chain_key_subnets(),
                &method.to_string(),
                &payload,
                subnet_test_id(1),
                canister_test_id(1),
                false,
                &logger,
            )
            .unwrap_err(),
            ResolveDestinationError::ChainKeyError(err) => assert_eq!(
                    err,
                    format!(
                        "Requested unknown or disabled threshold key: {}, existing enabled keys: []",
                        master_key_id,
                    )
                )
            )
        }
    }

    #[test]
    fn resolve_chain_key_public_key_works_with_disabled_keys() {
        let logger = no_op_logger();
        for (network_topology, method, payload) in [
            (
                network_with_ecdsa_subnets(),
                Ic00Method::ECDSAPublicKey,
                ecdsa_public_key_request(ecdsa_key_id(1)),
            ),
            (
                network_with_schnorr_subnets(),
                Ic00Method::SchnorrPublicKey,
                schnorr_public_key_request(schnorr_key_id(1)),
            ),
            (
                network_with_vetkd_subnets(),
                Ic00Method::VetKdPublicKey,
                vetkd_public_key_request(vetkd_key_id(1)),
            ),
        ] {
            assert_eq!(
                resolve_destination(
                    &network_topology,
                    &method.to_string(),
                    &payload,
                    subnet_test_id(1),
                    canister_test_id(1),
                    false,
                    &logger,
                )
                .unwrap(),
                PrincipalId::new_subnet_test_id(0)
            );
        }
    }

    #[test]
    fn resolve_reshare_chain_key_works_with_disabled_keys() {
        let logger = no_op_logger();
        for (network_topology, key_id) in [
            (network_with_ecdsa_subnets(), ecdsa_master_key_id(1)),
            (network_with_schnorr_subnets(), schnorr_master_key_id(1)),
            (network_with_vetkd_subnets(), vetkd_master_key_id(1)),
        ] {
            assert_eq!(
                resolve_destination(
                    &network_topology,
                    &Ic00Method::ReshareChainKey.to_string(),
                    &reshare_chain_key_request(key_id, subnet_test_id(0)),
                    subnet_test_id(1),
                    canister_test_id(1),
                    false,
                    &logger,
                )
                .unwrap(),
                PrincipalId::new_subnet_test_id(0)
            );
        }
    }

    #[test]
    fn route_chain_key_message_subnet_enabled() {
        // subnet_test_id(0) is enabled to use X_master_key_id(1).
        for (key_id, network_topology) in [
            (ecdsa_master_key_id(1), network_with_ecdsa_subnets()),
            (schnorr_master_key_id(1), network_with_schnorr_subnets()),
            (vetkd_master_key_id(1), network_with_vetkd_subnets()),
        ] {
            assert_eq!(
                route_chain_key_message(
                    &key_id,
                    &network_topology,
                    &Some(subnet_test_id(0)),
                    ChainKeySubnetKind::HoldsEnabledKey
                )
                .unwrap(),
                subnet_test_id(0).get()
            );
        }
    }

    #[test]
    fn route_chain_key_message_key_disabled() {
        // subnet_test_id(1) is not enabled to use X_master_key_id(1).
        for (key_id, network_topology) in [
            (ecdsa_master_key_id(1), network_with_ecdsa_subnets()),
            (schnorr_master_key_id(1), network_with_schnorr_subnets()),
            (vetkd_master_key_id(1), network_with_vetkd_subnets()),
        ] {
            let subnet_id = subnet_test_id(1);
            match route_chain_key_message(
                &key_id,
                &network_topology,
                &Some(subnet_id),
                ChainKeySubnetKind::HoldsEnabledKey,
            ) {
                Err(ResolveDestinationError::ChainKeyError(msg)) => assert_eq!(
                    msg,
                    format!("Subnet {subnet_id} is not enabled to use threshold key {key_id}",)
                ),
                _ => panic!("Unexpected result."),
            };
        }
    }

    #[test]
    fn route_chain_key_message_key_disabled_unknown_subnet() {
        for (key_id, network_topology) in [
            (ecdsa_master_key_id(1), network_with_ecdsa_subnets()),
            (schnorr_master_key_id(1), network_with_schnorr_subnets()),
            (vetkd_master_key_id(1), network_with_vetkd_subnets()),
        ] {
            let unknown_subnet_id = subnet_test_id(3);
            match route_chain_key_message(
                &key_id,
                &network_topology,
                &Some(unknown_subnet_id),
                ChainKeySubnetKind::HoldsEnabledKey,
            ) {
                Err(ResolveDestinationError::ChainKeyError(msg)) => assert_eq!(
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
    fn route_chain_key_message_subnet_unknown_disabled_key() {
        for (key_id, network_topology) in [
            (ecdsa_master_key_id(1), network_with_ecdsa_subnets()),
            (schnorr_master_key_id(1), network_with_schnorr_subnets()),
            (vetkd_master_key_id(1), network_with_vetkd_subnets()),
        ] {
            let subnet_id = subnet_test_id(2);
            match route_chain_key_message(
                &key_id,
                &network_topology,
                &Some(subnet_id),
                ChainKeySubnetKind::HoldsEnabledKey,
            ) {
                Err(ResolveDestinationError::ChainKeyError(msg)) => assert_eq!(
                    msg,
                    format!(
                        "Requested unknown threshold key {key_id} on subnet {subnet_id}, subnet has keys: []",
                    )
                ),
                _ => panic!("Unexpected result."),
            };
        }
    }

    #[test]
    fn route_chain_key_message_subnet_no_requested_subnet_unknown_disabled_key() {
        for (known_key_id, unknown_key_id, network_topology) in [
            (
                ecdsa_master_key_id(1),
                ecdsa_master_key_id(3),
                network_with_ecdsa_subnets(),
            ),
            (
                schnorr_master_key_id(1),
                schnorr_master_key_id(3),
                network_with_schnorr_subnets(),
            ),
            (
                vetkd_master_key_id(1),
                vetkd_master_key_id(3),
                network_with_vetkd_subnets(),
            ),
        ] {
            match route_chain_key_message(
                &unknown_key_id,
                &network_topology,
                &None,
                ChainKeySubnetKind::HoldsEnabledKey,
            ) {
                Err(ResolveDestinationError::ChainKeyError(msg)) => assert_eq!(
                    msg,
                    format!(
                        "Requested unknown or disabled threshold key: {unknown_key_id}, existing enabled keys: [{known_key_id}]",
                    )
                ),
                _ => panic!("Unexpected result."),
            };
        }
    }

    #[test]
    fn route_chain_key_message_subnet_not_required_key_disabled_unknown_key() {
        for (key_id1, key_id2, unknown_key_id, network_topology) in [
            (
                ecdsa_master_key_id(1),
                ecdsa_master_key_id(2),
                ecdsa_master_key_id(3),
                network_with_ecdsa_subnets(),
            ),
            (
                schnorr_master_key_id(1),
                schnorr_master_key_id(2),
                schnorr_master_key_id(3),
                network_with_schnorr_subnets(),
            ),
            (
                vetkd_master_key_id(1),
                vetkd_master_key_id(2),
                vetkd_master_key_id(3),
                network_with_vetkd_subnets(),
            ),
        ] {
            match route_chain_key_message(
                &unknown_key_id,
                &network_topology,
                &None,
                ChainKeySubnetKind::OnlyHoldsKey,
            ) {
                Err(ResolveDestinationError::ChainKeyError(msg)) => assert_eq!(
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
