use crate::state_api::state::{HasStateLabel, OpOut, PocketIcError, StateLabel};
use crate::BlobStore;
use crate::OpId;
use crate::Operation;
use ic_config::execution_environment;
use ic_config::subnet_config::SubnetConfig;
use ic_crypto_sha2::Sha256;
use ic_crypto_utils_threshold_sig_der::threshold_sig_public_key_to_der;
use ic_ic00_types::CanisterInstallMode;
use ic_registry_proto_data_provider::ProtoRegistryDataProvider;
use ic_registry_routing_table::{CanisterIdRange, RoutingTable, CANISTER_IDS_PER_SUBNET};
use ic_registry_subnet_type::SubnetType;
use ic_state_machine_tests::{
    EcdsaCurve, EcdsaKeyId, IngressState, IngressStatus, StateMachine, StateMachineBuilder,
    StateMachineConfig, Time,
};
use ic_test_utilities::types::ids::subnet_test_id;
use ic_types::{CanisterId, PrincipalId, SubnetId};
use itertools::Itertools;
use pocket_ic::common::rest::{
    self, BinaryBlob, BlobCompression, RawAddCycles, RawCanisterCall, RawEffectivePrincipal,
    RawSetStableMemory, Topology,
};
use rand::rngs::StdRng;
use rand::Rng;
use rand::SeedableRng;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
    time::SystemTime,
};
use tokio::runtime::Runtime;

pub struct PocketIc {
    subnets: Arc<RwLock<HashMap<SubnetId, Arc<StateMachine>>>>,
    routing_table: RoutingTable,
    /// Constant for now. Filled on initialization.
    pub topology: Topology,
    // Used for choosing a random subnet when the user does not specify
    // a subnet where a canister should be created. This value is seeded,
    // so we still maintain reproducibility.
    randomness: StdRng,
}

impl PocketIc {
    pub fn new(runtime: Arc<Runtime>, subnet_configs: Vec<rest::SubnetConfig>) -> Self {
        // The user may request an NNS. We must make sure there is at most one, and that only an NNS
        // has the canister range [0, 2^20-1].
        // If an NNS config exists, pull it to the front and filter out all other NNS configs.
        let nns_predicate = |conf: &rest::SubnetConfig| conf.subnet_type == rest::SubnetKind::NNS;
        let nns_cfg = subnet_configs.iter().cloned().find(nns_predicate);
        let mut cfgs: Vec<rest::SubnetConfig> = subnet_configs
            .into_iter()
            .filter(|conf| !nns_predicate(conf))
            .collect();
        // We start the subnet ranges from 0 if we have an NNS, and from 1 otherwise.
        let start_index = if let Some(nns_cfg) = nns_cfg {
            cfgs.insert(0, nns_cfg);
            0
        } else {
            1
        };
        // The subnet id and range are now derived from the index in this vec and the start_index.
        // Before we can create the individual subnets, we need to create a routing table, which needs info
        // about the whole set of subnets.
        let subnet_config_info: Vec<(SubnetId, CanisterIdRange, rest::SubnetConfig)> = cfgs
            .into_iter()
            .enumerate()
            .map(|(i, cfg)| {
                let i: u64 = i as u64 + start_index;
                let range = CanisterIdRange {
                    start: CanisterId::from_u64(i * CANISTER_IDS_PER_SUBNET),
                    end: CanisterId::from_u64((i + 1) * CANISTER_IDS_PER_SUBNET - 1),
                };
                let subnet_id = subnet_test_id(i);
                (subnet_id, range, cfg)
            })
            .collect();

        // Set up routing table and subnet list for registry.
        let mut routing_table = RoutingTable::new();
        let mut subnet_id_list = Vec::new();
        for (subnet_id, range, _) in subnet_config_info.iter() {
            routing_table.insert(*range, *subnet_id).unwrap();
            subnet_id_list.push(*subnet_id);
        }
        // Set up registry data provider.
        let registry_data_provider = Arc::new(ProtoRegistryDataProvider::new());

        // Now we can create all subnets and the topology.
        let subnets: Arc<RwLock<HashMap<SubnetId, Arc<StateMachine>>>> =
            Arc::new(RwLock::new(HashMap::new()));
        let mut topology = Topology(HashMap::new());
        for (subnet_id, range, cfg) in subnet_config_info {
            let subnet_config = SubnetConfig::new(conv_type(cfg.subnet_type));
            let config =
                StateMachineConfig::new(subnet_config, execution_environment::Config::default());
            let subnet = StateMachineBuilder::new()
                .with_runtime(runtime.clone())
                .with_config(Some(config))
                .with_subnet_id(subnet_id)
                .with_subnet_list(subnet_id_list.clone())
                .with_routing_table(routing_table.clone())
                .with_registry_data_provider(registry_data_provider.clone())
                .with_ecdsa_keys(vec![EcdsaKeyId {
                    curve: EcdsaCurve::Secp256k1,
                    name: format!("master_ecdsa_public_key_{}", subnet_id),
                }])
                .build_with_subnets(subnets.clone());
            subnet.set_time(SystemTime::now());

            topology.0.insert(
                subnet_id.get().0,
                (
                    rest::CanisterIdRange {
                        start: range.start.into(),
                        end: range.end.into(),
                    },
                    cfg,
                ),
            );
        }

        for subnet in subnets.read().unwrap().values() {
            // Reload registry on the state machines to make sure
            // the registry contains all subnet records
            // added incrementally to the registry data provider
            // when creating the individual state machines.
            subnet.reload_registry();
        }

        Self {
            subnets,
            routing_table,
            topology,
            randomness: StdRng::seed_from_u64(42),
        }
    }

    fn try_route_canister(&self, canister_id: CanisterId) -> Option<Arc<StateMachine>> {
        let subnet_id = self.routing_table.route(canister_id.into());
        subnet_id.map(|subnet_id| self.get_subnet_with_id(subnet_id))
    }

    fn any_subnet(&self) -> Arc<StateMachine> {
        self.subnets
            .read()
            .unwrap()
            .values()
            .next()
            .unwrap()
            .clone()
    }

    fn random_subnet(&mut self) -> Arc<StateMachine> {
        // A new canister should be installed on an app subnet by default.
        // If there are no app subnets, we fall back to non-NNS system subnets.
        // If there are none of these, we install in the NNS subnet.
        let random_application_subnet =
            self.get_random_subnet_of_type(rest::SubnetKind::Application);
        if let Some(subnet) = random_application_subnet {
            return subnet;
        }
        let random_system_subnet = self.get_random_subnet_of_type(rest::SubnetKind::System);
        if let Some(subnet) = random_system_subnet {
            return subnet;
        }
        // If there are no application or system subnets, return the (only) NNS subnet.
        self.any_subnet()
    }

    fn get_subnet_with_id(&self, subnet_id: SubnetId) -> Arc<StateMachine> {
        self.subnets
            .read()
            .expect("Failed to get read lock on subnets")
            .get(&subnet_id)
            .expect("Subnet not found")
            .clone()
    }

    fn get_random_subnet_of_type(
        &mut self,
        subnet_type: rest::SubnetKind,
    ) -> Option<Arc<StateMachine>> {
        let subnets = self
            .topology
            .0
            .iter()
            .filter(|(_, (_, config))| config.subnet_type == subnet_type)
            .collect_vec();
        if !subnets.is_empty() {
            let n = subnets.len();
            let index = self.randomness.gen_range(0..n);
            let (subnet_principal, _) = subnets[index];
            let subnet_id = SubnetId::new(PrincipalId(*subnet_principal));
            Some(self.get_subnet_with_id(subnet_id))
        } else {
            None
        }
    }
}

impl Default for PocketIc {
    fn default() -> Self {
        Self::new(Runtime::new().unwrap().into(), vec![rest::STANDARD])
    }
}

impl HasStateLabel for PocketIc {
    fn get_state_label(&self) -> StateLabel {
        let mut hasher = Sha256::new();
        for subnet in self.subnets.read().unwrap().values() {
            let subnet_state_hash = subnet
                .state_manager
                .latest_state_certification_hash()
                .map(|(_, h)| h.0)
                .unwrap_or_else(|| [0u8; 32].to_vec());
            let nanos = systemtime_to_unix_epoch_nanos(subnet.time());
            hasher.write(&subnet_state_hash[..]);
            hasher.write(&nanos.to_be_bytes());
        }
        StateLabel(hasher.finish())
    }
}

fn conv_type(inp: rest::SubnetKind) -> SubnetType {
    match inp {
        rest::SubnetKind::Application => SubnetType::Application,
        rest::SubnetKind::System => SubnetType::System,
        rest::SubnetKind::NNS => SubnetType::System,
    }
}

// ---------------------------------------------------------------------------------------- //
// Operations on PocketIc

// When raw (rest) types are cast to operations, errors can occur.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct ConversionError {
    message: String,
}

#[derive(Clone, Debug)]
pub struct SetTime {
    pub time: Time,
}

impl Operation for SetTime {
    type TargetType = PocketIc;

    fn compute(self, pic: &mut PocketIc) -> OpOut {
        // Sets the time on all subnets.
        for subnet in pic.subnets.read().unwrap().values() {
            subnet.set_time(self.time.into());
        }
        OpOut::NoOutput
    }

    fn id(&self) -> OpId {
        OpId(format!("set_time_{}", self.time))
    }
}

#[derive(Clone, Copy, Debug)]
pub struct GetTime;

impl Operation for GetTime {
    type TargetType = PocketIc;

    fn compute(self, pic: &mut PocketIc) -> OpOut {
        // Time is kept in sync across subnets, so we can take any subnet.
        let nanos = systemtime_to_unix_epoch_nanos(pic.any_subnet().time());
        OpOut::Time(nanos)
    }

    fn id(&self) -> OpId {
        OpId("get_time".into())
    }
}

#[derive(Clone, Debug, Copy)]
pub struct PubKey {
    pub subnet_id: SubnetId,
}

impl Operation for PubKey {
    type TargetType = PocketIc;

    fn compute(self, pic: &mut PocketIc) -> OpOut {
        if !pic.topology.0.contains_key(&self.subnet_id.get().0) {
            return OpOut::Error(PocketIcError::SubnetNotFound(self.subnet_id.get().0));
        }
        let subnet = pic.get_subnet_with_id(self.subnet_id);
        let bytes = threshold_sig_public_key_to_der(subnet.root_key()).unwrap();
        OpOut::Bytes(bytes)
    }

    fn id(&self) -> OpId {
        OpId(format!("root_key_{}", self.subnet_id))
    }
}

#[derive(Clone, Debug, Copy)]
pub struct Tick;

impl Operation for Tick {
    type TargetType = PocketIc;

    fn compute(self, pic: &mut PocketIc) -> OpOut {
        for subnet in pic.subnets.read().unwrap().values() {
            subnet.execute_round();
        }
        OpOut::NoOutput
    }

    fn id(&self) -> OpId {
        OpId("tick".to_string())
    }
}

#[derive(Clone, Debug)]
pub struct ExecuteIngressMessage(pub CanisterCall);

impl Operation for ExecuteIngressMessage {
    type TargetType = PocketIc;

    fn compute(self, pic: &mut PocketIc) -> OpOut {
        let canister_call = self.0.clone();
        let subnet = route_call(pic, canister_call);

        match subnet.submit_ingress_as(
            self.0.sender,
            self.0.canister_id,
            self.0.method,
            self.0.payload,
        ) {
            Err(e) => {
                eprintln!("Failed to submit ingress message: {}", e);
                OpOut::Error(PocketIcError::BadIngressMessage(e))
            }
            Ok(msg_id) => {
                // Now, we execute on all subnets until we have the result
                let max_rounds = 100;
                for _i in 0..max_rounds {
                    for subnet_ in pic.subnets.read().unwrap().values() {
                        subnet_.execute_round();
                    }
                    match subnet.ingress_status(&msg_id) {
                        IngressStatus::Known {
                            state: IngressState::Completed(result),
                            ..
                        } => return Ok(result).into(),
                        IngressStatus::Known {
                            state: IngressState::Failed(error),
                            ..
                        } => {
                            return Err::<
                                ic_state_machine_tests::WasmResult,
                                ic_state_machine_tests::UserError,
                            >(error)
                            .into()
                        }
                        _ => {}
                    }
                }
                panic!(
                    "Failed to answer to ingress {} after {} xnet rounds.",
                    msg_id, max_rounds
                );
            }
        }
    }

    fn id(&self) -> OpId {
        let call_id = self.0.id();
        OpId(format!("canister_update_{}", call_id.0))
    }
}

pub struct Query(pub CanisterCall);

impl Operation for Query {
    type TargetType = PocketIc;
    fn compute(self, pic: &mut PocketIc) -> OpOut {
        let canister_call = self.0.clone();
        let subnet = route_call(pic, canister_call);
        subnet
            .query_as(
                self.0.sender,
                self.0.canister_id,
                self.0.method,
                self.0.payload,
            )
            .into()
    }

    fn id(&self) -> OpId {
        let call_id = self.0.id();
        OpId(format!("canister_query_{}", call_id.0))
    }
}

#[derive(Clone, Debug)]
pub enum EffectivePrincipal {
    None,
    SubnetId(SubnetId),
    CanisterId(CanisterId),
}

#[derive(Clone, Debug)]
pub struct CanisterCall {
    pub effective_principal: EffectivePrincipal,
    pub sender: PrincipalId,
    pub canister_id: CanisterId,
    pub method: String,
    pub payload: Vec<u8>,
}

impl TryFrom<RawCanisterCall> for CanisterCall {
    type Error = ConversionError;
    fn try_from(
        RawCanisterCall {
            sender,
            canister_id,
            method,
            payload,
            effective_principal,
        }: RawCanisterCall,
    ) -> Result<Self, Self::Error> {
        let effective_principal = match effective_principal {
            RawEffectivePrincipal::SubnetId(subnet_id) => {
                let sid = PrincipalId::try_from(subnet_id);
                match sid {
                    Ok(sid) => EffectivePrincipal::SubnetId(SubnetId::new(sid)),
                    Err(_) => {
                        return Err(ConversionError {
                            message: "Bad subnet id".to_string(),
                        })
                    }
                }
            }
            RawEffectivePrincipal::CanisterId(canister_id) => {
                match CanisterId::try_from(canister_id) {
                    Ok(canister_id) => EffectivePrincipal::CanisterId(canister_id),
                    Err(_) => {
                        return Err(ConversionError {
                            message: "Bad effective canister id".to_string(),
                        })
                    }
                }
            }
            RawEffectivePrincipal::None => EffectivePrincipal::None,
        };
        let sender = match PrincipalId::try_from(sender) {
            Ok(sender) => sender,
            Err(_) => {
                return Err(ConversionError {
                    message: "Bad sender principal".to_string(),
                })
            }
        };
        let canister_id = match CanisterId::try_from(canister_id) {
            Ok(canister_id) => canister_id,
            Err(_) => {
                return Err(ConversionError {
                    message: "Bad canister id".to_string(),
                })
            }
        };

        Ok(CanisterCall {
            effective_principal,
            sender,
            canister_id,
            method,
            payload,
        })
    }
}

impl CanisterCall {
    fn id(&self) -> OpId {
        let mut hasher = Sha256::new();
        hasher.write(&self.payload);
        let hash = Digest(hasher.finish());
        OpId(format!(
            "call({:?},{},{},{},{})",
            self.effective_principal, self.sender, self.canister_id, self.method, hash
        ))
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SetStableMemory {
    pub canister_id: CanisterId,
    pub data: Vec<u8>,
}

impl SetStableMemory {
    pub async fn from_store(
        raw: RawSetStableMemory,
        store: Arc<dyn BlobStore>,
    ) -> Result<Self, ConversionError> {
        if let Ok(canister_id) = CanisterId::try_from(raw.canister_id) {
            if let Some(BinaryBlob { data, compression }) = store.fetch(raw.blob_id).await {
                if let Some(data) = decompress(data, compression) {
                    Ok(SetStableMemory { canister_id, data })
                } else {
                    Err(ConversionError {
                        message: "Decompression failed".to_string(),
                    })
                }
            } else {
                Err(ConversionError {
                    message: "Bad blob id".to_string(),
                })
            }
        } else {
            Err(ConversionError {
                message: "Bad canister id".to_string(),
            })
        }
    }
}

fn decompress(data: Vec<u8>, compression: BlobCompression) -> Option<Vec<u8>> {
    use std::io::Read;
    match compression {
        BlobCompression::Gzip => {
            let mut decoder = flate2::read::GzDecoder::new(&data[..]);
            let mut out = Vec::new();
            let result = decoder.read_to_end(&mut out);
            if result.is_err() {
                return None;
            }
            Some(out)
        }
        BlobCompression::NoCompression => Some(data),
    }
}

impl Operation for SetStableMemory {
    type TargetType = PocketIc;
    fn compute(self, pocket_ic: &mut Self::TargetType) -> OpOut {
        pocket_ic
            .try_route_canister(self.canister_id)
            .unwrap()
            .set_stable_memory(self.canister_id, &self.data);
        OpOut::NoOutput
    }

    fn id(&self) -> OpId {
        // TODO: consider tupling the hash with the data everywhere,
        // from the sender up to here. so the blobstore can be lazier,
        // we _can_ check for consistency, but we don't _have to_ re-
        // calculate it here.
        let mut hasher = Sha256::new();
        hasher.write(&self.data);
        let hash = Digest(hasher.finish());
        OpId(format!("set_stable_memory({}_{})", self.canister_id, hash))
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct GetStableMemory {
    pub canister_id: CanisterId,
}

impl Operation for GetStableMemory {
    type TargetType = PocketIc;
    fn compute(self, pocket_ic: &mut Self::TargetType) -> OpOut {
        OpOut::Bytes(
            pocket_ic
                .try_route_canister(self.canister_id)
                .unwrap()
                .stable_memory(self.canister_id),
        )
    }

    fn id(&self) -> OpId {
        OpId(format!("get_stable_memory({})", self.canister_id))
    }
}

#[derive(Clone, Debug)]
pub struct GetCyclesBalance {
    pub canister_id: CanisterId,
}

impl Operation for GetCyclesBalance {
    type TargetType = PocketIc;
    fn compute(self, pic: &mut PocketIc) -> OpOut {
        let result = pic
            .try_route_canister(self.canister_id)
            .unwrap()
            .cycle_balance(self.canister_id);
        OpOut::Cycles(result)
    }

    fn id(&self) -> OpId {
        OpId(format!("get_cycles_balance({})", self.canister_id))
    }
}

#[derive(Clone, Debug)]
pub struct GetSubnet {
    pub canister_id: CanisterId,
}

impl Operation for GetSubnet {
    type TargetType = PocketIc;
    fn compute(self, pic: &mut PocketIc) -> OpOut {
        let sm = pic.try_route_canister(self.canister_id);
        match sm {
            Some(sm) => OpOut::SubnetId(sm.get_subnet_id()),
            None => OpOut::Error(PocketIcError::CanisterNotFound(self.canister_id)),
        }
    }

    fn id(&self) -> OpId {
        OpId(format!("get_subnet({})", self.canister_id))
    }
}

/// Add cycles to a given canister.
///
/// # Panics
///
/// Panics if the canister does not exist.
#[derive(Clone, Debug)]
pub struct AddCycles {
    canister_id: CanisterId,
    amount: u128,
}

impl TryFrom<RawAddCycles> for AddCycles {
    type Error = ConversionError;
    fn try_from(
        RawAddCycles {
            canister_id,
            amount,
        }: RawAddCycles,
    ) -> Result<Self, Self::Error> {
        match CanisterId::try_from(canister_id) {
            Ok(canister_id) => Ok(AddCycles {
                canister_id,
                amount,
            }),
            Err(_) => Err(ConversionError {
                message: "Bad canister id".to_string(),
            }),
        }
    }
}

impl Operation for AddCycles {
    type TargetType = PocketIc;

    fn compute(self, pic: &mut PocketIc) -> OpOut {
        let result = pic
            .try_route_canister(self.canister_id)
            .unwrap()
            .add_cycles(self.canister_id, self.amount);
        OpOut::Cycles(result)
    }

    fn id(&self) -> OpId {
        OpId(format!("add_cycles({},{})", self.canister_id, self.amount))
    }
}

struct Digest([u8; 32]);

impl std::fmt::Debug for Digest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Digest(")?;
        self.0.iter().try_for_each(|b| write!(f, "{:02X}", b))?;
        write!(f, ")")
    }
}

impl std::fmt::Display for Digest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

// TODO: deprecate this as an Op; implement it as a client library convenience function

/// A convenience method that installs the given wasm module at the given canister id. The first
/// controller of the given canister is set as the sender. If the canister has no controller set,
/// the anynmous user is used.
pub struct InstallCanisterAsController {
    pub canister_id: CanisterId,
    pub mode: CanisterInstallMode,
    pub module: Vec<u8>,
    pub payload: Vec<u8>,
}

impl Operation for InstallCanisterAsController {
    type TargetType = PocketIc;

    fn compute(self, pic: &mut PocketIc) -> OpOut {
        pic.try_route_canister(self.canister_id)
            .unwrap()
            .install_wasm_in_mode(self.canister_id, self.mode, self.module, self.payload)
            .into()
    }

    fn id(&self) -> OpId {
        OpId("".into())
    }
}

// ================================================================================================================= //
// Helpers

fn route_call(pic: &mut PocketIc, canister_call: CanisterCall) -> Arc<StateMachine> {
    let effective_principal = canister_call.effective_principal.clone();
    match effective_principal {
        EffectivePrincipal::SubnetId(subnet_id) => pic.get_subnet_with_id(subnet_id),
        EffectivePrincipal::CanisterId(effective_canister_id) => {
            pic.try_route_canister(effective_canister_id).unwrap()
        }
        EffectivePrincipal::None => {
            if canister_call.canister_id == CanisterId::ic_00() {
                pic.random_subnet()
            } else {
                pic.try_route_canister(canister_call.canister_id).unwrap()
            }
        }
    }
}

fn systemtime_to_unix_epoch_nanos(st: SystemTime) -> u64 {
    st.duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_nanos()
        .try_into()
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_label_test() {
        let pic = PocketIc::default();

        let state0 = pic.get_state_label();
        let canister_id = pic.any_subnet().create_canister(None);
        let state1 = pic.get_state_label();
        let _ = pic.any_subnet().delete_canister(canister_id);
        let state2 = pic.get_state_label();

        assert_ne!(state0, state1);
        assert_ne!(state1, state2);
        assert_ne!(state0, state2);
    }

    #[test]
    fn test_time() {
        let mut pic = PocketIc::default();

        let time = Time::from_nanos_since_unix_epoch(21);
        compute_assert_state_change(&mut pic, SetTime { time });
        let expected_time = OpOut::Time(21);
        let actual_time = compute_assert_state_immutable(&mut pic, GetTime {});

        assert_eq!(expected_time, actual_time);
    }

    #[test]
    fn test_execute_message() {
        let (mut pic, canister_id) = new_pic_counter_installed();
        let amount: u128 = 20_000_000_000_000;
        let add_cycles = AddCycles {
            canister_id,
            amount,
        };
        add_cycles.compute(&mut pic);

        let update = ExecuteIngressMessage(CanisterCall {
            sender: PrincipalId::new_anonymous(),
            canister_id,
            method: "write".into(),
            payload: vec![],
            effective_principal: EffectivePrincipal::None,
        });

        compute_assert_state_change(&mut pic, update);
    }

    #[test]
    fn test_cycles_burn_app_subnet() {
        let (mut pic, canister_id) = new_pic_counter_installed();
        let (_, update) = query_update_constructors(canister_id);
        let cycles_balance = GetCyclesBalance { canister_id };
        let OpOut::Cycles(initial_balance) =
            compute_assert_state_immutable(&mut pic, cycles_balance.clone())
        else {
            unreachable!()
        };
        compute_assert_state_change(&mut pic, update("write"));
        let OpOut::Cycles(new_balance) = compute_assert_state_immutable(&mut pic, cycles_balance)
        else {
            unreachable!()
        };
        assert_ne!(initial_balance, new_balance);
    }

    #[test]
    fn test_cycles_burn_system_subnet() {
        let (mut pic, canister_id) = new_pic_counter_installed_system_subnet();
        let (_, update) = query_update_constructors(canister_id);

        let cycles_balance = GetCyclesBalance { canister_id };
        let OpOut::Cycles(initial_balance) =
            compute_assert_state_immutable(&mut pic, cycles_balance.clone())
        else {
            unreachable!()
        };
        compute_assert_state_change(&mut pic, update("write"));
        let OpOut::Cycles(new_balance) = compute_assert_state_immutable(&mut pic, cycles_balance)
        else {
            unreachable!()
        };
        assert_eq!(initial_balance, new_balance);
    }

    fn query_update_constructors(
        canister_id: CanisterId,
    ) -> (
        impl Fn(&str) -> Query,
        impl Fn(&str) -> ExecuteIngressMessage,
    ) {
        let call = move |method: &str| CanisterCall {
            sender: PrincipalId::new_anonymous(),
            canister_id,
            method: method.into(),
            payload: vec![],
            effective_principal: EffectivePrincipal::None,
        };

        let update = move |m: &str| ExecuteIngressMessage(call(m));
        let query = move |m: &str| Query(call(m));

        (query, update)
    }

    fn new_pic_counter_installed() -> (PocketIc, CanisterId) {
        let mut pic = PocketIc::default();
        let canister_id = pic.any_subnet().create_canister(None);

        let amount: u128 = 20_000_000_000_000;
        let add_cycles = AddCycles {
            canister_id,
            amount,
        };
        add_cycles.compute(&mut pic);

        let module = counter_wasm();
        let install_op = InstallCanisterAsController {
            canister_id,
            mode: CanisterInstallMode::Install,
            module,
            payload: vec![],
        };

        compute_assert_state_change(&mut pic, install_op);

        (pic, canister_id)
    }

    fn new_pic_counter_installed_system_subnet() -> (PocketIc, CanisterId) {
        let mut pic = PocketIc::new(Runtime::new().unwrap().into(), vec![rest::II]);
        let canister_id = pic.any_subnet().create_canister(None);

        let module = counter_wasm();
        let install_op = InstallCanisterAsController {
            canister_id,
            mode: CanisterInstallMode::Install,
            module,
            payload: vec![],
        };

        compute_assert_state_change(&mut pic, install_op);

        (pic, canister_id)
    }

    fn compute_assert_state_change<O>(pic: &mut PocketIc, op: O) -> OpOut
    where
        O: Operation<TargetType = PocketIc>,
    {
        let state0 = pic.get_state_label();
        let res = op.compute(pic);
        let state1 = pic.get_state_label();
        assert_ne!(state0, state1);
        res
    }

    fn compute_assert_state_immutable<O>(pic: &mut PocketIc, op: O) -> OpOut
    where
        O: Operation<TargetType = PocketIc>,
    {
        let state0 = pic.get_state_label();
        let res = op.compute(pic);
        let state1 = pic.get_state_label();
        assert_eq!(state0, state1);
        res
    }

    fn counter_wasm() -> Vec<u8> {
        wat::parse_str(COUNTER_WAT).unwrap().as_slice().to_vec()
    }

    const COUNTER_WAT: &str = r#"
;; Counter with global variable ;;
(module
  (import "ic0" "msg_reply" (func $msg_reply))
  (import "ic0" "msg_reply_data_append"
    (func $msg_reply_data_append (param i32 i32)))

  (func $read
    (i32.store
      (i32.const 0)
      (global.get 0)
    )
    (call $msg_reply_data_append
      (i32.const 0)
      (i32.const 4))
    (call $msg_reply))

  (func $write
    (global.set 0
      (i32.add
        (global.get 0)
        (i32.const 1)
      )
    )
    (call $read)
  )

  (memory $memory 1)
  (export "memory" (memory $memory))
  (global (export "counter_global") (mut i32) (i32.const 0))
  (export "canister_query read" (func $read))
  (export "canister_query inc_read" (func $write))
  (export "canister_update write" (func $write))
)
    "#;
}
