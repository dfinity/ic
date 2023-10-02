use crate::state_api::state::HasStateLabel;
use crate::state_api::state::OpOut;
use crate::state_api::state::StateLabel;
use crate::BlobStore;
use crate::OpId;
use crate::Operation;
use ic_config::execution_environment;
use ic_config::subnet_config::SubnetConfig;
use ic_crypto::threshold_sig_public_key_to_der;
use ic_crypto_sha2::Sha256;
use ic_ic00_types::CanisterInstallMode;
use ic_interfaces_state_manager::StateReader;
use ic_registry_subnet_type::SubnetType;
use ic_state_machine_tests::Cycles;
use ic_state_machine_tests::StateMachine;
use ic_state_machine_tests::StateMachineBuilder;
use ic_state_machine_tests::StateMachineConfig;
use ic_state_machine_tests::Time;
use ic_types::{CanisterId, PrincipalId};
use pocket_ic::common::blob::{BinaryBlob, BlobCompression};
use pocket_ic::common::rest::RawAddCycles;
use pocket_ic::common::rest::RawCanisterCall;
use pocket_ic::common::rest::RawSetStableMemory;
use serde::Deserialize;
use serde::Serialize;
use std::{sync::Arc, time::SystemTime};
use tempfile::TempDir;
use tokio::runtime::Runtime;

pub struct PocketIc {
    subnet: StateMachine,
}

#[allow(clippy::new_without_default)]
impl PocketIc {
    pub fn new(sm: StateMachine) -> Self {
        Self { subnet: sm }
    }
}
impl Default for PocketIc {
    fn default() -> Self {
        let hypervisor_config = execution_environment::Config {
            default_provisional_cycles_balance: Cycles::new(0),
            ..Default::default()
        };
        let config =
            StateMachineConfig::new(SubnetConfig::new(SubnetType::System), hypervisor_config);
        let sm = StateMachineBuilder::new().with_config(Some(config)).build();
        Self::new(sm)
    }
}

impl HasStateLabel for PocketIc {
    fn get_state_label(&self) -> StateLabel {
        let subnet_state_hash = self
            .subnet
            .state_manager
            .latest_state_certification_hash()
            .map(|(_, h)| h.0)
            .unwrap_or_else(|| [0u8; 32].to_vec());
        let mut hasher = Sha256::new();
        let nanos = systemtime_to_unix_epoch_nanos(self.subnet.time());
        hasher.write(&subnet_state_hash[..]);
        // XXX: We should make the nonce part of the environment.
        // hasher.write(&self.nonce.to_be_bytes());
        hasher.write(&nanos.to_be_bytes());
        StateLabel(hasher.finish())
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
        // XXX: for now, we use the StateMachine's time as the system time. Later, we will take
        // StateMachine appart and have a system time that applies to all subnets.
        pic.subnet.set_time(self.time.into());
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
        let nanos = systemtime_to_unix_epoch_nanos(pic.subnet.time());
        OpOut::Time(nanos)
    }

    fn id(&self) -> OpId {
        OpId("get_time".into())
    }
}

#[derive(Clone, Debug, Copy)]
pub struct RootKey;

impl Operation for RootKey {
    type TargetType = PocketIc;

    fn compute(self, pic: &mut PocketIc) -> OpOut {
        let bytes = threshold_sig_public_key_to_der(pic.subnet.root_key()).unwrap();
        OpOut::Bytes(bytes)
    }

    fn id(&self) -> OpId {
        OpId("root_key".to_string())
    }
}

#[derive(Clone, Debug, Copy)]
pub struct Tick;

impl Operation for Tick {
    type TargetType = PocketIc;

    fn compute(self, pic: &mut PocketIc) -> OpOut {
        pic.subnet.tick();
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
        pic.subnet
            .execute_ingress_as(
                self.0.sender,
                self.0.canister_id,
                self.0.method,
                self.0.payload,
            )
            .into()
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
        pic.subnet
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

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CanisterCall {
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
        }: RawCanisterCall,
    ) -> Result<Self, Self::Error> {
        match PrincipalId::try_from(sender) {
            Ok(sender) => match CanisterId::try_from(canister_id) {
                Ok(canister_id) => Ok(Self {
                    sender,
                    canister_id,
                    method,
                    payload,
                }),
                Err(_) => Err(ConversionError {
                    message: "Bad canister id".to_string(),
                }),
            },
            Err(_) => Err(ConversionError {
                message: "Bad principal id".to_string(),
            }),
        }
    }
}

impl CanisterCall {
    fn id(&self) -> OpId {
        let mut hasher = Sha256::new();
        hasher.write(&self.payload);
        let hash = Digest(hasher.finish());
        OpId(format!(
            "call({},{},{},{})",
            self.sender, self.canister_id, self.method, hash
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
            .subnet
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
        OpOut::Bytes(pocket_ic.subnet.stable_memory(self.canister_id))
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
        let result = pic.subnet.cycle_balance(self.canister_id);
        OpOut::Cycles(result)
    }

    fn id(&self) -> OpId {
        OpId(format!("get_cycles_balance({})", self.canister_id))
    }
}

#[derive(Clone, Debug)]
pub struct CanisterExists {
    pub canister_id: CanisterId,
}

impl Operation for CanisterExists {
    type TargetType = PocketIc;
    fn compute(self, pic: &mut PocketIc) -> OpOut {
        let result = pic
            .subnet
            .state_manager
            .get_latest_state()
            .take()
            .canister_states
            .contains_key(&self.canister_id);
        OpOut::Bool(result)
    }

    fn id(&self) -> OpId {
        OpId(format!("canister_exists({})", self.canister_id))
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
        let result = pic.subnet.add_cycles(self.canister_id, self.amount);
        OpOut::Cycles(result)
    }

    fn id(&self) -> OpId {
        OpId(format!("add_cycles({},{})", self.canister_id, self.amount))
    }
}

/// Writes a checkpoint directory to the disk.
/// This directory is saved in the state graph, so a later
/// call could copy the directory and name it -> named checkpoints.
/// This operation, however, is only concerned with persisting the
/// subnet state to disk and storing the directory in the graph.
#[derive(Clone, Debug, Copy)]
pub struct Checkpoint;

impl Operation for Checkpoint {
    type TargetType = PocketIc;
    fn compute(self, pocket_ic: &mut Self::TargetType) -> OpOut {
        pocket_ic.subnet.set_checkpoints_enabled(true);
        pocket_ic.subnet.tick();
        pocket_ic.subnet.set_checkpoints_enabled(false);

        let state_dir = pocket_ic.subnet.state_dir.path();
        // find most recent checkpoint in the state_dir/checkpoints/ directory
        let checkpoint_dir = std::fs::read_dir(state_dir)
            .expect("Failed to read state dir")
            .max_by_key(|dir| {
                dir.as_ref()
                    .unwrap()
                    .metadata()
                    .unwrap()
                    .modified()
                    .unwrap()
            })
            .unwrap()
            .unwrap()
            .path();
        OpOut::Checkpoint(checkpoint_dir.to_str().unwrap().to_string())
    }

    fn id(&self) -> OpId {
        OpId("checkpoint".to_string())
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
        pic.subnet
            .install_wasm_in_mode(self.canister_id, self.mode, self.module, self.payload)
            .into()
    }

    fn id(&self) -> OpId {
        OpId("".into())
    }
}

// ================================================================================================================= //
// Helpers

pub fn create_state_machine(state_dir: Option<TempDir>, runtime: Arc<Runtime>) -> StateMachine {
    let hypervisor_config = execution_environment::Config {
        default_provisional_cycles_balance: Cycles::new(0),
        ..Default::default()
    };
    let config = StateMachineConfig::new(SubnetConfig::new(SubnetType::System), hypervisor_config);
    if let Some(state_dir) = state_dir {
        StateMachineBuilder::new()
            .with_config(Some(config))
            .with_state_dir(state_dir)
            .with_runtime(runtime)
            .build()
    } else {
        StateMachineBuilder::new()
            .with_config(Some(config))
            .with_runtime(runtime)
            .build()
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
    use pocket_ic::WasmResult;

    #[test]
    fn state_label_test() {
        let pic = PocketIc::default();

        let state0 = pic.get_state_label();
        let canister_id = pic.subnet.create_canister(None);
        let state1 = pic.get_state_label();
        let _ = pic.subnet.delete_canister(canister_id);
        let state2 = pic.get_state_label();

        assert!(state0 != state1);
        assert!(state1 != state2);
        assert!(state0 != state2);
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

        let update = ExecuteIngressMessage(CanisterCall {
            sender: PrincipalId::new_anonymous(),
            canister_id,
            method: "write".into(),
            payload: vec![],
        });

        compute_assert_state_change(&mut pic, update);
    }

    #[test]
    fn test_query() {
        let (mut pic, canister_id) = new_pic_counter_installed();
        let (query, update) = query_update_constructors(canister_id);

        let OpOut::CanisterResult(Ok(WasmResult::Reply(initial_bytes))) =
            compute_assert_state_immutable(&mut pic, query("read"))
        else {
            unreachable!()
        };
        compute_assert_state_change(&mut pic, update("write"));
        let OpOut::CanisterResult(Ok(WasmResult::Reply(updated_bytes))) =
            compute_assert_state_immutable(&mut pic, query("read"))
        else {
            unreachable!()
        };

        assert_eq!(updated_bytes[0], initial_bytes[0] + 1);
    }

    #[test]
    fn test_cycles() {
        let (mut pic, canister_id) = new_pic_counter_installed();
        let (_, update) = query_update_constructors(canister_id);

        let cycles_balance = GetCyclesBalance { canister_id };
        let OpOut::Cycles(orig_balance) =
            compute_assert_state_immutable(&mut pic, cycles_balance.clone())
        else {
            unreachable!()
        };
        compute_assert_state_change(&mut pic, update("write"));
        let OpOut::Cycles(changed_balance) =
            compute_assert_state_immutable(&mut pic, cycles_balance)
        else {
            unreachable!()
        };

        // nothing is charged on a system subnet
        assert_eq!(changed_balance, orig_balance);

        let amount: u128 = 20_000_000_000_000;
        let add_cycles = AddCycles {
            canister_id,
            amount,
        };

        let OpOut::Cycles(final_balance) = compute_assert_state_change(&mut pic, add_cycles) else {
            unreachable!()
        };

        assert_eq!(final_balance, changed_balance + amount);
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
        };

        let update = move |m: &str| ExecuteIngressMessage(call(m));
        let query = move |m: &str| Query(call(m));

        (query, update)
    }

    fn new_pic_counter_installed() -> (PocketIc, CanisterId) {
        let mut pic = PocketIc::default();
        let canister_id = pic.subnet.create_canister(None);

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
        assert!(state0 != state1);
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
