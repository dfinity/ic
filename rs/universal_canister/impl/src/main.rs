use candid::{CandidType, Decode, Deserialize, Encode, Principal};
use std::convert::TryInto;
use std::hint::black_box;
use universal_canister::Ops;

mod api;

const ONE_WAY_CALL: u32 = u32::MAX;

// Canister http_request types

#[derive(CandidType, Deserialize)]
pub struct HttpHeader {
    pub name: String,
    pub value: String,
}

#[derive(CandidType, Deserialize)]
pub struct HttpResponse {
    pub status: u128,
    pub headers: Vec<HttpHeader>,
    pub body: Vec<u8>,
}

#[derive(CandidType, Deserialize)]
pub struct TransformArg {
    pub response: HttpResponse,
    pub context: Vec<u8>,
}

fn http_reply_with_body(body: &[u8]) -> Vec<u8> {
    Encode!(&HttpResponse {
        status: 200_u128,
        headers: vec![],
        body: body.to_vec(),
    })
    .unwrap()
}

// A simple dynamically typed stack

enum Val {
    I32(u32),
    I64(u64),
    Blob(Vec<u8>),
}

struct Stack(Vec<Val>);

impl Stack {
    fn new() -> Self {
        Stack(Vec::new())
    }

    fn drop(&mut self) {
        self.0.pop();
    }

    fn push_int(&mut self, x: u32) {
        self.0.push(Val::I32(x));
    }

    fn push_int64(&mut self, x: u64) {
        self.0.push(Val::I64(x));
    }

    fn push_blob(&mut self, x: Vec<u8>) {
        self.0.push(Val::Blob(x));
    }

    fn pop_int(&mut self) -> u32 {
        if let Some(Val::I32(i)) = self.0.pop() {
            i
        } else {
            api::trap_with("did not find I32 on stack")
        }
    }

    fn pop_int64(&mut self) -> u64 {
        if let Some(Val::I64(i)) = self.0.pop() {
            i
        } else {
            api::trap_with("did not find I64 on stack")
        }
    }

    fn pop_blob(&mut self) -> Vec<u8> {
        if let Some(Val::Blob(blob)) = self.0.pop() {
            blob
        } else {
            api::trap_with("did not find blob on stack")
        }
    }
}

// Reading data from the operations stream

type OpsBytes<'a> = &'a [u8];

fn read_bytes<'a>(ops_bytes: &mut OpsBytes<'a>, len: usize) -> &'a [u8] {
    if len < ops_bytes.len() {
        let (bytes, rest) = ops_bytes.split_at(len);
        *ops_bytes = rest;
        bytes
    } else {
        panic!(
            "cannot read {} bytes of a {} byte string",
            len,
            ops_bytes.len()
        );
    }
}

fn read_int(ops_bytes: &mut OpsBytes) -> u32 {
    let bytes = read_bytes(ops_bytes, std::mem::size_of::<u32>());
    u32::from_le_bytes(bytes.try_into().unwrap())
}

fn read_int64(ops_bytes: &mut OpsBytes) -> u64 {
    let bytes = read_bytes(ops_bytes, std::mem::size_of::<u64>());
    u64::from_le_bytes(bytes.try_into().unwrap())
}

fn delay(value: u64) {
    for _ in 0..value {
        // Using `black_box` to make sure this no-op cycle is not removed by the compiler optimization.
        black_box(0);
    }
}

fn eval(ops_bytes: OpsBytes) {
    let mut ops_bytes: OpsBytes = ops_bytes;
    let mut stack: Stack = Stack::new();

    while let Some((op_code, rest)) = ops_bytes.split_first() {
        ops_bytes = rest;
        let op = match Ops::try_from(*op_code) {
            Err(..) => {
                api::trap_with(&format!("unknown op {}", op_code));
            }
            Ok(op) => op,
        };
        match op {
            Ops::Noop => (),
            Ops::Drop => stack.drop(),
            Ops::PushInt => {
                let a = read_int(&mut ops_bytes);
                stack.push_int(a);
            }
            Ops::PushBytes => {
                let len = read_int(&mut ops_bytes);
                let blob = read_bytes(&mut ops_bytes, len as usize).to_vec();
                stack.push_blob(blob);
            }
            Ops::ReplyDataAppend => api::reply_data_append(&stack.pop_blob()),
            Ops::Reply => api::reply(),
            Ops::Self_ => stack.push_blob(api::id()),
            Ops::Reject => api::reject(&stack.pop_blob()),
            Ops::Caller => stack.push_blob(api::caller()),
            Ops::InstructionCounterIsAtLeast => {
                let amount = stack.pop_int64();
                // Perform a no-op delay for high instruction counter values
                // to reduce the overhead of charging for performance_counter system call.
                // Delay values are based on experiment to satisfy conditions:
                //  - instructions used should be low enough, eg. 3_700...5_000
                //  - execution CPU complexity should not be too high comparing to instructions used.
                // Initially using only 16.5*B instructions would hit a 20*B message complexity limit,
                // 18% which is too far off.
                if amount < 1_000_000 {
                    // Approx. instruction tolerance: 3_700.
                    while api::performance_counter(0) < amount {}
                } else if amount < 100_000_000 {
                    // Approx. instruction tolerance: 4_300.
                    while api::performance_counter(0) < amount {
                        delay(10);
                    }
                } else {
                    // Approx. instruction tolerance: 4_900.
                    while api::performance_counter(0) < amount {
                        delay(100);
                    }
                }
            }
            Ops::RejectMessage => stack.push_blob(api::reject_message()),
            Ops::RejectCode => stack.push_int(api::reject_code()),
            Ops::IntToBlob => {
                let i = stack.pop_int();
                stack.push_blob(i.to_le_bytes().to_vec())
            }
            Ops::MessagePayload => stack.push_blob(api::arg_data()),
            Ops::Concat => {
                let mut b = stack.pop_blob();
                let mut a = stack.pop_blob();
                a.append(&mut b);
                stack.push_blob(a);
            }
            Ops::StableSize => stack.push_int(api::stable_size()),
            Ops::StableGrow => {
                let i = stack.pop_int();
                stack.push_int(api::stable_grow(i))
            }
            Ops::StableRead => {
                let size = stack.pop_int();
                let offset = stack.pop_int();
                stack.push_blob(api::stable_read(offset, size))
            }
            Ops::StableWrite => {
                let data = stack.pop_blob();
                let offset = stack.pop_int();
                api::stable_write(offset, &data)
            }
            Ops::DebugPrint => api::print(&stack.pop_blob()),
            Ops::Trap => api::trap_with_blob(&stack.pop_blob()),
            Ops::SetGlobal => set_global(stack.pop_blob()),
            Ops::AppendGlobal => append_global(stack.pop_blob()),
            Ops::GetGlobal => stack.push_blob(get_global()),
            Ops::BadPrint => api::bad_print(),
            Ops::SetPreUpgrade => set_pre_upgrade(stack.pop_blob()),
            Ops::Int64ToBlob => {
                let i = stack.pop_int64();
                stack.push_blob(i.to_le_bytes().to_vec())
            }
            Ops::Time => stack.push_int64(api::time()),
            Ops::CyclesAvailable => stack.push_int64(api::cycles_available()),
            Ops::CyclesBalance => stack.push_int64(api::balance()),
            Ops::CyclesRefunded => stack.push_int64(api::cycles_refunded()),
            Ops::AcceptCycles => {
                let a = stack.pop_int64();
                stack.push_int64(api::accept(a))
            }
            Ops::PushInt64 => {
                let a = read_int64(&mut ops_bytes);
                stack.push_int64(a);
            }
            Ops::CallNew => {
                // pop in reverse order!
                let reject_code = stack.pop_blob();
                let reply_code = stack.pop_blob();
                let method = stack.pop_blob();
                let callee = stack.pop_blob();

                let reject_env = add_callback(reject_code);
                let reply_env = add_callback(reply_code);

                api::call_new(&callee, &method, callback, reply_env, callback, reject_env);
            }
            Ops::CallDataAppend => api::call_data_append(&stack.pop_blob()),
            Ops::CallCyclesAdd => api::call_cycles_add(stack.pop_int64()),
            Ops::CallPerform => {
                let err_code = api::call_perform();
                if err_code != 0 {
                    api::trap_with("call_perform failed")
                }
            }
            Ops::CertifiedDataSet => api::certified_data_set(&stack.pop_blob()),
            Ops::DataCertificatePresent => stack.push_int(api::data_certificate_present()),
            Ops::DataCertificate => stack.push_blob(api::data_certificate()),
            Ops::CanisterStatus => stack.push_int(api::status()),
            Ops::SetHeartbeat => set_heartbeat(stack.pop_blob()),
            Ops::AcceptMessage => api::accept_message(),
            Ops::SetInspectMessage => set_inspect_message(stack.pop_blob()),
            Ops::TrapIfEq => {
                let c = stack.pop_blob();
                let b = stack.pop_blob();
                let a = stack.pop_blob();
                if a == b {
                    api::trap_with_blob(&c)
                }
            }
            Ops::CallOnCleanup => {
                let cleanup_code = stack.pop_blob();
                let cleanup_env = add_callback(cleanup_code);
                api::call_on_cleanup(callback, cleanup_env);
            }
            Ops::StableFill => {
                let length = stack.pop_int();
                let byte = stack.pop_int();
                let offset = stack.pop_int();

                let data = vec![byte as u8; length as usize];

                api::stable_write(offset, &data);
            }
            Ops::StableSize64 => stack.push_int64(api::stable64_size()),
            Ops::StableGrow64 => {
                let i = stack.pop_int64();
                stack.push_int64(api::stable64_grow(i))
            }
            Ops::StableRead64 => {
                let size = stack.pop_int64();
                let offset = stack.pop_int64();
                stack.push_blob(api::stable64_read(offset, size))
            }
            Ops::StableWrite64 => {
                let data = stack.pop_blob();
                let offset = stack.pop_int64();
                api::stable64_write(offset, &data)
            }
            Ops::CyclesAvailable128 => stack.push_blob(api::cycles_available128()),
            Ops::CyclesBalance128 => stack.push_blob(api::balance128()),
            Ops::CyclesRefunded128 => stack.push_blob(api::cycles_refunded128()),
            Ops::AcceptCycles128 => {
                let amount_low = stack.pop_int64();
                let amount_high = stack.pop_int64();
                stack.push_blob(api::accept128(amount_high, amount_low))
            }
            Ops::CallCyclesAdd128 => {
                let amount_low = stack.pop_int64();
                let amount_high = stack.pop_int64();
                api::call_cycles_add128(amount_high, amount_low)
            }
            Ops::MsgArgDataSize => stack.push_int(api::msg_arg_data_size()),
            Ops::MsgArgDataCopy => {
                let size = stack.pop_int();
                let offset = stack.pop_int();
                stack.push_blob(api::msg_arg_data_copy(offset, size));
            }
            Ops::MsgCallerSize => stack.push_int(api::msg_caller_size()),
            Ops::MsgCallerCopy => {
                let size = stack.pop_int();
                let offset = stack.pop_int();
                stack.push_blob(api::msg_caller_copy(offset, size));
            }
            Ops::MsgRejectMsgSize => stack.push_int(api::msg_reject_msg_size()),
            Ops::MsgRejectMsgCopy => {
                let size = stack.pop_int();
                let offset = stack.pop_int();
                stack.push_blob(api::msg_reject_msg_copy(offset, size));
            }
            Ops::SetGlobalTimerMethod => set_global_timer_method(stack.pop_blob()),
            Ops::ApiGlobalTimerSet => {
                let timestamp = stack.pop_int64();
                stack.push_int64(api::global_timer_set(timestamp))
            }
            Ops::IncGlobalCounter => {
                let c = *GLOBAL_COUNTER.lock().unwrap() + 1;
                *GLOBAL_COUNTER.lock().unwrap() = c;
            }
            Ops::GetGlobalCounter => stack.push_int64(*GLOBAL_COUNTER.lock().unwrap()),
            Ops::GetPerformanceCounter => {
                let _type = stack.pop_int();
                stack.push_int64(api::performance_counter(_type))
            }
            Ops::MsgMethodName => stack.push_blob(api::method_name()),
            Ops::ParsePrincipal => {
                let arg = stack.pop_blob();
                stack.push_blob(Principal::from_slice(&arg).to_string().as_bytes().to_vec())
            }
            Ops::SetTransform => set_transform(stack.pop_blob()),
            Ops::GetHttpReplyWithBody => {
                let body = stack.pop_blob();
                stack.push_blob(http_reply_with_body(&body));
            }
            Ops::GetHttpTransformContext => {
                let arg = Decode!(stack.pop_blob().as_ref(), TransformArg).unwrap();
                stack.push_blob(arg.context);
            }
            Ops::StableFill64 => {
                let length = stack.pop_int64();
                let byte = stack.pop_int64();
                let offset = stack.pop_int64();

                let data = vec![byte as u8; length as usize];

                api::stable64_write(offset, &data);
            }
            Ops::CanisterVersion => {
                stack.push_int64(api::canister_version());
            }
            Ops::TrapIfNeq => {
                let c = stack.pop_blob();
                let b = stack.pop_blob();
                let a = stack.pop_blob();
                if a != b {
                    api::trap_with_blob(&c)
                }
            }
            Ops::MintCycles => {
                let amount = stack.pop_int64();
                stack.push_int64(api::mint_cycles(amount));
            }
            Ops::OneWayCallNew => {
                // pop in reverse order!
                let method = stack.pop_blob();
                let callee = stack.pop_blob();

                api::call_new(
                    &callee,
                    &method,
                    callback,
                    ONE_WAY_CALL,
                    callback,
                    ONE_WAY_CALL,
                );
            }
            Ops::IsController => {
                let data = stack.pop_blob();
                stack.push_int(api::is_controller(&data));
            }
            Ops::CyclesBurn128 => {
                let amount_low = stack.pop_int64();
                let amount_high = stack.pop_int64();
                stack.push_blob(api::cycles_burn128(amount_high, amount_low))
            }
            Ops::BlobLength => {
                let data = stack.pop_blob();
                stack.push_int(data.len() as u32);
            }
            Ops::PushEqualBytes => {
                let length = stack.pop_int();
                let byte = stack.pop_int();
                let data = vec![byte as u8; length as usize];
                stack.push_blob(data);
            }
            Ops::InReplicatedExecution => stack.push_int(api::in_replicated_execution()),
            Ops::CallWithBestEffortResponse => api::call_with_best_effort_response(stack.pop_int()),
            Ops::MsgDeadline => stack.push_int64(api::msg_deadline()),
            Ops::MemorySizeIsAtLeast => {
                #[cfg(target_arch = "wasm32")]
                let current_memory_size = || {
                    let wasm_page_size = wee_alloc::PAGE_SIZE.0;
                    core::arch::wasm32::memory_size::<0>() * wasm_page_size
                };

                #[cfg(not(target_arch = "wasm32"))]
                let current_memory_size = || usize::MAX;

                let target_memory_size = stack.pop_int64() as usize;
                let mut a = vec![];
                loop {
                    if current_memory_size() > target_memory_size {
                        break;
                    }
                    // Allocate a megabyte more.
                    a.push(vec![13u8; 1024 * 1024]);
                }
                std::hint::black_box(a);
            }
            Ops::CallCyclesAdd128UpTo => {
                let amount_low = stack.pop_int64();
                let amount_high = stack.pop_int64();
                stack.push_blob(api::call_cycles_add128_up_to(amount_high, amount_low))
            }
        }
    }
}
#[export_name = "canister_update update"]
fn update() {
    setup();
    eval(&api::arg_data());
}

#[export_name = "canister_query query"]
fn query() {
    setup();
    eval(&api::arg_data());
}

#[export_name = "canister_composite_query composite_query"]
fn composite_query() {
    setup();
    eval(&api::arg_data());
}

#[export_name = "canister_query transform"]
fn transform() {
    setup();
    eval(&get_transform());
}

#[export_name = "canister_init"]
fn init() {
    setup();
    eval(&api::arg_data());
}

#[export_name = "canister_pre_upgrade"]
fn pre_upgrade() {
    setup();
    eval(&get_pre_upgrade());
}

#[export_name = "canister_heartbeat"]
fn heartbeat() {
    setup();
    eval(&get_heartbeat());
}

#[export_name = "canister_global_timer"]
fn global_timer() {
    setup();
    eval(&get_global_timer_method());
}

#[export_name = "canister_inspect_message"]
fn inspect_message() {
    setup();
    eval(&get_inspect_message());
}

#[export_name = "canister_post_upgrade"]
fn post_upgrade() {
    setup();
    eval(&api::arg_data());
}

/* A global variable */
lazy_static! {
    static ref GLOBAL: Mutex<Vec<u8>> = Mutex::new(Vec::new());
}
fn set_global(data: Vec<u8>) {
    *GLOBAL.lock().unwrap() = data;
}
fn append_global(mut data: Vec<u8>) {
    GLOBAL.lock().unwrap().append(&mut data);
}
fn get_global() -> Vec<u8> {
    GLOBAL.lock().unwrap().clone()
}

/* A global counter */
lazy_static! {
    static ref GLOBAL_COUNTER: Mutex<u64> = Mutex::new(0);
}

/* A variable to store what to execute upon pre_upgrade */
lazy_static! {
    static ref PRE_UPGRADE: Mutex<Vec<u8>> = Mutex::new(Vec::new());
}
fn set_pre_upgrade(data: Vec<u8>) {
    *PRE_UPGRADE.lock().unwrap() = data;
}
fn get_pre_upgrade() -> Vec<u8> {
    PRE_UPGRADE.lock().unwrap().clone()
}

/* A variable to store what to execute in canister_heartbeat */
lazy_static! {
    static ref HEARTBEAT: Mutex<Vec<u8>> = Mutex::new(Vec::new());
}
fn set_heartbeat(data: Vec<u8>) {
    *HEARTBEAT.lock().unwrap() = data;
}
fn get_heartbeat() -> Vec<u8> {
    HEARTBEAT.lock().unwrap().clone()
}

/* A variable to store what to execute in canister_global_timer */
lazy_static! {
    static ref GLOBAL_TIMER_METHOD: Mutex<Vec<u8>> = Mutex::new(Vec::new());
}
fn set_global_timer_method(data: Vec<u8>) {
    *GLOBAL_TIMER_METHOD.lock().unwrap() = data;
}
fn get_global_timer_method() -> Vec<u8> {
    GLOBAL_TIMER_METHOD.lock().unwrap().clone()
}

lazy_static! {
    static ref TRANSFORM: Mutex<Vec<u8>> = Mutex::new(Vec::new());
}
fn set_transform(data: Vec<u8>) {
    *TRANSFORM.lock().unwrap() = data;
}
fn get_transform() -> Vec<u8> {
    TRANSFORM.lock().unwrap().clone()
}

/* A variable to store what to execute in canister_inspect_message */
/* (By default allows all) */
lazy_static! {
    static ref INSPECT_MESSAGE: Mutex<Vec<u8>> = Mutex::new(vec![41]);
}
fn set_inspect_message(data: Vec<u8>) {
    *INSPECT_MESSAGE.lock().unwrap() = data;
}
fn get_inspect_message() -> Vec<u8> {
    INSPECT_MESSAGE.lock().unwrap().clone()
}

/* Callback handling */

#[macro_use]
extern crate lazy_static;
use std::sync::Mutex;
lazy_static! {
    static ref CALLBACKS: Mutex<Vec<Option<Vec<u8>>>> = Mutex::new(Vec::new());
}

fn add_callback(code: Vec<u8>) -> u32 {
    let mut vec = CALLBACKS.lock().unwrap();
    vec.push(Some(code));
    vec.len() as u32 - 1
}

fn get_callback(idx: u32) -> Vec<u8> {
    let mut vec = CALLBACKS.lock().unwrap();
    if let Some(entry) = vec.get_mut(idx as usize) {
        if let Some(code) = entry.take() {
            code
        } else {
            panic!("get_callback: {} already taken", idx)
        }
    } else {
        panic!("get_callback: {} out of bounds", idx)
    }
}

fn callback(env: u32) {
    if env != ONE_WAY_CALL {
        eval(&get_callback(env));
    }
}

/* Panic setup */

use std::sync::Once;

static START: Once = Once::new();

fn setup() {
    START.call_once(|| {
        api::set_panic_hook();
    });
}

fn main() {}
