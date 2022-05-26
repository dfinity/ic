use std::convert::TryInto;

mod api;

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

    fn drop(self: &mut Self) {
        self.0.pop();
    }

    fn push_int(self: &mut Self, x: u32) {
        self.0.push(Val::I32(x));
    }

    fn push_int64(self: &mut Self, x: u64) {
        self.0.push(Val::I64(x));
    }

    fn push_blob(self: &mut Self, x: Vec<u8>) {
        self.0.push(Val::Blob(x));
    }

    fn pop_int(self: &mut Self) -> u32 {
        if let Some(Val::I32(i)) = self.0.pop() {
            i
        } else {
            api::trap_with("did not find I32 on stack")
        }
    }

    fn pop_int64(self: &mut Self) -> u64 {
        if let Some(Val::I64(i)) = self.0.pop() {
            i
        } else {
            api::trap_with("did not find I64 on stack")
        }
    }

    fn pop_blob(self: &mut Self) -> Vec<u8> {
        if let Some(Val::Blob(blob)) = self.0.pop() {
            blob
        } else {
            api::trap_with("did not find blob on stack")
        }
    }
}

// Reading data from the operations stream

type Ops<'a> = &'a [u8];

fn read_bytes<'a>(ops: &mut Ops<'a>, len: usize) -> &'a [u8] {
    if len < ops.len() {
        let (bytes, rest) = ops.split_at(len as usize);
        *ops = rest;
        bytes
    } else {
        panic!("cannot read {} bytes of a {} byte string", len, ops.len());
    }
}

fn read_int(ops: &mut Ops) -> u32 {
    let bytes = read_bytes(ops, std::mem::size_of::<u32>());
    u32::from_le_bytes(bytes.try_into().unwrap())
}

fn read_int64(ops: &mut Ops) -> u64 {
    let bytes = read_bytes(ops, std::mem::size_of::<u64>());
    u64::from_le_bytes(bytes.try_into().unwrap())
}

fn eval(ops: Ops) {
    let mut ops: Ops = ops;
    let mut stack: Stack = Stack::new();

    while let Some((op, rest)) = ops.split_first() {
        ops = rest;
        match op {
            // noop
            0 => (),
            // drop
            1 => stack.drop(),
            // push int
            2 => {
                let a = read_int(&mut ops);
                stack.push_int(a);
            }
            // push bytes
            3 => {
                let len = read_int(&mut ops);
                let blob = read_bytes(&mut ops, len as usize).to_vec();
                stack.push_blob(blob);
            }
            // reply_data_append
            4 => api::reply_data_append(&stack.pop_blob()),
            // reply
            5 => api::reply(),

            // self
            6 => stack.push_blob(api::id()),

            // reject
            7 => api::reject(&stack.pop_blob()),

            // caller
            8 => stack.push_blob(api::caller()),

            // reject_msg
            10 => stack.push_blob(api::reject_message()),

            // reject_code
            11 => stack.push_int(api::reject_code()),

            // int to blob
            12 => {
                let i = stack.pop_int();
                stack.push_blob(i.to_le_bytes().to_vec())
            }

            // msg_data
            13 => stack.push_blob(api::arg_data()),

            // concat
            14 => {
                let mut b = stack.pop_blob();
                let mut a = stack.pop_blob();
                a.append(&mut b);
                stack.push_blob(a);
            }

            // stable memory
            15 => stack.push_int(api::stable_size()),
            16 => {
                let i = stack.pop_int();
                stack.push_int(api::stable_grow(i))
            }
            17 => {
                let size = stack.pop_int();
                let offset = stack.pop_int();
                stack.push_blob(api::stable_read(offset, size))
            }
            18 => {
                let data = stack.pop_blob();
                let offset = stack.pop_int();
                api::stable_write(offset, &data)
            }

            // debugging
            19 => api::print(&stack.pop_blob()),
            20 => api::trap_with_blob(&stack.pop_blob()),

            // some simple state
            21 => set_global(stack.pop_blob()),
            22 => stack.push_blob(get_global()),

            // bad print
            23 => api::bad_print(),

            // the pre-upgrade script
            24 => set_pre_upgrade(stack.pop_blob()),

            // int64 to blob
            25 => {
                let i = stack.pop_int64();
                stack.push_blob(i.to_le_bytes().to_vec())
            }

            // time
            26 => stack.push_int64(api::time()),

            // available cycles
            27 => stack.push_int64(api::cycles_available()),

            // balance
            28 => stack.push_int64(api::balance()),

            // refunded
            29 => stack.push_int64(api::cycles_refunded()),

            // accept
            30 => {
                let a = stack.pop_int64();
                stack.push_int64(api::accept(a))
            }

            // push int64
            31 => {
                let a = read_int64(&mut ops);
                stack.push_int64(a);
            }

            // call_new
            32 => {
                // pop in reverse order!
                let reject_code = stack.pop_blob();
                let reply_code = stack.pop_blob();
                let method = stack.pop_blob();
                let callee = stack.pop_blob();

                let reject_env = add_callback(reject_code);
                let reply_env = add_callback(reply_code);

                api::call_new(&callee, &method, callback, reply_env, callback, reject_env);
            }

            // append arg
            33 => api::call_data_append(&stack.pop_blob()),

            // append cycles
            34 => api::call_cycles_add(stack.pop_int64()),

            // perform
            35 => {
                let err_code = api::call_perform();
                if err_code != 0 {
                    api::trap_with("call_perform failed")
                }
            }

            // certified variables
            36 => api::certified_data_set(&stack.pop_blob()),
            37 => stack.push_int(api::data_certificate_present()),
            38 => stack.push_blob(api::data_certificate()),

            // canister_status
            39 => stack.push_int(api::status()),

            // canister heartbeat script.
            40 => set_heartbeat(stack.pop_blob()),

            // accept_message
            41 => api::accept_message(),

            // inspect message script.
            42 => set_inspect_message(stack.pop_blob()),

            // trap if blob equal
            43 => {
                let c = stack.pop_blob();
                let b = stack.pop_blob();
                let a = stack.pop_blob();
                if a == b {
                    api::trap_with_blob(&c)
                }
            }

            // on_cleanup
            44 => {
                let cleanup_code = stack.pop_blob();
                let cleanup_env = add_callback(cleanup_code);
                api::call_on_cleanup(callback, cleanup_env);
            }

            // Fill stable memory
            45 => {
                let length = stack.pop_int();
                let byte = stack.pop_int();
                let offset = stack.pop_int();

                let data = vec![byte as u8; length as usize];

                api::stable_write(offset, &data);
            }

            // Stable size for 64-bit memory.
            46 => stack.push_int64(api::stable64_size()),

            // Stable grow for 64-bit memory.
            47 => {
                let i = stack.pop_int64();
                stack.push_int64(api::stable64_grow(i))
            }

            // Stable read for 64-bit memory.
            48 => {
                let size = stack.pop_int64();
                let offset = stack.pop_int64();
                stack.push_blob(api::stable64_read(offset, size))
            }

            // Stable write 64-bit memory.
            49 => {
                let length = stack.pop_int64();
                let byte = stack.pop_int64();
                let offset = stack.pop_int64();

                let data = vec![byte as u8; length as usize];

                api::stable64_write(offset, &data);
            }

            // int64 to blob
            50 => {
                let i = stack.pop_int64();
                stack.push_blob(i.to_le_bytes().to_vec())
            }

            // available cycles 128-bit
            51 => stack.push_blob(api::cycles_available128()),

            // balance 128-bit
            52 => stack.push_blob(api::balance128()),

            // refunded 128-bit
            53 => stack.push_blob(api::cycles_refunded128()),

            // accept 128-bit
            54 => {
                let amount_low = stack.pop_int64();
                let amount_high = stack.pop_int64();
                stack.push_blob(api::accept128(amount_high, amount_low))
            }

            // append cycles 128-bit
            55 => {
                let amount_low = stack.pop_int64();
                let amount_high = stack.pop_int64();
                api::call_cycles_add128(amount_high, amount_low)
            }

            // get the size of the argument data
            56 => stack.push_int(api::msg_arg_data_size()),

            // copy the argument data
            57 => {
                let size = stack.pop_int();
                let offset = stack.pop_int();
                stack.push_blob(api::msg_arg_data_copy(offset, size));
            }

            // get the size of the caller bytes
            58 => stack.push_int(api::msg_caller_size()),

            // copy the caller bytes
            59 => {
                let size = stack.pop_int();
                let offset = stack.pop_int();
                stack.push_blob(api::msg_caller_copy(offset, size));
            }

            // get the size of the reject message
            60 => stack.push_int(api::msg_reject_msg_size()),

            // copy the reject message
            61 => {
                let size = stack.pop_int();
                let offset = stack.pop_int();
                stack.push_blob(api::msg_reject_msg_copy(offset, size));
            }

            _ => api::trap_with(&format!("unknown op {}", op)),
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
fn get_global() -> Vec<u8> {
    GLOBAL.lock().unwrap().clone()
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
    return (vec.len() as u32) - 1;
}

fn get_callback(idx: u32) -> Vec<u8> {
    let mut vec = CALLBACKS.lock().unwrap();
    if let Some(entry) = vec.get_mut(idx as usize) {
        if let Some(code) = entry.take() {
            return code;
        } else {
            panic!("get_callback: {} already taken", idx)
        }
    } else {
        panic!("get_callback: {} out of bounds", idx)
    }
}

fn callback(env: u32) {
    eval(&get_callback(env));
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
