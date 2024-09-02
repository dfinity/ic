use std::collections::HashMap;
use std::fmt;
use strum_macros::EnumIter;

const STEP: &str = "    ";
const INDENT: &str = "\n            ";

const MEMORY_FILL_MAX: i32 = 100;
const MEMORY_OFFSET_START: i32 = 1_000;
// `MEMORY_OFFSET_START` must be greater than `MEMORY_FILL_MAX`
// to make sure memory.fill in `_wait` function does not corrupt other memory data.
#[allow(clippy::assertions_on_constants)]
const _: () = assert!(MEMORY_FILL_MAX < MEMORY_OFFSET_START);

const MEMORY_LIMIT: i32 = 64 * 1_024;

enum FnCall {
    StableGrow(i32),
    StableRead(i32, i32),
    GlobalTimerSet(i64),
    DebugPrint(Vec<u8>),
    Trap(Vec<u8>),
    Wait(i64),
}

/// Create a new WAT function code builder.
pub fn wat_fn() -> WatFnCode {
    WatFnCode::new()
}

/// WAT function code builder, allows to chain function calls.
pub struct WatFnCode {
    calls: Vec<FnCall>,
}

impl WatFnCode {
    /// Create the content of a WAT function.
    pub fn new() -> Self {
        Self { calls: vec![] }
    }

    /// Call the `ic0.stable_grow` function.
    pub fn stable_grow(mut self, additional_pages: i32) -> Self {
        self.calls.push(FnCall::StableGrow(additional_pages));
        self
    }

    /// Call the `ic0.stable_read` function.
    pub fn stable_read(mut self, offset: i32, size: i32) -> Self {
        self.calls.push(FnCall::StableRead(offset, size));
        self
    }

    /// Call the `ic0.global_timer_set` function.
    pub fn api_global_timer_set(mut self, timestamp: i64) -> Self {
        self.calls.push(FnCall::GlobalTimerSet(timestamp));
        self
    }

    /// Call the `ic0.debug_print` function.
    pub fn debug_print(mut self, message: &[u8]) -> Self {
        self.calls.push(FnCall::DebugPrint(message.to_vec()));
        self
    }

    /// Call the `ic0.trap` function.
    pub fn trap_with_blob(mut self, message: &[u8]) -> Self {
        self.calls.push(FnCall::Trap(message.to_vec()));
        self
    }

    /// Call the `ic0.trap` function.
    pub fn trap(self) -> Self {
        self.trap_with_blob(&[])
    }

    /// Wait for a given number of instructions.
    pub fn wait(mut self, instructions: i64) -> Self {
        self.calls.push(FnCall::Wait(instructions));
        self
    }
}

impl Default for WatFnCode {
    fn default() -> Self {
        Self::new()
    }
}

enum WatConst {
    I32(i32),
    I64(i64),
}

impl fmt::Display for WatConst {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            WatConst::I32(value) => write!(f, "(i32.const {})", value),
            WatConst::I64(value) => write!(f, "(i64.const {})", value),
        }
    }
}

struct WatCall {
    func: String,
    params: Vec<WatConst>,
    drop_result: bool,
}

impl WatCall {
    fn stable_grow(new_pages: i32) -> Self {
        Self {
            func: "ic0_stable_grow".to_string(),
            params: vec![WatConst::I32(new_pages)],
            drop_result: false,
        }
    }

    fn stable_read(offset: i32, size: i32) -> Self {
        Self {
            func: "ic0_stable_read".to_string(),
            params: vec![WatConst::I32(offset), WatConst::I32(size)],
            drop_result: false,
        }
    }

    fn global_timer_set(timestamp: i64) -> Self {
        Self {
            func: "ic0_global_timer_set".to_string(),
            params: vec![WatConst::I64(timestamp)],
            drop_result: true,
        }
    }

    fn debug_print(offset: i32, size: i32) -> Self {
        Self {
            func: "ic0_debug_print".to_string(),
            params: vec![WatConst::I32(offset), WatConst::I32(size)],
            drop_result: false,
        }
    }

    fn trap(offset: i32, size: i32) -> Self {
        Self {
            func: "ic0_trap".to_string(),
            params: vec![WatConst::I32(offset), WatConst::I32(size)],
            drop_result: false,
        }
    }

    fn wait(instructions: i64) -> Self {
        Self {
            func: "_wait".to_string(),
            params: vec![WatConst::I64(instructions)],
            drop_result: false,
        }
    }
}

impl fmt::Display for WatCall {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut result = format!(
            "(call ${} {})",
            self.func,
            self.params
                .iter()
                .map(|p| p.to_string())
                .collect::<Vec<_>>()
                .join(" ")
        );
        if self.drop_result {
            result = format!("(drop {result})")
        }
        write!(f, "{result}")
    }
}

struct WatData {
    offset: WatConst,
    data: Vec<u8>,
}

impl WatData {
    #[cfg(test)]
    fn new(offset: i32, data: &[u8]) -> Self {
        Self {
            offset: WatConst::I32(offset),
            data: data.to_vec(),
        }
    }
}

fn format_bytes(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("\\{:02X}", b))
        .collect::<Vec<String>>()
        .join("")
}

impl fmt::Display for WatData {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let message = if let Ok(s) = String::from_utf8(self.data.clone()) {
            if format!("{s:?}").contains('\\') {
                format_bytes(&self.data.clone())
            } else {
                s
            }
        } else {
            format_bytes(&self.data.clone())
        };
        write!(f, "(data {} \"{}\")", self.offset, message)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, EnumIter)]
enum Method {
    Start,
    Init,
    PreUpgrade,
    PostUpgrade,
    InspectMessage,
    Heartbeat,
    GlobalTimer,
    Update,
    Query,
    CompositeQuery,
}

struct WatFunc {
    method: Method,
    name: String,
    calls: Vec<WatCall>,
}

impl fmt::Display for WatFunc {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let declaration = match self.method {
            Method::Start => format!(r#"start $start){INDENT}(func $start"#),
            Method::Init => r#"func $init (export "canister_init")"#.to_string(),
            Method::PreUpgrade => {
                r#"func $pre_upgrade (export "canister_pre_upgrade")"#.to_string()
            }
            Method::PostUpgrade => {
                r#"func $post_upgrade (export "canister_post_upgrade")"#.to_string()
            }
            Method::InspectMessage => {
                r#"func $inspect_message (export "canister_inspect_message")"#.to_string()
            }
            Method::Heartbeat => r#"func $heartbeat (export "canister_heartbeat")"#.to_string(),
            Method::GlobalTimer => {
                r#"func $global_timer (export "canister_global_timer")"#.to_string()
            }
            Method::Update => format!(
                r#"func ${} (export "canister_update {}")"#,
                self.name, self.name
            ),
            Method::Query => format!(
                r#"func ${} (export "canister_query {}")"#,
                self.name, self.name
            ),
            Method::CompositeQuery => format!(
                r#"func ${} (export "canister_composite_query {}")"#,
                self.name, self.name
            ),
        };
        let calls = self
            .calls
            .iter()
            .map(|c| c.to_string())
            .collect::<Vec<_>>()
            .join(&format!("{INDENT}{STEP}"));
        if !calls.is_empty() {
            write!(f, "{INDENT}({declaration}{INDENT}{STEP}{calls}{INDENT})",)
        } else {
            write!(f, "({declaration}{calls})",)
        }
    }
}

/// Create a new WAT canister builder.
pub fn wat_canister() -> WatCanisterBuilder {
    WatCanisterBuilder::new()
}

/// The WAT canister builder creates a WAT canister with multiple functions of varying content.
///
/// A WAT canister allows for modifiable behavior within tests.
/// It is similar to the `universal_canister` but addresses specific cases the UC can't.
/// It modifies methods that occur right after start and before any update call,
/// covering `init()`, `start()`, and `post_upgrade()` methods.
pub struct WatCanisterBuilder {
    functions: Vec<WatFunc>,
    memory_offset: i32,
    memory: HashMap<Vec<u8>, i32>,
}

impl WatCanisterBuilder {
    /// Create a builder for a new WAT canister.
    pub fn new() -> Self {
        Self {
            functions: Vec::new(),
            memory_offset: MEMORY_OFFSET_START,
            memory: HashMap::new(),
        }
    }

    /// Add `start` function to the WAT canister.
    pub fn start(&mut self, code: WatFnCode) -> &mut Self {
        self.process_method(Method::Start, "start", code)
    }

    /// Add `canister_init` exported function to the WAT canister.
    pub fn init(&mut self, code: WatFnCode) -> &mut Self {
        self.process_method(Method::Init, "init", code)
    }

    /// Add `canister_pre_upgrade` exported function to the WAT canister.
    pub fn pre_upgrade(&mut self, code: WatFnCode) -> &mut Self {
        self.process_method(Method::PreUpgrade, "pre_upgrade", code)
    }

    /// Add `canister_post_upgrade` exported function to the WAT canister.
    pub fn post_upgrade(&mut self, code: WatFnCode) -> &mut Self {
        self.process_method(Method::PostUpgrade, "post_upgrade", code)
    }

    /// Add `canister_inspect_message` exported function to the WAT canister.
    pub fn inspect_message(&mut self, code: WatFnCode) -> &mut Self {
        self.process_method(Method::InspectMessage, "inspect_message", code)
    }

    /// Add `canister_heartbeat` exported function to the WAT canister.
    pub fn heartbeat(&mut self, code: WatFnCode) -> &mut Self {
        self.process_method(Method::Heartbeat, "heartbeat", code)
    }

    /// Add `canister_global_timer` exported function to the WAT canister.
    pub fn global_timer(&mut self, code: WatFnCode) -> &mut Self {
        self.process_method(Method::GlobalTimer, "global_timer", code)
    }

    /// Add `canister_update <name>` exported function to the WAT canister.
    pub fn update(&mut self, name: &str, code: WatFnCode) -> &mut Self {
        self.process_method(Method::Update, name, code)
    }

    /// Add `canister_query <name>` exported function to the WAT canister.
    pub fn query(&mut self, name: &str, code: WatFnCode) -> &mut Self {
        self.process_method(Method::Query, name, code)
    }

    /// Add `canister_composite_query <name>` exported function to the WAT canister.
    pub fn composite_query(&mut self, name: &str, code: WatFnCode) -> &mut Self {
        self.process_method(Method::CompositeQuery, name, code)
    }

    /// Build the WAT canister.
    pub fn build(&self) -> String {
        let functions = self
            .functions
            .iter()
            .map(|f| f.to_string())
            .collect::<Vec<_>>()
            .join("\n");
        let data = self
            .data()
            .iter()
            .map(|d| d.to_string())
            .collect::<Vec<_>>()
            .join(INDENT);
        format!(
            r#"
        (module
            ;; Import functions
            (import "ic0" "stable_grow" (func $ic0_stable_grow (param $pages i32) (result i32)))
            (import "ic0" "stable_read" (func $ic0_stable_read (param i32 i32 i32)))
            (import "ic0" "global_timer_set" (func $ic0_global_timer_set (param i64) (result i64)))
            (import "ic0" "performance_counter" (func $ic0_performance_counter (param i32) (result i64)))
            (import "ic0" "debug_print" (func $ic0_debug_print (param i32) (param i32)))
            (import "ic0" "trap" (func $ic0_trap (param i32) (param i32)))

            ;; Define functions
            (func $_wait (param $instructions i64)
                ;; Calculate the instruction limit
                (local $limit i64)
                (local.set $limit (i64.add (call $ic0_performance_counter (i32.const 0)) (local.get $instructions)))
                (loop $loop
                    (if (i64.lt_s
                            (call $ic0_performance_counter (i32.const 0))
                            (local.get $limit))
                        (then
                            ;; Placeholder instruction for simulating work
                            (memory.fill (i32.const 0) (i32.const 0) (i32.const {MEMORY_FILL_MAX}))
                            (br $loop)
                        )
                    )
                )
            )
            {functions}

            ;; Define memory
            (memory $memory 1)
            (export "memory" (memory $memory))

            ;; Initialize memory with data
            {data}
        )"#
        )
    }

    /// Build the Wasm for the WAT canister.
    pub fn build_wasm(&self) -> Vec<u8> {
        wat::parse_str(self.build()).unwrap()
    }

    fn get_memory_offset(&mut self, message: &[u8]) -> i32 {
        if let Some(&offset) = self.memory.get(message) {
            offset
        } else {
            let offset = self.memory_offset;
            let message_size = message.len() as i32;

            if offset + message_size > MEMORY_LIMIT {
                panic!("Memory limit exceeded, current implementation supports only 1 page of memory (64KiB)");
            }

            self.memory.insert(message.to_vec(), offset);
            self.memory_offset += message_size;

            offset
        }
    }

    fn data(&self) -> Vec<WatData> {
        let mut data: Vec<_> = self
            .memory
            .iter()
            .map(|(message, &offset)| (message.clone(), offset))
            .collect();
        data.sort_by_key(|&(_, offset)| offset);

        data.into_iter()
            .map(|(message, offset)| WatData {
                offset: WatConst::I32(offset),
                data: message.to_vec(),
            })
            .collect()
    }

    fn process_method(&mut self, method: Method, name: &str, code: WatFnCode) -> &mut Self {
        let name = name.to_string();
        // It's OK to use linear search here because this is a test util
        // and the number of functions is small.
        if self
            .functions
            .iter()
            .any(|f| f.method == method && f.name == *name)
        {
            panic!("Method '{method:?}' with the name '{name}' already exists");
        }
        let calls = self.process_calls(code);
        self.functions.push(WatFunc {
            method,
            name,
            calls,
        });
        self
    }

    fn process_calls(&mut self, code: WatFnCode) -> Vec<WatCall> {
        code.calls
            .iter()
            .map(|call| match call {
                FnCall::StableGrow(new_pages) => WatCall::stable_grow(*new_pages),
                FnCall::StableRead(offset, size) => WatCall::stable_read(*offset, *size),
                FnCall::GlobalTimerSet(timestamp) => WatCall::global_timer_set(*timestamp),
                FnCall::DebugPrint(message) => {
                    WatCall::debug_print(self.get_memory_offset(message), message.len() as i32)
                }
                FnCall::Trap(message) => {
                    WatCall::trap(self.get_memory_offset(message), message.len() as i32)
                }
                FnCall::Wait(instructions) => WatCall::wait(*instructions),
            })
            .collect()
    }
}

impl Default for WatCanisterBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use strum::IntoEnumIterator;

    #[test]
    fn test_fmt_wat_const() {
        assert_eq!(WatConst::I32(5).to_string(), r#"(i32.const 5)"#);
        assert_eq!(WatConst::I64(7).to_string(), r#"(i64.const 7)"#);
    }

    #[test]
    fn test_fmt_wat_call() {
        let test_cases = vec![
            (
                WatCall::stable_grow(7),
                "(call $ic0_stable_grow (i32.const 7))",
            ),
            (
                WatCall::stable_read(4, 7),
                "(call $ic0_stable_read (i32.const 4) (i32.const 7))",
            ),
            (
                WatCall::global_timer_set(42),
                "(drop (call $ic0_global_timer_set (i64.const 42)))",
            ),
            (
                WatCall::debug_print(0, 4),
                "(call $ic0_debug_print (i32.const 0) (i32.const 4))",
            ),
            (
                WatCall::trap(2, 4),
                "(call $ic0_trap (i32.const 2) (i32.const 4))",
            ),
            (WatCall::wait(10_000), "(call $_wait (i64.const 10000))"),
        ];
        for (call, expected) in test_cases.into_iter() {
            assert_eq!(call.to_string(), expected);
        }
    }

    #[test]
    fn test_fmt_wat_data() {
        assert_eq!(
            WatData::new(3, b"hello world").to_string(),
            r#"(data (i32.const 3) "hello world")"#
        );
        assert_eq!(
            WatData::new(5, &[1, 2, 3]).to_string(),
            r#"(data (i32.const 5) "\01\02\03")"#
        );
        assert_eq!(
            WatData::new(7, &[0xc0, 0xff, 0xee]).to_string(),
            r#"(data (i32.const 7) "\C0\FF\EE")"#
        );
        assert_eq!(
            WatData::new(11, &[92, 198, 186, 50, 37]).to_string(),
            r#"(data (i32.const 11) "\5C\C6\BA\32\25")"#
        );
    }

    #[test]
    #[should_panic(expected = "Method 'Start' with the name 'start' already exists")]
    fn test_wat_func_unique_start() {
        wat_canister().start(wat_fn()).start(wat_fn());
    }

    #[test]
    #[should_panic(expected = "Method 'Init' with the name 'init' already exists")]
    fn test_wat_func_unique_init() {
        wat_canister().init(wat_fn()).init(wat_fn());
    }

    #[test]
    #[should_panic(expected = "Method 'PreUpgrade' with the name 'pre_upgrade' already exists")]
    fn test_wat_func_unique_pre_upgrade() {
        wat_canister().pre_upgrade(wat_fn()).pre_upgrade(wat_fn());
    }

    #[test]
    #[should_panic(expected = "Method 'PostUpgrade' with the name 'post_upgrade' already exists")]
    fn test_wat_func_unique_post_upgrade() {
        wat_canister().post_upgrade(wat_fn()).post_upgrade(wat_fn());
    }

    #[test]
    #[should_panic(
        expected = "Method 'InspectMessage' with the name 'inspect_message' already exists"
    )]
    fn test_wat_func_unique_inspect_message() {
        wat_canister()
            .inspect_message(wat_fn())
            .inspect_message(wat_fn());
    }

    #[test]
    #[should_panic(expected = "Method 'Heartbeat' with the name 'heartbeat' already exists")]
    fn test_wat_func_unique_heartbeat() {
        wat_canister().heartbeat(wat_fn()).heartbeat(wat_fn());
    }

    #[test]
    #[should_panic(expected = "Method 'GlobalTimer' with the name 'global_timer' already exists")]
    fn test_wat_func_unique_global_timer() {
        wat_canister().global_timer(wat_fn()).global_timer(wat_fn());
    }

    #[test]
    #[should_panic(expected = "Method 'Update' with the name 'test_3' already exists")]
    fn test_wat_func_unique_update() {
        wat_canister()
            .update("test_1", wat_fn())
            .update("test_2", wat_fn());
        wat_canister()
            .update("test_3", wat_fn())
            .update("test_3", wat_fn());
    }

    #[test]
    #[should_panic(expected = "Method 'Query' with the name 'test_3' already exists")]
    fn test_wat_func_unique_query() {
        wat_canister()
            .query("test_1", wat_fn())
            .query("test_2", wat_fn());
        wat_canister()
            .query("test_3", wat_fn())
            .query("test_3", wat_fn());
    }

    #[test]
    #[should_panic(expected = "Method 'CompositeQuery' with the name 'test_3' already exists")]
    fn test_wat_func_unique_composite_query() {
        wat_canister()
            .composite_query("test_1", wat_fn())
            .composite_query("test_2", wat_fn());
        wat_canister()
            .composite_query("test_3", wat_fn())
            .composite_query("test_3", wat_fn());
    }

    #[test]
    fn test_fmt_wat_func_no_calls() {
        for (method, expected) in Method::iter().zip(vec![
            r#"(start $start)
            (func $start)"#,
            r#"(func $init (export "canister_init"))"#,
            r#"(func $pre_upgrade (export "canister_pre_upgrade"))"#,
            r#"(func $post_upgrade (export "canister_post_upgrade"))"#,
            r#"(func $inspect_message (export "canister_inspect_message"))"#,
            r#"(func $heartbeat (export "canister_heartbeat"))"#,
            r#"(func $global_timer (export "canister_global_timer"))"#,
            r#"(func $custom_name (export "canister_update custom_name"))"#,
            r#"(func $custom_name (export "canister_query custom_name"))"#,
            r#"(func $custom_name (export "canister_composite_query custom_name"))"#,
        ]) {
            assert_eq!(
                WatFunc {
                    method,
                    name: "custom_name".to_string(),
                    calls: vec![],
                }
                .to_string(),
                *expected
            );
        }
    }

    #[test]
    fn test_fmt_wat_func_one_call() {
        assert_eq!(
            WatFunc {
                method: Method::Update,
                name: "test".to_string(),
                calls: vec![WatCall::debug_print(0, 4)],
            }
            .to_string(),
            r#"
            (func $test (export "canister_update test")
                (call $ic0_debug_print (i32.const 0) (i32.const 4))
            )"#
        );
    }

    #[test]
    fn test_fmt_wat_func_many_calls() {
        assert_eq!(
            WatFunc {
                method: Method::Update,
                name: "test".to_string(),
                calls: vec![
                    WatCall::stable_grow(1),
                    WatCall::stable_read(4, 7),
                    WatCall::global_timer_set(1),
                    WatCall::debug_print(0, 4),
                    WatCall::trap(10, 4),
                    WatCall::wait(10_000),
                ],
            }
            .to_string(),
            r#"
            (func $test (export "canister_update test")
                (call $ic0_stable_grow (i32.const 1))
                (call $ic0_stable_read (i32.const 4) (i32.const 7))
                (drop (call $ic0_global_timer_set (i64.const 1)))
                (call $ic0_debug_print (i32.const 0) (i32.const 4))
                (call $ic0_trap (i32.const 10) (i32.const 4))
                (call $_wait (i64.const 10000))
            )"#
        );
    }

    #[test]
    fn test_wat_canister_builder() {
        let wat = wat_canister()
            .start(wat_fn().debug_print(b"start"))
            .init(wat_fn().debug_print(b"init").api_global_timer_set(1))
            .pre_upgrade(wat_fn().debug_print(b"pre_upgrade"))
            .post_upgrade(wat_fn().debug_print(b"post_upgrade"))
            .inspect_message(wat_fn().debug_print(b"inspect_message"))
            .heartbeat(wat_fn().debug_print(b"heartbeat"))
            .global_timer(wat_fn().debug_print(b"global_timer"))
            .update(
                "test_1",
                wat_fn()
                    .debug_print(b"aa")
                    .debug_print(b"aa")
                    .debug_print(b"bbb")
                    .wait(5_000)
                    .debug_print(b"cccc")
                    .trap_with_blob(b"bbb"),
            )
            .query(
                "test_2",
                wat_fn()
                    .debug_print(b"cccc")
                    .wait(10_000)
                    .trap_with_blob(b"query"),
            )
            .composite_query("test_3", wat_fn().trap_with_blob(b"composite_query"))
            .build();

        let wasm_module = wat::parse_str(wat.clone()).unwrap();
        assert!(!wasm_module.is_empty());
        assert_eq!(
            wat,
            r#"
        (module
            ;; Import functions
            (import "ic0" "stable_grow" (func $ic0_stable_grow (param $pages i32) (result i32)))
            (import "ic0" "stable_read" (func $ic0_stable_read (param i32 i32 i32)))
            (import "ic0" "global_timer_set" (func $ic0_global_timer_set (param i64) (result i64)))
            (import "ic0" "performance_counter" (func $ic0_performance_counter (param i32) (result i64)))
            (import "ic0" "debug_print" (func $ic0_debug_print (param i32) (param i32)))
            (import "ic0" "trap" (func $ic0_trap (param i32) (param i32)))

            ;; Define functions
            (func $_wait (param $instructions i64)
                ;; Calculate the instruction limit
                (local $limit i64)
                (local.set $limit (i64.add (call $ic0_performance_counter (i32.const 0)) (local.get $instructions)))
                (loop $loop
                    (if (i64.lt_s
                            (call $ic0_performance_counter (i32.const 0))
                            (local.get $limit))
                        (then
                            ;; Placeholder instruction for simulating work
                            (memory.fill (i32.const 0) (i32.const 0) (i32.const 100))
                            (br $loop)
                        )
                    )
                )
            )
            
            (start $start)
            (func $start
                (call $ic0_debug_print (i32.const 1000) (i32.const 5))
            )

            (func $init (export "canister_init")
                (call $ic0_debug_print (i32.const 1005) (i32.const 4))
                (drop (call $ic0_global_timer_set (i64.const 1)))
            )

            (func $pre_upgrade (export "canister_pre_upgrade")
                (call $ic0_debug_print (i32.const 1009) (i32.const 11))
            )

            (func $post_upgrade (export "canister_post_upgrade")
                (call $ic0_debug_print (i32.const 1020) (i32.const 12))
            )

            (func $inspect_message (export "canister_inspect_message")
                (call $ic0_debug_print (i32.const 1032) (i32.const 15))
            )

            (func $heartbeat (export "canister_heartbeat")
                (call $ic0_debug_print (i32.const 1047) (i32.const 9))
            )

            (func $global_timer (export "canister_global_timer")
                (call $ic0_debug_print (i32.const 1056) (i32.const 12))
            )

            (func $test_1 (export "canister_update test_1")
                (call $ic0_debug_print (i32.const 1068) (i32.const 2))
                (call $ic0_debug_print (i32.const 1068) (i32.const 2))
                (call $ic0_debug_print (i32.const 1070) (i32.const 3))
                (call $_wait (i64.const 5000))
                (call $ic0_debug_print (i32.const 1073) (i32.const 4))
                (call $ic0_trap (i32.const 1070) (i32.const 3))
            )

            (func $test_2 (export "canister_query test_2")
                (call $ic0_debug_print (i32.const 1073) (i32.const 4))
                (call $_wait (i64.const 10000))
                (call $ic0_trap (i32.const 1077) (i32.const 5))
            )

            (func $test_3 (export "canister_composite_query test_3")
                (call $ic0_trap (i32.const 1082) (i32.const 15))
            )

            ;; Define memory
            (memory $memory 1)
            (export "memory" (memory $memory))

            ;; Initialize memory with data
            (data (i32.const 1000) "start")
            (data (i32.const 1005) "init")
            (data (i32.const 1009) "pre_upgrade")
            (data (i32.const 1020) "post_upgrade")
            (data (i32.const 1032) "inspect_message")
            (data (i32.const 1047) "heartbeat")
            (data (i32.const 1056) "global_timer")
            (data (i32.const 1068) "aa")
            (data (i32.const 1070) "bbb")
            (data (i32.const 1073) "cccc")
            (data (i32.const 1077) "query")
            (data (i32.const 1082) "composite_query")
        )"#
        );
    }
}
