//! Provides the high-level builder (`WatCanisterBuilder`) that composes
//! the full Wasm module from individual functions.

use std::collections::HashMap;

use crate::wat_canister::fn_builder::{MEMORY_OFFSET_START, WAIT_SCRATCHPAD_START, WatFnCode};
use crate::wat_canister::render::{RenderState, format_wasm_string};

const STEP: &str = "    ";
const INDENT: &str = "\n            ";

const MEMORY_FILL_MAX: i32 = 100;

#[derive(Copy, Clone, PartialEq, Debug)]
pub(crate) enum Method {
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

#[derive(Clone)]
pub(crate) struct WatFunc {
    pub(crate) method: Method,
    pub(crate) name: String,
    pub(crate) code: WatFnCode,
}

impl WatFunc {
    /// Emit the declaration prefix for this Wasm function.
    pub(crate) fn export_declaration(&self) -> String {
        match self.method {
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
#[derive(Clone)]
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
    pub fn start(self, code: WatFnCode) -> Self {
        self.process_method(Method::Start, "start", code)
    }

    /// Add `canister_init` exported function to the WAT canister.
    pub fn init(self, code: WatFnCode) -> Self {
        self.process_method(Method::Init, "init", code)
    }

    /// Add `canister_pre_upgrade` exported function to the WAT canister.
    pub fn pre_upgrade(self, code: WatFnCode) -> Self {
        self.process_method(Method::PreUpgrade, "pre_upgrade", code)
    }

    /// Add `canister_post_upgrade` exported function to the WAT canister.
    pub fn post_upgrade(self, code: WatFnCode) -> Self {
        self.process_method(Method::PostUpgrade, "post_upgrade", code)
    }

    /// Add `canister_inspect_message` exported function to the WAT canister.
    pub fn inspect_message(self, code: WatFnCode) -> Self {
        self.process_method(Method::InspectMessage, "inspect_message", code)
    }

    /// Add `canister_heartbeat` exported function to the WAT canister.
    pub fn heartbeat(self, code: WatFnCode) -> Self {
        self.process_method(Method::Heartbeat, "heartbeat", code)
    }

    /// Add `canister_global_timer` exported function to the WAT canister.
    pub fn global_timer(self, code: WatFnCode) -> Self {
        self.process_method(Method::GlobalTimer, "global_timer", code)
    }

    /// Add `canister_update <name>` exported function to the WAT canister.
    pub fn update(self, name: &str, code: WatFnCode) -> Self {
        self.process_method(Method::Update, name, code)
    }

    /// Add `canister_query <name>` exported function to the WAT canister.
    pub fn query(self, name: &str, code: WatFnCode) -> Self {
        self.process_method(Method::Query, name, code)
    }

    /// Add `canister_composite_query <name>` exported function to the WAT canister.
    pub fn composite_query(self, name: &str, code: WatFnCode) -> Self {
        self.process_method(Method::CompositeQuery, name, code)
    }

    /// Build the WAT canister.
    pub fn build(mut self) -> String {
        let mut rendered_functions = Vec::new();

        // Drain the ASTs to compute rendering
        let funcs: Vec<WatFunc> = self.functions.drain(..).collect();

        for func in funcs {
            let declaration = func.export_declaration();

            // Perform single-pass rendering over the function's AST
            let mut state = RenderState {
                next_loop_id: 0,
                memory: &mut self.memory,
                memory_offset: &mut self.memory_offset,
                instructions: Vec::new(),
            };

            let top_level_locals = RenderState::count_loops(&func.code.calls);
            state.process_calls(&func.code.calls, STEP);

            // Piece together the exact Text block.
            let locals: String = (0..top_level_locals)
                .map(|i| format!("{INDENT}{STEP}(local $loop_counter_{i} i32)"))
                .collect::<Vec<_>>()
                .join("");

            let body = state.instructions.join(&format!("{INDENT}{STEP}"));

            if !body.is_empty() {
                rendered_functions.push(format!(
                    "({declaration}{locals}{INDENT}{STEP}{body}{INDENT})"
                ));
            } else {
                rendered_functions.push(format!("({declaration}{locals})"));
            }
        }

        let functions_block = rendered_functions.join(INDENT);

        let mut data_entries: Vec<_> = self.memory.into_iter().collect();
        data_entries.sort_by_key(|&(_, offset)| offset);

        let data_block = data_entries
            .into_iter()
            .map(|(message, offset)| {
                format!(
                    r#"(data (i32.const {}) "{}")"#,
                    offset,
                    format_wasm_string(&message)
                )
            })
            .collect::<Vec<_>>()
            .join(INDENT);

        format!(
            r#"
        (module
            ;; Import functions
            (import "ic0" "stable_grow" (func $ic0_stable_grow (param i32) (result i32)))
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
                            ;; Placeholder instruction for simulating work in a reserved memory block
                            (memory.fill (i32.const {WAIT_SCRATCHPAD_START}) (i32.const 0) (i32.const {MEMORY_FILL_MAX}))
                            (br $loop)
                        )
                    )
                )
            )
            {functions_block}

            ;; Define memory
            (memory $memory 1)
            (export "memory" (memory $memory))

            ;; Initialize memory with data
            {data_block}
        )"#
        )
    }

    /// Build the Wasm for the WAT canister.
    pub fn build_wasm(self) -> Vec<u8> {
        wat::parse_str(self.build()).unwrap()
    }

    fn process_method(mut self, method: Method, name: &str, code: WatFnCode) -> Self {
        let name = name.to_string();
        // It's OK to use linear search here because this is a test util
        // and the number of functions is small.
        if self.functions.iter().any(|f| f.name == *name) {
            panic!("Method '{method:?}' with the name '{name}' already exists");
        }
        self.functions.push(WatFunc { method, name, code });
        self
    }
}

impl Default for WatCanisterBuilder {
    fn default() -> Self {
        Self::new()
    }
}
