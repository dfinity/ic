///
/// WAT templates and snippets.
//
use crate::common::Wasm64;

/// Number of internal loop iterations for a benchmark.
pub enum LoopIterations {
    /// Default internal loop is 1M iterations.
    Mi,
    /// One iteration, i.e. no loop.
    One,
}

/// Type of WAT module to render.
/// The dead code is allowed as this common module is used across a few benchmark binaries.
#[allow(dead_code)]
pub enum Module {
    /// WAT module with a test function.
    Test,
    /// WAT module with a test function with stable memory import.
    StableTest,
    /// WAT module with a `ic0_call_new()` System API call in a loop.
    CallNewLoop,
    /// WAT module with a message callback handler.
    Callback,
    /// WAT module with an inspect message handler.
    InspectMessage,
    /// WAT module with a query test function.
    QueryTest,
}

impl Module {
    /// Render a complete WAT module for a system call executing in a loop, with params and result.
    #[allow(clippy::wrong_self_convention)]
    pub fn from_ic0<N, P>(
        &self,
        name: N,
        params: P,
        result: Result,
        wasm64_enabled: Wasm64,
    ) -> String
    where
        N: std::fmt::Display,
        P: RenderParams,
    {
        let loop_iterations = match self {
            Module::Test
            | Module::StableTest
            | Module::Callback
            | Module::InspectMessage
            | Module::QueryTest => LoopIterations::Mi,
            // The call new module has a built-in loop with a `ic0_call_new()`
            Module::CallNewLoop => LoopIterations::One,
        };
        self.from_sections(
            Self::sections(loop_iterations, name, params, result, wasm64_enabled),
            wasm64_enabled,
        )
    }

    /// Render a complete WAT module from imports and body.
    #[allow(clippy::wrong_self_convention)]
    pub fn from_sections<I, B>(&self, (imports, body): (I, B), wasm64_enabled: Wasm64) -> String
    where
        I: core::fmt::Display,
        B: core::fmt::Display,
    {
        let memory = if wasm64_enabled == Wasm64::Enabled {
            "(memory i64 131072)"
        } else {
            "(memory 1)"
        };
        let call_new_params = if wasm64_enabled == Wasm64::Enabled {
            "(call $ic0_call_new
                (i64.const 0)   (i64.const 10)
                (i64.const 100) (i64.const 18)
                (i64.const 11)  (i64.const 0) ;; non-existent function
                (i64.const 22)  (i64.const 0) ;; non-existent function
            )"
        } else {
            "(call $ic0_call_new
                (i32.const 0)   (i32.const 10)
                (i32.const 100) (i32.const 18)
                (i32.const 11)  (i32.const 0) ;; non-existent function
                (i32.const 22)  (i32.const 0) ;; non-existent function
            )"
        };
        let call_new_signature = if wasm64_enabled == Wasm64::Enabled {
            r#"(import "ic0" "call_new"
                (func $ic0_call_new
                (param $callee_src i64)         (param $callee_size i64)
                (param $name_src i64)           (param $name_size i64)
                (param $reply_fun i64)          (param $reply_env i64)
                (param $reject_fun i64)         (param $reject_env i64)
            ))"#
        } else {
            r#"(import "ic0" "call_new"
                (func $ic0_call_new
                (param $callee_src i32)         (param $callee_size i32)
                (param $name_src i32)           (param $name_size i32)
                (param $reply_fun i32)          (param $reply_env i32)
                (param $reject_fun i32)         (param $reject_env i32)
            ))"#
        };

        match self {
            Module::Test => {
                format!(
                    // Note: the indents below are to match with other WAT sections
                    r#"
        (module
            {IMPORTS}
            {MEMORY}
            (func $test (export "canister_update test")
                {VARS_DECLARATION}
                {BODY}
            )
        )
            "#,
                    IMPORTS = imports,
                    MEMORY = memory,
                    VARS_DECLARATION = if wasm64_enabled == Wasm64::Enabled {
                        "(local $i i64) (local $s i64)"
                    } else {
                        "(local $i i32) (local $s i32)"
                    },
                    BODY = body
                )
            }
            Module::StableTest => {
                format!(
                    r#"
        (module
            {STABLE_GROW_IMPORT}
            {IMPORTS}
            {MEMORY}
            (func $test (export "canister_update test")
                {LOCAL_COUNTER_DECLARATION}
                {CALL_STABLE_GROW}
                {BODY}
            )
        )
            "#,
                    STABLE_GROW_IMPORT = if wasm64_enabled == Wasm64::Enabled {
                        r#"(import "ic0" "stable64_grow"
                            (func $ic0_stable64_grow (param $additional_pages i64) (result i64)))"#
                    } else {
                        r#"(import "ic0" "stable_grow"
                            (func $ic0_stable_grow (param $additional_pages i32) (result i32)))"#
                    },
                    IMPORTS = imports,
                    MEMORY = memory,
                    LOCAL_COUNTER_DECLARATION = if wasm64_enabled == Wasm64::Enabled {
                        "(local $i i64) (local $s i64)"
                    } else {
                        "(local $i i32) (local $s i32)"
                    },
                    CALL_STABLE_GROW = if wasm64_enabled == Wasm64::Enabled {
                        "(drop (call $ic0_stable64_grow (i64.const 1)))"
                    } else {
                        "(drop (call $ic0_stable_grow (i32.const 1)))"
                    },
                    BODY = body
                )
            }
            Module::CallNewLoop => {
                let body = Self::render_loop(
                    LoopIterations::Mi,
                    format!(
                        r#"
                            {CALL_NEW_PARAMS}
                            {BODY}"#,
                        CALL_NEW_PARAMS = call_new_params,
                        BODY = body
                    ),
                    wasm64_enabled,
                );
                format!(
                    r#"
        (module
            {CALL_NEW_SIGNATURE}
            {IMPORTS}
            {MEMORY}
            (func $test (export "canister_update test")
                {VARS_DECLARATION}
                {BODY}
            )
        )
            "#,
                    CALL_NEW_SIGNATURE = call_new_signature,
                    IMPORTS = imports,
                    MEMORY = memory,
                    VARS_DECLARATION = if wasm64_enabled == Wasm64::Enabled {
                        "(local $i i64) (local $s i64)"
                    } else {
                        "(local $i i32) (local $s i32)"
                    },
                    BODY = body
                )
            }
            Module::InspectMessage => {
                format!(
                    r#"
        (module
            (import "ic0" "accept_message" (func $ic0_accept_message))
            {IMPORTS}
            {MEMORY}
            (func (export "canister_inspect_message")
                (local $i i32) (local $s i32)
                {BODY}
                (call $ic0_accept_message)
            )
        )
            "#,
                    IMPORTS = imports,
                    MEMORY = memory,
                    BODY = body
                )
            }
            Module::Callback => {
                format!(
                    r#"
        (module
            {IMPORTS}
            {MEMORY}
            (table funcref (elem $test))
            (func $test (param $env i32)
                (local $i i32) (local $s i32)
                {BODY}
            )
        )
            "#,
                    IMPORTS = imports,
                    MEMORY = memory,
                    BODY = body
                )
            }
            Module::QueryTest => {
                format!(
                    // Note: the indents below are to match with other WAT sections
                    r#"
        (module
            {IMPORTS}
            {MEMORY}
            (func $test (export "canister_query test")
                (local $i i32) (local $s i32)
                {BODY}
            )
        )
            "#,
                    IMPORTS = imports,
                    MEMORY = memory,
                    BODY = body
                )
            }
        }
    }

    /// Get WAT module parts: imports and body.
    pub fn sections<N, P>(
        loop_iterations: LoopIterations,
        name: N,
        params: P,
        result: Result,
        wasm64_enabled: Wasm64,
    ) -> (String, String)
    where
        N: std::fmt::Display,
        P: RenderParams,
    {
        let imports = format!(
            r#"
                (import "ic0" "{NAME}"
                    (func $ic0_{NAME} {PARAMS} {RESULT}))
            "#,
            NAME = name,
            PARAMS = params.import(),
            RESULT = result.import()
        );
        let body = Self::render_loop(
            loop_iterations,
            result.ignore(format!(
                "(call $ic0_{NAME} {PARAMS})",
                NAME = name,
                PARAMS = params.call()
            )),
            wasm64_enabled,
        );
        (imports, body)
    }

    /// Return WAT for a simple loop.
    pub fn render_loop<B>(
        loop_iterations: LoopIterations,
        loop_body: B,
        wasm64_enabled: Wasm64,
    ) -> String
    where
        B: core::fmt::Display,
    {
        match loop_iterations {
            LoopIterations::One => format!(
                // Indent to match module and function
                "{LOOP_BODY}",
                LOOP_BODY = loop_body
            ),
            LoopIterations::Mi => format!(
                r#"
                (loop $loop
                    (if {BRANCH_CONDITION} {LOOP_ITERATIONS}))
                        (then
                            {INCREMENT_COUNTER}

                            {LOOP_BODY}

                            (br $loop)
                        )
                    )
                )
        "#,
                BRANCH_CONDITION = if wasm64_enabled == Wasm64::Enabled {
                    "(i64.lt_s (local.get $i) (i64.const"
                } else {
                    "(i32.lt_s (local.get $i) (i32.const"
                },
                LOOP_ITERATIONS = 1_000_000,
                INCREMENT_COUNTER = if wasm64_enabled == Wasm64::Enabled {
                    "(local.set $i (i64.add (local.get $i) (i64.const 1)))"
                } else {
                    "(local.set $i (i32.add (local.get $i) (i32.const 1)))"
                },
                LOOP_BODY = loop_body
            ),
        }
    }
}

/// System API call with no parameters.
pub struct NoParams;

/// System API call with 1 parameter.
pub struct Param1<P1>(pub P1);

/// System API call with 2 parameters.
pub struct Params2<P1, P2>(pub P1, pub P2);

/// System API call with 3 parameters.
pub struct Params3<P1, P2, P3>(pub P1, pub P2, pub P3);

/// Trait to render System API call parameters.
pub trait RenderParams {
    /// Render System API call parameter import.
    fn import(&self) -> String;
    /// Render System API call parameter call.
    fn call(&self) -> String;
}

/// Implement RenderParams trait for i32.
impl RenderParams for i32 {
    fn import(&self) -> String {
        "(param i32)".into()
    }
    fn call(&self) -> String {
        format!("(i32.const {self})")
    }
}

/// Implement RenderParams trait for i64.
impl RenderParams for i64 {
    fn import(&self) -> String {
        "(param i64)".into()
    }
    fn call(&self) -> String {
        format!("(i64.const {self})")
    }
}

/// Implement RenderParams trait for a System API call with no parameters.
impl RenderParams for NoParams {
    fn import(&self) -> String {
        String::new()
    }
    fn call(&self) -> String {
        String::new()
    }
}

/// Implement RenderParams trait for a System API call with 1 parameter.
impl<P1: RenderParams> RenderParams for Param1<P1> {
    fn import(&self) -> String {
        self.0.import()
    }
    fn call(&self) -> String {
        self.0.call()
    }
}

/// Implement RenderParams trait for a System API call with 2 parameters.
impl<P1: RenderParams, P2: RenderParams> RenderParams for Params2<P1, P2> {
    fn import(&self) -> String {
        format!("{P1} {P2}", P1 = self.0.import(), P2 = self.1.import())
    }
    fn call(&self) -> String {
        format!("{P1} {P2}", P1 = self.0.call(), P2 = self.1.call())
    }
}

/// Implement RenderParams trait for a System API call with 3 parameters.
impl<P1: RenderParams, P2: RenderParams, P3: RenderParams> RenderParams for Params3<P1, P2, P3> {
    fn import(&self) -> String {
        format!(
            "{P1} {P2} {P3}",
            P1 = self.0.import(),
            P2 = self.1.import(),
            P3 = self.2.import()
        )
    }
    fn call(&self) -> String {
        format!(
            "{P1} {P2} {P3}",
            P1 = self.0.call(),
            P2 = self.1.call(),
            P3 = self.2.call()
        )
    }
}

/// System API call result.
/// The dead code is allowed as this common module is used across a few benchmark binaries.
#[allow(dead_code)]
pub enum Result {
    /// System API call with no result.
    No,
    /// System API call with an i32 result.
    I32,
    /// System API call with an i64 result.
    I64,
}

/// Implement RenderResult trait for a System API call result.
impl Result {
    fn import(&self) -> String {
        match self {
            Result::No => String::new(),
            Result::I32 => "(result i32)".into(),
            Result::I64 => "(result i64)".into(),
        }
    }
    fn ignore<B: core::fmt::Display>(&self, body: B) -> String {
        match self {
            Result::No => format!("{body}"),
            Result::I32 | Result::I64 => format!("(drop {body})"),
        }
    }
}
