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
        wasm64_status: Wasm64,
    ) -> String
    where
        N: std::fmt::Display,
        P: RenderParams,
    {
        self.from_ic0_with_data(name, params, result, DataSections::default(), wasm64_status)
    }

    /// Render a complete WAT module for a system call executing in a loop, with params and result,
    /// and a data segment
    #[allow(clippy::wrong_self_convention)]
    pub fn from_ic0_with_data<N, D, P>(
        &self,
        name: N,
        params: P,
        result: Result,
        data: D,
        wasm64_status: Wasm64,
    ) -> String
    where
        N: std::fmt::Display,
        P: RenderParams,
        D: std::fmt::Display,
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
            Self::sections(loop_iterations, name, params, result, data, wasm64_status),
            wasm64_status,
        )
    }

    /// Render a complete WAT module from imports and body.
    #[allow(clippy::wrong_self_convention)]
    pub fn from_sections<I, D, B>(
        &self,
        (imports, data, body): (I, D, B),
        wasm64_status: Wasm64,
    ) -> String
    where
        I: core::fmt::Display,
        D: core::fmt::Display,
        B: core::fmt::Display,
    {
        let memory = if wasm64_status == Wasm64::Enabled {
            "(memory i64 131072)"
        } else {
            "(memory 1)"
        };
        let ty = if wasm64_status == Wasm64::Enabled {
            "i64"
        } else {
            "i32"
        };
        let call_new_params = format!(
            r#"(call $ic0_call_new
                ({ty}.const 0)   ({ty}.const 10)
                ({ty}.const 100) ({ty}.const 18)
                ({ty}.const 11)  ({ty}.const 0) ;; non-existent function
                ({ty}.const 22)  ({ty}.const 0) ;; non-existent function
            )"#
        );
        let call_new_signature = format!(
            r#"(import "ic0" "call_new"
                (func $ic0_call_new
                (param $callee_src {ty})         (param $callee_size {ty})
                (param $name_src {ty})           (param $name_size {ty})
                (param $reply_fun {ty})          (param $reply_env {ty})
                (param $reject_fun {ty})         (param $reject_env {ty})
                ))"#
        );

        match self {
            Module::Test => {
                format!(
                    // Note: the indents below are to match with other WAT sections
                    r#"
        (module
            {IMPORTS}
            {MEMORY}
            {DATA}
            (func $test (export "canister_update test")
                {VARS_DECLARATION}
                {BODY}
            )
        )
            "#,
                    IMPORTS = imports,
                    MEMORY = memory,
                    DATA = data,
                    VARS_DECLARATION = if wasm64_status == Wasm64::Enabled {
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
            {DATA}
            (func $test (export "canister_update test")
                {LOCAL_COUNTER_DECLARATION}
                {CALL_STABLE_GROW}
                {BODY}
            )
        )
            "#,
                    STABLE_GROW_IMPORT = if wasm64_status == Wasm64::Enabled {
                        r#"(import "ic0" "stable64_grow"
                            (func $ic0_stable64_grow (param $additional_pages i64) (result i64)))"#
                    } else {
                        r#"(import "ic0" "stable_grow"
                            (func $ic0_stable_grow (param $additional_pages i32) (result i32)))"#
                    },
                    IMPORTS = imports,
                    MEMORY = memory,
                    DATA = data,
                    LOCAL_COUNTER_DECLARATION = if wasm64_status == Wasm64::Enabled {
                        "(local $i i64) (local $s i64)"
                    } else {
                        "(local $i i32) (local $s i32)"
                    },
                    CALL_STABLE_GROW = if wasm64_status == Wasm64::Enabled {
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
                            {call_new_params}
                            {body}"#
                    ),
                    wasm64_status,
                );
                format!(
                    r#"
        (module
            {CALL_NEW_SIGNATURE}
            {IMPORTS}
            {MEMORY}
            {DATA}
            (func $test (export "canister_update test")
                {VARS_DECLARATION}
                {BODY}
            )
        )
            "#,
                    CALL_NEW_SIGNATURE = call_new_signature,
                    IMPORTS = imports,
                    MEMORY = memory,
                    DATA = data,
                    VARS_DECLARATION = if wasm64_status == Wasm64::Enabled {
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
            {DATA}
            (func (export "canister_inspect_message")
                {VARS_DECLARATION}
                {BODY}
                (call $ic0_accept_message)
            )
        )
            "#,
                    IMPORTS = imports,
                    MEMORY = memory,
                    DATA = data,
                    VARS_DECLARATION = if wasm64_status == Wasm64::Enabled {
                        "(local $i i64) (local $s i64)"
                    } else {
                        "(local $i i32) (local $s i32)"
                    },
                    BODY = body
                )
            }
            Module::Callback => {
                format!(
                    r#"
        (module
            {imports}
            {memory}
            {data}
            (table funcref (elem $test))
            (func $test (param $env i32)
                (local $i i32) (local $s i32)
                {body}
            )
        )
            "#
                )
            }
            Module::QueryTest => {
                format!(
                    // Note: the indents below are to match with other WAT sections
                    r#"
        (module
            {IMPORTS}
            {MEMORY}
            {DATA}
            (func $test (export "canister_query test")
                {VARS_DECLARATION}
                {BODY}
            )
        )
            "#,
                    IMPORTS = imports,
                    MEMORY = memory,
                    DATA = data,
                    VARS_DECLARATION = if wasm64_status == Wasm64::Enabled {
                        "(local $i i64) (local $s i64)"
                    } else {
                        "(local $i i32) (local $s i32)"
                    },
                    BODY = body
                )
            }
        }
    }

    /// Get WAT module parts: imports and body.
    pub fn sections<N, P, D>(
        loop_iterations: LoopIterations,
        name: N,
        params: P,
        result: Result,
        data: D,
        wasm64_status: Wasm64,
    ) -> (String, String, String)
    where
        N: std::fmt::Display,
        P: RenderParams,
        D: std::fmt::Display,
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
            wasm64_status,
        );
        (imports, data.to_string(), body)
    }

    /// Return WAT for a simple loop.
    pub fn render_loop<B>(
        loop_iterations: LoopIterations,
        loop_body: B,
        wasm64_status: Wasm64,
    ) -> String
    where
        B: core::fmt::Display,
    {
        match loop_iterations {
            LoopIterations::One => format!(
                // Indent to match module and function
                "{loop_body}"
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
                BRANCH_CONDITION = if wasm64_status == Wasm64::Enabled {
                    "(i64.lt_s (local.get $i) (i64.const"
                } else {
                    "(i32.lt_s (local.get $i) (i32.const"
                },
                LOOP_ITERATIONS = 1_000_000,
                INCREMENT_COUNTER = if wasm64_status == Wasm64::Enabled {
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

/// System API call with 4 parameters.
pub struct Params4<P1, P2, P3, P4>(pub P1, pub P2, pub P3, pub P4);

/// Trait to render System API call parameters.
pub trait RenderParams {
    /// Render System API call parameter import.
    fn import(&self) -> String;
    /// Render System API call parameter call.
    fn call(&self) -> String;
}

#[derive(Default)]
pub struct DataSections {
    pub use_64_bit: bool,
    pub sections: Vec<(u32, Vec<u8>)>,
}

impl core::fmt::Display for DataSections {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for (offset, bytes) in &self.sections {
            write!(
                f,
                r#"(data ({address_space}.const {offset}) "{bytes}")"#,
                address_space = if self.use_64_bit { "i64" } else { "i32" },
                offset = offset,
                bytes = bytes
                    .iter()
                    .map(|b| format!("\\{:02x}", b))
                    .collect::<String>()
            )?;
        }
        Ok(())
    }
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

/// Implement RenderParams trait for a System API call with 4 parameters.
impl<P1: RenderParams, P2: RenderParams, P3: RenderParams, P4: RenderParams> RenderParams
    for Params4<P1, P2, P3, P4>
{
    fn import(&self) -> String {
        format!(
            "{P1} {P2} {P3} {P4}",
            P1 = self.0.import(),
            P2 = self.1.import(),
            P3 = self.2.import(),
            P4 = self.3.import(),
        )
    }
    fn call(&self) -> String {
        format!(
            "{P1} {P2} {P3} {P4}",
            P1 = self.0.call(),
            P2 = self.1.call(),
            P3 = self.2.call(),
            P4 = self.3.call()
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
