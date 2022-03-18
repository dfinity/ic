///
/// WAT templates and snippets.
//

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
}

impl Module {
    /// Render a complete WAT module for a system call executing in a loop, with params and result.
    pub fn from_ic0<N, P>(&self, name: N, params: P, result: Result) -> String
    where
        N: std::fmt::Display,
        P: RenderParams,
    {
        self.from_sections(Self::sections(LoopIterations::Mi, name, params, result))
    }

    /// Render a complete WAT module from imports and body.
    pub fn from_sections<I, B>(&self, (imports, body): (I, B)) -> String
    where
        I: core::fmt::Display,
        B: core::fmt::Display,
    {
        match self {
            Module::Test => {
                format!(
                    // Note: the indents below are to match with other WAT sections
                    r#"
        (module
            {IMPORTS}
            (memory $mem 1)
            (func $test (export "canister_update test")
                (local $i i32) (local $s i32)
                {BODY}
            )
        )
            "#,
                    IMPORTS = imports,
                    BODY = body
                )
            }
            Module::StableTest => {
                format!(
                    r#"
        (module
            (import "ic0" "stable_grow"
                (func $ic0_stable_grow (param $additional_pages i32) (result i32)))
            {IMPORTS}
            (memory $mem 1)
            (func $test (export "canister_update test")
                (local $i i32) (local $s i32)
                (drop (call $ic0_stable_grow (i32.const 1)))
                {BODY}
            )
        )
            "#,
                    IMPORTS = imports,
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
        );
        (imports, body)
    }

    /// Return WAT for a simple loop.
    pub fn render_loop<B>(loop_iterations: LoopIterations, loop_body: B) -> String
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
                    (if (i32.lt_s (get_local $i) (i32.const {LOOP_ITERATIONS}))
                        (then
                            (set_local $i (i32.add (get_local $i) (i32.const 1)))

                            {LOOP_BODY}

                            (br $loop)
                        )
                    )
                )
        "#,
                LOOP_ITERATIONS = 1_000_000,
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
