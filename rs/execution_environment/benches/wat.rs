///
/// WAT templates/snippets to benchmark
//
// TODO: ic0_call_* require to create call context, so will be done in another
// iteration
//
// assert_api_supported(api.ic0_call_simple(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, &[]));
// assert_api_supported(api.ic0_call_new(0, 0, 0, 0, 0, 0, 0, 0, &[]));
// assert_api_supported(api.ic0_call_data_append(0, 0, &[]));
// assert_api_supported(api.ic0_call_on_cleanup(0, 0));
// assert_api_supported(api.ic0_call_cycles_add(0));
// assert_api_supported(api.ic0_call_perform());

// Render normal test function
pub fn render_test_func<I, B>(imports: I, func_body: B) -> String
where
    I: core::fmt::Display,
    B: core::fmt::Display,
{
    format!(
        r#"
        (module
            {IMPORTS}
            (memory $mem 1)
            (func $test (export "canister_update test") (local $i i32) (local $s i32)
                {FUNC_BODY}
            )
        )
            "#,
        IMPORTS = imports,
        FUNC_BODY = func_body
    )
}

/// Render stable memory test function (imports and calls `stable_grow()`).
pub fn render_stable_test_func<I, B>(imports: I, func_body: B) -> String
where
    I: core::fmt::Display,
    B: core::fmt::Display,
{
    let stable_imports = format!(
        r#"
            (import "ic0" "stable_grow"
                (func $ic0_stable_grow (param $additional_pages i32) (result i32)))
            {IMPORTS}
            "#,
        IMPORTS = imports
    );
    let stable_body = format!(
        r#"
                (drop (call $ic0_stable_grow (i32.const 1)))
                {FUNC_BODY}
            "#,
        FUNC_BODY = func_body
    );
    render_test_func(stable_imports, stable_body)
}

/// Return WAT for a system call executing in a loop, with params and results.
/// The results of the call get dropped.
///
/// The following name params are supported:
/// * `/i64` to use i64 type
/// * `/stable` to use stable memory (import and call `ic0_stable_grow()`)
pub fn render<N, P, R>(loop_iterations: usize, name: N, params: P, results: R) -> String
where
    N: AsRef<str>,
    P: RenderParams,
    R: RenderResults,
{
    let clean_name = name.as_ref().replace("/i64", "").replace("/stable", "");
    let params_type = match name.as_ref() {
        name if name.contains("64") => "i64",
        _ => "i32",
    };
    let imports = format!(
        r#"
            (import "ic0" "{NAME}"
                (func $ic0_{NAME} {PARAMS} {RESULTS}))
        "#,
        NAME = clean_name,
        PARAMS = params.import(params_type),
        RESULTS = results.import(params_type)
    );
    let func_body = render_loop(
        loop_iterations,
        results.ignore(format!(
            "(call $ic0_{NAME} {PARAMS})",
            NAME = clean_name,
            PARAMS = params.call(params_type)
        )),
    );
    // Prevent import redefinition of `stable_grow()`
    match name.as_ref().contains("stable") && !name.as_ref().contains("stable_grow") {
        true => render_stable_test_func(imports, func_body),
        false => render_test_func(imports, func_body),
    }
}

/// Return WAT for a simple loop.
pub fn render_loop<B>(loop_iterations: usize, loop_body: B) -> String
where
    B: core::fmt::Display,
{
    match loop_iterations {
        1 => format!(
            // Indent to match module and function
            r#"
            {LOOP_BODY}
            "#,
            LOOP_BODY = loop_body
        ),
        _ => format!(
            // Indent to match module and function
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
            LOOP_ITERATIONS = loop_iterations,
            LOOP_BODY = loop_body
        ),
    }
}

/// Function with no parameters
pub struct NoParams();

/// Function with 1 parameter.
pub struct Param1(pub usize);

/// Function with 2 parameters.
pub struct Params2(pub usize, pub usize);

/// Function with 3 parameters.
pub struct Params3(pub usize, pub usize, pub usize);

/// Render function parameters.
pub trait RenderParams {
    /// Render an import of function params.
    fn import<T: core::fmt::Display>(&self, params_type: T) -> String;
    /// Render a call of function params.
    fn call<T: core::fmt::Display>(&self, params_type: T) -> String;
}

/// Implement RenderParams trait for no parameters function.
impl RenderParams for NoParams {
    fn import<T: core::fmt::Display>(&self, _params_type: T) -> String {
        format!("")
    }
    fn call<T: core::fmt::Display>(&self, _params_type: T) -> String {
        format!("")
    }
}

/// Implement RenderParams trait for 1 parameter function.
impl RenderParams for Param1 {
    fn import<T: core::fmt::Display>(&self, params_type: T) -> String {
        format!("(param $p1 {T})", T = params_type)
    }
    fn call<T: core::fmt::Display>(&self, params_type: T) -> String {
        format!("({T}.const {P1})", T = params_type, P1 = self.0)
    }
}

/// Implement RenderParams trait for 2 parameters function.
impl RenderParams for Params2 {
    fn import<T: core::fmt::Display>(&self, params_type: T) -> String {
        format!("(param $p1 {T}) (param $p2 {T})", T = params_type)
    }
    fn call<T: core::fmt::Display>(&self, params_type: T) -> String {
        format!(
            "({T}.const {P1}) ({T}.const {P2})",
            T = params_type,
            P1 = self.0,
            P2 = self.1
        )
    }
}

/// Implement RenderParams trait for 3 parameters function.
impl RenderParams for Params3 {
    fn import<T: core::fmt::Display>(&self, params_type: T) -> String {
        format!(
            "(param $p1 {T}) (param $p2 {T}) (param $p3 {T})",
            T = params_type
        )
    }
    fn call<T: core::fmt::Display>(&self, params_type: T) -> String {
        format!(
            "({T}.const {P1}) ({T}.const {P2}) ({T}.const {P3})",
            T = params_type,
            P1 = self.0,
            P2 = self.1,
            P3 = self.2
        )
    }
}

/// Function with no results
pub struct NoResults();

/// Function with 1 result.
pub struct Result1();

/// Function with 2 results.
pub struct Results2();

/// Render function results.
pub trait RenderResults {
    /// Render an import of function results.
    fn import<T: core::fmt::Display>(&self, results_type: T) -> String;
    /// Render a drop of function results.
    fn ignore<B: core::fmt::Display>(&self, func_body: B) -> String;
}

/// Implement RenderResults trait for no results function.
impl RenderResults for NoResults {
    fn import<T: core::fmt::Display>(&self, _params_type: T) -> String {
        format!("")
    }
    fn ignore<B: core::fmt::Display>(&self, func_body: B) -> String {
        format!("{FUNC_BODY}", FUNC_BODY = func_body)
    }
}

/// Implement RenderResults trait for 1 result function.
impl RenderResults for Result1 {
    fn import<T: core::fmt::Display>(&self, results_type: T) -> String {
        format!("(result {T})", T = results_type)
    }
    fn ignore<B: core::fmt::Display>(&self, func_body: B) -> String {
        format!("(drop {FUNC_BODY})", FUNC_BODY = func_body)
    }
}

/// Implement RenderResults trait for 2 results function.
impl RenderResults for Results2 {
    fn import<T: core::fmt::Display>(&self, results_type: T) -> String {
        format!("(result {T} {T})", T = results_type)
    }
    fn ignore<B: core::fmt::Display>(&self, func_body: B) -> String {
        format!("(drop {FUNC_BODY})", FUNC_BODY = func_body)
    }
}

pub const LOOP_1M: usize = 1_000_000;

use lazy_static::lazy_static;

lazy_static! {
    /// All WATs with their id, WAT, loop iterations, and expected number of
    /// Instructions.
    ///
    /// The number of Instructions is used to calculate the IPS metric
    /// (instructions per second) and calculated as follow:
    /// number of init Instructions + (number of loop Instructions) * loop
    /// iterations
    ///
    /// The easiest way to update it is to run the benchmark, and if it fails,
    /// put the number from the error log. It's a benchmark, it's not a
    /// validation, it's fine.
    pub static ref ALL: Vec<(&'static str, String, u64)> = vec![
        (
            "baseline/empty test",
            render_test_func("", "(drop (i32.const 0))"),
            2,
        ),
        (
            "baseline/empty loop/1M",
            render_test_func("", render_loop(LOOP_1M, "")),
            9_000_004,
        ),
        (
            "baseline/adds loop/1M",
            render_test_func(
                "",
                render_loop(
                    LOOP_1M,
                    "(set_local $s (i32.add (get_local $s) (i32.load (i32.const 0))))",
                ),
            ),
            14_000_004,
        ),
        (
            "ic0.msg_caller_copy() loop/1M/1B",
            render(LOOP_1M, "msg_caller_copy", Params3(0, 0, 1), NoResults()),
            13_000_004,
        ),
        (
            "ic0.msg_caller_copy() loop/1M/29B",
            render(LOOP_1M, "msg_caller_copy", Params3(0, 0, 29), NoResults()), // 29B max
            13_000_004,
        ),
        (
            "ic0.msg_caller_size() loop/1M",
            render(LOOP_1M, "msg_caller_size", NoParams(), Result1()),
            11_000_004,
        ),
        (
            "ic0.msg_arg_data_size() loop/1M",
            render(LOOP_1M, "msg_arg_data_size", NoParams(), Result1()),
            11_000_004,
        ),
        (
            "ic0.msg_arg_data_copy() loop/1M/1B",
            render(LOOP_1M, "msg_arg_data_copy", Params3(0, 0, 1), NoResults()),
            34_000_004, // was: 14_000_004,
        ),
        (
            "ic0.msg_arg_data_copy() loop/1M/8KiB",
            render(
                LOOP_1M,
                "msg_arg_data_copy",
                Params3(0, 0, 8192),
                NoResults(),
            ),
            8_225_000_004, // was: 8_205_000_004,
        ),
        (
            "ic0.msg_reply_data_append() loop/1M/1B",
            render(LOOP_1M, "msg_reply_data_append", Params2(0, 1), NoResults()), // 2MiB max
            33_000_004, // was: 13_000_004,
        ),
        (
            "ic0.msg_reply_data_append() loop/1M/2B",
            render(LOOP_1M, "msg_reply_data_append", Params2(0, 2), NoResults()), // 2MiB max
            34_000_004, // was: 14_000_004,
        ),
        (
            "ic0.msg_reply()",
            render(1, "msg_reply", NoParams(), NoResults()), // We can reply just once
            1,
        ),
        (
            "ic0.msg_reject()",
            render(1, "msg_reject", Params2(0, 0), NoResults()), // We can reject just once
            3,
        ),
        (
            "ic0.canister_self_size() loop/1M",
            render(LOOP_1M, "canister_self_size", NoParams(), Result1()),
            11_000_004,
        ),
        (
            "ic0.canister_self_copy() loop/1M/1B",
            render(LOOP_1M, "canister_self_copy", Params3(0, 0, 1), NoResults()),
            13_000_004,
        ),
        (
            "ic0.canister_self_copy() loop/1M/10B",
            render(
                LOOP_1M,
                "canister_self_copy",
                Params3(0, 0, 10),
                NoResults(),
            ), // 10B max
            13_000_004,
        ),
        (
            "ic0.controller_size() loop/1M",
            render(LOOP_1M, "controller_size", NoParams(), Result1()),
            11_000_004,
        ),
        (
            "ic0.controller_copy() loop/1M/1B",
            render(LOOP_1M, "controller_copy", Params3(0, 0, 1), NoResults()),
            13_000_004,
        ),
        (
            "ic0.controller_copy() loop/1M/10B",
            render(LOOP_1M, "controller_copy", Params3(0, 0, 10), NoResults()), // 10B max
            13_000_004,
        ),
        (
            "ic0.stable_size() loop/1M",
            render(LOOP_1M, "stable_size", NoParams(), Result1()),
            11_000_007,
        ),
        (
            "ic0.stable_grow() loop/1M",
            render(LOOP_1M, "stable_grow", Param1(1), Result1()),
            12_000_004,
        ),
        (
            "ic0.stable_read() loop/1M/1B",
            render(LOOP_1M, "stable_read", Params3(0, 0, 1), NoResults()),
            34_000_007, // was: 14_000_007,
        ),
        (
            "ic0.stable_read() loop/1M/8KiB",
            render(LOOP_1M, "stable_read", Params3(0, 0, 8192), NoResults()),
            8_225_000_007, // was: 8_205_000_007,
        ),
        (
            "ic0.stable_write() loop/1M/1B",
            render(LOOP_1M, "stable_write", Params3(0, 0, 1), NoResults()),
            34_000_007, // was: 14_000_007,
        ),
        (
            "ic0.stable_write() loop/1M/8KiB",
            render(LOOP_1M, "stable_write", Params3(0, 0, 8192), NoResults()),
            8_225_000_007, // was: 8_205_000_007,
        ),
        (
            "ic0.stable64_size() loop/1M",
            render(LOOP_1M, "stable64_size", NoParams(), Result1()),
            11_000_007,
        ),
        (
            "ic0.stable64_grow() loop/1M",
            render(LOOP_1M, "stable64_grow", Param1(1), Result1()),
            12_000_007,
        ),
        (
            "ic0.stable64_read() loop/1M/1B",
            render(LOOP_1M, "stable64_read", Params3(0, 0, 1), NoResults()),
            34_000_007, // was: 14_000_007,
        ),
        (
            "ic0.stable64_read() loop/1M/8KiB",
            render(LOOP_1M, "stable64_read", Params3(0, 0, 8192), NoResults()),
            8_225_000_007, // was: 8_205_000_007,
        ),
        (
            "ic0.stable64_write() loop/1M/1B",
            render(LOOP_1M, "stable64_write", Params3(0, 0, 1), NoResults()),
            34_000_007, // was: 14_000_007,
        ),
        (
            "ic0.stable64_write() loop/1M/8KiB",
            render(LOOP_1M, "stable64_write", Params3(0, 0, 8192), NoResults()),
            8_225_000_007, // was: 8_205_000_007,
        ),
        (
            "ic0.time() loop/1M",
            render(LOOP_1M, "time/i64", NoParams(), Result1()),
            11_000_004,
        ),
        (
            "ic0.canister_cycle_balance() loop/1M",
            render(LOOP_1M, "canister_cycle_balance/i64", NoParams(), Result1()),
            11_000_004,
        ),
        (
            "ic0.canister_cycles_balance128() loop/1M",
            render(
                LOOP_1M,
                "canister_cycles_balance128",
               Param1(0),
               NoResults(),
            ),
            11_000_004,
        ),
        (
            "ic0.msg_cycles_available() loop/1M",
            render(LOOP_1M, "msg_cycles_available/i64", NoParams(), Result1()),
            11_000_004,
        ),
        (
            "ic0.msg_cycles_available128() loop/1M",
            render(LOOP_1M, "msg_cycles_available128", Param1(0), NoResults()),
            11_000_004,
        ),
        (
            "ic0.msg_cycles_accept() loop/1M",
            render(LOOP_1M, "msg_cycles_accept/i64", Param1(1), Result1()),
            12_000_004,
        ),
        (
            "ic0.data_certificate_present() loop/1M",
            render(LOOP_1M, "data_certificate_present", NoParams(), Result1()),
            11_000_004,
        ),
        (
            "ic0.certified_data_set() loop/1M/1B",
            render(LOOP_1M, "certified_data_set", Params2(0, 1), NoResults()),
            12_000_004,
        ),
        (
            "ic0.certified_data_set() loop/1M/32B",
            render(LOOP_1M, "certified_data_set", Params2(0, 32), NoResults()), // 32B max
            12_000_004,
        ),
        (
            "ic0.canister_status() loop/1M",
            render(LOOP_1M, "canister_status", NoParams(), Result1()),
            11_000_004,
        ),
    ];
}
