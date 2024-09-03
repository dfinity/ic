///
/// The new WAT builder.
//

/// Default number of loop iterations.
pub const DEFAULT_LOOP_ITERATIONS: usize = 1_000;
/// Default number of repeat times.
pub const DEFAULT_REPEAT_TIMES: usize = 7_000;
/// Number of loop iterations to confirm the result.
///
/// The main overhead comes from the call itself, so 1000 times more loop iterations
/// take just 4 time more in the wall time.
pub const CONFIRMATION_LOOP_ITERATIONS: usize = 1_000_000;
/// Number of repeat times to confirm the result.
///
/// The idea behind the confirmation is that the same operation but repeated twice
/// should take roughly two times more time to execute, i.e. there are no optimizations.
///
/// Note, the maximum compilation complexity is 15K.
pub const CONFIRMATION_REPEAT_TIMES: usize = 14_000;

use crate::common::Wasm64;

////////////////////////////////////////////////////////////////////////
/// WAT Block Builder

/// Represent a block of WAT code with corresponding imports and local variables.
#[derive(Default)]
pub struct Block {
    imports: Vec<String>,
    locals: Vec<String>,
    lines: Vec<String>,
}

impl Block {
    /// Add a new `line` of code.
    pub fn line(&mut self, code: &str) -> &mut Self {
        self.lines.push(code.into());
        self
    }

    /// Add a new `import`.
    pub fn import(&mut self, code: &str) -> &mut Self {
        self.imports.push(code.into());
        self
    }

    /// Add a new `local`.
    pub fn local(&mut self, code: &str) -> &mut Self {
        self.locals.push(code.into());
        self
    }

    /// Loop the current block of code for `n` iterations.
    pub fn loop_n(mut self, n: usize) -> Self {
        self.local("(local $i i32)");

        self.lines = wrap_lines(
            &format!("(local.set $i (i32.const {n})) (loop $loop"),
            self.lines,
            "(br_if $loop (local.tee $i (i32.sub (local.get $i) (i32.const 1)))))",
        );

        self
    }

    /// Repeat the line of code `n` times.
    pub fn repeat_n(mut self, n: usize, code: &str) -> Self {
        for _ in 0..n {
            self.line(code);
        }
        self
    }

    /// Define variables and functions used in the `code` snippet.
    pub fn define_variables_and_functions(mut self, code: &str, wasm64_enabled: Wasm64) -> Self {
        for name in ["x", "y", "z", "zero", "address", "one"] {
            for ty in ["i32", "i64", "f32", "f64", "v128"] {
                if code.contains(&format!("${name}_{ty}")) {
                    self.declare_variable(name, ty, wasm64_enabled);
                }
            }
        }
        if code.contains("$empty") {
            self.import("(func $empty (result i32) (i32.const 0))");
        }
        if code.contains("$empty_return_call") {
            self.import("(func $empty_return_call (result i32) return_call $empty)");
        }
        if code.contains("$result_i32") || code.contains("table.get") || code.contains("table.size")
        {
            self.import("(type $result_i32 (func (result i32)))")
                .import("(func $empty_indirect (type $result_i32) (i32.const 0))")
                .import("(table $table 10 funcref)")
                .import("(elem (i32.const 7) $empty_indirect)")
                .import("(elem func 0)");
        }
        self
    }

    /// Declare a `black_box` variable with specified `name` and `type`.
    pub fn declare_variable(&mut self, name: &str, ty: &str, wasm64_enabled: Wasm64) -> &mut Self {
        let memory_var_address = if wasm64_enabled == Wasm64::Enabled {
            // The address should be somewhere beyond 4 GiB.
            // This is 5 GB.
            "5368709120"
        } else {
            "16"
        };
        let init_val = match name {
            "x" => "1000000007",
            "y" => "1337",
            "z" => "2147483647",
            "zero" => "0",
            "address" => memory_var_address,
            "one" => "1",
            _ => panic!("Error getting initial value for variable {name}"),
        };
        let var = format!("${name}_{ty}");
        let init_val = if ty != "v128" {
            init_val.into()
        } else {
            format!("i64x2 {init_val} {init_val}")
        };
        self.import(&format!(
            "(global {var} (mut {ty}) ({ty}.const {init_val}))"
        ))
        .local(&format!("(local {var} {ty})"));
        self.lines
            .insert(0, format!("(local.set {var} (global.get {var}))"));
        self.line(&format!("(global.set {var} (local.get {var}))"));
        self
    }

    /// Transform the block into an update function.
    pub fn into_update_func(self) -> Func {
        Func {
            imports: self.imports,
            lines: wrap_lines(
                r#"(func $test (export "canister_update test")"#,
                [self.locals, self.lines].concat(),
                ")",
            ),
        }
    }
}

////////////////////////////////////////////////////////////////////////
/// WAT Function Builder

/// Represent a WAT function with corresponding imports.
#[derive(Default)]
pub struct Func {
    imports: Vec<String>,
    lines: Vec<String>,
}

impl Func {
    /// Transform the function into a test module WAT representation.
    pub fn into_test_module_wat(self, wasm64_enabled: Wasm64) -> String {
        let memory = if wasm64_enabled == Wasm64::Enabled {
            "(memory $mem i64 131072)"
        } else {
            "(memory $mem 1)"
        };
        wrap_lines(
            "(module",
            [self.imports, vec![memory.into()], self.lines].concat(),
            ")",
        )
        .join("\n")
    }
}

////////////////////////////////////////////////////////////////////////
/// Helper functions

/// Return a new block prepended and appended with the specified lines.
fn wrap_lines(prefix: &str, lines: Vec<String>, suffix: &str) -> Vec<String> {
    vec![prefix.into()]
        .into_iter()
        .chain(lines.into_iter().map(|l| format!("    {l}")))
        .chain(vec![suffix.into()])
        .collect()
}

/// Return the destination type for the given operation, i.e. for `i32.wrap_i64` returns `i32`
pub fn dst_type(op: &str) -> &'static str {
    if op.starts_with("i64") {
        return "i64";
    } else if op.starts_with("f32") {
        return "f32";
    } else if op.starts_with("f64") {
        return "f64";
    } else if op.starts_with("v128") {
        return "v128";
    }
    // Fallback to i32 type.
    "i32"
}

/// Return the source type for the given operation, i.e. for `i32.wrap_i64` returns `i64`
pub fn src_type(op: &str) -> &'static str {
    if op.contains("_i32") {
        return "i32";
    } else if op.contains("_i64") {
        return "i64";
    } else if op.contains("_f32") {
        return "f32";
    } else if op.contains("_f64") {
        return "f64";
    }
    // Fallback to the destination type, i.e. for `i64.eqz` returns `i64`.
    dst_type(op)
}
