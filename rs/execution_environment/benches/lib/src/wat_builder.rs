///
/// The new WAT builder.
//

/// Default number of loop iterations.
const DEFAULT_LOOP_ITERATIONS: usize = 1_000_000;
/// Default number of repeat times.
const DEFAULT_REPEAT_TIMES: usize = 1_000;

////////////////////////////////////////////////////////////////////////
/// WAT Block Builder

/// Represents a block of WAT code with corresponding imports and local variables.
#[derive(Default)]
pub struct Block {
    imports: Vec<String>,
    locals: Vec<String>,
    lines: Vec<String>,
}

impl Block {
    /// Appends a line of code to the back of the block.
    pub fn line<S: Into<String>>(mut self, code: S) -> Self {
        self.lines.push(code.into());
        self
    }

    /// Loops the block code.
    pub fn loop_(mut self) -> Self {
        self.locals.push("(local $i i32)".into());

        self.lines = wrap_lines(
            "(loop $loop",
            wrap_lines(
                format!(
                    "(if (i32.lt_s (get_local $i) (i32.const {DEFAULT_LOOP_ITERATIONS})) (then"
                ),
                wrap_lines(
                    "(set_local $i (i32.add (get_local $i) (i32.const 1)))",
                    self.lines,
                    "(br $loop)",
                ),
                ")",
            ),
            "))",
        );

        self
    }

    /// Repeats the line of code.
    pub fn repeat<B, R, E>(mut self, begin: B, repeat: R, end: E) -> Self
    where
        B: Into<String>,
        R: Into<String>,
        E: Into<String>,
    {
        self.lines.extend(vec![
            begin.into(),
            repeat.into().repeat(DEFAULT_REPEAT_TIMES),
            end.into(),
        ]);
        self
    }

    /// Disables compiler optimizations for the value on stack by adding it
    /// to the local `black_box` variable.
    pub fn black_box_result(mut self) -> Self {
        self.lines
            .push("(set_local $black_box (i32.add (get_local $black_box)))".into());
        self
    }

    /// Disable compiler optimizations for the local `black_box` variable.
    pub fn global_black_box(mut self) -> Self {
        self.imports
            .push("(global $black_box (mut i32) (i32.const 0))".into());
        self.locals.push("(local $black_box i32)".into());
        self.lines
            .push("(set_global $black_box (get_local $black_box))".into());
        self
    }

    /// Transforms the block into an update function.
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

/// Represents a WAT function with corresponding imports.
#[derive(Default)]
pub struct Func {
    imports: Vec<String>,
    lines: Vec<String>,
}

impl Func {
    /// Transforms the function into a test module WAT representation.
    pub fn into_test_module_wat(self) -> String {
        wrap_lines(
            "(module",
            [self.imports, vec!["(memory $mem 1)".into()], self.lines].concat(),
            ")",
        )
        .join("\n")
    }
}

////////////////////////////////////////////////////////////////////////
/// Helper functions

/// Returns a new block prepended and appended with the specified lines.
fn wrap_lines<P, S>(prefix: P, lines: Vec<String>, suffix: S) -> Vec<String>
where
    P: Into<String>,
    S: Into<String>,
{
    vec![prefix.into()]
        .into_iter()
        .chain(lines.into_iter().map(|l| format!("    {l}")))
        .chain(vec![suffix.into()].into_iter())
        .collect()
}
