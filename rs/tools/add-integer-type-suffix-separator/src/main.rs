use lazy_static::lazy_static;
use regex::Regex;
use std::{fs, ops::Range, path::Path, process::ExitCode};
use syn::{LitInt, visit::Visit as SynVisit};
use walkdir::WalkDir;

fn list_integer_literals(rust_code: &str) -> syn::Result<Vec<(Range<usize>, &str)>> {
    #[derive(Default)]
    struct IntegerLiterals {
        locations: Vec<Range<usize>>,
    }

    impl<'ast> SynVisit<'ast> for IntegerLiterals {
        fn visit_lit_int(&mut self, i: &'ast LitInt) {
            self.locations.push(i.span().byte_range());
        }
    }

    let file = syn::parse_file(rust_code)?;

    let mut integer_literals = IntegerLiterals::default();
    integer_literals.visit_file(&file);

    // Recover code snippets from locations.
    let result = integer_literals
        .locations
        .into_iter()
        .map(|location| {
            let snippet = &rust_code[location.clone()];
            (location, snippet)
        })
        .collect();

    Ok(result)
}

fn list_corrections(integer_literals: Vec<(Range<usize>, &str)>) -> Vec<(Range<usize>, String)> {
    let mut result: Vec<(Range<usize>, String)> = vec![];

    for (location, original_code) in integer_literals {
        lazy_static! {
            static ref SUFFIX_RE: Regex = Regex::new(concat!(
                r"^",                             // start
                r"(.+?)",                         // prefix
                r"([iu](?:8|16|32|64|128|size))", // type suffix
                r"$",                             // end
            )).unwrap();
        }
        let Some(chunks) = SUFFIX_RE.captures(original_code) else {
            // No suffix -> no defect.
            continue;
        };

        let prefix = &chunks[1];
        let suffix = &chunks[2];

        if prefix.ends_with('_') {
            // Suffix is separated. Good job!
            continue;
        }

        // Found broken code (e.g. 42u64).
        // Fix it by adding an underscore separator (e.g. 42_u64).
        result.push((location.clone(), format!("{}_{}", prefix, suffix)));
    }

    result
}

/// It is assumed that corrections are listed from beginning to end (and do not overlap).
fn apply_corrections(rust_code: &str, corrections: Vec<(Range<usize>, String)>) -> String {
    let mut result = rust_code.to_owned();

    // So that locations remain valid, we iterate over corrections in reverse order.
    for (location, new_code) in corrections.into_iter().rev() {
        result.replace_range(location, &new_code);
    }

    result
}

fn fix_file(path: &Path) -> anyhow::Result<usize> {
    let original_rust_code = fs::read_to_string(path)?;
    let integer_literals = list_integer_literals(&original_rust_code)?;
    let corrections = list_corrections(integer_literals);

    let correction_count = corrections.len();
    if correction_count > 0 {
        let new_rust_code = apply_corrections(&original_rust_code, corrections);
        // Overwrite the original file with the new code.
        fs::write(path, new_rust_code)?;
    }

    Ok(correction_count)
}

#[derive(Default)]
struct Report {
    broken_literal_count: usize,
    modified_file_count: usize,
    failure_count: usize,
}

impl Report {
    fn handle_fix_file_result(&mut self, path: &str, fix_file_result: anyhow::Result<usize>) {
        let fix_count = match fix_file_result {
            Ok(ok) => ok,
            Err(err) => {
                eprintln!("Error processing {path}: {err}");
                self.failure_count += 1;
                return;
            }
        };

        self.broken_literal_count += fix_count;
        if fix_count > 0 {
            eprintln!("Fixed {fix_count} literals in {path}");
            self.modified_file_count += 1;
        }
    }

    fn handle_iterating_over_files_error(&mut self, error: walkdir::Error) {
        eprintln!("Error while scanning files: {error}");
        self.failure_count += 1;
    }

    fn eprint(&self) -> ExitCode {
        eprintln!();
        eprintln!("Processing complete");
        eprintln!("  Files modified: {}", self.modified_file_count);
        eprintln!("  Literals fixed: {}", self.broken_literal_count);

        if self.failure_count == 0 {
            eprintln!("🎉 Success!");
            ExitCode::SUCCESS
        } else {
            eprintln!(
                "💥 Ran into {} problems while scanning Rust files for broken integer literals!",
                self.failure_count,
            );
            ExitCode::from(1)
        }
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();

    let search_root = match args.len() {
        1 => ".",
        2 => &args[1],
        _ => {
            eprintln!("Usage: add-integer-type-suffix-separator [target_directory]");
            return ExitCode::from(1);
        }
    };

    let search_root = Path::new(search_root);
    if !search_root.exists() {
        eprintln!("Error: directory not found: {}", search_root.display());
        return ExitCode::from(1);
    }

    let mut report = Report::default();

    for file in WalkDir::new(search_root).into_iter() {
        let file = match file {
            Ok(ok) => ok,
            Err(err) => {
                report.handle_iterating_over_files_error(err);
                continue;
            }
        };

        // Skip non-Rust files.
        let path = file.path();
        if path.extension().unwrap_or_default() != "rs" {
            continue;
        }

        report.handle_fix_file_result(&path.display().to_string(), fix_file(path));
    }

    report.eprint()
}
