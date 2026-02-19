use crate::data::Entry;
use std::io::Write;

/// Delimiter used in the CSV file.
/// Use `,` for GitHub/VSCode preview.
/// Use `\t` for better compatibility with Google Sheets.
const DELIMITER: char = ',';

/// Write benchmark results to a CSV file.
pub(crate) fn write<W: Write>(writer: &mut W, data: &[Entry]) -> std::io::Result<()> {
    const HEADERS: &[&str] = &[
        "status",
        "name",
        "scope_calls",
        "scope_calls Δ",
        "scope_calls Δ%",
        "instructions",
        "instructions Δ",
        "instructions Δ%",
        "heap_increase",
        "heap_increase Δ",
        "heap_increase Δ%",
        "stable_memory_increase",
        "stable_memory_increase Δ",
        "stable_memory_increase Δ%",
    ];

    writeln!(writer, "{}", HEADERS.join(&DELIMITER.to_string()))?;

    for entry in data {
        let name = entry.benchmark.full_name();
        let scope_calls = if entry.has_scope() {
            let c = &entry.calls;
            (c.fmt_current(), c.fmt_abs_delta(), c.fmt_percent())
        } else {
            ("".to_string(), "".to_string(), "".to_string())
        };
        let row = [
            entry.status.clone(),
            name.clone(),
            // CSV report uses full numbers
            scope_calls.0,
            scope_calls.1,
            scope_calls.2,
            entry.instructions.fmt_current(),
            entry.instructions.fmt_abs_delta(),
            entry.instructions.fmt_percent(),
            entry.heap_increase.fmt_current(),
            entry.heap_increase.fmt_abs_delta(),
            entry.heap_increase.fmt_percent(),
            entry.stable_memory_increase.fmt_current(),
            entry.stable_memory_increase.fmt_abs_delta(),
            entry.stable_memory_increase.fmt_percent(),
        ];

        writeln!(writer, "{}", row.join(&DELIMITER.to_string()))?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data::{Benchmark, Values};

    fn run_write_csv_case(entries: &[Entry], expected_output: &str) {
        let mut output = Vec::new();
        let _ = write(&mut output, entries);

        let output_str = String::from_utf8_lossy(&output);
        assert_eq!(
            output_str, expected_output,
            "Unexpected output:\n{}",
            output_str
        );
    }

    #[test]
    fn test_write_csv() {
        run_write_csv_case(
            &[
                Entry {
                    status: "".to_string(),
                    benchmark: Benchmark::new("bench_regression", None),
                    instructions: Values::new(Some(11_000_000), Some(10_000_000)),
                    heap_increase: Values::new(Some(0), None),
                    stable_memory_increase: Values::new(Some(0), None),
                    calls: Values::new(None, None),
                },
                Entry {
                    status: "".to_string(),
                    benchmark: Benchmark::new("bench_no_change", None),
                    instructions: Values::new(Some(10_000_000), Some(10_000_000)),
                    heap_increase: Values::new(Some(0), None),
                    stable_memory_increase: Values::new(Some(0), None),
                    calls: Values::new(None, None),
                },
                Entry {
                    status: "".to_string(),
                    benchmark: Benchmark::new("bench_improvement", None),
                    instructions: Values::new(Some(9_000_000), Some(10_000_000)),
                    heap_increase: Values::new(Some(0), None),
                    stable_memory_increase: Values::new(Some(0), None),
                    calls: Values::new(None, None),
                },
                Entry {
                    status: "".to_string(),
                    benchmark: Benchmark::new("bench_positive_inf", None),
                    instructions: Values::new(Some(10_000_000), Some(0)),
                    heap_increase: Values::new(Some(0), None),
                    stable_memory_increase: Values::new(Some(0), None),
                    calls: Values::new(None, None),
                },
                Entry {
                    status: "".to_string(),
                    benchmark: Benchmark::new("bench_from_10M_to_0", None),
                    instructions: Values::new(Some(0), Some(10_000_000)),
                    heap_increase: Values::new(Some(0), None),
                    stable_memory_increase: Values::new(Some(0), None),
                    calls: Values::new(None, None),
                },
                Entry {
                    status: "".to_string(),
                    benchmark: Benchmark::new("bench_with_scope", Some("my_scope")),
                    instructions: Values::new(Some(10_000_000), Some(9_000_000)),
                    heap_increase: Values::new(Some(0), None),
                    stable_memory_increase: Values::new(Some(0), None),
                    calls: Values::new(Some(100), Some(50)),
                },
            ],
            "\
status,name,scope_calls,scope_calls Δ,scope_calls Δ%,instructions,instructions Δ,instructions Δ%,heap_increase,heap_increase Δ,heap_increase Δ%,stable_memory_increase,stable_memory_increase Δ,stable_memory_increase Δ%
,bench_regression,,,,11000000,1000000,10.00%,0,,,0,,
,bench_no_change,,,,10000000,0,0.00%,0,,,0,,
,bench_improvement,,,,9000000,-1000000,-10.00%,0,,,0,,
,bench_positive_inf,,,,10000000,10000000,1.0E99,0,,,0,,
,bench_from_10M_to_0,,,,0,-10000000,-100.00%,0,,,0,,
,bench_with_scope::my_scope,100,50,100.00%,10000000,1000000,11.11%,0,,,0,,
",
        );
    }
}
