use crate::data::{Change, Entry};
use std::io::{self, Write};

pub(crate) fn filter_entries(data: &[Entry], noise_threshold: f64) -> Vec<Entry> {
    let mut filtered: Vec<Entry> = data
        .iter()
        .filter_map(|entry| {
            let metrics = [
                &entry.instructions,
                &entry.heap_increase,
                &entry.stable_memory_increase,
            ];

            let is_significant = metrics.iter().any(|v| {
                matches!(
                    v.status(noise_threshold),
                    Change::New | Change::Improved | Change::Regressed
                )
            });

            if !is_significant {
                return None;
            }

            let mut status = String::new();
            if entry.status.is_empty() {
                if metrics
                    .iter()
                    .any(|v| v.status(noise_threshold) == Change::Regressed)
                {
                    status.push('+');
                }
                if metrics
                    .iter()
                    .any(|v| v.status(noise_threshold) == Change::Improved)
                {
                    if !status.is_empty() {
                        status.push('/');
                    }
                    status.push('-');
                }
            } else {
                status = entry.status.clone();
            }

            let mut updated = entry.clone();
            updated.status = status;
            Some(updated)
        })
        .collect();

    // Sort by name, ascending.
    filtered.sort_by(|a, b| a.benchmark.full_name().cmp(&b.benchmark.full_name()));
    // Sort by status.
    filtered.sort_by(|a, b| a.status.cmp(&b.status));
    // Sort by instructions percent diff, descending.
    const EMPTY: f64 = f64::MIN;
    filtered.sort_by(|a, b| {
        a.instructions
            .percent_diff()
            .unwrap_or(EMPTY)
            .partial_cmp(&b.instructions.percent_diff().unwrap_or(EMPTY))
            .unwrap_or(std::cmp::Ordering::Equal)
            .reverse()
    });

    filtered
}

pub(crate) fn print_table<W: Write>(
    writer: &mut W,
    data: &[Entry],
    max_displayed_rows: usize,
) -> io::Result<()> {
    let columns = [
        "status", "name", "calls", "ins", "ins Δ%", "HI", "HI Δ%", "SMI", "SMI Δ%",
    ];
    let mut rows: Vec<_> = data
        .iter()
        .map(|entry| {
            let scope_calls = if entry.has_scope() {
                entry.calls.fmt_human_current()
            } else {
                "".to_string()
            };
            vec![
                entry.status.clone(),
                entry.benchmark.full_name(),
                scope_calls,
                entry.instructions.fmt_human_current(),
                entry.instructions.fmt_human_percent(),
                entry.heap_increase.fmt_human_current(),
                entry.heap_increase.fmt_human_percent(),
                entry.stable_memory_increase.fmt_human_current(),
                entry.stable_memory_increase.fmt_human_percent(),
            ]
        })
        .collect();

    let total_rows = rows.len();

    if total_rows > max_displayed_rows {
        let omitted_count = total_rows - max_displayed_rows;
        let head_rows = max_displayed_rows / 2;
        let tail_rows = max_displayed_rows - head_rows;

        let mut limited_rows = Vec::new();
        if head_rows > 0 {
            limited_rows.extend_from_slice(&rows[..head_rows]);
        }

        let mut omitted_row = vec!["".to_string(); columns.len()];
        omitted_row[0] = "...".to_string();
        omitted_row[1] = format!(
            "... {} row{} omitted ...",
            omitted_count,
            if omitted_count == 1 { "" } else { "s" }
        );
        limited_rows.push(omitted_row);

        if tail_rows > 0 {
            limited_rows.extend_from_slice(&rows[total_rows - tail_rows..]);
        }

        rows = limited_rows;
    }

    let mut col_widths: Vec<_> = columns.iter().map(|h| h.len()).collect();
    for row in &rows {
        for (i, cell) in row.iter().enumerate() {
            col_widths[i] = col_widths[i].max(cell.len());
        }
    }

    let print_row = |writer: &mut W, row: &[String]| -> io::Result<()> {
        write!(writer, "|")?;
        for (i, cell) in row.iter().enumerate() {
            let width = col_widths[i];
            match i {
                0 => write!(writer, " {:^width$} |", cell, width = width)?,
                1 => write!(writer, " {:<width$} |", cell, width = width)?,
                _ => write!(writer, " {:>width$} |", cell, width = width)?,
            }
        }
        writeln!(writer)
    };

    print_row(
        writer,
        &columns.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
    )?;
    write!(writer, "|")?;
    for width in &col_widths {
        write!(writer, "{}|", "-".repeat(width + 2))?;
    }
    writeln!(writer)?;

    for row in &rows {
        print_row(writer, row)?;
    }

    writeln!(writer)?;
    writeln!(
        writer,
        "ins = instructions, HI = heap_increase, SMI = stable_memory_increase, Δ% = percent change"
    )?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data::{Benchmark, Values};

    fn create_entry(name: &str, scope: Option<&str>) -> Entry {
        Entry {
            status: "".to_string(),
            benchmark: Benchmark::new(name, scope),
            calls: Values::new(Some(10), None),
            instructions: Values::new(Some(9_000_000), Some(10_000_000)),
            heap_increase: Values::new(Some(0), None),
            stable_memory_increase: Values::new(Some(0), None),
        }
    }

    fn run_table_test_case(max_displayed_rows: usize, expected_output: &str) {
        let entries: Vec<Entry> = (1..=5)
            .flat_map(|i| {
                let bench = format!("bench_{}", i);
                let mut v = vec![create_entry(&bench, None)];
                if i >= 5 {
                    v.push(create_entry(&bench, Some("scope_0")));
                }
                v
            })
            .collect();

        let mut output = Vec::new();
        print_table(&mut output, &entries, max_displayed_rows).unwrap();

        let output_str = String::from_utf8_lossy(&output);
        assert_eq!(
            output_str, expected_output,
            "Unexpected output with max_displayed_rows = {}:\n{}",
            max_displayed_rows, output_str
        );
    }

    #[test]
    fn test_print_table_variants_0() {
        run_table_test_case(
            0,
            "\
| status | name                   | calls | ins |  ins Δ% | HI |  HI Δ% | SMI |  SMI Δ% |
|--------|------------------------|-------|-----|---------|----|--------|-----|---------|
|  ...   | ... 6 rows omitted ... |       |     |         |    |        |     |         |

ins = instructions, HI = heap_increase, SMI = stable_memory_increase, Δ% = percent change
",
        );
    }

    #[test]
    fn test_print_table_variants_1() {
        run_table_test_case(
            1,
            "\
| status | name                   | calls |   ins |  ins Δ% | HI |  HI Δ% | SMI |  SMI Δ% |
|--------|------------------------|-------|-------|---------|----|--------|-----|---------|
|  ...   | ... 5 rows omitted ... |       |       |         |    |        |     |         |
|        | bench_5::scope_0       |    10 | 9.00M | -10.00% |  0 |        |   0 |         |

ins = instructions, HI = heap_increase, SMI = stable_memory_increase, Δ% = percent change
",
        );
    }

    #[test]
    fn test_print_table_variants_2() {
        run_table_test_case(
            2,
            "\
| status | name                   | calls |   ins |  ins Δ% | HI |  HI Δ% | SMI |  SMI Δ% |
|--------|------------------------|-------|-------|---------|----|--------|-----|---------|
|        | bench_1                |       | 9.00M | -10.00% |  0 |        |   0 |         |
|  ...   | ... 4 rows omitted ... |       |       |         |    |        |     |         |
|        | bench_5::scope_0       |    10 | 9.00M | -10.00% |  0 |        |   0 |         |

ins = instructions, HI = heap_increase, SMI = stable_memory_increase, Δ% = percent change
",
        );
    }

    #[test]
    fn test_print_table_variants_3() {
        run_table_test_case(
            3,
            "\
| status | name                   | calls |   ins |  ins Δ% | HI |  HI Δ% | SMI |  SMI Δ% |
|--------|------------------------|-------|-------|---------|----|--------|-----|---------|
|        | bench_1                |       | 9.00M | -10.00% |  0 |        |   0 |         |
|  ...   | ... 3 rows omitted ... |       |       |         |    |        |     |         |
|        | bench_5                |       | 9.00M | -10.00% |  0 |        |   0 |         |
|        | bench_5::scope_0       |    10 | 9.00M | -10.00% |  0 |        |   0 |         |

ins = instructions, HI = heap_increase, SMI = stable_memory_increase, Δ% = percent change
",
        );
    }

    #[test]
    fn test_print_table_variants_4() {
        run_table_test_case(
            4,
            "\
| status | name                   | calls |   ins |  ins Δ% | HI |  HI Δ% | SMI |  SMI Δ% |
|--------|------------------------|-------|-------|---------|----|--------|-----|---------|
|        | bench_1                |       | 9.00M | -10.00% |  0 |        |   0 |         |
|        | bench_2                |       | 9.00M | -10.00% |  0 |        |   0 |         |
|  ...   | ... 2 rows omitted ... |       |       |         |    |        |     |         |
|        | bench_5                |       | 9.00M | -10.00% |  0 |        |   0 |         |
|        | bench_5::scope_0       |    10 | 9.00M | -10.00% |  0 |        |   0 |         |

ins = instructions, HI = heap_increase, SMI = stable_memory_increase, Δ% = percent change
",
        );
    }

    #[test]
    fn test_print_table_variants_5() {
        run_table_test_case(
            5,
            "\
| status | name                  | calls |   ins |  ins Δ% | HI |  HI Δ% | SMI |  SMI Δ% |
|--------|-----------------------|-------|-------|---------|----|--------|-----|---------|
|        | bench_1               |       | 9.00M | -10.00% |  0 |        |   0 |         |
|        | bench_2               |       | 9.00M | -10.00% |  0 |        |   0 |         |
|  ...   | ... 1 row omitted ... |       |       |         |    |        |     |         |
|        | bench_4               |       | 9.00M | -10.00% |  0 |        |   0 |         |
|        | bench_5               |       | 9.00M | -10.00% |  0 |        |   0 |         |
|        | bench_5::scope_0      |    10 | 9.00M | -10.00% |  0 |        |   0 |         |

ins = instructions, HI = heap_increase, SMI = stable_memory_increase, Δ% = percent change
",
        );
    }

    #[test]
    fn test_print_table_variants_6() {
        run_table_test_case(
            6,
            "\
| status | name             | calls |   ins |  ins Δ% | HI |  HI Δ% | SMI |  SMI Δ% |
|--------|------------------|-------|-------|---------|----|--------|-----|---------|
|        | bench_1          |       | 9.00M | -10.00% |  0 |        |   0 |         |
|        | bench_2          |       | 9.00M | -10.00% |  0 |        |   0 |         |
|        | bench_3          |       | 9.00M | -10.00% |  0 |        |   0 |         |
|        | bench_4          |       | 9.00M | -10.00% |  0 |        |   0 |         |
|        | bench_5          |       | 9.00M | -10.00% |  0 |        |   0 |         |
|        | bench_5::scope_0 |    10 | 9.00M | -10.00% |  0 |        |   0 |         |

ins = instructions, HI = heap_increase, SMI = stable_memory_increase, Δ% = percent change
",
        );
    }
}
