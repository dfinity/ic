use crate::{BenchResult, Measurement};
use colored::Colorize;

/// Prints a benchmark to stdout, comparing it to the previous result if available.
pub(crate) fn print_benchmark(
    name: &str,
    new: &BenchResult,
    old: Option<&BenchResult>,
    noise_threshold: f64,
) {
    // Print benchmark name.
    if old.is_some() {
        println!("Benchmark: {}", name.bold());
    } else {
        println!("Benchmark: {} {}", name.bold(), "(new)".blue().bold());
    }

    // Print totals, skip calls number, since it's always should be 1.
    println!("  total:");
    print_measurement(&new.total, old.map(|m| &m.total), noise_threshold, false);

    // Print scopes
    for (scope, measurement) in &new.scopes {
        println!();
        println!("  {} (scope):", scope);
        print_measurement(
            measurement,
            old.map(|m| &m.scopes).and_then(|m| m.get(scope)),
            noise_threshold,
            true,
        );
    }
}

// Prints a measurement along with a comparison with the old value if available.
fn print_measurement(
    new: &Measurement,
    old: Option<&Measurement>,
    noise_threshold: f64,
    print_calls: bool,
) {
    if print_calls {
        print_metric("calls", new.calls, old.map(|m| m.calls), noise_threshold);
    }
    print_metric(
        "instructions",
        new.instructions,
        old.map(|m| m.instructions),
        noise_threshold,
    );
    print_metric(
        "heap_increase",
        new.heap_increase,
        old.map(|m| m.heap_increase),
        noise_threshold,
    );
    print_metric(
        "stable_memory_increase",
        new.stable_memory_increase,
        old.map(|m| m.stable_memory_increase),
        noise_threshold,
    );
}

// Prints a metric along with its percentage change relative to the old value.
fn print_metric(metric: &str, value: u64, old_value: Option<u64>, noise_threshold: f64) {
    // Convert value to a more readable representation.
    let value_str = if value < 10_000 {
        format!("{}", value)
    } else if value < 1_000_000 {
        format!("{:.2} K", value as f64 / 1_000.0)
    } else if value < 1_000_000_000 {
        format!("{:.2} M", value as f64 / 1_000_000.0)
    } else if value < 1_000_000_000_000 {
        format!("{:.2} B", value as f64 / 1_000_000_000.0)
    } else {
        format!("{:.2} T", value as f64 / 1_000_000_000_000.0)
    };

    // Add unit to value depending on the metric.
    let value_str = match metric {
        "calls" => value_str,        // Units are clear from the metric name.
        "instructions" => value_str, // Units are clear from the metric name.
        "heap_increase" => format!("{value_str} pages"),
        "stable_memory_increase" => format!("{value_str} pages"),
        other => panic!("unknown metric {}", other),
    };

    let old_value = match old_value {
        Some(old_value) => old_value,
        None => {
            // No old value exists. This is a new metric.
            println!("    {metric}: {value_str} (new)");
            return;
        }
    };

    match old_value {
        0 => {
            // The old value is zero, so changes cannot be reported as a percentage.
            if value == 0 {
                println!("    {metric}: {value_str} (no change)",);
            } else {
                println!(
                    "    {}",
                    format!("{metric}: {value_str} (regressed from 0)")
                        .red()
                        .bold()
                );
            }
        }
        _ => {
            // The old value is > 0. Report changes as percentages.
            let diff = ((value as f64 - old_value as f64) / old_value as f64) * 100.0;
            if diff == 0.0 {
                println!("    {metric}: {value_str} (no change)");
            } else if diff.abs() < noise_threshold {
                println!(
                    "    {metric}: {value_str} ({:.2}%) (change within noise threshold)",
                    diff
                );
            } else if diff > 0.0 {
                println!(
                    "    {}",
                    format!("{}: {value_str} (regressed by {:.2}%)", metric, diff,)
                        .red()
                        .bold()
                );
            } else {
                println!(
                    "    {}",
                    format!("{}: {value_str} (improved by {:.2}%)", metric, diff.abs(),)
                        .green()
                        .bold()
                );
            }
        }
    }
}
