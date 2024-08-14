use anyhow::{format_err, Context, Result};
use ic_sys::fs::write_string_using_tmp_file;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::time::Duration;

pub use metrics::FsTrimMetrics;

mod metrics;
#[cfg(test)]
mod tests;

fn run_command(command: &str, target: &str) -> Result<()> {
    let maybe_target_directory = Path::new(target);
    if !maybe_target_directory.is_dir() {
        Err(format_err!("Target {} is not a directory", target))?
    };
    match std::process::Command::new(command).arg(target).status() {
        Ok(status) => {
            if status.success() {
                Ok(())
            } else {
                Err(format_err!(
                    "Failed to run command '{}' on {}, return value: {}",
                    command,
                    target,
                    status
                ))
            }
        }
        Err(err) => Err(format_err!(
            "Failed to run command '{}' on {}, error {}",
            command,
            target,
            err
        )),
    }
}

fn parse_existing_metrics_from_file(metrics_filename: &str) -> Result<Option<FsTrimMetrics>> {
    let path = Path::new(metrics_filename);
    let file = match File::open(path) {
        Ok(file) => file,
        Err(e) => {
            return if e.kind() == std::io::ErrorKind::NotFound {
                Ok(None)
            } else {
                Err(format_err!("failed to open {}: {}", metrics_filename, e))
            }
        }
    };
    let reader = BufReader::new(file);
    let lines = reader.lines();
    Ok(Some(FsTrimMetrics::try_from(lines)?))
}

fn write_metrics_using_tmp_file(metrics: &FsTrimMetrics, metrics_filename: &str) -> Result<()> {
    let path = PathBuf::from(metrics_filename);
    write_string_using_tmp_file(path, metrics.to_p8s_metrics_string().as_str())
        .context("Failed to write metrics to file")
}

fn update_metrics(elapsed: Duration, is_success: bool, metrics_filename: &str) -> Result<()> {
    let mut metrics = parse_existing_metrics_from_file(metrics_filename)
        .unwrap_or_else(|e| {
            eprintln!("error parsing existing metrics: {}", e);
            Some(FsTrimMetrics::default())
        })
        .unwrap_or_else(|| {
            eprintln!("no existing metrics found");
            FsTrimMetrics::default()
        });
    metrics.update(is_success, elapsed)?;
    write_metrics_using_tmp_file(&metrics, metrics_filename)
}

fn write_initialized_metrics_if_not_exist(metrics_filename: &str) -> Result<()> {
    let metrics = parse_existing_metrics_from_file(metrics_filename)
        .unwrap_or_else(|e| {
            eprintln!("error parsing existing metrics: {}", e);
            Some(FsTrimMetrics::default())
        })
        .unwrap_or_default();
    write_metrics_using_tmp_file(&metrics, metrics_filename)
}

pub fn fstrim_tool(
    command: &str,
    metrics_filename: String,
    target: String,
    init_only: bool,
) -> Result<()> {
    let res = match init_only {
        false => {
            let start = std::time::Instant::now();
            let res = run_command(command, &target);
            let elapsed = start.elapsed();
            update_metrics(elapsed, res.is_ok(), &metrics_filename)?;
            res
        }
        true => write_initialized_metrics_if_not_exist(&metrics_filename),
    };

    res.map_err(|e| format_err!("{}", e))
}
