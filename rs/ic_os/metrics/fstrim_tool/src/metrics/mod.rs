use super::*;
use std::io::Lines;

#[cfg(test)]
mod tests;

const METRICS_LAST_RUN_DURATION_MILLISECONDS: &str = "fstrim_last_run_duration_milliseconds";
const METRICS_LAST_RUN_SUCCESS: &str = "fstrim_last_run_success";
const METRICS_RUNS_TOTAL: &str = "fstrim_runs_total";

const METRICS_LAST_RUN_DURATION_MILLISECONDS_DATADIR: &str =
    "fstrim_datadir_last_run_duration_milliseconds";
const METRICS_LAST_RUN_SUCCESS_DATADIR: &str = "fstrim_datadir_last_run_success";
const METRICS_RUNS_TOTAL_DATADIR: &str = "fstrim_datadir_runs_total";

#[derive(Debug)]
pub struct FsTrimMetrics {
    pub last_duration_milliseconds: f64,
    pub last_run_success: bool,
    pub total_runs: f64,

    pub last_duration_milliseconds_datadir: f64,
    pub last_run_success_datadir: bool,
    pub total_runs_datadir: f64,
}

impl Default for FsTrimMetrics {
    fn default() -> Self {
        Self {
            last_duration_milliseconds: 0f64,
            last_run_success: true,
            total_runs: 0f64,

            last_duration_milliseconds_datadir: 0f64,
            last_run_success_datadir: true,
            total_runs_datadir: 0f64,
        }
    }
}

impl FsTrimMetrics {
    pub(crate) fn update(&mut self, success: bool, duration: Duration) -> Result<()> {
        self.total_runs += 1f64;
        self.last_run_success = success;
        self.last_duration_milliseconds = duration.as_millis() as f64;
        Ok(())
    }

    pub(crate) fn update_datadir(&mut self, success: bool, duration: Duration) -> Result<()> {
        self.total_runs_datadir += 1f64;
        self.last_run_success_datadir = success;
        self.last_duration_milliseconds_datadir = duration.as_millis() as f64;
        Ok(())
    }

    pub fn to_p8s_metrics_string(&self) -> String {
        let fstrim_last_run_duration_milliseconds = to_go_f64(self.last_duration_milliseconds);
        let fstrim_last_run_success = if self.last_run_success { "1" } else { "0" };
        let fstrim_runs_total = to_go_f64(self.total_runs);

        let fstrim_datadir_last_run_duration_milliseconds =
            to_go_f64(self.last_duration_milliseconds_datadir);
        let fstrim_datadir_last_run_success = if self.last_run_success_datadir {
            "1"
        } else {
            "0"
        };
        let fstrim_datadir_runs_total = to_go_f64(self.total_runs_datadir);

        format!(
            "# HELP fstrim_last_run_duration_milliseconds Duration of last run of fstrim in milliseconds\n\
            # TYPE fstrim_last_run_duration_milliseconds gauge\n\
            fstrim_last_run_duration_milliseconds {fstrim_last_run_duration_milliseconds}\n\
            # HELP fstrim_last_run_success Success status of last run of fstrim (success: 1, failure: 0)\n\
            # TYPE fstrim_last_run_success gauge\n\
            fstrim_last_run_success {fstrim_last_run_success}\n\
            # HELP fstrim_runs_total Total number of runs of fstrim\n\
            # TYPE fstrim_runs_total counter\n\
            fstrim_runs_total {fstrim_runs_total}\n\
            # HELP fstrim_datadir_last_run_duration_milliseconds Duration of last run of fstrim on datadir in milliseconds\n\
            # TYPE fstrim_datadir_last_run_duration_milliseconds gauge\n\
            fstrim_datadir_last_run_duration_milliseconds {fstrim_datadir_last_run_duration_milliseconds}\n\
            # HELP fstrim_datadir_last_run_success Success status of last run of fstrim on datadir (success: 1, failure: 0)\n\
            # TYPE fstrim_datadir_last_run_success gauge\n\
            fstrim_datadir_last_run_success {fstrim_datadir_last_run_success}\n\
            # HELP fstrim_datadir_runs_total Total number of runs of fstrim on datadir\n\
            # TYPE fstrim_datadir_runs_total counter\n\
            fstrim_datadir_runs_total {fstrim_datadir_runs_total}\n"
        )
    }

    fn are_valid(&self) -> bool {
        is_f64_finite_and_0_or_larger(self.total_runs)
            && is_f64_finite_and_0_or_larger(self.last_duration_milliseconds)
            && is_f64_finite_and_0_or_larger(self.total_runs_datadir)
            && is_f64_finite_and_0_or_larger(self.last_duration_milliseconds_datadir)
    }
}

fn to_go_f64(value: f64) -> String {
    if value.is_nan() {
        "NaN".to_string()
    } else if value.is_infinite() {
        if value.is_sign_positive() {
            "+Inf".to_string()
        } else {
            "-Inf".to_string()
        }
    } else {
        value.to_string()
    }
}

fn is_f64_finite_and_0_or_larger(value: f64) -> bool {
    value.is_finite() && value.is_sign_positive() && value >= 0f64
}

fn parse_metrics_value(key: &str, value: &str) -> Result<f64> {
    parse_go_f64(value).with_context(|| format!("key: {key}"))
}

fn parse_go_f64(value: &str) -> Result<f64> {
    value.parse::<f64>().or_else(|e| {
        if value == "+Inf" {
            Ok(f64::INFINITY)
        } else if value == "-Inf" {
            Ok(f64::NEG_INFINITY)
        } else if value == "NaN" {
            Ok(f64::NAN)
        } else {
            Err(format_err!("failed to parse value '{}': {}", value, e))
        }
    })
}

impl<S> TryFrom<Lines<S>> for FsTrimMetrics
where
    S: Sized + BufRead,
{
    type Error = anyhow::Error;

    fn try_from(lines: Lines<S>) -> Result<Self> {
        let mut last_duration_milliseconds: Option<f64> = None;
        let mut last_run_success: Option<bool> = None;
        let mut total_runs: Option<f64> = None;

        // Default datadir fields (we treat them as optional in the metrics file)
        let mut datadir_last_duration_milliseconds: f64 = 0f64;
        let mut datadir_last_run_success: bool = true;
        let mut datadir_total_runs: f64 = 0f64;

        for line_or_err in lines {
            let line = line_or_err.map_err(|e| format_err!("failed to read line: {}", e))?;
            match line.split(' ').collect::<Vec<_>>()[..] {
                ["#", ..] => continue,
                [key, value] => match key {
                    METRICS_LAST_RUN_DURATION_MILLISECONDS => {
                        last_duration_milliseconds.get_or_insert(parse_metrics_value(key, value)?);
                    }
                    METRICS_LAST_RUN_SUCCESS => {
                        last_run_success.get_or_insert(parse_metrics_value(key, value)? > 0f64);
                    }
                    METRICS_RUNS_TOTAL => {
                        total_runs.get_or_insert(parse_metrics_value(key, value)?);
                    }
                    METRICS_LAST_RUN_DURATION_MILLISECONDS_DATADIR => {
                        datadir_last_duration_milliseconds = parse_metrics_value(key, value)?;
                    }
                    METRICS_LAST_RUN_SUCCESS_DATADIR => {
                        datadir_last_run_success = parse_metrics_value(key, value)? > 0f64;
                    }
                    METRICS_RUNS_TOTAL_DATADIR => {
                        datadir_total_runs = parse_metrics_value(key, value)?;
                    }
                    _ => return Err(format_err!("unknown metric key: {}", key)),
                },
                _ => return Err(format_err!("invalid metric line: {:?}", line)),
            }
        }

        let metrics = FsTrimMetrics {
            last_duration_milliseconds: last_duration_milliseconds.ok_or(format_err!(
                "missing metric: {}",
                METRICS_LAST_RUN_DURATION_MILLISECONDS
            ))?,
            last_run_success: last_run_success
                .ok_or(format_err!("missing metric: {}", METRICS_LAST_RUN_SUCCESS))?,
            total_runs: total_runs.ok_or(format_err!("missing metric: {}", METRICS_RUNS_TOTAL))?,
            last_duration_milliseconds_datadir: datadir_last_duration_milliseconds,
            last_run_success_datadir: datadir_last_run_success,
            total_runs_datadir: datadir_total_runs,
        };
        if !metrics.are_valid() {
            return Err(format_err!("parsed metrics are invalid"));
        }
        Ok(metrics)
    }
}

#[cfg(test)]
impl PartialEq for FsTrimMetrics {
    fn eq(&self, other: &Self) -> bool {
        f64_approx_eq(self.total_runs, other.total_runs)
            && f64_approx_eq(
                self.last_duration_milliseconds,
                other.last_duration_milliseconds,
            )
            && (self.last_run_success == other.last_run_success)
            && f64_approx_eq(
                self.last_duration_milliseconds_datadir,
                other.last_duration_milliseconds_datadir,
            )
            && (self.last_run_success_datadir == other.last_run_success_datadir)
            && f64_approx_eq(self.total_runs_datadir, other.total_runs_datadir)
    }
}

#[cfg(test)]
fn f64_approx_eq(a: f64, b: f64) -> bool {
    (a.is_finite() && b.is_finite() && (a - b).abs() < f64::EPSILON)
        || (a == f64::INFINITY && b == f64::INFINITY)
        || (a == f64::NEG_INFINITY && b == f64::NEG_INFINITY)
        || (a.is_nan() && b.is_nan())
}
