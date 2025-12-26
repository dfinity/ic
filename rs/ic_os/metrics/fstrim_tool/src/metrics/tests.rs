use super::*;
use assert_matches::assert_matches;
use ic_crypto_test_utils_reproducible_rng::reproducible_rng;
use rand::Rng;
use std::fs::write;
use std::time::Duration;
use tempfile::tempdir;

#[test]
fn compare_f64() {
    assert!(f64_approx_eq(f64::NAN, f64::NAN));
    assert!(f64_approx_eq(f64::INFINITY, f64::INFINITY));
    assert!(f64_approx_eq(f64::INFINITY + 1f64, f64::INFINITY));
    assert!(f64_approx_eq(f64::NEG_INFINITY, f64::NEG_INFINITY));
    assert!(f64_approx_eq(f64::NEG_INFINITY + 1f64, f64::NEG_INFINITY));
    assert!(f64_approx_eq(1f64, 1f64));
    assert!(f64_approx_eq(f64::NAN + 1f64, f64::NAN));
}

#[test]
fn parse_valid_metrics_file() {
    let temp_dir = tempdir().expect("failed to create a temporary directory");
    let test_file = temp_dir.as_ref().join("test_file");
    let metrics_file_content = "# HELP fstrim_last_run_duration_milliseconds Duration of last run of fstrim in milliseconds\n\
        # TYPE fstrim_last_run_duration_milliseconds gauge\n\
        fstrim_last_run_duration_milliseconds 6\n\
        # HELP fstrim_last_run_success Success status of last run of fstrim (success: 1, failure: 0)\n\
        # TYPE fstrim_last_run_success gauge\n\
        fstrim_last_run_success 1\n\
        # HELP fstrim_runs_total Total number of runs of fstrim\n\
        # TYPE fstrim_runs_total counter\n\
        fstrim_runs_total 1\n";
    write(&test_file, metrics_file_content).expect("error writing to file");

    let parsed_metrics = parse_existing_metrics_from_file(&test_file.to_string_lossy()).unwrap();
    let expected_metrics = FsTrimMetrics {
        last_duration_milliseconds: 6.0,
        last_run_success: true,
        total_runs: 1.0,
        last_duration_milliseconds_datadir: 0.0,
        last_run_success_datadir: true,
        total_runs_datadir: 0.0,
    };
    assert_eq!(parsed_metrics, Some(expected_metrics));
}

#[test]
fn ignore_subsequent_values_for_same_metric() {
    let temp_dir = tempdir().expect("failed to create a temporary directory");
    let test_file = temp_dir.as_ref().join("test_file");
    let metrics_file_content = "# HELP fstrim_last_run_duration_milliseconds Duration of last run of fstrim in milliseconds\n\
        # TYPE fstrim_last_run_duration_milliseconds gauge\n\
        fstrim_last_run_duration_milliseconds 6\n\
        fstrim_last_run_duration_milliseconds 97\n\
        # HELP fstrim_last_run_success Success status of last run of fstrim (success: 1, failure: 0)\n\
        # TYPE fstrim_last_run_success gauge\n\
        fstrim_last_run_success 1\n\
        fstrim_last_run_success 0\n\
        # HELP fstrim_runs_total Total number of runs of fstrim\n\
        # TYPE fstrim_runs_total counter\n\
        fstrim_runs_total 12\n\
        fstrim_runs_total 1\n";
    write(&test_file, metrics_file_content).expect("error writing to file");

    let parsed_metrics = parse_existing_metrics_from_file(&test_file.to_string_lossy()).unwrap();
    let expected_metrics = FsTrimMetrics {
        last_duration_milliseconds: 6.0,
        last_run_success: true,
        total_runs: 12.0,
        last_duration_milliseconds_datadir: 0.0,
        last_run_success_datadir: true,
        total_runs_datadir: 0.0,
    };
    assert_eq!(parsed_metrics, Some(expected_metrics));
}

#[test]
fn should_error_on_empty_metrics_file() {
    let temp_dir = tempfile::TempDir::new().expect("failed to create a temporary directory");
    let test_file = temp_dir.as_ref().join("test_file");
    write(&test_file, "").expect("error writing to file");
    let parsed_metrics = parse_existing_metrics_from_file(&test_file.to_string_lossy());
    assert_matches!(parsed_metrics, Err(err) if err.to_string().contains("missing metric: fstrim_last_run_duration_milliseconds"));
}

#[test]
fn should_error_when_metrics_file_has_too_many_tokens() {
    let temp_dir = tempfile::TempDir::new().expect("failed to create a temporary directory");
    let test_file = temp_dir.as_ref().join("test_file");
    write(&test_file, "pineapple on pizza is delicious").expect("error writing to file");
    assert_matches!(
        parse_existing_metrics_from_file(&test_file.to_string_lossy()),
        Err(err) if format!("{}", err.root_cause()).contains("invalid metric line")
    );
}

#[test]
fn should_error_when_unknown_metric_name() {
    let temp_dir = tempfile::TempDir::new().expect("failed to create a temporary directory");
    let test_file = temp_dir.as_ref().join("test_file");
    write(&test_file, "pineapple pizza").expect("error writing to file");
    assert_matches!(
        parse_existing_metrics_from_file(&test_file.to_string_lossy()),
        Err(err) if format!("{}", err.root_cause()).contains("unknown metric key: pineapple")
    );
}

#[test]
fn should_error_when_metrics_file_has_timestamp() {
    let temp_dir = tempfile::TempDir::new().expect("failed to create a temporary directory");
    let test_file = temp_dir.as_ref().join("test_file");
    write(
        &test_file,
        "fstrim_last_run_duration_milliseconds 6 1234567890",
    )
    .expect("error writing to file");
    assert_matches!(
        parse_existing_metrics_from_file(&test_file.to_string_lossy()),
        Err(err) if format!("{}", err.root_cause()).contains("invalid metric line")
    );
}

#[test]
fn should_error_when_metrics_file_has_non_numeric_value() {
    let temp_dir = tempfile::TempDir::new().expect("failed to create a temporary directory");
    let test_file = temp_dir.as_ref().join("test_file");
    write(&test_file, format!("{METRICS_RUNS_TOTAL} pizza").as_str())
        .expect("error writing to file");
    assert_matches!(
        parse_existing_metrics_from_file(&test_file.to_string_lossy()),
        Err(err) if format!("{}", err.root_cause()).contains("invalid float literal")
    );
}

#[test]
fn file_does_not_exist() {
    let temp_dir = tempfile::TempDir::new().expect("failed to create a temporary directory");
    let test_file = temp_dir.as_ref().join("test_file");
    let parsed_metrics = parse_existing_metrics_from_file(&test_file.to_string_lossy()).unwrap();
    assert_eq!(parsed_metrics, None);
}

#[test]
fn set_metrics() {
    let mut existing_metrics = FsTrimMetrics::default();
    existing_metrics
        .update(true, Duration::from_millis(110))
        .expect("should update metrics successfully");
    let expected_metrics = FsTrimMetrics {
        last_duration_milliseconds: 110.0,
        last_run_success: true,
        total_runs: 1.0,
        ..FsTrimMetrics::default()
    };
    assert_eq!(existing_metrics, expected_metrics);
}

#[test]
fn update_metrics() {
    let mut rng = reproducible_rng();
    for _ in 0..100 {
        let total_runs: u64 = rng.gen_range(0..10000000);
        let mut expected_metrics = FsTrimMetrics {
            total_runs: total_runs as f64,
            ..FsTrimMetrics::default()
        };
        let mut updated_metrics = FsTrimMetrics {
            total_runs: total_runs as f64,
            ..FsTrimMetrics::default()
        };
        for _ in 0..100 {
            let success = rng.gen_bool(0.5);
            let duration = Duration::from_millis(rng.gen_range(0..15000));
            update_metrics_locally(&mut expected_metrics, success, duration);
            updated_metrics
                .update(success, duration)
                .expect("should update metrics successfully");
            assert_eq!(expected_metrics, updated_metrics);

            let exported_metrics_string = updated_metrics.to_p8s_metrics_string();
            let buf_reader = BufReader::new(exported_metrics_string.as_bytes());
            let reimported_updated_metrics = FsTrimMetrics::try_from(buf_reader.lines())
                .expect("should reimport metrics successfully");
            assert_eq!(updated_metrics, reimported_updated_metrics);
        }
    }
}

// Simple local "update" for the test reference
fn update_metrics_locally(metrics: &mut FsTrimMetrics, success: bool, duration: Duration) {
    metrics.total_runs += 1f64;
    metrics.last_run_success = success;
    metrics.last_duration_milliseconds = duration.as_millis() as f64;
}

#[test]
fn update_metrics_with_infinite_values() {
    let mut existing_metrics = FsTrimMetrics {
        total_runs: f64::INFINITY,
        ..FsTrimMetrics::default()
    };
    let success = true;
    let duration = Duration::from_millis(110);
    existing_metrics
        .update(success, duration)
        .expect("should update metrics successfully");
    let expected_metrics = FsTrimMetrics {
        last_duration_milliseconds: duration.as_millis() as f64,
        last_run_success: success,
        total_runs: f64::INFINITY,
        ..FsTrimMetrics::default()
    };

    assert_eq!(existing_metrics, expected_metrics);
}

#[test]
fn update_metrics_with_nan_values() {
    let mut existing_metrics = FsTrimMetrics {
        total_runs: f64::NAN,
        ..FsTrimMetrics::default()
    };
    let success = true;
    let duration = Duration::from_millis(110);
    existing_metrics
        .update(success, duration)
        .expect("should update metrics successfully");
    let expected_metrics = FsTrimMetrics {
        last_duration_milliseconds: duration.as_millis() as f64,
        last_run_success: success,
        total_runs: f64::NAN,
        ..FsTrimMetrics::default()
    };

    assert_eq!(existing_metrics, expected_metrics);
}

fn verify_invariants(i: f64, existing_metrics: &FsTrimMetrics) {
    assert_eq!(i + 1f64, existing_metrics.total_runs);
    assert!(existing_metrics.last_duration_milliseconds.is_finite());
    assert!(existing_metrics.last_duration_milliseconds >= 0f64);
}

#[test]
fn maintain_invariants() {
    let mut existing_metrics = FsTrimMetrics::default();
    let rng = &mut reproducible_rng();
    for i in 0..100 {
        let success = rng.gen_bool(0.5);
        let duration = Duration::from_millis(rng.gen_range(1..1000));
        existing_metrics
            .update(success, duration)
            .expect("should update metrics successfully");
        verify_invariants(i as f64, &existing_metrics);
    }
}

#[test]
fn update_datadir_metrics() {
    let mut metrics = FsTrimMetrics::default();
    assert_eq!(metrics.total_runs_datadir, 0.0);
    assert_eq!(metrics.last_duration_milliseconds_datadir, 0.0);
    assert!(metrics.last_run_success_datadir);

    metrics
        .update_datadir(false, Duration::from_millis(123))
        .expect("should update datadir metrics");

    assert_eq!(metrics.total_runs_datadir, 1.0);
    assert_eq!(metrics.last_duration_milliseconds_datadir, 123.0);
    assert!(!metrics.last_run_success_datadir);

    // Check that normal fields remain untouched
    assert_eq!(metrics.total_runs, 0.0);
    assert_eq!(metrics.last_duration_milliseconds, 0.0);
    assert!(metrics.last_run_success);
}

#[test]
fn format_metrics_output() {
    let metrics = FsTrimMetrics {
        last_duration_milliseconds: 123.45,
        last_run_success: true,
        total_runs: 6.0,
        last_duration_milliseconds_datadir: 678.9,
        last_run_success_datadir: false,
        total_runs_datadir: 4.0,
    };

    let metrics_str = metrics.to_p8s_metrics_string();
    let expected_str = "\
# HELP fstrim_last_run_duration_milliseconds Duration of last run of fstrim in milliseconds
# TYPE fstrim_last_run_duration_milliseconds gauge
fstrim_last_run_duration_milliseconds 123.45
# HELP fstrim_last_run_success Success status of last run of fstrim (success: 1, failure: 0)
# TYPE fstrim_last_run_success gauge
fstrim_last_run_success 1
# HELP fstrim_runs_total Total number of runs of fstrim
# TYPE fstrim_runs_total counter
fstrim_runs_total 6
# HELP fstrim_datadir_last_run_duration_milliseconds Duration of last run of fstrim on datadir in milliseconds
# TYPE fstrim_datadir_last_run_duration_milliseconds gauge
fstrim_datadir_last_run_duration_milliseconds 678.9
# HELP fstrim_datadir_last_run_success Success status of last run of fstrim on datadir (success: 1, failure: 0)
# TYPE fstrim_datadir_last_run_success gauge
fstrim_datadir_last_run_success 0
# HELP fstrim_datadir_runs_total Total number of runs of fstrim on datadir
# TYPE fstrim_datadir_runs_total counter
fstrim_datadir_runs_total 4
";

    assert_eq!(metrics_str, expected_str);
}
