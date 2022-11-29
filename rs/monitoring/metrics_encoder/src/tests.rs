use super::{validate_prometheus_name, MetricsEncoder};

fn as_string(encoder: MetricsEncoder<Vec<u8>>) -> String {
    String::from_utf8(encoder.into_inner()).unwrap()
}

#[test]
fn test_labeled_counter_metrics() {
    let mut encoder = MetricsEncoder::new(vec![0u8; 0], 1395066363000);
    encoder
        .counter_vec("http_requests_total", "The total number of HTTP requests.")
        .unwrap()
        .value(&[("method", "post"), ("code", "200")], 1027.0)
        .unwrap()
        .value(&[("method", "post"), ("code", "400")], 3.0)
        .unwrap();

    assert_eq!(
        r#"# HELP http_requests_total The total number of HTTP requests.
# TYPE http_requests_total counter
http_requests_total{method="post",code="200"} 1027 1395066363000
http_requests_total{method="post",code="400"} 3 1395066363000
"#,
        as_string(encoder)
    );
}

#[test]
fn test_labeled_gauge_metrics() {
    let mut encoder = MetricsEncoder::new(vec![0u8; 0], 1395066363000);
    encoder
        .gauge_vec("cpu_temperature", "CPU temperature in celsius.")
        .unwrap()
        .value(&[("core", "1")], 40.0)
        .unwrap()
        .value(&[("core", "2")], 43.0)
        .unwrap();

    assert_eq!(
        r#"# HELP cpu_temperature CPU temperature in celsius.
# TYPE cpu_temperature gauge
cpu_temperature{core="1"} 40 1395066363000
cpu_temperature{core="2"} 43 1395066363000
"#,
        as_string(encoder)
    );
}

#[test]
#[should_panic(expected = "Empty names are not allowed")]
fn validate_empty_name() {
    validate_prometheus_name("")
}

#[test]
#[should_panic(expected = "Name '⇒Γ' does not match pattern [a-zA-Z_][a-zA-Z0-9_]")]
fn validate_unicode_name() {
    validate_prometheus_name("⇒Γ")
}

#[test]
#[should_panic(expected = "Name 'http:rule' does not match pattern [a-zA-Z_][a-zA-Z0-9_]")]
fn validate_rule_name() {
    validate_prometheus_name("http:rule")
}
