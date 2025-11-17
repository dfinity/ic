use crate::config::HttpProxyTarget;
use crate::{cache::SampleCacheStore, client, config};
use axum::http::header;
use axum::http::HeaderMap;
use axum::http::HeaderValue;
use axum::http::StatusCode;
use http::HeaderName;
use hyper::body::Bytes;
use itertools::Itertools;
use log::error;
use prometheus_parse::{self, Sample, Value};
use rand::Rng;
use reqwest::Client;
use std::collections::HashMap;
use std::f64;
use std::iter::zip;
use std::sync::{Arc, Mutex};
use std::time::Duration;

// Headers that must not be relayed from backend to client or vice versa.
static HOPBYHOP: [&str; 8] = [
    "keep-alive",
    "transfer-encoding",
    "te",
    "connection",
    "trailer",
    "upgrade",
    "proxy-authorization",
    "proxy-authenticate",
];
// Headers that must be stripped from response of backend.
static STRIP_FROM_RESPONSE: [&str; 1] = ["content-length"];

// Headers that may be relayed from client to backend.
static PROXIED_CLIENT_HEADERS: [&str; 1] = ["accept"];

fn safely_clone_response_headers(orgheaders: reqwest::header::HeaderMap) -> HeaderMap {
    // Some of this code can be deleted once reqwest updates
    // to a later http crate version.
    let mut headers = HeaderMap::new();
    for (k, v) in orgheaders {
        if let Some(kk) = k {
            let lower = kk.to_string().to_lowercase();
            if !HOPBYHOP.contains(&lower.as_str()) && !STRIP_FROM_RESPONSE.contains(&lower.as_str())
            {
                let vv = v.as_ref();
                {
                    match HeaderValue::from_bytes(vv) {
                        Ok(vvv) => {
                            match HeaderName::from_bytes(kk.as_ref()) {
                                Ok(kkk) => {
                                    headers.insert(kkk, vvv);
                                }
                                Err(err) => {
                                    error!("Invalid response header name: {}", err)
                                }
                            };
                        }
                        // Ignore such headers;
                        Err(err) => {
                            error!("Invalid response header value: {}", err)
                        }
                    }
                }
            }
        }
    }
    headers
}

fn safely_clone_request_headers(orgheaders: HeaderMap) -> reqwest::header::HeaderMap {
    // Some of this code can be deleted once reqwest updates
    // to a later http crate version.
    let mut headers = reqwest::header::HeaderMap::new();
    for (k, v) in orgheaders {
        if let Some(kk) = k {
            if PROXIED_CLIENT_HEADERS.contains(&kk.to_string().to_lowercase().as_str()) {
                let vv = v.as_ref();
                match reqwest::header::HeaderValue::from_bytes(vv) {
                    Ok(vvv) => {
                        match reqwest::header::HeaderName::from_bytes(kk.as_ref()) {
                            Ok(kkk) => {
                                headers.insert(kkk, vvv);
                            }
                            Err(err) => {
                                error!("Invalid request header name: {}", err)
                            }
                        };
                    }
                    // Ignore such headers;
                    Err(err) => {
                        error!("Invalid request header value: {}", err)
                    }
                }
            }
        }
    }
    headers
}

fn fallback_headers() -> HeaderMap {
    let mut fallback_headers = HeaderMap::new();
    fallback_headers.insert(header::CONTENT_TYPE, "text/plain".parse().unwrap());
    fallback_headers
}

fn render_labels(labels: &prometheus_parse::Labels, extra: Option<String>) -> String {
    let mut joined = labels
        .iter()
        .map(|(n, v)| format!("{n}=\"{v}\""))
        .collect::<Vec<String>>();

    joined.sort();
    if let Some(o) = extra {
        joined.push(o);
    };

    if joined.is_empty() {
        String::new()
    } else {
        "{".to_string() + &joined.join(",") + "}"
    }
}

fn render_sample(sample: &prometheus_parse::Sample) -> Vec<String> {
    let values = match &sample.value {
        Value::Untyped(val) | Value::Counter(val) | Value::Gauge(val) => vec![format!("{:e}", val)],
        Value::Histogram(val) => val
            .iter()
            .map(|h| format!("{:e}", h.count))
            .collect::<Vec<String>>(),
        Value::Summary(val) => val
            .iter()
            .map(|h| format!("{:e}", h.count))
            .collect::<Vec<String>>(),
    };
    let labels = match &sample.value {
        Value::Untyped(_val) | Value::Counter(_val) | Value::Gauge(_val) => vec![None],
        Value::Histogram(val) => val
            .iter()
            .map(|h| {
                Some(format!("le=\"{}\"", {
                    if h.less_than == f64::INFINITY {
                        "+Inf".to_string()
                    } else if h.less_than == f64::NEG_INFINITY {
                        "-Inf".to_string()
                    } else {
                        format!("{}", h.less_than)
                    }
                }))
            })
            .collect::<Vec<Option<String>>>(),
        Value::Summary(val) => val
            .iter()
            .map(|h| Some(format!("quantile=\"{}\"", h.quantile)))
            .collect::<Vec<Option<String>>>(),
    };

    zip(values, labels)
        .map(|(value, extra_label)| {
            format!(
                "{}{} {}",
                sample.metric,
                render_labels(&sample.labels, extra_label),
                value
            )
        })
        .collect::<Vec<String>>()
}

fn render_scrape_data(scrape: &prometheus_parse::Scrape) -> Bytes {
    let mut help = scrape.docs.clone();
    let rendered = scrape
        .samples
        .iter()
        .sorted_by(|sample1, sample2| sample1.metric.cmp(&sample2.metric))
        .map(|sample| {
            (
                &sample.metric,
                &sample.value,
                render_sample(sample).join("\n"),
            )
        })
        .map(|(metric, value, rendered)| {
            if let Some(h) = help.remove(metric) {
                format!(
                    "# HELP {} {}\n# TYPE {} {}\n{}",
                    metric,
                    h,
                    metric,
                    match value {
                        Value::Untyped(_) => "untyped",
                        Value::Counter(_) => "counter",
                        Value::Gauge(_) => "gauge",
                        Value::Histogram(_) => "histogram",
                        Value::Summary(_) => "summary",
                    },
                    rendered
                )
            } else {
                rendered
            }
        })
        .collect::<Vec<String>>()
        .join("\n")
        + "\n";
    Bytes::from(rendered)
}

#[derive(Clone)]
/// The metrics proxy is in charge of receiving requests relayed by the server,
/// contacting the backend via the scraper, and finally processing the response
/// so that it complies with the policies defined in the configuration.
pub struct MetricsProxier {
    target: HttpProxyTarget,
    cache: Arc<Mutex<SampleCacheStore>>,
    client: Client,
}

impl From<HttpProxyTarget> for MetricsProxier {
    fn from(target: HttpProxyTarget) -> Self {
        let client =
            Client::builder().danger_accept_invalid_certs(target.connect_to.tolerate_bad_tls);
        MetricsProxier {
            target,
            cache: Arc::new(Mutex::new(SampleCacheStore::default())),
            client: client.build().unwrap(),
        }
    }
}

impl MetricsProxier {
    pub async fn handle(&self, headers: HeaderMap) -> (StatusCode, HeaderMap, Bytes) {
        let clientheaders: reqwest::header::HeaderMap = safely_clone_request_headers(headers);
        let result =
            client::scrape(self.client.clone(), &self.target.connect_to, clientheaders).await;
        match result {
            Err(error) => match error {
                client::ScrapeError::Non200(non200) => {
                    // Must do this because reqwest StatusCode and axum StatusCode
                    // come from different versions of the http crates.
                    // TODO: once reqwest uses newer versions of the http crate,
                    // simply pass through the status code reqwest returns.
                    let statuscode = match StatusCode::from_u16(non200.status.as_u16()) {
                        Ok(s) => s,
                        Err(_) => StatusCode::INTERNAL_SERVER_ERROR,
                    };
                    (
                        statuscode,
                        safely_clone_response_headers(non200.headers),
                        non200.data,
                    )
                }
                client::ScrapeError::ParseError(parseerror) => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    fallback_headers(),
                    Bytes::from(format!("Error parsing output.\n\n{parseerror:#?}")),
                ),
                client::ScrapeError::DecodeError(decodeerror) => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    fallback_headers(),
                    Bytes::from(format!("Error decoding UTF-8 output.\n\n{decodeerror:#?}")),
                ),
                client::ScrapeError::FetchError(fetcherror) => {
                    let mut statuscode = StatusCode::BAD_GATEWAY;
                    let mut errmsg = format!("The target is down.\n\n{fetcherror:#?}");
                    if fetcherror.is_timeout() {
                        // 504 target timed out
                        statuscode = StatusCode::GATEWAY_TIMEOUT;
                        errmsg = format!("The target is timing out.\n\n{fetcherror:#?}");
                    }
                    (statuscode, fallback_headers(), Bytes::from(errmsg))
                }
            },
            Ok(parsed) => (
                StatusCode::OK,
                safely_clone_response_headers(parsed.headers),
                render_scrape_data(&self.apply_filters(parsed.series)),
            ),
        }
    }

    fn apply_filters(&self, series: prometheus_parse::Scrape) -> prometheus_parse::Scrape {
        fn label_value(
            metric: &String,
            labels: &prometheus_parse::Labels,
            label_name: &String,
        ) -> String {
            if label_name == "__name__" {
                metric.to_string()
            } else if labels.contains_key(label_name.as_str()) {
                labels.get(label_name.as_str()).unwrap().to_string()
            } else {
                // No label with that name.  No match.
                // This is consistent with how Prometheus metric relabeling
                // deals with absent labels.
                String::new()
            }
        }

        let selectors = &self.target.label_filters;
        let mut samples: Vec<prometheus_parse::Sample> = vec![];
        let mut docs: HashMap<String, String> = HashMap::new();

        {
            let now = std::time::Instant::now();
            let mut cache = self.cache.lock().unwrap();

            for mut sample in series.samples {
                let mut keep: Option<bool> = None;
                // The following value, if true at the end of this loop,
                // indicates whether the sample should be cached for
                // future lookups.  Values are only cached when the
                // cache is consulted and the result is a cache miss.
                let mut must_cache_sample = false;

                for selector in selectors {
                    let source_labels = &selector.source_labels;
                    let label_values = source_labels
                        .iter()
                        .map(|label_name| label_value(&sample.metric, &sample.labels, label_name))
                        .collect::<Vec<String>>()
                        .join(selector.separator.as_str());
                    for action in &selector.actions {
                        if selector.regex.is_match(&label_values) {
                            match action {
                                config::LabelFilterAction::Keep => {
                                    keep = Some(true);
                                }
                                config::LabelFilterAction::Drop => {
                                    keep = Some(false);
                                }
                                config::LabelFilterAction::ReduceTimeResolution { resolution } => {
                                    // If the cache has not expired according to the duration,
                                    // then the cache returns the cached sample.
                                    // Else, if the cache has expired according to the duration,
                                    // then the cache returns nothing.
                                    // Below, we insert it into the cache if nothing was returned
                                    // into the cache at all.
                                    let staleness: Duration = (*resolution).into();
                                    match cache.get(&sample, now, staleness) {
                                        Some(got) => sample = got,
                                        None => must_cache_sample = true,
                                    }
                                }
                                config::LabelFilterAction::AddAbsoluteNoise {
                                    amplitude,
                                    quantum,
                                } => {
                                    // If the cache has not expired according to the duration,
                                    // then the cache returns the cached sample.
                                    // Else, if the cache has expired according to the duration,
                                    // then the cache returns nothing.
                                    // Below, we insert it into the cache if nothing was returned
                                    // into the cache at all.
                                    let mut rng = rand::thread_rng();
                                    let wnd = *amplitude;
                                    let randomness: f64 = rng.gen_range(-wnd..wnd);
                                    let quantized =
                                        (randomness * (1.0 / quantum)).round() * quantum;
                                    let new_value = match sample.value {
                                        Value::Counter(c) => Value::Counter(c + quantized),
                                        Value::Gauge(c) => Value::Gauge(c + quantized),
                                        Value::Untyped(c) => Value::Untyped(c + quantized),
                                        Value::Histogram(hc) => Value::Histogram(
                                            hc.iter()
                                                .map(|vv| prometheus_parse::HistogramCount {
                                                    less_than: vv.less_than,
                                                    count: vv.count + quantized,
                                                })
                                                .collect::<Vec<_>>(),
                                        ),
                                        Value::Summary(summ) => Value::Summary(
                                            summ.iter()
                                                .map(|vv| prometheus_parse::SummaryCount {
                                                    quantile: vv.quantile,
                                                    count: vv.count + quantized,
                                                })
                                                .collect::<Vec<_>>(),
                                        ),
                                    };
                                    sample = Sample {
                                        metric: sample.metric,
                                        value: new_value,
                                        labels: sample.labels,
                                        timestamp: sample.timestamp,
                                    };
                                }
                            }
                        }
                    }
                }

                // Ignore this sample if the conclusion is that we were going to drop it anyway.
                if let Some(trulykeep) = keep {
                    if !trulykeep {
                        continue;
                    }
                }

                // Add this sample's metric name documentation if not yet added.
                if !docs.contains_key(&sample.metric) && series.docs.contains_key(&sample.metric) {
                    docs.insert(
                        sample.metric.clone(),
                        series.docs.get(&sample.metric).unwrap().clone(),
                    );
                }

                if must_cache_sample {
                    cache.put(sample.clone(), now);
                }
                samples.push(sample);
            }
        }

        prometheus_parse::Scrape { docs, samples }
    }
}

#[cfg(test)]
mod tests {
    use super::render_scrape_data;
    use crate::config::{ConnectTo, HttpProxyTarget, LabelFilter};
    use duration_string::DurationString;
    use pretty_assertions::assert_eq as pretty_assert_eq;
    use std::{str::FromStr, time::Duration};

    fn make_test_proxy_target(filters: Vec<LabelFilter>) -> HttpProxyTarget {
        HttpProxyTarget {
            connect_to: ConnectTo {
                url: url::Url::from_str("http://localhost:8080/metrics").unwrap(),
                timeout: DurationString::new(Duration::new(5, 0)),
                tolerate_bad_tls: false,
            },
            label_filters: filters,
            cache_duration: DurationString::new(Duration::new(0, 0)),
        }
    }

    fn make_adapter_filter_tester(filters: Vec<LabelFilter>) -> crate::proxy::MetricsProxier {
        crate::proxy::MetricsProxier::from(make_test_proxy_target(filters))
    }

    struct TestPayload {
        sorted_text: String,
        parsed_scrape: prometheus_parse::Scrape,
    }

    impl TestPayload {
        fn from_scrape(scrape: prometheus_parse::Scrape) -> Self {
            let chunk = render_scrape_data(&scrape);
            let rendered = std::str::from_utf8(chunk.as_ref()).unwrap();
            let mut sorted_rendered: Vec<String> = rendered.lines().map(|s| s.to_owned()).collect();
            sorted_rendered.sort();
            let sorted_text = sorted_rendered.join("\n");
            TestPayload {
                sorted_text,
                parsed_scrape: scrape,
            }
        }

        fn from_text(text: &str) -> Self {
            let parsed_scrape =
                prometheus_parse::Scrape::parse(text.lines().map(|s| Ok(s.to_owned()))).unwrap();
            TestPayload::from_scrape(parsed_scrape)
        }
    }

    #[test]
    fn test_proxy_no_filtering() {
        let adapter = make_adapter_filter_tester(vec![]);
        let text = r#"
# HELP node_softnet_times_squeezed_total Number of times processing packets ran out of quota
# TYPE node_softnet_times_squeezed_total counter
node_softnet_times_squeezed_total{cpu="0"} 0
node_softnet_times_squeezed_total{cpu="1"} 0
node_softnet_times_squeezed_total{cpu="10"} 0
node_softnet_times_squeezed_total{cpu="11"} 0
node_softnet_times_squeezed_total{cpu="12"} 0
node_softnet_times_squeezed_total{cpu="13"} 0
node_softnet_times_squeezed_total{cpu="14"} 0
node_softnet_times_squeezed_total{cpu="15"} 0
node_softnet_times_squeezed_total{cpu="2"} 0
node_softnet_times_squeezed_total{cpu="3"} 0
node_softnet_times_squeezed_total{cpu="4"} 0
node_softnet_times_squeezed_total{cpu="5"} 0
node_softnet_times_squeezed_total{cpu="6"} 0
node_softnet_times_squeezed_total{cpu="7"} 0
node_softnet_times_squeezed_total{cpu="8"} 0
node_softnet_times_squeezed_total{cpu="9"} 0
"#;
        let inp_ = TestPayload::from_text(text);
        let exp_ = TestPayload::from_text(text);
        let filtered = adapter.apply_filters(inp_.parsed_scrape);
        let out_ = TestPayload::from_scrape(filtered);
        pretty_assert_eq!(exp_.sorted_text.as_str(), out_.sorted_text.as_str());
    }

    #[test]
    fn test_proxy_one_label_filtering() {
        let adapter = make_adapter_filter_tester(
            serde_yaml::from_str(
                r#"
- regex: node_softnet_times_squeezed_total
  actions: [drop]
- source_labels: [cpu]
  regex: "1"
  actions: [keep]
"#,
            )
            .unwrap(),
        );
        let inp_ = TestPayload::from_text(
            r#"
# HELP node_softnet_times_squeezed_total Number of times processing packets ran out of quota
# TYPE node_softnet_times_squeezed_total counter
node_softnet_times_squeezed_total{cpu="0"} 0
node_softnet_times_squeezed_total{cpu="1"} 0
node_softnet_times_squeezed_total{cpu="10"} 0
node_softnet_times_squeezed_total{cpu="11"} 0
node_softnet_times_squeezed_total{cpu="12"} 0
node_softnet_times_squeezed_total{cpu="13"} 0
node_softnet_times_squeezed_total{cpu="14"} 0
node_softnet_times_squeezed_total{cpu="15"} 0
node_softnet_times_squeezed_total{cpu="2"} 0
node_softnet_times_squeezed_total{cpu="3"} 0
node_softnet_times_squeezed_total{cpu="4"} 0
node_softnet_times_squeezed_total{cpu="5"} 0
node_softnet_times_squeezed_total{cpu="6"} 0
node_softnet_times_squeezed_total{cpu="7"} 0
node_softnet_times_squeezed_total{cpu="8"} 0
node_softnet_times_squeezed_total{cpu="9"} 0
"#,
        );
        let exp_ = TestPayload::from_text(
            r#"
# HELP node_softnet_times_squeezed_total Number of times processing packets ran out of quota
# TYPE node_softnet_times_squeezed_total counter
node_softnet_times_squeezed_total{cpu="1"} 0
"#,
        );
        let filtered = adapter.apply_filters(inp_.parsed_scrape);
        let out_ = TestPayload::from_scrape(filtered);
        pretty_assert_eq!(exp_.sorted_text.as_str(), out_.sorted_text.as_str());
    }

    #[test]
    fn test_caching() {
        let adapter = make_adapter_filter_tester(
            serde_yaml::from_str(
                r#"
- regex: node_frobnicated
  actions:
  - reduce_time_resolution:
      resolution: 10ms
"#,
            )
            .unwrap(),
        );

        // First scrape.  Metric should be there, and
        // will not be filtered.  Input should be same as output.
        let first_input = TestPayload::from_text(
            r#"
# HELP node_frobnicated Number of times processing packets ran out of quota
# TYPE node_frobnicated counter
node_frobnicated{cpu="0"} 0
"#,
        );
        let first_filtered = adapter.apply_filters(first_input.parsed_scrape);
        let first_output = TestPayload::from_scrape(first_filtered);
        pretty_assert_eq!(
            first_input.sorted_text.as_str(),
            first_output.sorted_text.as_str()
        );

        // Now we run a different metric value thru the filter.
        // The filter should have given us the same value since 10ms have not passed.
        // In other words, the output of this one should be
        // the same as the input of the prior filter run.
        let second_input = TestPayload::from_text(
            r#"
# HELP node_frobnicated Number of times processing packets ran out of quota
# TYPE node_frobnicated counter
node_frobnicated{cpu="0"} 25.1
"#,
        );
        let second_output =
            TestPayload::from_scrape(adapter.apply_filters(second_input.parsed_scrape.clone()));
        pretty_assert_eq!(
            first_input.sorted_text.as_str(),
            second_output.sorted_text.as_str()
        );

        std::thread::sleep(Duration::from_millis(10));

        // Now we run the same input as in the prior step, but because
        // time has passed, then the filter will let the updated value pass.
        // In other words, the output of this filter round should be the
        // input of the prior (-> the second) round.
        let third_output =
            TestPayload::from_scrape(adapter.apply_filters(second_input.parsed_scrape.clone()));
        pretty_assert_eq!(
            second_input.sorted_text.as_str(),
            third_output.sorted_text.as_str()
        );
    }

    #[test]
    fn test_random() {
        let adapter = make_adapter_filter_tester(
            serde_yaml::from_str(
                r#"
- regex: node_frobnicated
  actions:
  - add_absolute_noise:
      amplitude: 1000
      quantum: 10
  - reduce_time_resolution:
      resolution: 1s
"#,
            )
            .unwrap(),
        );

        // First scrape.  Metric should be there, and
        // will not be filtered.  Input should be same as output.
        let input = TestPayload::from_text(
            r#"
# HELP node_frobnicated Number of times processing packets ran out of quota
# TYPE node_frobnicated gauge
node_frobnicated{cpu="0"} 4500.1
"#,
        );
        let filtered = adapter.apply_filters(input.parsed_scrape);
        let output = TestPayload::from_scrape(filtered);
        let original_value =
            if let prometheus_parse::Value::Gauge(v) = output.parsed_scrape.samples[0].value {
                assert!(
                    format!("{:.2}", v).contains("0.1"),
                    "Noise added to value {:.2} is not rounded to ten.",
                    v
                );
                Some(v)
            } else {
                assert!(false, "Value was not a Gauge");
                None
            };
        // Now let's check that the cache returns the same value, since
        // the caching happens *after* the noise addition, and therefore
        // the returned value should be cached, not noised.
        let new_input = TestPayload::from_text(
            r#"
# HELP node_frobnicated Number of times processing packets ran out of quota
# TYPE node_frobnicated gauge
node_frobnicated{cpu="0"} 4600.1
"#,
        );
        let filtered_again = adapter.apply_filters(new_input.parsed_scrape);
        let new_output = TestPayload::from_scrape(filtered_again);
        if let prometheus_parse::Value::Gauge(v) = new_output.parsed_scrape.samples[0].value {
            pretty_assert_eq!(v, original_value.unwrap());
        } else {
            assert!(false, "Value was not a Gauge");
        }
    }
}
