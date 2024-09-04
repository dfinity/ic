use std::time::Instant;

use anyhow::Error;
use opentelemetry::KeyValue;
use serde::Serialize;

use crate::metrics::{MetricParams, WithMetrics};

#[derive(PartialEq, Debug, Serialize)]
pub struct Context<'a> {
    pub name: &'a str,
    pub canister_id: &'a str,
    pub ssl_certificate_key_path: &'a str,
    pub ssl_certificate_path: &'a str,
}

pub trait Render: Sync + Send {
    fn render(&self, cx: &Context) -> Result<String, Error>;
}

pub struct Renderer {
    template: String,
}

impl Renderer {
    pub fn new(template: &str) -> Self {
        Self {
            template: template.to_owned(),
        }
    }
}

impl Render for Renderer {
    fn render(&self, cx: &Context) -> Result<String, Error> {
        let out = self.template.clone();
        let out = out.replace("{name}", cx.name);
        let out = out.replace("{canister_id}", cx.canister_id);
        let out = out.replace("{ssl_certificate_key_path}", cx.ssl_certificate_key_path);
        let out = out.replace("{ssl_certificate_path}", cx.ssl_certificate_path);

        Ok(out)
    }
}

impl<T: Render> Render for WithMetrics<T> {
    fn render(&self, cx: &Context) -> Result<String, Error> {
        let start_time = Instant::now();

        let out = self.0.render(cx);

        let status = if out.is_ok() { "ok" } else { "fail" };
        let duration = start_time.elapsed().as_secs_f64();

        let labels = &[KeyValue::new("status", status)];

        let MetricParams {
            counter, recorder, ..
        } = &self.1;

        counter.add(1, labels);
        recorder.record(duration, labels);

        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_render() {
        let r =
            Renderer::new("{name}|{canister_id}|{ssl_certificate_key_path}|{ssl_certificate_path}");

        let out = r
            .render(&Context {
                name: "A",
                canister_id: "B",
                ssl_certificate_key_path: "2",
                ssl_certificate_path: "3",
            })
            .expect("failed to render");

        assert_eq!(out, "A|B|2|3");

        let out = r
            .render(&Context {
                name: "X",
                canister_id: "Y",
                ssl_certificate_key_path: "2",
                ssl_certificate_path: "3",
            })
            .expect("failed to render");

        assert_eq!(out, "X|Y|2|3");
    }
}
