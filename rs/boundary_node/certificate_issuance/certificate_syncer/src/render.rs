use std::time::Instant;

use anyhow::Error;
use opentelemetry::{Context as OtContext, KeyValue};
use serde::Serialize;

use crate::metrics::{MetricParams, WithMetrics};

#[derive(Debug, PartialEq, Serialize)]
pub struct Context<'a> {
    pub name: &'a str,
    pub ssl_certificate_key_path: &'a str,
    pub ssl_certificate_path: &'a str,
}

pub trait Render: Sync + Send {
    fn render(&self, cx: &Context) -> Result<String, Error>;
}

pub struct Renderer {
    tmpl: String,
}

impl Renderer {
    pub fn new(tmpl: &str) -> Self {
        Self {
            tmpl: tmpl.to_owned(),
        }
    }
}

impl Render for Renderer {
    fn render(&self, cx: &Context) -> Result<String, Error> {
        let out = self.tmpl.clone();
        let out = out.replace("{name}", cx.name);
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

        let cx = OtContext::current();

        counter.add(&cx, 1, labels);
        recorder.record(&cx, duration, labels);

        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_render() {
        let r = Renderer::new("{name}|{ssl_certificate_key_path}|{ssl_certificate_path}");

        let out = r
            .render(&Context {
                name: "1",
                ssl_certificate_key_path: "2",
                ssl_certificate_path: "3",
            })
            .expect("failed to render");

        assert_eq!(out, "1|2|3");
    }
}
