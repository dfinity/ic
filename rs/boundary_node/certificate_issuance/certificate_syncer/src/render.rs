use std::time::Instant;

use anyhow::Error;
use opentelemetry::KeyValue;
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
    template_with_service_worker: String,
    template_with_icx_proxy: String,
    no_sw_domains: Vec<String>,
}

impl Renderer {
    pub fn new(
        template_with_service_worker: &str,
        template_with_icx_proxy: &str,
        no_sw_domains: Vec<String>,
    ) -> Self {
        Self {
            template_with_service_worker: template_with_service_worker.to_owned(),
            template_with_icx_proxy: template_with_icx_proxy.to_owned(),
            no_sw_domains: no_sw_domains.to_owned(),
        }
    }
}

impl Render for Renderer {
    fn render(&self, cx: &Context) -> Result<String, Error> {
        let out = if self.no_sw_domains.contains(&cx.name.to_string()) {
            self.template_with_icx_proxy.clone()
        } else {
            self.template_with_service_worker.clone()
        };
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
        let r = Renderer::new(
            "{name}|{ssl_certificate_key_path}|{ssl_certificate_path}",
            "{name}|{ssl_certificate_path}|{ssl_certificate_key_path}",
            vec!["X".to_string(), "Y".to_string(), "Z".to_string()],
        );

        let out = r
            .render(&Context {
                name: "A",
                ssl_certificate_key_path: "2",
                ssl_certificate_path: "3",
            })
            .expect("failed to render");

        assert_eq!(out, "A|2|3");

        let out = r
            .render(&Context {
                name: "X",
                ssl_certificate_key_path: "2",
                ssl_certificate_path: "3",
            })
            .expect("failed to render");

        assert_eq!(out, "X|3|2");
    }
}
