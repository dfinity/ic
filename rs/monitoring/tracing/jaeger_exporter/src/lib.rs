use anyhow::anyhow;
use opentelemetry::{trace::TracerProvider, KeyValue};
use opentelemetry_otlp::{SpanExporter, WithExportConfig};
use opentelemetry_sdk::{runtime as sdk_runtime, trace as sdk_trace, Resource};
use tracing_opentelemetry::OpenTelemetryLayer;
use tracing_subscriber::{Layer, Registry};

pub fn jaeger_exporter(
    jaeger_addr: &str,
    service_name: &'static str,
    rt_handle: &tokio::runtime::Handle,
) -> Result<impl Layer<Registry> + Send + Sync, anyhow::Error> {
    if jaeger_addr.is_empty() {
        return Err(anyhow!("Empty jaeger addr."));
    }

    let _rt_enter = rt_handle.enter();

    let span_exporter = SpanExporter::builder()
        .with_tonic()
        .with_endpoint(jaeger_addr)
        .with_protocol(opentelemetry_otlp::Protocol::Grpc)
        .build()?;

    let tracer = sdk_trace::TracerProvider::builder()
        .with_config(
            sdk_trace::Config::default()
                .with_sampler(sdk_trace::Sampler::TraceIdRatioBased(0.01))
                .with_resource(Resource::new(vec![KeyValue::new(
                    "service.name",
                    service_name,
                )])),
        )
        .with_batch_exporter(span_exporter, sdk_runtime::Tokio)
        .build();

    Ok(OpenTelemetryLayer::new(tracer.tracer("jaeger-exporter")))
}
