use anyhow::anyhow;
use opentelemetry::{KeyValue, trace::TracerProvider};
use opentelemetry_otlp::{SpanExporter, WithExportConfig};
use opentelemetry_sdk::{Resource, runtime as sdk_runtime, trace as sdk_trace};
use tracing_opentelemetry::OpenTelemetryLayer;
use tracing_subscriber::{Layer, Registry};

pub fn jaeger_exporter(
    jaeger_addr: &str,
    service_name: &'static str,
    rt_handle: &tokio::runtime::Handle,
) -> Result<impl Layer<Registry> + Send + Sync + use<>, anyhow::Error> {
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
        .with_sampler(sdk_trace::Sampler::TraceIdRatioBased(0.01))
        .with_resource(Resource::new(vec![KeyValue::new(
            "service.name",
            service_name,
        )]))
        .with_batch_exporter(span_exporter, sdk_runtime::Tokio)
        .build();

    Ok(OpenTelemetryLayer::new(tracer.tracer("jaeger-exporter")))
}
