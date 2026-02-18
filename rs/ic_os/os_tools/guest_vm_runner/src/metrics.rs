use crate::GuestVMType;
use anyhow::{Context, Result};
use prometheus::{Encoder, IntGaugeVec, Opts, Registry, TextEncoder};
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;

/// Metrics for the guest VM runner service
pub struct GuestVmMetrics {
    registry: Registry,
    metrics_file_path: PathBuf,

    /// Metric indicating whether the GuestOS service started successfully
    /// Labels: vm_type (default or upgrade)
    pub service_start: IntGaugeVec,
}

impl GuestVmMetrics {
    /// Create a new GuestVmMetrics instance
    pub fn new(metrics_file_path: PathBuf) -> Result<Self> {
        let registry = Registry::new();

        let service_start = IntGaugeVec::new(
            Opts::new(
                "hostos_guestos_service_start",
                "GuestOS virtual machine define state",
            ),
            &["vm_type"],
        )
        .context("Failed to create service_start gauge")?;

        registry
            .register(Box::new(service_start.clone()))
            .context("Failed to register service_start metric")?;

        Ok(Self {
            registry,
            metrics_file_path,
            service_start,
        })
    }

    /// Write all metrics to the metrics file
    pub fn write_to_file(&self) -> Result<()> {
        let metric_families = self.registry.gather();
        let encoder = TextEncoder::new();

        let mut buffer = Vec::new();
        encoder
            .encode(&metric_families, &mut buffer)
            .context("Failed to encode metrics")?;

        let mut file = File::create(&self.metrics_file_path).with_context(|| {
            format!(
                "Failed to create metrics file: {}",
                self.metrics_file_path.display()
            )
        })?;

        file.write_all(&buffer)
            .context("Failed to write metrics to file")?;

        Ok(())
    }

    /// Set the service start metric
    pub fn set_service_start(&self, vm_type: GuestVMType, success: bool) {
        self.service_start
            .with_label_values(&[vm_type.as_ref()])
            .set(if success { 1 } else { 0 });

        if let Err(e) = self.write_to_file() {
            eprintln!("Failed to write metrics to file: {e}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_metrics_values() {
        let temp_file = NamedTempFile::new().unwrap();
        let metrics = GuestVmMetrics::new(temp_file.path().to_path_buf()).unwrap();

        metrics.set_service_start(GuestVMType::Upgrade, false);

        let content = std::fs::read_to_string(temp_file.path()).unwrap();
        assert!(
            content.contains("hostos_guestos_service_start{vm_type=\"upgrade\"} 0"),
            "Content: {content}"
        );

        // Override metrics
        metrics.set_service_start(GuestVMType::Upgrade, true);

        let content = std::fs::read_to_string(temp_file.path()).unwrap();
        assert!(
            !content.contains("hostos_guestos_service_start{vm_type=\"upgrade\"} 0"),
            "Content: {content}"
        );
        assert!(
            content.contains("hostos_guestos_service_start{vm_type=\"upgrade\"} 1"),
            "Content: {content}"
        );
    }
}
