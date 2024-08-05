use prometheus::{IntCounter, IntCounterVec, IntGauge, IntGaugeVec};
use strum::IntoEnumIterator;
use strum_macros::{EnumIter, IntoStaticStr};

pub const PROMETHEUS_HTTP_PORT: u16 = 9091;

#[derive(Clone)]
pub struct OrchestratorMetrics {
    pub ssh_access_registry_version: IntGauge,
    pub firewall_registry_version: IntGauge,
    pub ipv4_registry_version: IntGauge,
    pub reboot_duration: IntGauge,
    pub orchestrator_info: IntGaugeVec,
    pub key_rotation_status: IntGaugeVec,
    pub master_public_key_changed_errors: IntCounterVec,
    pub failed_consecutive_upgrade_checks: IntCounter,
    pub critical_error_cup_deserialization_failed: IntCounter,
}

#[derive(Copy, Clone, Debug, EnumIter, Eq, IntoStaticStr, PartialOrd, Ord, PartialEq)]
pub enum KeyRotationStatus {
    Disabled,
    TooRecent,
    Rotating,
    Registering,
    Registered,
    Error,
}

impl KeyRotationStatus {
    fn is_transient(self) -> bool {
        matches!(
            self,
            KeyRotationStatus::Registering | KeyRotationStatus::Rotating
        )
    }

    fn is_error(self) -> bool {
        matches!(self, KeyRotationStatus::Error)
    }
}

impl OrchestratorMetrics {
    pub fn new(metrics_registry: &ic_metrics::MetricsRegistry) -> Self {
        Self {
            ssh_access_registry_version: metrics_registry.int_gauge(
                "ssh_access_registry_version",
                "Registry version last used to update the SSH public keys",
            ),
            firewall_registry_version: metrics_registry.int_gauge(
                "firewall_registry_version",
                "Latest registry version used for firewall configuration",
            ),
            ipv4_registry_version: metrics_registry.int_gauge(
                "ipv4_registry_version",
                "Latest registry version used for the IPv4 configuration",
            ),
            reboot_duration: metrics_registry.int_gauge(
                "reboot_duration_seconds",
                "The time it took for the node to reboot",
            ),
            orchestrator_info: metrics_registry.int_gauge_vec(
                "ic_orchestrator_info",
                "version info for the internet computer orchestrator running.",
                &["ic_active_version"],
            ),
            key_rotation_status: metrics_registry.int_gauge_vec(
                "orchestrator_key_rotation_status",
                "The current key rotation status.",
                &["status"],
            ),
            master_public_key_changed_errors: metrics_registry.int_counter_vec(
                "orchestrator_master_public_key_changed_errors_total",
                "Critical error counter monitoring changed threshold master public keys",
                &["key_id"],
            ),
            failed_consecutive_upgrade_checks: metrics_registry.int_counter(
                "orchestrator_failed_consecutive_upgrade_checks_total",
                "Number of times the upgrade check failed consecutively",
            ),
            critical_error_cup_deserialization_failed: metrics_registry.int_counter(
                "orchestrator_cup_deserialization_failed_total",
                "Number of times the deserialization of the locally persisted CUP failed",
            ),
        }
    }

    /// Set the current key rotation status to the given status and clear all other states.
    /// If the given status is a transient state, do not clear the error status.
    pub fn observe_key_rotation_status(&self, status: KeyRotationStatus) {
        // don't clear error status when going through transient states
        KeyRotationStatus::iter()
            .filter(|s| !status.is_transient() || !s.is_error())
            .for_each(|s| {
                self.key_rotation_status
                    .with_label_values(&[s.into()])
                    .set((s == status) as i64);
            });
    }

    /// Set the error status to '1'.
    pub fn observe_key_rotation_error(&self) {
        self.key_rotation_status
            .with_label_values(&[KeyRotationStatus::Error.into()])
            .set(1);
    }
}
