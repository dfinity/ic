use anyhow::{Context, Result, ensure};
use ic_nns_governance_api::BlessAlternativeGuestOsVersion;
use ic_nns_governance_conversions::convert_guest_launch_measurements_from_api_to_pb;
use ic_protobuf::registry::replica_version::v1::{GuestLaunchMeasurement, GuestLaunchMeasurements};
use std::collections::HashSet;

pub fn validate_measurements(
    proposal: &BlessAlternativeGuestOsVersion,
    local_measurements_json: &str,
) -> Result<()> {
    let local_measurements: GuestLaunchMeasurements = serde_json::from_str(local_measurements_json)
        .context("Failed to parse locally generated launch measurements JSON")?;
    let proposal_measurements = proposal_measurements(proposal)?;
    let local_measurements = local_measurements.guest_launch_measurements;
    let local_measurement_bytes = measurement_bytes(&local_measurements);
    let proposal_measurement_bytes = measurement_bytes(&proposal_measurements);

    let shared_measurement_count = local_measurement_bytes
        .intersection(&proposal_measurement_bytes)
        .count();

    ensure!(
        shared_measurement_count > 0,
        "Local and proposal measurements do not overlap.\nLocal measurements: {:?}\nProposal measurements: {:?}",
        local_measurements,
        proposal_measurements,
    );

    Ok(())
}

fn measurement_bytes(measurements: &[GuestLaunchMeasurement]) -> HashSet<Vec<u8>> {
    measurements
        .iter()
        .map(|measurement| measurement.measurement.clone())
        .collect()
}

fn proposal_measurements(
    proposal: &BlessAlternativeGuestOsVersion,
) -> Result<Vec<GuestLaunchMeasurement>> {
    Ok(convert_guest_launch_measurements_from_api_to_pb(
        proposal
            .base_guest_launch_measurements
            .clone()
            .context("Proposal is missing base_guest_launch_measurements")?,
    )
    .guest_launch_measurements)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_nns_governance_api::{
        GuestLaunchMeasurement as ApiGuestLaunchMeasurement,
        GuestLaunchMeasurementMetadata as ApiGuestLaunchMeasurementMetadata,
        GuestLaunchMeasurements as ApiGuestLaunchMeasurements,
    };
    use serde_json::json;

    fn proposal(
        kernel_cmdlines: &[&str],
        measurements: &[Vec<u8>],
    ) -> BlessAlternativeGuestOsVersion {
        BlessAlternativeGuestOsVersion {
            chip_ids: Some(vec![vec![0; 64]]),
            rootfs_hash: Some("ignored-by-build-tool".into()),
            base_guest_launch_measurements: Some(ApiGuestLaunchMeasurements {
                guest_launch_measurements: Some(
                    kernel_cmdlines
                        .iter()
                        .zip(measurements.iter())
                        .map(|(kernel_cmdline, measurement)| ApiGuestLaunchMeasurement {
                            measurement: Some(measurement.clone()),
                            metadata: Some(ApiGuestLaunchMeasurementMetadata {
                                kernel_cmdline: Some((*kernel_cmdline).into()),
                                vcpu_type: Some("EPYC-Genoa".into()),
                            }),
                        })
                        .collect(),
                ),
            }),
        }
    }

    #[test]
    fn accepts_exact_measurement_match() {
        let proposal = proposal(
            &[
                "console=ttyS0 root_hash=abcd",
                "console=ttyS0 root_hash=abcd dfinity.tee=1",
            ],
            &[vec![1, 2], vec![3, 4]],
        );
        let local_measurements = json!({
            "guest_launch_measurements": [
                {"measurement": [1, 2], "metadata": {"kernel_cmdline": "console=ttyS0 root_hash=abcd", "vcpu_type": "EPYC-Genoa"}},
                {"measurement": [3, 4], "metadata": {"kernel_cmdline": "console=ttyS0 root_hash=abcd dfinity.tee=1", "vcpu_type": "EPYC-Genoa"}}
            ]
        });

        validate_measurements(&proposal, &local_measurements.to_string()).unwrap();
    }

    #[test]
    fn accepts_when_local_has_extra_measurement_but_overlap_exists() {
        let proposal = proposal(&["console=ttyS0 root_hash=abcd"], &[vec![1, 2]]);
        let local_measurements = json!({
            "guest_launch_measurements": [
                {"measurement": [1, 2], "metadata": {"kernel_cmdline": "console=ttyS0 root_hash=abcd", "vcpu_type": "EPYC-Genoa"}},
                {"measurement": [3, 4], "metadata": {"kernel_cmdline": "console=ttyS0 root_hash=abcd dfinity.tee=1", "vcpu_type": "EPYC-Genoa"}}
            ]
        });

        validate_measurements(&proposal, &local_measurements.to_string()).unwrap();
    }

    #[test]
    fn rejects_when_measurements_do_not_overlap() {
        let proposal = proposal(&["console=ttyS0 root_hash=abcd"], &[vec![1, 2]]);
        let local_measurements = json!({
            "guest_launch_measurements": [
                {"measurement": [3, 4], "metadata": {"kernel_cmdline": "console=ttyS0 root_hash=other", "vcpu_type": "EPYC-Genoa"}}
            ]
        });

        assert!(validate_measurements(&proposal, &local_measurements.to_string()).is_err());
    }
}
