use ic_nns_governance_api::{
    GuestLaunchMeasurement, GuestLaunchMeasurementMetadata, GuestLaunchMeasurements,
};
use ic_protobuf::registry::replica_version::v1::{
    GuestLaunchMeasurement as PbGuestLaunchMeasurement,
    GuestLaunchMeasurementMetadata as PbGuestLaunchMeasurementMetadata,
    GuestLaunchMeasurements as PbGuestLaunchMeasurements,
};

pub fn convert_guest_launch_measurements_from_pb_to_api(
    item: PbGuestLaunchMeasurements,
) -> GuestLaunchMeasurements {
    GuestLaunchMeasurements {
        guest_launch_measurements: Some(
            item.guest_launch_measurements
                .into_iter()
                .map(convert_guest_launch_measurement_from_pb_to_api)
                .collect(),
        ),
    }
}

pub fn convert_guest_launch_measurements_from_api_to_pb(
    item: GuestLaunchMeasurements,
) -> PbGuestLaunchMeasurements {
    PbGuestLaunchMeasurements {
        guest_launch_measurements: item
            .guest_launch_measurements
            .unwrap_or_default()
            .into_iter()
            .map(convert_guest_launch_measurement_from_api_to_pb)
            .collect(),
    }
}

fn convert_guest_launch_measurement_from_pb_to_api(
    item: PbGuestLaunchMeasurement,
) -> GuestLaunchMeasurement {
    GuestLaunchMeasurement {
        measurement: Some(item.measurement),
        metadata: item
            .metadata
            .map(convert_guest_launch_measurement_metadata_from_pb_to_api),
    }
}

fn convert_guest_launch_measurement_from_api_to_pb(
    item: GuestLaunchMeasurement,
) -> PbGuestLaunchMeasurement {
    PbGuestLaunchMeasurement {
        measurement: item.measurement.unwrap_or_default(),
        metadata: item
            .metadata
            .map(convert_guest_launch_measurement_metadata_from_api_to_pb),
    }
}

fn convert_guest_launch_measurement_metadata_from_pb_to_api(
    item: PbGuestLaunchMeasurementMetadata,
) -> GuestLaunchMeasurementMetadata {
    GuestLaunchMeasurementMetadata {
        kernel_cmdline: item.kernel_cmdline,
    }
}

fn convert_guest_launch_measurement_metadata_from_api_to_pb(
    item: GuestLaunchMeasurementMetadata,
) -> PbGuestLaunchMeasurementMetadata {
    PbGuestLaunchMeasurementMetadata {
        kernel_cmdline: item.kernel_cmdline,
    }
}
