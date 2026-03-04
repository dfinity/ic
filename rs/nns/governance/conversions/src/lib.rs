use ic_nns_governance_api as api;
use ic_protobuf::registry::replica_version::v1 as pb;

pub fn convert_guest_launch_measurements_from_pb_to_api(
    item: pb::GuestLaunchMeasurements,
) -> api::GuestLaunchMeasurements {
    api::GuestLaunchMeasurements {
        guest_launch_measurements: Some(
            item.guest_launch_measurements
                .into_iter()
                .map(convert_guest_launch_measurement_from_pb_to_api)
                .collect(),
        ),
    }
}

pub fn convert_guest_launch_measurements_from_api_to_pb(
    item: api::GuestLaunchMeasurements,
) -> pb::GuestLaunchMeasurements {
    pb::GuestLaunchMeasurements {
        guest_launch_measurements: item
            .guest_launch_measurements
            .unwrap_or_default()
            .into_iter()
            .map(convert_guest_launch_measurement_from_api_to_pb)
            .collect(),
    }
}

fn convert_guest_launch_measurement_from_pb_to_api(
    item: pb::GuestLaunchMeasurement,
) -> api::GuestLaunchMeasurement {
    api::GuestLaunchMeasurement {
        measurement: Some(item.measurement),
        metadata: item
            .metadata
            .map(convert_guest_launch_measurement_metadata_from_pb_to_api),
    }
}

fn convert_guest_launch_measurement_from_api_to_pb(
    item: api::GuestLaunchMeasurement,
) -> pb::GuestLaunchMeasurement {
    pb::GuestLaunchMeasurement {
        measurement: item.measurement.unwrap_or_default(),
        metadata: item
            .metadata
            .map(convert_guest_launch_measurement_metadata_from_api_to_pb),
    }
}

fn convert_guest_launch_measurement_metadata_from_pb_to_api(
    item: pb::GuestLaunchMeasurementMetadata,
) -> api::GuestLaunchMeasurementMetadata {
    api::GuestLaunchMeasurementMetadata {
        kernel_cmdline: item.kernel_cmdline,
    }
}

fn convert_guest_launch_measurement_metadata_from_api_to_pb(
    item: api::GuestLaunchMeasurementMetadata,
) -> pb::GuestLaunchMeasurementMetadata {
    pb::GuestLaunchMeasurementMetadata {
        kernel_cmdline: item.kernel_cmdline,
    }
}
