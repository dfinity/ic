//! The following are helpers for tests that use ICOS images. Each artifact has the triplet (version, URL, hash).

use crate::driver::test_env_api::read_dependency_from_env_to_string;
use anyhow::Result;
use ic_protobuf::registry::replica_version::v1::GuestLaunchMeasurements;
use ic_types::{ReplicaVersion, hostos_version::HostosVersion};
use url::Url;

/// Pull the version of the initial GuestOS image from the environment.
pub fn get_guestos_img_version() -> ReplicaVersion {
    try_get_guestos_img_version().expect("Invalid ReplicaVersion")
}

/// Pull the version of the initial GuestOS image from the environment,
/// allowing failure.
pub fn try_get_guestos_img_version() -> Result<ReplicaVersion> {
    let env = "ENV_DEPS__GUESTOS_DISK_IMG_VERSION";

    Ok(ReplicaVersion::try_from(std::env::var(env)?)?)
}

/// Pull the URL of the initial GuestOS image from the environment.
pub fn get_guestos_img_url() -> Url {
    let env = "ENV_DEPS__GUESTOS_DISK_IMG_URL";

    Url::parse(&std::env::var(env).unwrap_or_else(|_| panic!("Failed to read '{env}'")))
        .expect("Invalid Url")
}

/// Pull the hash of the initial GuestOS image from the environment.
pub fn get_guestos_img_sha256() -> String {
    let env = "ENV_DEPS__GUESTOS_DISK_IMG_HASH";

    std::env::var(env).unwrap_or_else(|_| panic!("Failed to read '{env}'"))
}

/// Pull the URL of the initial GuestOS update image from the environment.
///
/// With the initial image, there is also a corresponding initial update image.
/// The version is shared, so only the URL and hash are provided.
pub fn get_guestos_initial_update_img_url() -> Url {
    let env = "ENV_DEPS__GUESTOS_INITIAL_UPDATE_IMG_URL";

    Url::parse(&std::env::var(env).unwrap_or_else(|_| panic!("Failed to read '{env}'")))
        .expect("Invalid Url")
}

/// Pull the hash of the initial GuestOS update image from the environment.
///
/// With the initial image, there is also a corresponding initial update image.
/// The version is shared, so only the URL and hash are provided.
pub fn get_guestos_initial_update_img_sha256() -> String {
    let env = "ENV_DEPS__GUESTOS_INITIAL_UPDATE_IMG_HASH";

    std::env::var(env).unwrap_or_else(|_| panic!("Failed to read '{env}'"))
}

/// Pull the launch measurement of the initial GuestOS update image from the environment.
pub fn get_guestos_initial_launch_measurements() -> GuestLaunchMeasurements {
    let env = "ENV_DEPS__GUESTOS_INITIAL_LAUNCH_MEASUREMENTS_FILE";

    serde_json::from_str(&read_dependency_from_env_to_string(env).unwrap())
        .expect("Could not deserialize guest launch measurements")
}

/// Pull the version of the target GuestOS update image from the environment.
pub fn get_guestos_update_img_version() -> ReplicaVersion {
    let env = "ENV_DEPS__GUESTOS_UPDATE_IMG_VERSION";

    ReplicaVersion::try_from(
        std::env::var(env).unwrap_or_else(|_| panic!("Failed to read '{env}'")),
    )
    .expect("Invalid ReplicaVersion")
}

/// Pull the URL of the target GuestOS update image from the environment.
pub fn get_guestos_update_img_url() -> Url {
    let env = "ENV_DEPS__GUESTOS_UPDATE_IMG_URL";

    Url::parse(&std::env::var(env).unwrap_or_else(|_| panic!("Failed to read '{env}'")))
        .expect("Invalid Url")
}

/// Pull the hash of the target GuestOS update image from the environment.
pub fn get_guestos_update_img_sha256() -> String {
    let env = "ENV_DEPS__GUESTOS_UPDATE_IMG_HASH";

    std::env::var(env).unwrap_or_else(|_| panic!("Failed to read '{env}'"))
}

/// Pull the launch measurement of the target GuestOS update image from the environment.
pub fn get_guestos_launch_measurements() -> GuestLaunchMeasurements {
    let env = "ENV_DEPS__GUESTOS_LAUNCH_MEASUREMENTS_FILE";

    serde_json::from_str(&read_dependency_from_env_to_string(env).unwrap())
        .expect("Could not deserialize guest launch measurements")
}

/// Pull the version of the initial SetupOS image from the environment.
pub fn get_setupos_img_version() -> ReplicaVersion {
    let env = "ENV_DEPS__SETUPOS_DISK_IMG_VERSION";

    ReplicaVersion::try_from(
        std::env::var(env).unwrap_or_else(|_| panic!("Failed to read '{env}'")),
    )
    .expect("Invalid ReplicaVersion")
}

/// Pull the URL of the initial SetupOS image from the environment.
pub fn get_setupos_img_url() -> Url {
    let env = "ENV_DEPS__SETUPOS_DISK_IMG_URL";

    Url::parse(&std::env::var(env).unwrap_or_else(|_| panic!("Failed to read '{env}'")))
        .expect("Invalid Url")
}

/// Pull the hash of the initial SetupOS image from the environment.
pub fn get_setupos_img_sha256() -> String {
    let env = "ENV_DEPS__SETUPOS_DISK_IMG_HASH";

    std::env::var(env).unwrap_or_else(|_| panic!("Failed to read '{env}'"))
}

/// Pull the version of the target HostOS update image from the environment.
pub fn get_hostos_update_img_version() -> HostosVersion {
    let env = "ENV_DEPS__HOSTOS_UPDATE_IMG_VERSION";

    HostosVersion::try_from(std::env::var(env).unwrap_or_else(|_| panic!("Failed to read '{env}'")))
        .expect("Invalid HostosVersion")
}

/// Pull the URL of the target HostOS update image from the environment.
pub fn get_hostos_update_img_url() -> Url {
    let env = "ENV_DEPS__HOSTOS_UPDATE_IMG_URL";

    Url::parse(&std::env::var(env).unwrap_or_else(|_| panic!("Failed to read '{env}'")))
        .expect("Invalid Url")
}

/// Pull the hash of the target HostOS update image from the environment.
pub fn get_hostos_update_img_sha256() -> String {
    let env = "ENV_DEPS__HOSTOS_UPDATE_IMG_HASH";

    std::env::var(env).unwrap_or_else(|_| panic!("Failed to read '{env}'"))
}
