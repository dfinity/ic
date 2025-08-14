//! The following are helpers for tests that use ICOS images. Each artifact has the triplet (version, URL, hash).

use crate::driver::test_env_api::read_dependency_from_env_to_string;
use anyhow::{Context, Result};
use ic_protobuf::registry::replica_version::v1::GuestLaunchMeasurements;
use ic_types::ReplicaVersion;
use url::Url;

/// Pull the version of the initial GuestOS image from the environment.
pub fn get_guestos_img_version() -> Result<ReplicaVersion> {
    let replica_version =
        ReplicaVersion::try_from(std::env::var("ENV_DEPS__GUESTOS_DISK_IMG_VERSION")?)?;

    Ok(replica_version)
}

/// Pull the URL of the initial GuestOS image from the environment.
pub fn get_guestos_img_url() -> Result<Url> {
    let url = Url::parse(&std::env::var("ENV_DEPS__GUESTOS_DISK_IMG_URL")?)?;

    Ok(url)
}

/// Pull the hash of the initial GuestOS image from the environment.
pub fn get_guestos_img_sha256() -> Result<String> {
    Ok(std::env::var("ENV_DEPS__GUESTOS_DISK_IMG_HASH")?)
}

/// Pull the URL of the initial GuestOS update image from the environment.
///
/// With the initial image, there is also a corresponding initial update image.
/// The version is shared, so only the URL and hash are provided.
pub fn get_guestos_initial_update_img_url() -> Result<Url> {
    let url = Url::parse(&std::env::var("ENV_DEPS__GUESTOS_INITIAL_UPDATE_IMG_URL")?)?;

    Ok(url)
}

/// Pull the hash of the initial GuestOS update image from the environment.
///
/// With the initial image, there is also a corresponding initial update image.
/// The version is shared, so only the URL and hash are provided.
pub fn get_guestos_initial_update_img_sha256() -> Result<String> {
    Ok(std::env::var("ENV_DEPS__GUESTOS_INITIAL_UPDATE_IMG_HASH")?)
}

/// Pull the launch measurement of the initial GuestOS update image from the environment.
pub fn get_guestos_initial_launch_measurements() -> Result<Option<GuestLaunchMeasurements>> {
    read_guest_launch_measurements("ENV_DEPS__GUESTOS_INITIAL_LAUNCH_MEASUREMENTS_FILE")
}

/// Pull the version of the initial unassigned nodes GuestOS update image from the environment.
///
/// This is the version that unassigned nodes will use for their initial update image.
/// Falls back to the regular GuestOS initial update image version if not specified.
pub fn get_guestos_initial_unassigned_update_img_version() -> Result<ReplicaVersion> {
    let env_var = std::env::var("ENV_DEPS__GUESTOS_INITIAL_UNASSIGNED_UPDATE_IMG_VERSION")
        .or_else(|_| std::env::var("ENV_DEPS__GUESTOS_INITIAL_UPDATE_IMG_VERSION"))?;
    let replica_version = ReplicaVersion::try_from(env_var)?;

    Ok(replica_version)
}

/// Pull the URL of the initial unassigned nodes GuestOS update image from the environment.
///
/// This is the URL that unassigned nodes will use to download their initial update image.
/// Falls back to the regular GuestOS initial update image URL if not specified.
pub fn get_guestos_initial_unassigned_update_img_url() -> Result<Url> {
    let env_var = std::env::var("ENV_DEPS__GUESTOS_INITIAL_UNASSIGNED_UPDATE_IMG_URL")
        .or_else(|_| std::env::var("ENV_DEPS__GUESTOS_INITIAL_UPDATE_IMG_URL"))?;
    let url = Url::parse(&env_var)?;

    Ok(url)
}

/// Pull the hash of the initial unassigned nodes GuestOS update image from the environment.
///
/// This is the hash that unassigned nodes will use to verify their initial update image.
/// Falls back to the regular GuestOS initial update image hash if not specified.
pub fn get_guestos_initial_unassigned_update_img_sha256() -> Result<String> {
    let env_var = std::env::var("ENV_DEPS__GUESTOS_INITIAL_UNASSIGNED_UPDATE_IMG_HASH")
        .or_else(|_| std::env::var("ENV_DEPS__GUESTOS_INITIAL_UPDATE_IMG_HASH"))?;
    Ok(env_var)
}

/// Pull the version of the target GuestOS update image from the environment.
pub fn get_guestos_update_img_version() -> Result<ReplicaVersion> {
    let replica_version =
        ReplicaVersion::try_from(std::env::var("ENV_DEPS__GUESTOS_UPDATE_IMG_VERSION")?)?;

    Ok(replica_version)
}

/// Pull the URL of the target GuestOS update image from the environment.
pub fn get_guestos_update_img_url() -> Result<Url> {
    let url = Url::parse(&std::env::var("ENV_DEPS__GUESTOS_UPDATE_IMG_URL")?)?;

    Ok(url)
}

/// Pull the hash of the target GuestOS update image from the environment.
pub fn get_guestos_update_img_sha256() -> Result<String> {
    Ok(std::env::var("ENV_DEPS__GUESTOS_UPDATE_IMG_HASH")?)
}

/// Pull the launch measurement of the target GuestOS update image from the environment.
pub fn get_guestos_launch_measurements() -> Result<Option<GuestLaunchMeasurements>> {
    read_guest_launch_measurements("ENV_DEPS__GUESTOS_LAUNCH_MEASUREMENTS_FILE")
}

/// Pull the version of the initial SetupOS image from the environment.
pub fn get_setupos_img_version() -> Result<ReplicaVersion> {
    let replica_version =
        ReplicaVersion::try_from(std::env::var("ENV_DEPS__SETUPOS_DISK_IMG_VERSION")?)?;

    Ok(replica_version)
}

/// Pull the URL of the initial SetupOS image from the environment.
pub fn get_setupos_img_url() -> Result<Url> {
    let url = Url::parse(&std::env::var("ENV_DEPS__SETUPOS_DISK_IMG_URL")?)?;

    Ok(url)
}

/// Pull the hash of the initial SetupOS image from the environment.
pub fn get_setupos_img_sha256() -> Result<String> {
    Ok(std::env::var("ENV_DEPS__SETUPOS_DISK_IMG_HASH")?)
}

/// Pull the version of the target HostOS update image from the environment.
pub fn get_hostos_update_img_version() -> Result<ReplicaVersion> {
    let replica_version =
        ReplicaVersion::try_from(std::env::var("ENV_DEPS__HOSTOS_UPDATE_IMG_VERSION")?)?;

    Ok(replica_version)
}

/// Pull the URL of the target HostOS update image from the environment.
pub fn get_hostos_update_img_url() -> Result<Url> {
    let url = Url::parse(&std::env::var("ENV_DEPS__HOSTOS_UPDATE_IMG_URL")?)?;

    Ok(url)
}

/// Pull the hash of the target HostOS update image from the environment.
pub fn get_hostos_update_img_sha256() -> Result<String> {
    Ok(std::env::var("ENV_DEPS__HOSTOS_UPDATE_IMG_HASH")?)
}

fn read_guest_launch_measurements(v: &str) -> Result<Option<GuestLaunchMeasurements>> {
    // The launch measurements are not always set.
    // TODO(NODE-1652): Remove this check once the environment variable is always set.
    if std::env::var(v).is_ok() {
        serde_json::from_str(&read_dependency_from_env_to_string(v)?)
            .context("Could not deserialize guest launch measurements")
    } else {
        Ok(None)
    }
}
