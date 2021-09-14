//! Module that deals with requests to /_/artifacts/<height>

use crate::common;
use flate2::{write::GzEncoder, Compression};
use hyper::{Body, Response, StatusCode};
use ic_config::artifact_pool::BACKUP_GROUP_SIZE;
use ic_interfaces::consensus_pool::ConsensusPoolCache;
use ic_logger::{error, ReplicaLogger};
use ic_types::{Height, SubnetId};
use std::{
    fs,
    path::{Path, PathBuf},
};

/// Handles a call to /_/artifacts/<height>. Returns a gunzipped tarball of all
/// artifacts corresponding to the specified height. The folder structure inside
/// the archive is `<SUBNET_ID>/<REPLICA_VERSION>/<HEIGHT>/`.
///
/// Note that for some heights the tarball can contain two replica versions
/// (e.g. for the heights right after the catch-up-package height at which an
/// upgrade has happened).
///
/// It returns a 404 response for all heights above the
/// finalized height or when the height was already purged.
pub(crate) fn handle(
    backup_spool_path: &Path,
    subnet_id: SubnetId,
    consensus_pool_cache: &dyn ConsensusPoolCache,
    val: u64,
    log: ReplicaLogger,
) -> Response<Body> {
    match create_tarball_response(backup_spool_path, subnet_id, consensus_pool_cache, val) {
        Ok(response) => response,
        Err(err) => {
            error!(
                log,
                "Couldn't retrieve the backup artifacts for height {:?}: {:?}", val, err
            );
            let mut response = Response::new(Body::from(""));
            *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
            response
        }
    }
}

pub(crate) fn create_tarball_response(
    backup_spool_path: &Path,
    subnet_id: SubnetId,
    consensus_pool_cache: &dyn ConsensusPoolCache,
    val: u64,
) -> Result<Response<Body>, Box<dyn std::error::Error>> {
    let height = Height::from(val);

    // We do not serve non-finalized heights.
    if height > consensus_pool_cache.finalized_block().height {
        return Ok(common::make_response(StatusCode::NOT_FOUND, ""));
    }

    // Find all non-empty height folders.
    let group_key = format!("{}", (height.get() / BACKUP_GROUP_SIZE) * BACKUP_GROUP_SIZE);

    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    {
        let mut empty_tarball = true;
        let mut tar = tar::Builder::new(&mut encoder);

        for version_dir in fs::read_dir(backup_spool_path.join(subnet_id.to_string()))? {
            let version_dir = version_dir?.path();
            for group_dir in fs::read_dir(&version_dir)? {
                let group_dir = group_dir?;
                if group_dir.file_name().to_str().unwrap_or("") != group_key.clone() {
                    continue;
                }
                let height_dir = group_dir.path().join(height.to_string());
                // If the height folder exists and is non-empty, add it to the tarball.
                if height_dir.exists() && height_dir.read_dir()?.next().is_some() {
                    tar.append_dir_all(
                        PathBuf::from(subnet_id.to_string())
                            .join(version_dir.file_name().unwrap_or_default())
                            .join(&group_key)
                            .join(height.to_string()),
                        height_dir,
                    )?;
                    empty_tarball = false;
                }
            }
        }

        if empty_tarball {
            return Ok(common::make_response(StatusCode::NOT_FOUND, ""));
        }

        tar.finish()?
    }
    Ok(cached_gunzip_response(encoder.finish()?))
}

fn cached_gunzip_response(data: Vec<u8>) -> Response<Body> {
    let mut response = common::make_response(StatusCode::OK, "");
    *response.body_mut() = Body::from(data);
    use hyper::header;
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("public"),
    );
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static("application/gzip"),
    );
    response
}
