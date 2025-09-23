use crate::{
    error::{RecoveryError, RecoveryResult},
    file_sync_helper::write_bytes,
};

use ic_base_types::{NodeId, PrincipalId, SubnetId};
use serde::{Deserialize, Serialize};
use slog::{Drain, Logger, o};
use std::{
    fmt,
    net::{IpAddr, Ipv6Addr},
};
use std::{future::Future, path::Path, str::FromStr};
use tokio::runtime::Runtime;

pub enum SshUser {
    Admin,
    Readonly,
    Backup,
}

impl fmt::Display for SshUser {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SshUser::Admin => write!(f, "admin"),
            SshUser::Readonly => write!(f, "readonly"),
            SshUser::Backup => write!(f, "backup"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum DataLocation {
    Local,
    Remote(IpAddr),
}

pub fn data_location_from_str(s: &str) -> RecoveryResult<DataLocation> {
    if s == "local" {
        return Ok(DataLocation::Local);
    }
    Ok(DataLocation::Remote(IpAddr::V6(
        Ipv6Addr::from_str(s).map_err(|e| {
            RecoveryError::UnexpectedError(format!("Unable to parse ipv6 address {e:?}"))
        })?,
    )))
}

pub fn block_on<F: Future>(f: F) -> F::Output {
    let rt = Runtime::new().unwrap_or_else(|err| panic!("Could not create tokio runtime: {err}"));
    rt.block_on(f)
}

pub fn parse_hex_str(string: &str) -> RecoveryResult<u64> {
    u64::from_str_radix(string, 16).map_err(|e| {
        RecoveryError::invalid_output_error(format!(
            "Could not read checkpoint height from dir name '{string}': {e}"
        ))
    })
}

pub fn subnet_id_from_str(s: &str) -> RecoveryResult<SubnetId> {
    PrincipalId::from_str(s)
        .map_err(|e| RecoveryError::UnexpectedError(format!("Unable to parse subnet_id {e:?}")))
        .map(SubnetId::from)
}

pub fn node_id_from_str(s: &str) -> RecoveryResult<NodeId> {
    PrincipalId::from_str(s)
        .map_err(|e| RecoveryError::UnexpectedError(format!("Unable to parse node_id {e:?}")))
        .map(NodeId::from)
}

pub fn make_logger() -> Logger {
    let decorator = slog_term::TermDecorator::new().build();
    let drain = slog_term::FullFormat::new(decorator).build().fuse();
    let drain = slog_async::Async::new(drain).build().fuse();
    slog::Logger::root(drain, o!())
}

pub fn write_public_key_to_file(der_bytes: &[u8], path: &Path) -> RecoveryResult<()> {
    let mut bytes = vec![];
    bytes.extend_from_slice(b"-----BEGIN PUBLIC KEY-----\n");
    for chunk in base64::encode(der_bytes).as_bytes().chunks(64) {
        bytes.extend_from_slice(chunk);
        bytes.extend_from_slice(b"\n");
    }
    bytes.extend_from_slice(b"-----END PUBLIC KEY-----\n");

    write_bytes(path, bytes)
}
