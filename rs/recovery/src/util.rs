use crate::{
    error::{RecoveryError, RecoveryResult},
    file_sync_helper::write_bytes,
};

use ic_base_types::{NodeId, PrincipalId, SubnetId};
use ic_crypto_utils_threshold_sig_der::public_key_der_to_pem;
use serde::{Deserialize, Serialize};
use slog::{Drain, Logger, o};
use std::{
    fmt,
    net::{IpAddr, Ipv6Addr},
};
use std::{future::Future, path::Path, str::FromStr};
use tokio::runtime::Runtime;

#[derive(Clone)]
pub enum SshUser {
    Admin,
    Readonly,
    Backup,
    Recovery,
    Other(String),
}

impl fmt::Display for SshUser {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SshUser::Admin => write!(f, "admin"),
            SshUser::Readonly => write!(f, "readonly"),
            SshUser::Backup => write!(f, "backup"),
            SshUser::Recovery => write!(f, "recovery"),
            SshUser::Other(user) => write!(f, "{}", user),
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

pub fn node_id_and_pub_key_from_str(s: &str) -> RecoveryResult<(NodeId, String)> {
    let parts: Vec<&str> = s.splitn(2, ':').collect();
    let [node_id_str, pub_key_str] = parts.as_slice() else {
        return Err(RecoveryError::UnexpectedError(format!(
            "Unable to parse node_id and public key from string: {s}"
        )));
    };

    let node_id = node_id_from_str(node_id_str)?;
    let pub_key = pub_key_str.to_string();
    Ok((node_id, pub_key))
}

pub fn make_logger() -> Logger {
    let decorator = slog_term::TermDecorator::new().build();
    let drain = slog_term::FullFormat::new(decorator).build().fuse();
    let drain = slog_async::Async::new(drain).build().fuse();
    slog::Logger::root(drain, o!())
}

pub fn write_public_key_to_file(der_bytes: &[u8], path: &Path) -> RecoveryResult<()> {
    write_bytes(path, public_key_der_to_pem(der_bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_node_id_and_pub_key_from_str() {
        let valid_node_id_str = "igjkj-job4m-om7ug-cmzok-admxb-ag2xv-xqlgk-2bxsr-ro2mx-r5i7q-hqe";
        let invalid_node_id_str = "igjkj-job4m";

        let valid_pub_key_str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPwS/0S6xH0g/xLDV0Tz7VeMZE9AKPeSbLmCsq9bY3F1 foo@dfinity.org";

        let valid_input = format!("{}:{}", valid_node_id_str, valid_pub_key_str);
        assert_eq!(
            node_id_and_pub_key_from_str(&valid_input).unwrap(),
            (
                node_id_from_str(valid_node_id_str).unwrap(),
                valid_pub_key_str.to_string()
            )
        );

        let valid_input = format!("{}::{}", valid_node_id_str, valid_pub_key_str);
        assert_eq!(
            node_id_and_pub_key_from_str(&valid_input).unwrap(),
            (
                node_id_from_str(valid_node_id_str).unwrap(),
                format!(":{}", valid_pub_key_str)
            )
        );

        let valid_input = format!("{}:{}:", valid_node_id_str, valid_pub_key_str);
        assert_eq!(
            node_id_and_pub_key_from_str(&valid_input).unwrap(),
            (
                node_id_from_str(valid_node_id_str).unwrap(),
                format!("{}:", valid_pub_key_str)
            )
        );

        let invalid_input = format!("");
        assert!(node_id_and_pub_key_from_str(&invalid_input).is_err());

        let invalid_input = format!("{}:{}", invalid_node_id_str, valid_pub_key_str);
        assert!(node_id_and_pub_key_from_str(&invalid_input).is_err());

        let invalid_input = format!("{}", valid_node_id_str);
        assert!(node_id_and_pub_key_from_str(&invalid_input).is_err());

        let invalid_input = format!("{}", valid_pub_key_str);
        assert!(node_id_and_pub_key_from_str(&invalid_input).is_err());
    }
}
