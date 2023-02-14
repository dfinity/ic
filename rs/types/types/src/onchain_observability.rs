use crate::crypto::SignedBytesWithoutDomainSeparator;
use candid::{CandidType, Encode};
use std::time::SystemTime;

#[derive(Debug, CandidType)]
pub struct SignedReport {
    pub report: Report,
    pub signature: Vec<u8>,
}

#[derive(Clone, Debug, CandidType)]
pub struct Report {
    pub start_time: SystemTime,
    pub end_time: SystemTime,
    pub reporting_node_id_binary: Vec<u8>,
    pub replica_last_start: SystemTime,
    pub peer_report: Vec<PeerReport>,
    // TODO - add other fields after we prototype peer id and peer uptime %
}

#[derive(Clone, Debug, CandidType)]
pub struct PeerReport {
    pub peer_id_binary: Vec<u8>,
    pub peer_uptime_percent: f32,
}

impl SignedBytesWithoutDomainSeparator for Report {
    fn as_signed_bytes_without_domain_separator(&self) -> Vec<u8> {
        Encode!(&self).unwrap()
    }
}
