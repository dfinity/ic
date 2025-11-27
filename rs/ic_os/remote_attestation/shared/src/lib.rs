pub const DEFAULT_PORT: u16 = 19523;

pub mod proto {
    tonic::include_proto!("remote_attestation");
}
