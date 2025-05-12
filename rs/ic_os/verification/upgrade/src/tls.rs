use std::any::Any;
use tokio_rustls::rustls::ConnectionCommon;

pub fn shared_key_for_attestation(connection_common: &ConnectionCommon<impl Any>) -> [u8; 32] {
    // The key must be the same on both ends of a connection, so changing the key must be done
    // carefully.
    const KEY: &'static [u8] = b"ic-upgrade-shared-key-for-attestation";
    let mut output = [0u8; 32];
    connection_common
        .export_keying_material(output.as_mut_slice(), KEY, None)
        .unwrap();

    output
}
