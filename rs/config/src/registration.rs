use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// We assume pre-agreed values when interacting with the USB HSM. The purpose
/// of this configuration is to override one or more of the default values if
/// necessary.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Config {
    /// The transport PIN required for the DC-owned USB HSM.
    #[serde(default = "pin_default")]
    pub pkcs11_keycard_transport_pin: String,

    /// The key id of the key to be used.
    #[serde(default = "key_id_default")]
    pub pkcs11_keycard_key_id: String,

    /// The slot to be used to fetch the public key.
    #[serde(default = "slot_default")]
    pub pkcs11_keycard_slot: String,

    /// During registration, this file is created the first time the node is
    /// registered with the NNS. It signals the host VM that the HSM can safely
    /// be ejected, if necessary.
    #[serde(default = "eject_keycard_signal_file")]
    pub eject_keycard_signal_file: PathBuf,

    /// When the orchestrator runs the first time, it will attempt to contact
    /// the NNS via those URLs to initialize the registry's local store.
    /// URLs should be provided coma-separated.
    pub nns_url: Option<String>,

    /// Public key of the NNS that is used to verify the response when setting
    /// up the initial state of the registry's local store.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nns_pub_key_pem: Option<PathBuf>,
}

// We allow for the operator to only specify some of the fields while the others
// assume default values. Hence we provide default methods for all fields.

fn pin_default() -> String {
    Config::default().pkcs11_keycard_transport_pin
}

fn key_id_default() -> String {
    Config::default().pkcs11_keycard_key_id
}

fn slot_default() -> String {
    Config::default().pkcs11_keycard_slot
}

fn eject_keycard_signal_file() -> PathBuf {
    Config::default().eject_keycard_signal_file
}

/// These are pre-agreed default values.
impl Default for Config {
    fn default() -> Self {
        Self {
            pkcs11_keycard_transport_pin: "358138".to_string(),
            pkcs11_keycard_key_id: "01".to_string(),
            pkcs11_keycard_slot: "0".to_string(),
            eject_keycard_signal_file: PathBuf::from("/var/lib/dfinity-node/eject-hsm"),
            nns_url: None,
            nns_pub_key_pem: None,
        }
    }
}
