use crate::protocol::{Payload, Response};
use std::sync::{Arc, Condvar, Mutex};

#[derive(Default)]
pub(crate) struct GuestUpgradeService(Mutex<GuestUpgradeSession>);

#[derive(Default)]
struct GuestUpgradeServiceState {
    old_vm_nonce: Option<Vec<u8>>,
    old_vm_encrypted_data_key_encryption_key: Option<Vec<u8>>,
    new_vm_nonce: Option<Vec<u8>>,
    new_vm_attestation_report: Option<Vec<u8>>,
}

struct InitiateUpgradeResponse {
    new_vm_attestation_report: Vec<u8>,
}

impl GuestUpgradeService {
    pub fn init_upgrade(&self, old_vm_nonce: &[u8]) -> Response {
        self.0.lock().unwrap().old_vm_nonce = Some(old_vm_nonce.to_vec());
        let state = self
            .1
            .wait_while(self.0.lock().unwrap(), |state| {
                state.new_vm_attestation_report.is_none()
            })
            .unwrap();
        Ok(Payload::NewVmData {
            attestation_report: state.new_vm_attestation_report.clone().unwrap(),
        })
    }

    pub fn initiate_get_data_key_encryption_key(&self, new_vm_nonce: &[u8]) -> Vec<u8> {
        let mut state = self.0.lock().unwrap();
        state.new_vm_nonce = Some(new_vm_nonce.to_vec());
        state.old_vm_nonce.clone().unwrap()
    }

    pub fn get_data_key_encryption_key(&self, attestation_report: &[u8]) -> Response {
        let mut state = self.0.lock().unwrap();
        state.new_vm_attestation_report = Some(attestation_report.to_vec());
        self.1.notify_all();
    }
}
