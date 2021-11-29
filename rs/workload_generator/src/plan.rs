use crate::RequestType;
use byte_unit::Byte;
use candid::Encode;
use ic_types::CanisterId;

#[derive(Clone)]
pub struct Plan {
    pub requests: usize,
    pub nonce: String,
    pub call_payload_size: Byte,
    pub call_payload: Vec<u8>,
    pub canister_id: CanisterId,
    pub request_type: RequestType,
    pub canister_method_name: String,
}

pub enum EngineCall {
    Read { method: String, arg: Vec<u8> },
    Write { method: String, arg: Vec<u8> },
}

impl Plan {
    pub fn new(
        requests: usize,
        nonce: String,
        call_payload_size: Byte,
        call_payload: Vec<u8>,
        canister_id: CanisterId,
        request_type: RequestType,
        canister_method_name: String,
    ) -> Self {
        Self {
            requests,
            nonce,
            call_payload_size,
            call_payload,
            canister_id,
            request_type,
            canister_method_name,
        }
    }

    pub fn generate_call(&self, n: usize) -> EngineCall {
        match self.request_type {
            // "read" is specific to the counter canister
            RequestType::QueryCounter => EngineCall::Read {
                method: String::from("read"),
                arg: vec![0; self.call_payload_size.get_bytes() as usize],
            },
            // "write" is specific to the counter canister
            RequestType::UpdateCounter => EngineCall::Write {
                method: String::from("write"),
                arg: vec![0; self.call_payload_size.get_bytes() as usize],
            },

            RequestType::StateSyncA if n % 3 == 0 => EngineCall::Write {
                method: String::from("change_state"),
                arg: serde_json::to_vec(&(n as u32 / 3)).unwrap(),
            },
            RequestType::StateSyncA if n % 3 == 1 => EngineCall::Write {
                method: String::from("expand_state"),
                arg: serde_json::to_vec(&(n as u32 / 3, n as u32 / 3)).unwrap(),
            },
            RequestType::StateSyncA => EngineCall::Read {
                method: String::from("read_state"),
                arg: serde_json::to_vec(&(n / 3)).unwrap(),
            },

            RequestType::CowSafetyA if n == 0 => EngineCall::Write {
                method: String::from("init_array"),
                arg: Encode!(&self.call_payload_size.get_bytes()).unwrap(),
            },
            RequestType::CowSafetyA if n % 2 == 0 => EngineCall::Write {
                method: String::from("query_and_update"),
                arg: Encode!(&((n / 2) as u8), &(self.call_payload_size.get_bytes() / 2)).unwrap(),
            },
            RequestType::CowSafetyA => EngineCall::Read {
                method: String::from("compute_sum"),
                arg: Encode!().unwrap(),
            },

            RequestType::Update => EngineCall::Write {
                method: self.canister_method_name.clone(),
                arg: self.call_payload.clone(),
            },
            RequestType::Query => EngineCall::Read {
                method: self.canister_method_name.clone(),
                arg: self.call_payload.clone(),
            },
        }
    }
}
