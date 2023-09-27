//! Temporary client library implementing the V2-version of the REST-API which will eventually
//! replace the existing PocketIc struct.

use crate::{
    common::rest::{
        ApiResponse, CreateInstanceResponse, InstanceId, RawCanisterCall, RawCanisterResult,
        RawTime, RawWasmResult,
    },
    UserError, WasmResult,
};
use candid::Principal;
use reqwest::Url;
use serde::{de::DeserializeOwned, Serialize};
use std::time::{Duration, SystemTime};

pub struct PocketIcV2 {
    pub instance_id: InstanceId,
    server_url: Url,
    reqwest_client: reqwest::blocking::Client,
}

impl PocketIcV2 {
    pub fn new() -> Self {
        let server_url = crate::start_or_reuse_server();
        let reqwest_client = reqwest::blocking::Client::new();
        use CreateInstanceResponse::*;
        let instance_id = match reqwest_client
            .post(server_url.join("v2/instances").unwrap())
            .send()
            .expect("Failed to get result")
            .json::<CreateInstanceResponse>()
            .expect("Could not parse response for create instance request")
        {
            Created { instance_id } => instance_id,
            Error { message } => panic!("{}", message),
        };

        Self {
            instance_id,
            server_url,
            reqwest_client,
        }
    }

    pub fn get_time(&self) -> SystemTime {
        let endpoint = "read/get_time";
        let result: RawTime = self.get(endpoint);
        SystemTime::UNIX_EPOCH + Duration::from_nanos(result.nanos_since_epoch)
    }

    pub fn set_time(&self, time: SystemTime) {
        let endpoint = "update/set_time";
        self.post::<(), _>(
            endpoint,
            RawTime {
                nanos_since_epoch: time
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .expect("Time went backwards")
                    .as_nanos() as u64,
            },
        );
    }

    pub fn update_call(
        &self,
        canister_id: Principal,
        sender: Principal,
        method: &str,
        payload: Vec<u8>,
    ) -> Result<WasmResult, UserError> {
        let endpoint = "update/execute_ingress_message";
        let raw_canister_call = RawCanisterCall {
            sender: sender.as_slice().to_vec(),
            canister_id: canister_id.as_slice().to_vec(),
            method: method.to_string(),
            payload,
        };

        let result: RawCanisterResult = self.post(endpoint, raw_canister_call);
        match result {
            RawCanisterResult::Ok(raw_wasm_result) => match raw_wasm_result {
                RawWasmResult::Reply(data) => Ok(WasmResult::Reply(data)),
                RawWasmResult::Reject(text) => Ok(WasmResult::Reject(text)),
            },
            RawCanisterResult::Err(user_error) => Err(user_error),
        }
    }

    fn instance_url(&self) -> Url {
        let instance_id = self.instance_id;
        self.server_url
            .join("/v2/instances/")
            .unwrap()
            .join(&format!("{instance_id}/"))
            .unwrap()
    }

    fn get<T: DeserializeOwned>(&self, endpoint: &str) -> T {
        let result = self
            .reqwest_client
            .get(self.instance_url().join(endpoint).unwrap())
            .send()
            .expect("HTTP failure")
            .into();

        match result {
            ApiResponse::Success(t) => t,
            ApiResponse::Error { message } => panic!("{}", message),
            ApiResponse::Busy { state_label, op_id } => {
                panic!("Busy: state_label: {}, op_id: {}", state_label, op_id)
            }
            ApiResponse::Started { state_label, op_id } => {
                panic!("Started: state_label: {}, op_id: {}", state_label, op_id)
            }
        }
    }

    fn post<T: DeserializeOwned, B: Serialize>(&self, endpoint: &str, body: B) -> T {
        let result = self
            .reqwest_client
            .post(self.instance_url().join(endpoint).unwrap())
            .json(&body)
            .send()
            .expect("HTTP failure")
            .into();

        match result {
            ApiResponse::Success(t) => t,
            ApiResponse::Error { message } => panic!("{}", message),
            ApiResponse::Busy { state_label, op_id } => {
                panic!("Busy: state_label: {}, op_id: {}", state_label, op_id)
            }
            ApiResponse::Started { state_label, op_id } => {
                panic!("Started: state_label: {}, op_id: {}", state_label, op_id)
            }
        }
    }
}

impl Default for PocketIcV2 {
    fn default() -> Self {
        Self::new()
    }
}
