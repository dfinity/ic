//! Temporary client library implementing the V2-version of the REST-API which will eventually
//! replace the existing PocketIc struct.

use crate::common::rest::{CreateInstanceResponse, InstanceId};
use reqwest::Url;

pub struct PocketIcV2 {
    pub instance_id: InstanceId,
    server_url: Url,
    #[allow(dead_code)]
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

    pub fn instance_url(&self) -> Url {
        let instance_id = self.instance_id;
        self.server_url
            .join("instances/")
            .unwrap()
            .join(&format!("{instance_id}/"))
            .unwrap()
    }
}

impl Default for PocketIcV2 {
    fn default() -> Self {
        Self::new()
    }
}
