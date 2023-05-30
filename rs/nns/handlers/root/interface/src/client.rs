use crate::{
    ChangeCanisterControllersError, ChangeCanisterControllersRequest,
    ChangeCanisterControllersResponse, ChangeCanisterControllersResult,
};
use async_trait::async_trait;
use dfn_candid::candid_one;
use dfn_core::call;
use ic_nns_constants::ROOT_CANISTER_ID;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

/// A trait for interacting with the APIs of the NNS Root Canister.
#[async_trait]
pub trait NnsRootCanisterClient {
    async fn change_canister_controllers(
        &self,
        change_canister_controllers_request: ChangeCanisterControllersRequest,
    ) -> Result<ChangeCanisterControllersResponse, (Option<i32>, String)>;
}

/// An example implementation of the NnsRootCanisterClient trait.
#[derive(Default)]
pub struct NnsRootCanisterClientImpl {}

/// Implementation of the NnsRootCanisterClient trait for the NnsRootCanisterClientImpl struct.
#[async_trait]
impl NnsRootCanisterClient for NnsRootCanisterClientImpl {
    async fn change_canister_controllers(
        &self,
        change_canister_controllers_request: ChangeCanisterControllersRequest,
    ) -> Result<ChangeCanisterControllersResponse, (Option<i32>, String)> {
        call(
            ROOT_CANISTER_ID,
            "change_canister_controllers",
            candid_one,
            change_canister_controllers_request,
        )
        .await
    }
}

/// An example implementation of the NnsRootCanisterClient trait to be used in unit tests.
pub struct SpyNnsRootCanisterClient {
    observed_calls: Arc<Mutex<VecDeque<SpyNnsRootCanisterClientCall>>>,
    replies: Arc<Mutex<VecDeque<SpyNnsRootCanisterClientReply>>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SpyNnsRootCanisterClientCall {
    ChangeCanisterControllers(ChangeCanisterControllersRequest),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SpyNnsRootCanisterClientReply {
    ChangeCanisterControllers(Result<ChangeCanisterControllersResponse, (Option<i32>, String)>),
}

impl ChangeCanisterControllersResponse {
    pub fn new_with_error(code: Option<i32>, description: String) -> Self {
        Self {
            change_canister_controllers_result: ChangeCanisterControllersResult::Err(
                ChangeCanisterControllersError { code, description },
            ),
        }
    }

    pub fn new_with_ok() -> Self {
        Self {
            change_canister_controllers_result: ChangeCanisterControllersResult::Ok(()),
        }
    }
}

#[async_trait]
impl NnsRootCanisterClient for SpyNnsRootCanisterClient {
    async fn change_canister_controllers(
        &self,
        change_canister_controllers_request: ChangeCanisterControllersRequest,
    ) -> Result<ChangeCanisterControllersResponse, (Option<i32>, String)> {
        self.observed_calls.lock().unwrap().push_back(
            SpyNnsRootCanisterClientCall::ChangeCanisterControllers(
                change_canister_controllers_request.clone(),
            ),
        );

        let reply = self.replies.lock().unwrap().pop_front().unwrap_or_else(|| {
            panic!(
                "More calls were made to SpyNnsRootCanisterClient then expected. Last call {:?}",
                change_canister_controllers_request
            )
        });

        match reply {
            SpyNnsRootCanisterClientReply::ChangeCanisterControllers(response) => response,
        }
    }
}

impl SpyNnsRootCanisterClient {
    pub fn new(replies: Vec<SpyNnsRootCanisterClientReply>) -> Self {
        Self {
            observed_calls: Arc::new(Mutex::new(VecDeque::new())),
            replies: Arc::new(Mutex::new(VecDeque::from(replies))),
        }
    }

    pub fn get_calls_snapshot(&self) -> Vec<SpyNnsRootCanisterClientCall> {
        self.observed_calls.lock().unwrap().clone().into()
    }

    pub fn assert_all_replies_consumed(&self) {
        assert!(self.replies.lock().unwrap().is_empty())
    }
}

impl Drop for SpyNnsRootCanisterClient {
    fn drop(&mut self) {
        self.assert_all_replies_consumed()
    }
}

impl SpyNnsRootCanisterClientReply {
    pub fn ok_from_root() -> SpyNnsRootCanisterClientReply {
        SpyNnsRootCanisterClientReply::ChangeCanisterControllers(Ok(
            ChangeCanisterControllersResponse {
                change_canister_controllers_result: ChangeCanisterControllersResult::Ok(()),
            },
        ))
    }

    pub fn err_from_root(code: Option<i32>, description: String) -> SpyNnsRootCanisterClientReply {
        SpyNnsRootCanisterClientReply::ChangeCanisterControllers(Ok(
            ChangeCanisterControllersResponse {
                change_canister_controllers_result: ChangeCanisterControllersResult::Err(
                    ChangeCanisterControllersError { code, description },
                ),
            },
        ))
    }

    pub fn err_from_replica(
        code: Option<i32>,
        description: String,
    ) -> SpyNnsRootCanisterClientReply {
        SpyNnsRootCanisterClientReply::ChangeCanisterControllers(Err((code, description)))
    }
}
