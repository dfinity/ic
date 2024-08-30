use crate::{
    ChangeCanisterControllersError, ChangeCanisterControllersRequest,
    ChangeCanisterControllersResponse, ChangeCanisterControllersResult,
};
use async_trait::async_trait;
use dfn_candid::candid_one;
use dfn_core::call;
use ic_base_types::PrincipalId;
use ic_nervous_system_clients::{
    canister_id_record::CanisterIdRecord,
    canister_status::{
        CanisterStatusResult, CanisterStatusType, DefiniteCanisterSettings, LogVisibility,
    },
};
use ic_nns_constants::ROOT_CANISTER_ID;
use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
};

/// A trait for interacting with the APIs of the NNS Root Canister.
#[async_trait]
pub trait NnsRootCanisterClient {
    async fn change_canister_controllers(
        &self,
        change_canister_controllers_request: ChangeCanisterControllersRequest,
    ) -> Result<ChangeCanisterControllersResponse, (Option<i32>, String)>;

    async fn canister_status(
        &self,
        canister_id_record: CanisterIdRecord,
    ) -> Result<CanisterStatusResult, (Option<i32>, String)>;
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

    async fn canister_status(
        &self,
        canister_id_record: CanisterIdRecord,
    ) -> Result<CanisterStatusResult, (Option<i32>, String)> {
        call(
            ROOT_CANISTER_ID,
            "canister_status",
            candid_one,
            canister_id_record,
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
    CanisterStatus(CanisterIdRecord),
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
pub enum SpyNnsRootCanisterClientReply {
    ChangeCanisterControllers(Result<ChangeCanisterControllersResponse, (Option<i32>, String)>),
    CanisterStatus(Result<CanisterStatusResult, (Option<i32>, String)>),
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

        // This is split into two statements to make sure that the lock is released
        // before we attempt to unwrap (which may panic). If the lock is held
        // during a panic, it becomes "poisoned" and can't be locked again.
        let reply = self.replies.lock().unwrap().pop_front();
        let reply = reply.unwrap_or_else(|| {
            panic!(
                "More calls were made to SpyNnsRootCanisterClient then expected. Last call change_canister_controllers({:?})",
                change_canister_controllers_request
            )
        });

        match reply {
            SpyNnsRootCanisterClientReply::ChangeCanisterControllers(response) => response,
            reply => panic!(
                "Expected a ChangeCanisterControllers reply. Instead have {:?}",
                reply
            ),
        }
    }

    async fn canister_status(
        &self,
        canister_id_record: CanisterIdRecord,
    ) -> Result<CanisterStatusResult, (Option<i32>, String)> {
        self.observed_calls.lock().unwrap().push_back(
            SpyNnsRootCanisterClientCall::CanisterStatus(canister_id_record),
        );

        // This is split into two statements to make sure that the lock is released
        // before we attempt to unwrap (which may panic). If the lock is held
        // during a panic, it becomes "poisoned" and can't be locked again.
        let reply = self.replies.lock().unwrap().pop_front();
        let reply = reply.unwrap_or_else(|| {
            panic!(
                "More calls were made to SpyNnsRootCanisterClient then expected. Last call canister_status({:?})",
                canister_id_record
            )
        });

        match reply {
            SpyNnsRootCanisterClientReply::CanisterStatus(response) => response,
            reply => panic!("Expected a CanisterStatus reply. Instead have {:?}", reply),
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

    #[track_caller]
    pub fn assert_all_replies_consumed(&self) {
        assert_eq!(
            self.replies.lock().unwrap().clone(),
            VecDeque::new(),
            "not all replies were consumed"
        )
    }
}

impl Drop for SpyNnsRootCanisterClient {
    fn drop(&mut self) {
        // We only want to assert if we're not currently panicking.
        // (If we are panicking, then this assert might panic too, which would
        // abort the program.)
        if !std::thread::panicking() {
            self.assert_all_replies_consumed()
        }
    }
}

impl SpyNnsRootCanisterClientReply {
    pub fn ok_change_canister_controllers_from_root() -> SpyNnsRootCanisterClientReply {
        SpyNnsRootCanisterClientReply::ChangeCanisterControllers(Ok(
            ChangeCanisterControllersResponse {
                change_canister_controllers_result: ChangeCanisterControllersResult::Ok(()),
            },
        ))
    }

    pub fn err_change_canister_controllers_from_root(
        code: Option<i32>,
        description: String,
    ) -> SpyNnsRootCanisterClientReply {
        SpyNnsRootCanisterClientReply::ChangeCanisterControllers(Ok(
            ChangeCanisterControllersResponse {
                change_canister_controllers_result: ChangeCanisterControllersResult::Err(
                    ChangeCanisterControllersError { code, description },
                ),
            },
        ))
    }

    pub fn err_change_canister_controllers_from_replica(
        code: Option<i32>,
        description: String,
    ) -> SpyNnsRootCanisterClientReply {
        SpyNnsRootCanisterClientReply::ChangeCanisterControllers(Err((code, description)))
    }

    pub fn ok_canister_status_from_root(
        controllers: Vec<PrincipalId>,
    ) -> SpyNnsRootCanisterClientReply {
        SpyNnsRootCanisterClientReply::CanisterStatus(Ok(CanisterStatusResult {
            status: CanisterStatusType::Running,
            module_hash: None,
            memory_size: Default::default(),
            settings: DefiniteCanisterSettings {
                controllers,
                compute_allocation: Some(candid::Nat::from(7_u32)),
                memory_allocation: Some(candid::Nat::from(8_u32)),
                freezing_threshold: Some(candid::Nat::from(9_u32)),
                reserved_cycles_limit: Some(candid::Nat::from(10_u32)),
                wasm_memory_limit: Some(candid::Nat::from(11_u32)),
                log_visibility: Some(LogVisibility::Controllers),
            },
            cycles: candid::Nat::from(42_u32),
            idle_cycles_burned_per_day: Some(candid::Nat::from(43_u32)),
            reserved_cycles: Some(candid::Nat::from(44_u32)),
        }))
    }

    // There is no `err_canister_status_from_root` because the NNS root's canister_status makes
    // use of the canister trap to propagate errors, therefore all errors come via the
    // replica level error
    pub fn err_canister_status_from_replica(
        code: Option<i32>,
        description: String,
    ) -> SpyNnsRootCanisterClientReply {
        SpyNnsRootCanisterClientReply::CanisterStatus(Err((code, description)))
    }
}
