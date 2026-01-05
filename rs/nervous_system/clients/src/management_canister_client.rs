use crate::{
    canister_id_record::CanisterIdRecord,
    canister_metadata::canister_metadata,
    canister_status::{CanisterStatusResultFromManagementCanister, canister_status},
    delete_canister::delete_canister,
    stop_canister::stop_canister,
    take_canister_snapshot::take_canister_snapshot,
    update_settings::{UpdateSettings, update_settings},
};
use async_trait::async_trait;
use candid::Encode;
use ic_base_types::PrincipalId;
use ic_error_types::RejectCode;
use ic_management_canister_types_private::{
    CanisterSnapshotResponse, IC_00, TakeCanisterSnapshotArgs,
};
use ic_nervous_system_proxied_canister_calls_tracker::ProxiedCanisterCallsTracker;
use ic_nervous_system_runtime::Runtime;
use std::{
    cell::RefCell,
    collections::VecDeque,
    marker::PhantomData,
    sync::{Arc, Mutex},
    thread::LocalKey,
};

/// The management (virtual) canister trait, also known as IC_00.
/// Reference: https://internetcomputer.org/docs/current/references/ic-interface-spec/#ic-management-canister
///
/// This trait allows for injection of clients to canister for easier unit testing.
#[async_trait]
pub trait ManagementCanisterClient {
    /// A call to the `canister_status` management canister endpoint.
    async fn canister_status(
        &self,
        canister_id_record: CanisterIdRecord,
    ) -> Result<CanisterStatusResultFromManagementCanister, (i32, String)>;

    /// A call to the `update_settings` management canister endpoint.
    async fn update_settings(&self, settings: UpdateSettings) -> Result<(), (i32, String)>;

    /// A call to the `canister_metadata` management canister endpoint.
    async fn canister_metadata(
        &self,
        canister_id: PrincipalId,
        name: String,
    ) -> Result<Vec<u8>, (i32, String)>;

    fn canister_version(&self) -> Option<u64>;

    async fn stop_canister(
        &self,
        canister_id_record: CanisterIdRecord,
    ) -> Result<(), (i32, String)>;

    async fn delete_canister(
        &self,
        canister_id_record: CanisterIdRecord,
    ) -> Result<(), (i32, String)>;

    async fn take_canister_snapshot(
        &self,
        args: TakeCanisterSnapshotArgs,
    ) -> Result<CanisterSnapshotResponse, (i32, String)>;
}

/// An example implementation of the ManagementCanisterClient trait.
#[derive(Default)]
pub struct ManagementCanisterClientImpl<Rt: Runtime> {
    proxied_canister_calls_tracker: Option<&'static LocalKey<RefCell<ProxiedCanisterCallsTracker>>>,
    _phantom: PhantomData<Rt>,
}

impl<Rt: Runtime> ManagementCanisterClientImpl<Rt> {
    pub fn new(
        proxied_canister_calls_tracker: Option<
            &'static LocalKey<RefCell<ProxiedCanisterCallsTracker>>,
        >,
    ) -> Self {
        Self {
            proxied_canister_calls_tracker,
            _phantom: PhantomData,
        }
    }
}

/// Implementation of the ManagementCanisterClient trait for the ManagementCanisterClientImpl
/// using the methods defined in this crate.
#[async_trait]
impl<Rt: Runtime + Sync> ManagementCanisterClient for ManagementCanisterClientImpl<Rt> {
    async fn canister_status(
        &self,
        canister_id_record: CanisterIdRecord,
    ) -> Result<CanisterStatusResultFromManagementCanister, (i32, String)> {
        let _tracker = self.proxied_canister_calls_tracker.map(|tracker| {
            let args = Encode!(&canister_id_record).unwrap_or_default();
            ProxiedCanisterCallsTracker::start_tracking(
                tracker,
                dfn_core::api::caller(),
                IC_00,
                "canister_status",
                &args,
            )
        });

        canister_status::<Rt>(canister_id_record).await
    }

    async fn update_settings(&self, settings: UpdateSettings) -> Result<(), (i32, String)> {
        let _tracker = self.proxied_canister_calls_tracker.map(|tracker| {
            let args = Encode!(&settings).unwrap_or_default();
            ProxiedCanisterCallsTracker::start_tracking(
                tracker,
                dfn_core::api::caller(),
                IC_00,
                "update_settings",
                &args,
            )
        });

        update_settings::<Rt>(settings).await
    }

    async fn canister_metadata(
        &self,
        canister_id: PrincipalId,
        name: String,
    ) -> Result<Vec<u8>, (i32, String)> {
        let _tracker = self.proxied_canister_calls_tracker.map(|tracker| {
            let args = Encode!(&(canister_id, &name)).unwrap_or_default();
            ProxiedCanisterCallsTracker::start_tracking(
                tracker,
                dfn_core::api::caller(),
                IC_00,
                "canister_metadata",
                &args,
            )
        });

        canister_metadata::<Rt>(canister_id, name).await
    }

    fn canister_version(&self) -> Option<u64> {
        Some(Rt::canister_version())
    }

    async fn stop_canister(
        &self,
        canister_id_record: CanisterIdRecord,
    ) -> Result<(), (i32, String)> {
        let _tracker = self.proxied_canister_calls_tracker.map(|tracker| {
            let args = Encode!(&canister_id_record).unwrap_or_default();
            ProxiedCanisterCallsTracker::start_tracking(
                tracker,
                dfn_core::api::caller(),
                IC_00,
                "stop_canister",
                &args,
            )
        });

        stop_canister::<Rt>(canister_id_record).await
    }

    async fn delete_canister(
        &self,
        canister_id_record: CanisterIdRecord,
    ) -> Result<(), (i32, String)> {
        let _tracker = self.proxied_canister_calls_tracker.map(|tracker| {
            let args = Encode!(&canister_id_record).unwrap_or_default();
            ProxiedCanisterCallsTracker::start_tracking(
                tracker,
                dfn_core::api::caller(),
                IC_00,
                "delete_canister",
                &args,
            )
        });

        delete_canister::<Rt>(canister_id_record).await
    }

    async fn take_canister_snapshot(
        &self,
        args: TakeCanisterSnapshotArgs,
    ) -> Result<CanisterSnapshotResponse, (i32, String)> {
        let _tracker = self.proxied_canister_calls_tracker.map(|tracker| {
            let encoded_args = Encode!(&args).unwrap_or_default();
            ProxiedCanisterCallsTracker::start_tracking(
                tracker,
                dfn_core::api::caller(),
                IC_00,
                "take_canister_snapshot",
                &encoded_args,
            )
        });

        take_canister_snapshot::<Rt>(args).await
    }
}

/// A ManagementCanisterClient that wraps another ManagementCanisterClient.
///
/// As the name says, this limits the number of outstanding calls that are made to the management
/// canister.
///
/// The number of allowed outstanding calls is controlled by available_slot_count.
///
/// When there are not enough slots, Err((SysTransient, message)) is returned. Otherwise, the call
/// is simply forwarded to inner.
// This was perhaps a mistake. A possibly superior alternative would be to implement a Runtime
// (named RuntimeThatLimitsCallsFromNonNnnsCanisterPrincipals or something like that) that wraps
// another Runtime. This would be better, because then it could be used more broadly (i.e. anywhere
// that Runtime is used), not just in the special case of ManagementCanisterClient.
pub struct LimitedOutstandingCallsManagementCanisterClient<Inner>
where
    Inner: ManagementCanisterClient + Send + Sync,
{
    inner: Inner,
    available_slot_count: &'static LocalKey<RefCell<u64>>,
    is_caller_vip: bool,
}

impl<Inner> LimitedOutstandingCallsManagementCanisterClient<Inner>
where
    Inner: ManagementCanisterClient + Send + Sync,
{
    pub fn new(
        inner: Inner,
        available_slot_count: &'static LocalKey<RefCell<u64>>,
        is_caller_vip: bool,
    ) -> Self {
        Self {
            inner,
            available_slot_count,
            is_caller_vip,
        }
    }

    fn try_borrow_slot(&self) -> Result<SlotLoan, (i32, String)> {
        let used_slot_count = if self.is_caller_vip { 0 } else { 1 };

        self.available_slot_count
            .with_borrow_mut(|available_slot_count| {
                if *available_slot_count == 0 {
                    // This is somewhat of a lie, but is the best fit.
                    let code = RejectCode::SysTransient as i32;

                    let message = "Unavailable. Maybe, try again later?".to_string();

                    return Err((code, message));
                }

                *available_slot_count = available_slot_count.saturating_sub(used_slot_count);
                Ok(())
            })?;

        let available_slot_count = self.available_slot_count;
        Ok(SlotLoan {
            available_slot_count,
            used_slot_count,
        })
    }
}

#[async_trait]
impl<Inner> ManagementCanisterClient for LimitedOutstandingCallsManagementCanisterClient<Inner>
where
    Inner: ManagementCanisterClient + Send + Sync,
{
    async fn canister_status(
        &self,
        canister_id_record: CanisterIdRecord,
    ) -> Result<CanisterStatusResultFromManagementCanister, (i32, String)> {
        let _loan = self.try_borrow_slot()?;
        self.inner.canister_status(canister_id_record).await
    }

    async fn update_settings(&self, settings: UpdateSettings) -> Result<(), (i32, String)> {
        let _loan = self.try_borrow_slot()?;
        self.inner.update_settings(settings).await
    }

    async fn canister_metadata(
        &self,
        canister_id: PrincipalId,
        name: String,
    ) -> Result<Vec<u8>, (i32, String)> {
        let _loan = self.try_borrow_slot()?;
        self.inner.canister_metadata(canister_id, name).await
    }

    fn canister_version(&self) -> Option<u64> {
        // This does not actually call the management canister. This implies a few things:
        //
        //   1. No need to call try_borrow_slot, as is done elsewhere.
        //   2. It was a mistake for this method to be included in this trait.
        //   3. No need for this method to be async.
        self.inner.canister_version()
    }

    async fn stop_canister(
        &self,
        canister_id_record: CanisterIdRecord,
    ) -> Result<(), (i32, String)> {
        let _loan = self.try_borrow_slot()?;
        self.inner.stop_canister(canister_id_record).await
    }

    async fn delete_canister(
        &self,
        canister_id_record: CanisterIdRecord,
    ) -> Result<(), (i32, String)> {
        let _loan = self.try_borrow_slot()?;
        self.inner.delete_canister(canister_id_record).await
    }

    async fn take_canister_snapshot(
        &self,
        args: TakeCanisterSnapshotArgs,
    ) -> Result<CanisterSnapshotResponse, (i32, String)> {
        let _loan = self.try_borrow_slot()?;
        self.inner.take_canister_snapshot(args).await
    }
}

/// Increments available_slot_count by used_slot_count when dropped.
struct SlotLoan {
    available_slot_count: &'static LocalKey<RefCell<u64>>,
    used_slot_count: u64,
}

impl Drop for SlotLoan {
    fn drop(&mut self) {
        self.available_slot_count
            .with_borrow_mut(|available_slot_count| {
                *available_slot_count = available_slot_count.saturating_add(self.used_slot_count);
            });
    }
}

/// An example implementation of the ManagementCanisterClient trait to be used in unit-tests
#[derive(Default)]
pub struct MockManagementCanisterClient {
    calls: Arc<Mutex<VecDeque<MockManagementCanisterClientCall>>>,
    replies: Arc<Mutex<VecDeque<MockManagementCanisterClientReply>>>,
}

impl MockManagementCanisterClient {
    pub fn new(replies: Vec<MockManagementCanisterClientReply>) -> Self {
        Self {
            calls: Arc::new(Mutex::new(VecDeque::new())),
            replies: Arc::new(Mutex::new(VecDeque::from(replies))),
        }
    }

    pub fn get_calls_snapshot(&self) -> Vec<MockManagementCanisterClientCall> {
        self.calls.lock().unwrap().clone().into()
    }

    #[track_caller]
    pub fn assert_all_replies_consumed(&self) {
        assert!(self.replies.lock().unwrap().is_empty())
    }

    pub fn push_reply(&mut self, reply: MockManagementCanisterClientReply) {
        self.replies.lock().unwrap().push_back(reply)
    }
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub enum MockManagementCanisterClientCall {
    CanisterStatus(CanisterIdRecord),
    UpdateSettings(UpdateSettings),
    CanisterMetadata(PrincipalId, String),
    StopCanister(CanisterIdRecord),
    DeleteCanister(CanisterIdRecord),
    TakeCanisterSnapshot(TakeCanisterSnapshotArgs),
}

#[derive(Clone, Eq, PartialEq, Debug)]
#[allow(clippy::large_enum_variant)]
pub enum MockManagementCanisterClientReply {
    CanisterStatus(Result<CanisterStatusResultFromManagementCanister, (i32, String)>),
    UpdateSettings(Result<(), (i32, String)>),
    CanisterMetadata(Result<Vec<u8>, (i32, String)>),
    StopCanister(Result<(), (i32, String)>),
    DeleteCanister(Result<(), (i32, String)>),
    TakeCanisterSnapshot(Result<CanisterSnapshotResponse, (i32, String)>),
}

#[async_trait]
impl ManagementCanisterClient for MockManagementCanisterClient {
    async fn canister_status(
        &self,
        canister_id_record: CanisterIdRecord,
    ) -> Result<CanisterStatusResultFromManagementCanister, (i32, String)> {
        self.calls
            .lock()
            .unwrap()
            .push_back(MockManagementCanisterClientCall::CanisterStatus(
                canister_id_record,
            ));

        let reply = self
            .replies
            .lock()
            .unwrap()
            .pop_front()
            .expect("Expected a MockManagementCanisterClientCall to be on the queue.");

        match reply {
            MockManagementCanisterClientReply::CanisterStatus(response) => response,
            err => panic!(
                "Expected MockManagementCanisterClientReply::CanisterStatus to be at \
                the front of the queue. Had {err:?}"
            ),
        }
    }

    async fn update_settings(&self, settings: UpdateSettings) -> Result<(), (i32, String)> {
        self.calls
            .lock()
            .unwrap()
            .push_back(MockManagementCanisterClientCall::UpdateSettings(settings));

        let reply = self
            .replies
            .lock()
            .unwrap()
            .pop_front()
            .expect("Expected a MockManagementCanisterClientCall to be on the queue.");

        match reply {
            MockManagementCanisterClientReply::UpdateSettings(response) => response,
            err => panic!(
                "Expected MockManagementCanisterClientReply::UpdateSettings to be at \
                the front of the queue. Had {err:?}"
            ),
        }
    }

    async fn canister_metadata(
        &self,
        canister_id: PrincipalId,
        name: String,
    ) -> Result<Vec<u8>, (i32, String)> {
        self.calls
            .lock()
            .unwrap()
            .push_back(MockManagementCanisterClientCall::CanisterMetadata(
                canister_id,
                name,
            ));

        let reply = self
            .replies
            .lock()
            .unwrap()
            .pop_front()
            .expect("Expected a MockManagementCanisterClientCall to be on the queue.");

        match reply {
            MockManagementCanisterClientReply::CanisterMetadata(response) => response,
            err => panic!(
                "Expected MockManagementCanisterClientReply::CanisterMetadata to be at \
                the front of the queue. Had {:?}",
                err
            ),
        }
    }

    fn canister_version(&self) -> Option<u64> {
        None
    }

    async fn stop_canister(
        &self,
        canister_id_record: CanisterIdRecord,
    ) -> Result<(), (i32, String)> {
        self.calls
            .lock()
            .unwrap()
            .push_back(MockManagementCanisterClientCall::StopCanister(
                canister_id_record,
            ));

        let reply = self
            .replies
            .lock()
            .unwrap()
            .pop_front()
            .expect("Expected a MockManagementCanisterClientCall to be on the queue.");

        match reply {
            MockManagementCanisterClientReply::StopCanister(result) => result,
            err => panic!(
                "Expected MockManagementCanisterClientReply::StopCanister to be at \
                the front of the queue. Had {:?}",
                err
            ),
        }
    }

    async fn delete_canister(
        &self,
        canister_id_record: CanisterIdRecord,
    ) -> Result<(), (i32, String)> {
        self.calls
            .lock()
            .unwrap()
            .push_back(MockManagementCanisterClientCall::DeleteCanister(
                canister_id_record,
            ));

        let reply = self
            .replies
            .lock()
            .unwrap()
            .pop_front()
            .expect("Expected a MockManagementCanisterClientCall to be on the queue.");

        match reply {
            MockManagementCanisterClientReply::DeleteCanister(result) => result,
            err => panic!(
                "Expected MockManagementCanisterClientReply::StopCanister to be at \
                the front of the queue. Had {:?}",
                err
            ),
        }
    }

    async fn take_canister_snapshot(
        &self,
        args: TakeCanisterSnapshotArgs,
    ) -> Result<CanisterSnapshotResponse, (i32, String)> {
        self.calls
            .lock()
            .unwrap()
            .push_back(MockManagementCanisterClientCall::TakeCanisterSnapshot(args));

        let reply = self
            .replies
            .lock()
            .unwrap()
            .pop_front()
            .expect("Expected a MockManagementCanisterClientCall to be on the queue.");

        match reply {
            MockManagementCanisterClientReply::TakeCanisterSnapshot(result) => result,
            err => panic!(
                "Expected MockManagementCanisterClientReply::TakeCanisterSnapshot to be at \
                the front of the queue. Had {:?}",
                err
            ),
        }
    }
}

impl Drop for MockManagementCanisterClient {
    fn drop(&mut self) {
        self.assert_all_replies_consumed()
    }
}

#[cfg(test)]
mod tests;
