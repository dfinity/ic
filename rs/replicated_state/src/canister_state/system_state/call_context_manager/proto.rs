use super::*;
use ic_protobuf::proxy::{ProxyDecodeError, try_from_option_field};
use ic_protobuf::state::canister_state_bits::v1 as pb;
use ic_protobuf::types::v1 as pb_types;

impl From<&CallContext> for pb::CallContext {
    fn from(item: &CallContext) -> Self {
        let funds = Funds::new(item.available_cycles);
        Self {
            call_origin: Some((&item.call_origin).into()),
            responded: item.responded,
            deleted: item.deleted,
            available_funds: Some((&funds).into()),
            time_nanos: item.time.as_nanos_since_unix_epoch(),
            metadata: Some((&item.metadata).into()),
            instructions_executed: item.instructions_executed.get(),
        }
    }
}

impl TryFrom<pb::CallContext> for CallContext {
    type Error = ProxyDecodeError;
    fn try_from(value: pb::CallContext) -> Result<Self, Self::Error> {
        let funds: Funds =
            try_from_option_field(value.available_funds, "CallContext::available_funds")?;

        Ok(Self {
            call_origin: try_from_option_field(value.call_origin, "CallContext::call_origin")?,
            responded: value.responded,
            deleted: value.deleted,
            available_cycles: funds.cycles(),
            time: Time::from_nanos_since_unix_epoch(value.time_nanos),
            metadata: value
                .metadata
                .map(From::from)
                .unwrap_or(RequestMetadata::for_new_call_tree(
                    Time::from_nanos_since_unix_epoch(0),
                )),
            instructions_executed: value.instructions_executed.into(),
        })
    }
}

impl From<&CallOrigin> for pb::call_context::CallOrigin {
    fn from(item: &CallOrigin) -> Self {
        match item {
            CallOrigin::Ingress(user_id, message_id, method_name) => {
                Self::Ingress(pb::call_context::Ingress {
                    user_id: Some(user_id_into_protobuf(*user_id)),
                    message_id: message_id.as_bytes().to_vec(),
                    method_name: method_name.clone(),
                })
            }
            CallOrigin::CanisterUpdate(canister_id, callback_id, deadline, method_name) => {
                Self::CanisterUpdate(pb::call_context::CanisterUpdateOrQuery {
                    canister_id: Some(pb_types::CanisterId::from(*canister_id)),
                    callback_id: callback_id.get(),
                    deadline_seconds: deadline.as_secs_since_unix_epoch(),
                    method_name: method_name.clone(),
                })
            }
            CallOrigin::Query(user_id, method_name) => Self::UserQuery(pb::call_context::Query {
                user_id: Some(user_id_into_protobuf(*user_id)),
                method_name: method_name.clone(),
            }),
            CallOrigin::CanisterQuery(canister_id, callback_id, method_name) => {
                Self::CanisterQuery(pb::call_context::CanisterUpdateOrQuery {
                    canister_id: Some(pb_types::CanisterId::from(*canister_id)),
                    callback_id: callback_id.get(),
                    deadline_seconds: NO_DEADLINE.as_secs_since_unix_epoch(),
                    method_name: method_name.clone(),
                })
            }
            CallOrigin::SystemTask => Self::SystemTask(pb::call_context::SystemTask {}),
        }
    }
}

impl TryFrom<pb::call_context::CallOrigin> for CallOrigin {
    type Error = ProxyDecodeError;
    fn try_from(value: pb::call_context::CallOrigin) -> Result<Self, Self::Error> {
        let call_origin = match value {
            pb::call_context::CallOrigin::Ingress(pb::call_context::Ingress {
                user_id,
                message_id,
                method_name,
            }) => Self::Ingress(
                user_id_try_from_protobuf(try_from_option_field(
                    user_id,
                    "CallOrigin::Ingress::user_id",
                )?)?,
                message_id.as_slice().try_into()?,
                method_name,
            ),
            pb::call_context::CallOrigin::CanisterUpdate(
                pb::call_context::CanisterUpdateOrQuery {
                    canister_id,
                    callback_id,
                    deadline_seconds,
                    method_name,
                },
            ) => Self::CanisterUpdate(
                try_from_option_field(canister_id, "CallOrigin::CanisterUpdate::canister_id")?,
                callback_id.into(),
                CoarseTime::from_secs_since_unix_epoch(deadline_seconds),
                method_name,
            ),
            pb::call_context::CallOrigin::CanisterQuery(
                pb::call_context::CanisterUpdateOrQuery {
                    canister_id,
                    callback_id,
                    deadline_seconds: _,
                    method_name,
                },
            ) => Self::CanisterQuery(
                try_from_option_field(canister_id, "CallOrigin::CanisterQuery::canister_id")?,
                callback_id.into(),
                method_name,
            ),
            pb::call_context::CallOrigin::UserQuery(pb::call_context::Query {
                user_id,
                method_name,
            }) => Self::Query(
                user_id_try_from_protobuf(try_from_option_field(
                    user_id,
                    "CallOrigin::UserQuery::user_id",
                )?)?,
                method_name,
            ),
            pb::call_context::CallOrigin::SystemTask { .. } => Self::SystemTask,
        };
        Ok(call_origin)
    }
}

impl From<&CallContextManager> for pb::CallContextManager {
    fn from(item: &CallContextManager) -> Self {
        Self {
            next_call_context_id: item.next_call_context_id,
            next_callback_id: item.next_callback_id,
            call_contexts: item
                .call_contexts
                .iter()
                .map(|(id, context)| pb::CallContextEntry {
                    call_context_id: id.get(),
                    call_context: Some(context.into()),
                })
                .collect(),
            callbacks: item
                .callbacks
                .iter()
                .map(|(id, callback)| pb::CallbackEntry {
                    callback_id: id.get(),
                    callback: Some(callback.as_ref().into()),
                })
                .collect(),
            unexpired_callbacks: item
                .unexpired_callbacks
                .iter()
                .map(|((_, id), ())| id.get())
                .collect(),
        }
    }
}

impl TryFrom<pb::CallContextManager> for CallContextManager {
    type Error = ProxyDecodeError;
    fn try_from(value: pb::CallContextManager) -> Result<Self, Self::Error> {
        let mut call_contexts = MutableIntMap::<CallContextId, CallContext>::new();
        let mut callbacks = MutableIntMap::<CallbackId, Arc<Callback>>::new();
        for pb::CallContextEntry {
            call_context_id,
            call_context,
        } in value.call_contexts.into_iter()
        {
            call_contexts.insert(
                call_context_id.into(),
                try_from_option_field(call_context, "CallContextManager::call_contexts::V")?,
            );
        }
        for pb::CallbackEntry {
            callback_id,
            callback,
        } in value.callbacks.into_iter()
        {
            callbacks.insert(
                callback_id.into(),
                Arc::new(try_from_option_field(
                    callback,
                    "CallContextManager::callbacks::V",
                )?),
            );
        }
        let outstanding_callbacks = calculate_outstanding_callbacks(&callbacks);
        let unexpired_callbacks = value
            .unexpired_callbacks
            .into_iter()
            .map(CallbackId::from)
            .map(|callback_id| {
                let callback = callbacks.get(&callback_id).ok_or_else(|| {
                    ProxyDecodeError::Other(format!("Unexpired callback not found: {callback_id}"))
                })?;
                Ok(((callback.deadline, callback_id), ()))
            })
            .collect::<Result<_, ProxyDecodeError>>()?;
        let stats = CallContextManagerStats::calculate_stats(&call_contexts, &callbacks);

        let ccm = Self {
            next_call_context_id: value.next_call_context_id,
            next_callback_id: value.next_callback_id,
            call_contexts,
            outstanding_callbacks,
            callbacks,
            unexpired_callbacks,
            stats,
        };
        debug_assert!(ccm.stats_ok());

        Ok(ccm)
    }
}
