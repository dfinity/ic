use crate::{sandbox_safe_system_state::SandboxSafeSystemState, valid_subslice};
use ic_interfaces::execution_environment::{HypervisorError, HypervisorResult};
use ic_logger::ReplicaLogger;
use ic_types::Time;
use ic_types::{
    messages::{CallContextId, Request, NO_DEADLINE},
    methods::{Callback, WasmClosure},
    time::CoarseTime,
    CanisterId, Cycles, NumBytes, PrincipalId,
};
use serde::{Deserialize, Serialize};
use std::{convert::TryFrom, time::Duration};

/// Represents an under construction `Request`.
///
/// The main differences from a `Request` are:
///
/// 1. The `callee` is stored as a `PrincipalId` instead of a `CanisterId`. If
///    the request is targeted to the management canister, then converting to
///    `CanisterId` requires the entire payload to be present which we are only
///    guaranteed to have available when `ic0_call_perform` is invoked.
///
/// 2. The `on_reply` and `on_reject` callbacks are stored as `WasmClosure`s so
///    we can register them when `ic0_call_perform` is invoked. Eagerly registering
///    them would require us to perform clean up in case the canister does not
///    actually call `ic0_call_perform`.
///
/// This is marked "serializable" because ApiType must be serializable. This
/// does not make much sense, actually -- it never needs to be transferred
/// across processes. It should probably be moved out of ApiType (such that
/// "mutable" bits are not part of it).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RequestInPrep {
    sender: CanisterId,
    callee: PrincipalId,
    on_reply: WasmClosure,
    on_reject: WasmClosure,
    on_cleanup: Option<WasmClosure>,
    cycles: Cycles,
    method_name: String,
    method_payload: Vec<u8>,
    /// The maximum size of a message that will go to a canister on another
    /// subnet.
    max_size_remote_subnet: NumBytes,
    /// Multiplying this with `max_size_remote_subnet` results in the maximum
    /// size of a message that will go to a canister on the same subnet. This
    /// could be stored as a `NumBytes` just like `max_size_remote_subnet`
    /// however then both limits will have the same type and we could easily mix
    /// them up creating tricky bugs. Storing this an integer means that the two
    /// limits are stored as different types and are more difficult to mix up.
    multiplier_max_size_local_subnet: u64,
    /// If `Some(_)`, this is a best-effort call.
    timeout_seconds: Option<u32>,
}

impl RequestInPrep {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        sender: CanisterId,
        callee_src: usize,
        callee_size: usize,
        method_name_src: usize,
        method_name_len: usize,
        heap: &[u8],
        on_reply: WasmClosure,
        on_reject: WasmClosure,
        max_size_remote_subnet: NumBytes,
        multiplier_max_size_local_subnet: u64,
        max_sum_exported_function_name_lengths: usize,
    ) -> HypervisorResult<Self> {
        let method_name = {
            // Check the conditions for method_name length separately to provide
            // a more specific error message instead of combining both based on
            // the minimum of the limits.

            // method_name checked against sum of exported function names.
            if method_name_len > max_sum_exported_function_name_lengths {
                return Err(HypervisorError::UserContractViolation {
                    error: format!(
                        "Size of method_name {} exceeds the allowed limit of {}.",
                        method_name_len, max_sum_exported_function_name_lengths
                    ),
                    suggestion: "".to_string(),
                    doc_link: "".to_string(),
                });
            }

            // method_name checked against payload on the call.
            let max_size_local_subnet = max_size_remote_subnet * multiplier_max_size_local_subnet;
            if method_name_len as u64 > max_size_local_subnet.get() {
                return Err(HypervisorError::UserContractViolation {
                    error: format!(
                        "Size of method_name {} exceeds the allowed limit of {}.",
                        method_name_len, max_size_local_subnet
                    ),
                    suggestion: "".to_string(),
                    doc_link: "".to_string(),
                });
            }
            let method_name = valid_subslice(
                "ic0.call_new method_name",
                method_name_src,
                method_name_len,
                heap,
            )?;
            String::from_utf8_lossy(method_name).to_string()
        };

        let callee = {
            let bytes = valid_subslice("ic0.call_new callee_src", callee_src, callee_size, heap)?;
            PrincipalId::try_from(bytes).map_err(HypervisorError::InvalidPrincipalId)?
        };

        Ok(Self {
            sender,
            callee,
            on_reply,
            on_reject,
            on_cleanup: None,
            cycles: Cycles::zero(),
            method_name,
            method_payload: Vec::new(),
            max_size_remote_subnet,
            multiplier_max_size_local_subnet,
            timeout_seconds: None,
        })
    }

    pub(crate) fn set_on_cleanup(&mut self, on_cleanup: WasmClosure) -> HypervisorResult<()> {
        if self.on_cleanup.is_some() {
            Err(HypervisorError::ToolchainContractViolation{
                error: "ic0.call_on_cleanup can be called at most once between `ic0.call_new` and `ic0.call_perform`"
                    .to_string(),
            })
        } else {
            self.on_cleanup = Some(on_cleanup);
            Ok(())
        }
    }

    pub(crate) fn take_cycles(self) -> Cycles {
        self.cycles
    }

    pub(crate) fn extend_method_payload(
        &mut self,
        src: usize,
        size: usize,
        heap: &[u8],
    ) -> HypervisorResult<()> {
        let current_size = self.method_name.len() + self.method_payload.len();
        let max_size_local_subnet =
            self.max_size_remote_subnet * self.multiplier_max_size_local_subnet;
        if size as u64 > max_size_local_subnet.get() - current_size as u64 {
            Err(HypervisorError::UserContractViolation {
                error: format!(
                "Request to {}:{} has a payload size of {}, which exceeds the allowed limit of {}.",
                self.callee,
                self.method_name,
                current_size + size,
                max_size_local_subnet
            ),
                suggestion: "".to_string(),
                doc_link: "".to_string(),
            })
        } else {
            let data = valid_subslice("ic0.call_data_append", src, size, heap)?;
            self.method_payload.extend_from_slice(data);
            Ok(())
        }
    }

    pub(crate) fn is_timeout_set(&self) -> bool {
        self.timeout_seconds.is_some()
    }

    pub(crate) fn set_timeout(&mut self, timeout_seconds: u32) {
        self.timeout_seconds = Some(timeout_seconds);
    }

    pub(crate) fn add_cycles(&mut self, cycles: Cycles) {
        self.cycles += cycles;
    }

    pub(crate) fn current_payload_size(&self) -> NumBytes {
        ((self.method_payload.len() + self.method_name.len()) as u64).into()
    }
}

pub(crate) struct RequestWithPrepayment {
    pub request: Request,
    pub prepayment_for_response_execution: Cycles,
    pub prepayment_for_response_transmission: Cycles,
}

/// Turns a `RequestInPrep` into a `Request`.
#[allow(clippy::too_many_arguments)]
pub(crate) fn into_request(
    RequestInPrep {
        sender,
        callee,
        on_reply,
        on_reject,
        on_cleanup,
        cycles,
        method_name,
        method_payload,
        max_size_remote_subnet,
        multiplier_max_size_local_subnet,
        timeout_seconds,
    }: RequestInPrep,
    call_context_id: CallContextId,
    sandbox_safe_system_state: &mut SandboxSafeSystemState,
    _logger: &ReplicaLogger,
    time: Time,
) -> HypervisorResult<RequestWithPrepayment> {
    let destination_canister = CanisterId::unchecked_from_principal(callee);

    let payload_size = (method_name.len() + method_payload.len()) as u64;
    {
        let max_size_local_subnet = max_size_remote_subnet * multiplier_max_size_local_subnet;
        if payload_size > max_size_local_subnet.get() {
            return Err(HypervisorError::UserContractViolation {
                error: format!(
                "Request to {}:{} has a payload size of {}, which exceeds the allowed limit of {}.",
                destination_canister,
                method_name,
                payload_size, max_size_remote_subnet
            ),
                suggestion: "".to_string(),
                doc_link: "".to_string(),
            });
        }
    }

    let prepayment_for_response_execution =
        sandbox_safe_system_state.prepayment_for_response_execution();
    let prepayment_for_response_transmission =
        sandbox_safe_system_state.prepayment_for_response_transmission();

    let deadline = if let Some(timeout_seconds) = timeout_seconds {
        match time.checked_add(Duration::from_secs(timeout_seconds.into())) {
            Some(deadline) => CoarseTime::floor(deadline),
            None => {
                debug_assert!(false);
                return Err(HypervisorError::UserContractViolation {
                    error: format!(
                        "Request to {}:{} has a timeout of {} seconds, which exceeds the allowed timeout duration.",
                        destination_canister,
                        method_name,
                        timeout_seconds
                    ).to_string(),
                    suggestion: "".to_string(),
                    doc_link: "".to_string(),
                });
            }
        }
    } else {
        NO_DEADLINE
    };

    let callback_id = sandbox_safe_system_state.register_callback(Callback::new(
        call_context_id,
        sender,
        destination_canister,
        cycles,
        prepayment_for_response_execution,
        prepayment_for_response_transmission,
        on_reply,
        on_reject,
        on_cleanup,
        deadline,
    ))?;

    let req = Request {
        sender,
        receiver: destination_canister,
        method_name,
        method_payload,
        sender_reply_callback: callback_id,
        payment: cycles,
        metadata: Some(sandbox_safe_system_state.request_metadata.clone()),
        deadline,
    };
    // We cannot call `Request::payload_size_bytes()` before constructing the
    // request, so ensure our separate calculation matches the actual size.
    debug_assert_eq!(
        req.payload_size_bytes().get(),
        payload_size,
        "Inconsistent request payload size calculation"
    );

    Ok(RequestWithPrepayment {
        request: req,
        prepayment_for_response_execution,
        prepayment_for_response_transmission,
    })
}

#[cfg(test)]
mod tests;
