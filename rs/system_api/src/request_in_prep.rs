use crate::{valid_subslice, SystemStateAccessor};
use ic_ic00_types::IC_00;
use ic_interfaces::execution_environment::{HypervisorError, HypervisorResult};
use ic_registry_routing_table::{resolve_destination, RoutingTable};
use ic_registry_subnet_type::SubnetType;
use ic_types::{
    messages::{CallContextId, Request},
    methods::{Callback, WasmClosure},
    CanisterId, Cycles, Funds, NumBytes, PrincipalId, SubnetId, ICP,
};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, convert::TryFrom, sync::Arc};

/// Represents an under construction `Request`.
///
/// The main differences from a `Request` are:
///
/// 1. The `callee` is stored as a `PrincipalId` instead of a `CanisterId`. If
/// the request is targetted to the management canister, then converting to
/// `CanisterId` requires the entire payload to be present which we are only
/// guaranteed to have available when `ic0_call_perform` is invoked.
///
/// 2. The `on_reply` and `on_reject` callbacks are stored as `WasmClosure`s so
/// we can register them when `ic0_call_perform` is invoked. Eagerly registering
/// them would require us to perform clean up in case the canister does not
/// actually call `ic0_call_perform`.
///
/// This is marked "serializable" because ApiType must be serializable. This
/// does not make much sense, actually -- it never needs to be transferred
/// across processes. It should probably be moved out of ApiType (such that
/// "mutable" bits are not part of it).
#[derive(Clone, Debug, Serialize, Deserialize)]
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
    max_size_inter_subnet: NumBytes,
    /// Multiplying this with `max_size_inter_subnet` results in the maximum
    /// size of a message that will go to a canister on the same subnet. This
    /// could be stored as a `NumBytes` just like `max_size_inter_subnet`
    /// however then both limits will have the same type and we could easily mix
    /// them up creating tricky bugs. Storing this an integer means that the two
    /// limits are stored as different types and are more difficult to mix up.
    multiplier_max_size_intra_subnet: u64,
}

impl RequestInPrep {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        sender: CanisterId,
        callee_src: u32,
        callee_size: u32,
        method_name_src: u32,
        method_name_len: u32,
        heap: &[u8],
        on_reply: WasmClosure,
        on_reject: WasmClosure,
        max_size_inter_subnet: NumBytes,
        multiplier_max_size_intra_subnet: u64,
    ) -> HypervisorResult<Self> {
        let method_name = {
            let max_size_intra_subnet = max_size_inter_subnet * multiplier_max_size_intra_subnet;
            if method_name_len as u64 > max_size_intra_subnet.get() {
                return Err(HypervisorError::ContractViolation(format!(
                    "RequestInPrep: size of method_name {} exceeded the allowed limit intra-subnet {} inter-subnet {}",
                    callee_size, max_size_intra_subnet, max_size_inter_subnet
                )));
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
            cycles: Cycles::from(0),
            method_name,
            method_payload: Vec::new(),
            max_size_inter_subnet,
            multiplier_max_size_intra_subnet,
        })
    }

    pub(crate) fn set_on_cleanup(&mut self, on_cleanup: WasmClosure) -> HypervisorResult<()> {
        if self.on_cleanup.is_some() {
            Err(HypervisorError::ContractViolation(
                "ic0.call_on_cleanup can be called at most once between `ic0.call_new` and `ic0.call_perform`"
                    .to_string(),
            ))
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
        src: u32,
        size: u32,
        heap: &[u8],
    ) -> HypervisorResult<()> {
        let current_size = self.method_name.len() + self.method_payload.len();
        let max_size_intra_subnet =
            self.max_size_inter_subnet * self.multiplier_max_size_intra_subnet;
        if size as u64 > max_size_intra_subnet.get() - current_size as u64 {
            Err(HypervisorError::ContractViolation(format!(
                "RequestInPrep: current_size {} exceeded the allowed limit intra-subnet {} inter-subnet {}",
                current_size, max_size_intra_subnet, self.max_size_inter_subnet
            )))
        } else {
            let data = valid_subslice("ic0.call_data_append", src, size, heap)?;
            self.method_payload.extend_from_slice(data);
            Ok(())
        }
    }

    pub(crate) fn add_cycles(&mut self, cycles: Cycles) {
        self.cycles += cycles;
    }
}

/// Turns a `RequestInPrep` into a `Request`.
pub(crate) fn into_request(
    routing_table: Arc<RoutingTable>,
    subnet_records: &BTreeMap<SubnetId, SubnetType>,
    RequestInPrep {
        sender,
        callee,
        on_reply,
        on_reject,
        on_cleanup,
        cycles,
        method_name,
        method_payload,
        max_size_inter_subnet,
        multiplier_max_size_intra_subnet,
    }: RequestInPrep,
    call_context_id: CallContextId,
    own_subnet_id: SubnetId,
    own_subnet_type: SubnetType,
    system_state_accessor: &dyn SystemStateAccessor,
) -> HypervisorResult<Request> {
    let payment = Funds::new(cycles, ICP::zero());
    let (destination_canister, destination_subnet) = if callee == IC_00.get() {
        // This is a request to ic:00. Update `callee` to be the appropriate
        // subnet.
        let destination_subnet = resolve_destination(
            routing_table,
            method_name.as_str(),
            method_payload.as_slice(),
            own_subnet_id,
        )
        .map(|subnet_id| subnet_id)
        .unwrap_or_else(|_| {
            // Couldn't find the right subnet. Send it to the current subnet,
            // which will handle rejecting the request gracefully.
            own_subnet_id
        });
        (
            CanisterId::new(destination_subnet.get()).unwrap(),
            destination_subnet,
        )
    } else {
        let destination_canister =
            CanisterId::new(callee).map_err(HypervisorError::InvalidCanisterId)?;
        let destination_subnet = routing_table
            .route(destination_canister.get())
            // Couldn't find the right subnet. Send it to the current subnet,
            // which will handle rejecting the request gracefully.
            .unwrap_or_else(|| own_subnet_id);
        (destination_canister, destination_subnet)
    };

    let destination_subnet_type = match subnet_records.get(&destination_subnet) {
        None => own_subnet_type,
        Some(subnet_type) => *subnet_type,
    };

    // Based on the types of the subnets the sending and the destination canisters
    // are on, apply the desired constraints.
    match (own_subnet_type, destination_subnet_type) {
        (SubnetType::Application, SubnetType::Application)
        | (SubnetType::VerifiedApplication, SubnetType::VerifiedApplication)
        | (SubnetType::System, SubnetType::System) => {}

        (SubnetType::Application, SubnetType::System)
        | (SubnetType::VerifiedApplication, SubnetType::Application)
        | (SubnetType::VerifiedApplication, SubnetType::System)
        | (SubnetType::System, SubnetType::Application)
        | (SubnetType::System, SubnetType::VerifiedApplication) => {}

        (SubnetType::Application, SubnetType::VerifiedApplication) => {
            if cycles != Cycles::from(0) {
                return Err(HypervisorError::ContractViolation(
                    "Canisters on Application subnets cannot send cycles to canisters on VerifiedApplication subnets".to_string(),
                ));
            }
        }
    }

    let current_size = method_name.len() + method_payload.len();
    {
        let max_size_intra_subnet = max_size_inter_subnet * multiplier_max_size_intra_subnet;
        assert!(current_size <= max_size_intra_subnet.get() as usize);
    }

    if destination_subnet != own_subnet_id && current_size > max_size_inter_subnet.get() as usize {
        return Err(HypervisorError::ContractViolation(format!(
            "RequestInPrep: size of message {} destined to another subnet cannot exceed {}",
            current_size, max_size_inter_subnet
        )));
    }

    let callback_id = system_state_accessor.register_callback(Callback::new(
        call_context_id,
        cycles,
        on_reply,
        on_reject,
        on_cleanup,
    ));

    Ok(Request {
        sender,
        receiver: destination_canister,
        method_name,
        method_payload,
        sender_reply_callback: callback_id,
        payment,
    })
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::SystemStateAccessorDirect;
    use ic_registry_routing_table::CanisterIdRange;
    use ic_test_utilities::{
        cycles_account_manager::CyclesAccountManagerBuilder, state::SystemStateBuilder,
        types::ids::subnet_test_id,
    };
    use maplit::btreemap;
    use std::convert::TryInto;

    #[test]
    fn large_methods_rejected() {
        let sender = CanisterId::from(1);
        let callee_source = 0;
        let callee_size = 10;
        let heap = vec![0; 1024];
        let method_name_source = 0;
        let method_name_len = 100;
        let callback = WasmClosure::new(0, 0);
        let max_size_inter_subnet = NumBytes::from(10);
        RequestInPrep::new(
            sender,
            callee_source,
            callee_size,
            method_name_source,
            method_name_len,
            &heap,
            callback.clone(),
            callback,
            max_size_inter_subnet,
            1,
        )
        .unwrap_err();
    }

    #[test]
    fn large_callee_rejected() {
        let sender = CanisterId::from(1);
        let callee_source = 0;
        let callee_size = 100;
        let heap = vec![0; 1024];
        let method_name_source = 0;
        let method_name_len = 1;
        let callback = WasmClosure::new(0, 0);
        let max_size_inter_subnet = NumBytes::from(10);
        RequestInPrep::new(
            sender,
            callee_source,
            callee_size,
            method_name_source,
            method_name_len,
            &heap,
            callback.clone(),
            callback,
            max_size_inter_subnet,
            1,
        )
        .unwrap_err();
    }

    #[test]
    fn payloads_larger_than_intra_limit_rejected() {
        let sender = CanisterId::from(1);
        let callee_source = 0;
        let callee_size = 1;
        let heap = vec![0; 1024];
        let method_name_source = 0;
        let method_name_len = 1;
        let callback = WasmClosure::new(0, 0);
        let max_size_inter_subnet = NumBytes::from(10);
        let mut req_in_prep = RequestInPrep::new(
            sender,
            callee_source,
            callee_size,
            method_name_source,
            method_name_len,
            &heap,
            callback.clone(),
            callback,
            max_size_inter_subnet,
            1,
        )
        .unwrap();
        req_in_prep
            .extend_method_payload(0, 100, &heap)
            .unwrap_err();
    }

    #[test]
    fn payloads_larger_than_inter_limit_rejected() {
        let (sender_subnet, sender_subnet_type, sender, dest, routing_table, subnet_records) = {
            let subnet_type = SubnetType::Application;
            let sender_subnet = subnet_test_id(1);
            let sender_subnet_canister_id_range = CanisterIdRange {
                start: CanisterId::from(0),
                end: CanisterId::from(0xffffffff),
            };
            let sender = CanisterId::from(0x1);
            assert!(sender_subnet_canister_id_range.start <= sender);
            assert!(sender <= sender_subnet_canister_id_range.end);

            let foreign_subnet_id = subnet_test_id(2);
            let foreign_subnet_canister_id_range = CanisterIdRange {
                start: CanisterId::from(0x100000000),
                end: CanisterId::from(0x1ffffffff),
            };
            let dest = CanisterId::from(0x100000001);
            assert!(foreign_subnet_canister_id_range.start <= dest);
            assert!(dest <= foreign_subnet_canister_id_range.end);

            let routing_table = Arc::new(RoutingTable::new(btreemap! {
                foreign_subnet_canister_id_range => foreign_subnet_id,
                sender_subnet_canister_id_range => sender_subnet,
            }));

            let subnet_records = btreemap! {
                sender_subnet => subnet_type,
                foreign_subnet_id => subnet_type,
            };

            (
                sender_subnet,
                subnet_type,
                sender,
                dest,
                routing_table,
                subnet_records,
            )
        };

        let callee_source = 0;
        let callee_size = dest.get().as_slice().len().try_into().unwrap();
        let mut heap = dest.get().as_slice().to_vec();
        heap.append(&mut vec![0; 1024]);
        let method_name_source = 0;
        let method_name_len = 1;
        let callback = WasmClosure::new(0, 0);
        let max_size_inter_subnet = NumBytes::from(10);
        let mut req_in_prep = RequestInPrep::new(
            sender,
            callee_source,
            callee_size,
            method_name_source,
            method_name_len,
            &heap,
            callback.clone(),
            callback,
            max_size_inter_subnet,
            10,
        )
        .unwrap();
        req_in_prep.extend_method_payload(0, 50, &heap).unwrap();
        let cycles_account_manager = Arc::new(CyclesAccountManagerBuilder::new().build());

        into_request(
            routing_table,
            &subnet_records,
            req_in_prep,
            CallContextId::from(1),
            sender_subnet,
            sender_subnet_type,
            &SystemStateAccessorDirect::new(
                SystemStateBuilder::default().build(),
                cycles_account_manager,
            ),
        )
        .unwrap_err();
    }

    #[test]
    fn application_subnet_cannot_send_cycles_to_verified_subnet() {
        let sender_subnet = subnet_test_id(1);
        let sender_subnet_type = SubnetType::Application;
        let sender_subnet_canister_id_range = CanisterIdRange {
            start: CanisterId::from(0),
            end: CanisterId::from(0xffffffff),
        };
        let sender = CanisterId::from(0x1);
        assert!(sender_subnet_canister_id_range.start <= sender);
        assert!(sender <= sender_subnet_canister_id_range.end);

        let dest_subnet = subnet_test_id(2);
        let dest_subnet_type = SubnetType::VerifiedApplication;
        let dest_subnet_canister_id_range = CanisterIdRange {
            start: CanisterId::from(0x100000000),
            end: CanisterId::from(0x1ffffffff),
        };
        let dest = CanisterId::from(0x100000001);
        assert!(dest_subnet_canister_id_range.start <= dest);
        assert!(dest <= dest_subnet_canister_id_range.end);

        let routing_table = Arc::new(RoutingTable::new(btreemap! {
            dest_subnet_canister_id_range => dest_subnet,
            sender_subnet_canister_id_range => sender_subnet,
        }));

        let subnet_records = btreemap! {
            sender_subnet => sender_subnet_type,
            dest_subnet => dest_subnet_type,
        };

        let callee_source = 0;
        let callee_size = dest.get().as_slice().len().try_into().unwrap();
        let mut heap = dest.get().as_slice().to_vec();
        heap.append(&mut vec![0; 1024]);
        let method_name_source = 0;
        let method_name_len = 1;
        let callback = WasmClosure::new(0, 0);
        let max_size_inter_subnet = NumBytes::from(1024);
        let mut req_in_prep = RequestInPrep::new(
            sender,
            callee_source,
            callee_size,
            method_name_source,
            method_name_len,
            &heap,
            callback.clone(),
            callback,
            max_size_inter_subnet,
            10,
        )
        .unwrap();
        req_in_prep.extend_method_payload(0, 50, &heap).unwrap();
        req_in_prep.add_cycles(Cycles::from(100));

        let cycles_account_manager = Arc::new(CyclesAccountManagerBuilder::new().build());
        into_request(
            routing_table,
            &subnet_records,
            req_in_prep,
            CallContextId::from(1),
            sender_subnet,
            sender_subnet_type,
            &SystemStateAccessorDirect::new(
                SystemStateBuilder::default().build(),
                cycles_account_manager,
            ),
        )
        .unwrap_err();
    }
}
