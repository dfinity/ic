use ic_interfaces::execution_environment::{
    HypervisorError::{self},
    HypervisorResult, SystemApi,
};
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::PageIndex;
use ic_sys::PageBytes;
use ic_types::{Cycles, NumBytes, NumInstructions, Time};

const MESSAGE_UNIMPLEMENTED: &str =
    "Empty System API should not be called. Only used by the embedder to create an ExecutionState instance";

/// This struct implements the SystemApi trait
/// and is only used by the `embedder` to create an `ExecutionState` instance.
pub struct SystemApiEmpty;

impl SystemApi for SystemApiEmpty {
    fn set_execution_error(&mut self, _error: HypervisorError) {
        unimplemented!("{}", MESSAGE_UNIMPLEMENTED)
    }
    fn get_execution_error(&self) -> Option<&HypervisorError> {
        unimplemented!("{}", MESSAGE_UNIMPLEMENTED)
    }
    fn get_num_instructions_from_bytes(&self, _num_bytes: NumBytes) -> NumInstructions {
        unimplemented!("{}", MESSAGE_UNIMPLEMENTED)
    }
    fn stable_memory_dirty_pages(&self) -> Vec<(PageIndex, &PageBytes)> {
        unimplemented!("{}", MESSAGE_UNIMPLEMENTED)
    }
    fn stable_memory_size(&self) -> usize {
        unimplemented!("{}", MESSAGE_UNIMPLEMENTED)
    }
    fn subnet_type(&self) -> SubnetType {
        unimplemented!("{}", MESSAGE_UNIMPLEMENTED)
    }
    fn ic0_msg_caller_copy(&self, _: u32, _: u32, _: u32, _: &mut [u8]) -> HypervisorResult<()> {
        unimplemented!("{}", MESSAGE_UNIMPLEMENTED)
    }
    fn ic0_msg_caller_size(&self) -> HypervisorResult<u32> {
        unimplemented!("{}", MESSAGE_UNIMPLEMENTED)
    }
    fn ic0_msg_arg_data_size(&self) -> HypervisorResult<u32> {
        unimplemented!("{}", MESSAGE_UNIMPLEMENTED)
    }
    fn ic0_msg_arg_data_copy(&self, _: u32, _: u32, _: u32, _: &mut [u8]) -> HypervisorResult<()> {
        unimplemented!("{}", MESSAGE_UNIMPLEMENTED)
    }
    fn ic0_msg_method_name_size(&self) -> HypervisorResult<u32> {
        unimplemented!("{}", MESSAGE_UNIMPLEMENTED)
    }
    fn ic0_msg_method_name_copy(
        &self,
        _: u32,
        _: u32,
        _: u32,
        _: &mut [u8],
    ) -> HypervisorResult<()> {
        unimplemented!("{}", MESSAGE_UNIMPLEMENTED)
    }
    fn ic0_accept_message(&mut self) -> HypervisorResult<()> {
        unimplemented!("{}", MESSAGE_UNIMPLEMENTED)
    }
    fn ic0_msg_reply_data_append(&mut self, _: u32, _: u32, _: &[u8]) -> HypervisorResult<()> {
        unimplemented!("{}", MESSAGE_UNIMPLEMENTED)
    }
    fn ic0_msg_reply(&mut self) -> HypervisorResult<()> {
        unimplemented!("{}", MESSAGE_UNIMPLEMENTED)
    }
    fn ic0_msg_reject_code(&self) -> HypervisorResult<i32> {
        unimplemented!("{}", MESSAGE_UNIMPLEMENTED)
    }
    fn ic0_msg_reject(&mut self, _: u32, _: u32, _: &[u8]) -> HypervisorResult<()> {
        unimplemented!("{}", MESSAGE_UNIMPLEMENTED)
    }
    fn ic0_msg_reject_msg_size(&self) -> HypervisorResult<u32> {
        unimplemented!("{}", MESSAGE_UNIMPLEMENTED)
    }
    fn ic0_msg_reject_msg_copy(
        &self,
        _: u32,
        _: u32,
        _: u32,
        _: &mut [u8],
    ) -> HypervisorResult<()> {
        unimplemented!("{}", MESSAGE_UNIMPLEMENTED)
    }
    fn ic0_canister_self_size(&self) -> HypervisorResult<usize> {
        unimplemented!("{}", MESSAGE_UNIMPLEMENTED)
    }
    fn ic0_canister_self_copy(
        &mut self,
        _: u32,
        _: u32,
        _: u32,
        _: &mut [u8],
    ) -> HypervisorResult<()> {
        unimplemented!("{}", MESSAGE_UNIMPLEMENTED)
    }
    fn ic0_controller_size(&self) -> HypervisorResult<usize> {
        unimplemented!("{}", MESSAGE_UNIMPLEMENTED)
    }
    fn ic0_controller_copy(
        &mut self,
        _: u32,
        _: u32,
        _: u32,
        _: &mut [u8],
    ) -> HypervisorResult<()> {
        unimplemented!("{}", MESSAGE_UNIMPLEMENTED)
    }
    fn ic0_debug_print(&self, _: u32, _: u32, _: &[u8]) {
        unimplemented!("{}", MESSAGE_UNIMPLEMENTED)
    }
    fn ic0_trap(&self, _: u32, _: u32, _: &[u8]) -> HypervisorError {
        unimplemented!("{}", MESSAGE_UNIMPLEMENTED)
    }
    fn ic0_call_simple(
        &mut self,
        _: u32,
        _: u32,
        _: u32,
        _: u32,
        _: u32,
        _: u32,
        _: u32,
        _: u32,
        _: u32,
        _: u32,
        _: &[u8],
    ) -> HypervisorResult<i32> {
        unimplemented!("{}", MESSAGE_UNIMPLEMENTED)
    }
    fn ic0_call_new(
        &mut self,
        _: u32,
        _: u32,
        _: u32,
        _: u32,
        _: u32,
        _: u32,
        _: u32,
        _: u32,
        _: &[u8],
    ) -> HypervisorResult<()> {
        unimplemented!("{}", MESSAGE_UNIMPLEMENTED)
    }
    fn ic0_call_data_append(&mut self, _: u32, _: u32, _: &[u8]) -> HypervisorResult<()> {
        unimplemented!("{}", MESSAGE_UNIMPLEMENTED)
    }
    fn ic0_call_on_cleanup(&mut self, _: u32, _: u32) -> HypervisorResult<()> {
        unimplemented!("{}", MESSAGE_UNIMPLEMENTED)
    }
    fn ic0_call_cycles_add(&mut self, _: u64) -> HypervisorResult<()> {
        unimplemented!("{}", MESSAGE_UNIMPLEMENTED)
    }
    fn ic0_call_cycles_add128(&mut self, _: Cycles) -> HypervisorResult<()> {
        unimplemented!("{}", MESSAGE_UNIMPLEMENTED)
    }
    fn ic0_call_perform(&mut self) -> HypervisorResult<i32> {
        unimplemented!("{}", MESSAGE_UNIMPLEMENTED)
    }
    fn ic0_stable_size(&self) -> HypervisorResult<u32> {
        unimplemented!("{}", MESSAGE_UNIMPLEMENTED)
    }
    fn ic0_stable_grow(&mut self, _: u32) -> HypervisorResult<i32> {
        unimplemented!("{}", MESSAGE_UNIMPLEMENTED)
    }
    fn ic0_stable_read(&self, _: u32, _: u32, _: u32, _: &mut [u8]) -> HypervisorResult<()> {
        unimplemented!("{}", MESSAGE_UNIMPLEMENTED)
    }
    fn ic0_stable_write(&mut self, _: u32, _: u32, _: u32, _: &[u8]) -> HypervisorResult<()> {
        unimplemented!("{}", MESSAGE_UNIMPLEMENTED)
    }
    fn ic0_stable64_size(&self) -> HypervisorResult<u64> {
        unimplemented!("{}", MESSAGE_UNIMPLEMENTED)
    }
    fn ic0_stable64_grow(&mut self, _: u64) -> HypervisorResult<i64> {
        unimplemented!("{}", MESSAGE_UNIMPLEMENTED)
    }
    fn ic0_stable64_read(&self, _: u64, _: u64, _: u64, _: &mut [u8]) -> HypervisorResult<()> {
        unimplemented!("{}", MESSAGE_UNIMPLEMENTED)
    }
    fn ic0_stable64_write(&mut self, _: u64, _: u64, _: u64, _: &[u8]) -> HypervisorResult<()> {
        unimplemented!("{}", MESSAGE_UNIMPLEMENTED)
    }
    fn ic0_time(&self) -> HypervisorResult<Time> {
        unimplemented!("{}", MESSAGE_UNIMPLEMENTED)
    }
    fn out_of_instructions(&self) -> Result<(), HypervisorError> {
        unimplemented!("{}", MESSAGE_UNIMPLEMENTED)
    }
    fn update_available_memory(&mut self, _: i32, _: u32) -> HypervisorResult<i32> {
        unimplemented!("{}", MESSAGE_UNIMPLEMENTED)
    }
    fn ic0_canister_cycle_balance(&self) -> HypervisorResult<u64> {
        unimplemented!("{}", MESSAGE_UNIMPLEMENTED)
    }
    fn ic0_canister_cycles_balance128(&self, _: u32, _: &mut [u8]) -> HypervisorResult<()> {
        unimplemented!("{}", MESSAGE_UNIMPLEMENTED)
    }
    fn ic0_msg_cycles_available(&self) -> HypervisorResult<u64> {
        unimplemented!("{}", MESSAGE_UNIMPLEMENTED)
    }
    fn ic0_msg_cycles_available128(&self, _: u32, _: &mut [u8]) -> HypervisorResult<()> {
        unimplemented!("{}", MESSAGE_UNIMPLEMENTED)
    }
    fn ic0_msg_cycles_refunded(&self) -> HypervisorResult<u64> {
        unimplemented!("{}", MESSAGE_UNIMPLEMENTED)
    }
    fn ic0_msg_cycles_refunded128(&self, _: u32, _: &mut [u8]) -> HypervisorResult<()> {
        unimplemented!("{}", MESSAGE_UNIMPLEMENTED)
    }
    fn ic0_msg_cycles_accept(&mut self, _: u64) -> HypervisorResult<u64> {
        unimplemented!("{}", MESSAGE_UNIMPLEMENTED)
    }
    fn ic0_msg_cycles_accept128(
        &mut self,
        _: Cycles,
        _: u32,
        _: &mut [u8],
    ) -> HypervisorResult<()> {
        unimplemented!("{}", MESSAGE_UNIMPLEMENTED)
    }
    fn ic0_certified_data_set(&mut self, _: u32, _: u32, _: &[u8]) -> HypervisorResult<()> {
        unimplemented!("{}", MESSAGE_UNIMPLEMENTED)
    }
    fn ic0_data_certificate_present(&self) -> HypervisorResult<i32> {
        unimplemented!("{}", MESSAGE_UNIMPLEMENTED)
    }
    fn ic0_data_certificate_size(&self) -> HypervisorResult<i32> {
        unimplemented!("{}", MESSAGE_UNIMPLEMENTED)
    }
    fn ic0_data_certificate_copy(
        &self,
        _: u32,
        _: u32,
        _: u32,
        _: &mut [u8],
    ) -> HypervisorResult<()> {
        unimplemented!("{}", MESSAGE_UNIMPLEMENTED)
    }
    fn ic0_canister_status(&self) -> HypervisorResult<u32> {
        unimplemented!("{}", MESSAGE_UNIMPLEMENTED)
    }
    fn ic0_mint_cycles(&mut self, _: u64) -> HypervisorResult<u64> {
        unimplemented!("{}", MESSAGE_UNIMPLEMENTED)
    }
}
