//! SNS-WASM stable memory management
//!
//! SNS-WASM stores and serves WASM binaries. If SNS-WASM stored these WASMs in-memory, then
//! on upgrade SNS-WASM would need to serialize all WASMs (potentially GBs of them) to stable
//! memory in pre-upgrade, and then deserialize back in post-upgrade. In order to avoid issues
//! with this "serialize/deserialize the world" approach, WASMs are written to stable memory
//! when they are received and are not held in-memory. What is then held in-memory is a map
//! from WASM hash to an offset into stable memory (and the WASM size), so that WASMs can be
//! served from stable memory. This stable memory approach requires that we persist special
//! indexes in stable memory. The SNS-WASM stable memory format looks something like:
//!
//! [reserved bytes][WASMs-end offset][Canister state size][WASM 1][WASM 2]...
//!
//! There are some initial reserved bytes that may be used in the future. There are then two
//! variables saved in stable memory: the WASMs-end offset and the canister state size. The
//! WASMs-end offset stores the offset of the end of the last WASM stored in stable memory. If
//! a new WASM is added, it will be written starting at this offset, and then the WASMs-end offset
//! will be updated to be the end of this newly written WASM. During an upgrade (in pre-upgrade)
//! the current canister state (containing the map from WASM hash to stable memory location of
//! the WASM, etc.) is written to stable memory starting at WASMs-end offset. The size of the
//! written bytes is written to "canister state size" in stable memory, so that in post-upgrade
//! SNS-WASM can use "WASMs-end offset" and "canister state size" to read canister state from
//! stable memory.
#![allow(deprecated)]

use crate::pb::v1::{SnsWasm, StableCanisterState};
use ic_cdk::api::stable::{StableMemory, StableMemoryError, StableReader, StableWriter};
use prost::Message;
use std::mem::size_of;

/// The initial chunk of stable memory that is reserved for future use
const RESERVED_INITIAL_STABLE_MEMORY_BYTES: u64 = 1_000_000; // 1MB

/// Provides convenient access to stable memory to read/write WASMs and canister state. See
/// the module comment for more details.
#[derive(Clone)]
pub struct SnsWasmStableMemory<M: StableMemory + Clone> {
    stable_memory: M,
    reserved_bytes: u64,
}

impl<M: StableMemory + Clone + Default> Default for SnsWasmStableMemory<M> {
    fn default() -> Self {
        Self {
            stable_memory: M::default(),
            reserved_bytes: RESERVED_INITIAL_STABLE_MEMORY_BYTES,
        }
    }
}

impl<M: StableMemory + Clone> SnsWasmStableMemory<M> {
    /// Initialize stable memory
    pub fn init(&self) -> Result<(), StableMemoryError> {
        let wasms_start_offset = self.get_canister_state_size_offset() + (size_of::<u64>() as u64);
        self.write_wasms_end_offset(wasms_start_offset as u32)
    }

    /// Return a `StableReader` constructed with the given offset
    fn get_stable_reader(&self, offset: u64) -> StableReader<M> {
        StableReader::with_memory(self.stable_memory.clone(), offset)
    }

    /// Return a `StableWriter` constructed with the given offset
    fn get_stable_writer(&self, offset: u64) -> StableWriter<M> {
        StableWriter::with_memory(self.stable_memory.clone(), offset)
    }

    /// Read a `u32` at the given offset in stable memory
    pub fn stable_read_u32(&self, offset: u64) -> Result<u32, StableMemoryError> {
        let mut reader = self.get_stable_reader(offset);
        let mut u32_bytes = [0u8; 4];
        reader.read(&mut u32_bytes)?;
        Ok(u32::from_be_bytes(u32_bytes))
    }

    /// Write `value` to the given offset in stable memory
    pub fn stable_write_u32(&self, offset: u64, value: u32) -> Result<(), StableMemoryError> {
        let mut writer = self.get_stable_writer(offset);
        writer.write(&value.to_be_bytes())?;
        Ok(())
    }

    /// Return the offset in stable memory where the WASMs-end offset can be read
    fn get_wasms_end_offset_offset(&self) -> u64 {
        self.reserved_bytes
    }

    /// Return the offset in stable memory where the canister state size can be read
    fn get_canister_state_size_offset(&self) -> u64 {
        self.get_wasms_end_offset_offset() + (size_of::<u64>() as u64)
    }

    /// Retrieve the offset in stable memory where the last WASM ends
    pub fn read_wasms_end_offset(&self) -> Result<u32, StableMemoryError> {
        self.stable_read_u32(self.get_wasms_end_offset_offset())
    }

    /// Write the WASMs-end offset
    pub fn write_wasms_end_offset(&self, wasms_end_offset: u32) -> Result<(), StableMemoryError> {
        self.stable_write_u32(self.get_wasms_end_offset_offset(), wasms_end_offset)
    }

    /// Read the canister state size
    pub fn read_canister_state_size(&self) -> Result<u32, StableMemoryError> {
        self.stable_read_u32(self.get_canister_state_size_offset())
    }

    /// Write the canister state size
    pub fn write_canister_state_size(
        &self,
        canister_state_size: u32,
    ) -> Result<(), StableMemoryError> {
        self.stable_write_u32(self.get_canister_state_size_offset(), canister_state_size)
    }

    /// Write the given `StableCanisterState` to stable memory, ensuring that no stored WASM
    /// is overwritten
    pub fn write_canister_state(
        &self,
        state: StableCanisterState,
    ) -> Result<(), StableMemoryError> {
        let wasms_end_offset = self.read_wasms_end_offset()?;
        let mut state_writer = self.get_stable_writer(wasms_end_offset as u64);
        let bytes_written = state_writer.write(&state.encode_to_vec())?;

        self.write_canister_state_size(bytes_written as u32)?;

        Ok(())
    }

    /// Read the `StableCanisterState` that was most recently written to stable memory
    pub fn read_canister_state(&self) -> Result<StableCanisterState, StableMemoryError> {
        let wasms_end_offset = self.read_wasms_end_offset()?;
        let canister_state_size = self.read_canister_state_size()?;

        let mut reader = self.get_stable_reader(wasms_end_offset as u64);
        let mut bytes = vec![0; canister_state_size as usize];
        reader.read(&mut bytes)?;

        Ok(StableCanisterState::decode(&*bytes).unwrap())
    }

    /// Write the given `SnsWasm` to stable memory and return the offset in stable memory that the
    /// WASM was written to and the size written
    pub fn write_wasm(&self, wasm: SnsWasm) -> Result<(u32, u32), StableMemoryError> {
        let wasms_end_offset = self.read_wasms_end_offset()?;
        let mut writer = self.get_stable_writer(wasms_end_offset as u64);
        let bytes_written = writer.write(&wasm.encode_to_vec())?;
        self.write_wasms_end_offset(wasms_end_offset + bytes_written as u32)?;

        Ok((wasms_end_offset, bytes_written as u32))
    }

    /// Read a WASM from stable memory at the given offset and with the given size
    pub fn read_wasm(&self, offset: u32, size: u32) -> Result<SnsWasm, StableMemoryError> {
        let mut reader = self.get_stable_reader(offset as u64);
        let mut bytes = vec![0; size as usize];
        reader.read(&mut bytes)?;

        Ok(SnsWasm::decode(&*bytes).unwrap())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        canister_stable_memory::TestCanisterStableMemory,
        pb::v1::{
            DeployedSns, MetadataSection as MetadataSectionPb, SnsSpecificSnsUpgrade, SnsUpgrade,
            SnsVersion, SnsWasmStableIndex, UpgradePath,
        },
    };
    use ic_base_types::PrincipalId;
    use maplit::btreemap;

    #[test]
    fn test_stable_write_and_read_u32() {
        let stable_memory = SnsWasmStableMemory::<TestCanisterStableMemory>::default();
        stable_memory.stable_write_u32(0, 12).unwrap();
        assert_eq!(stable_memory.stable_read_u32(0).unwrap(), 12);
    }

    #[test]
    fn test_stable_write_and_read_wasms_end_offset() {
        let stable_memory = SnsWasmStableMemory::<TestCanisterStableMemory>::default();
        stable_memory.write_wasms_end_offset(25).unwrap();
        assert_eq!(stable_memory.read_wasms_end_offset().unwrap(), 25);
    }

    #[test]
    fn test_stable_write_and_read_canister_state_size() {
        let stable_memory = SnsWasmStableMemory::<TestCanisterStableMemory>::default();
        stable_memory.write_canister_state_size(456).unwrap();
        assert_eq!(stable_memory.read_canister_state_size().unwrap(), 456);
    }

    fn get_test_canister_state() -> StableCanisterState {
        let wasm_indexes = vec![SnsWasmStableIndex {
            hash: vec![1, 3, 6],
            offset: 34811,
            size: 1200,
            metadata: vec![MetadataSectionPb {
                visibility: Some("icp:public".to_string()),
                name: Some("foo".to_string()),
                contents: Some(vec![1, 2, 3]),
            }],
        }];

        let sns_subnet_ids = vec![PrincipalId::new_subnet_test_id(34)];
        let deployed_sns_list = vec![DeployedSns {
            root_canister_id: Some(PrincipalId::new_subnet_test_id(560)),
            governance_canister_id: Some(PrincipalId::new_subnet_test_id(561)),
            ledger_canister_id: Some(PrincipalId::new_subnet_test_id(562)),
            swap_canister_id: Some(PrincipalId::new_subnet_test_id(563)),
            index_canister_id: Some(PrincipalId::new_subnet_test_id(564)),
        }];

        let sns_version1 = SnsVersion {
            governance_wasm_hash: [1u8; 32].to_vec(),
            root_wasm_hash: [2u8; 32].to_vec(),
            ledger_wasm_hash: [3u8; 32].to_vec(),
            swap_wasm_hash: [4u8; 32].to_vec(),
            archive_wasm_hash: [5u8; 32].to_vec(),
            index_wasm_hash: [6u8; 32].to_vec(),
        };
        let sns_version2 = SnsVersion {
            governance_wasm_hash: [6u8; 32].to_vec(),
            root_wasm_hash: [7u8; 32].to_vec(),
            ledger_wasm_hash: [8u8; 32].to_vec(),
            swap_wasm_hash: [9u8; 32].to_vec(),
            archive_wasm_hash: [10u8; 32].to_vec(),
            index_wasm_hash: [6u8; 32].to_vec(),
        };

        let upgrade_path = Some(UpgradePath {
            latest_version: Some(sns_version2.clone()),
            upgrade_path: vec![SnsUpgrade {
                current_version: Some(sns_version1.clone()),
                next_version: Some(sns_version2.clone()),
            }],
            sns_specific_upgrade_path: vec![SnsSpecificSnsUpgrade {
                governance_canister_id: None,
                upgrade_path: vec![SnsUpgrade {
                    current_version: Some(sns_version1),
                    next_version: Some(sns_version2),
                }],
            }],
        });

        StableCanisterState {
            wasm_indexes,
            sns_subnet_ids,
            deployed_sns_list,
            upgrade_path,
            access_controls_enabled: true,
            allowed_principals: vec![],
            nns_proposal_to_deployed_sns: btreemap! {1 => 0,},
        }
    }

    #[test]
    fn test_stable_write_and_read_canister_state() {
        let stable_memory = SnsWasmStableMemory::<TestCanisterStableMemory>::default();
        stable_memory.write_wasms_end_offset(80000).unwrap();

        let state = get_test_canister_state();
        stable_memory.write_canister_state(state.clone()).unwrap();
        assert_eq!(stable_memory.read_canister_state().unwrap(), state);
    }

    #[test]
    fn test_stable_write_and_read_wasm() {
        let stable_memory = SnsWasmStableMemory::<TestCanisterStableMemory>::default();
        stable_memory.write_wasms_end_offset(1000).unwrap();
        let sns_wasm = SnsWasm {
            wasm: vec![189, 201, 248],
            canister_type: 1,
            ..SnsWasm::default()
        };
        let (offset, size) = stable_memory.write_wasm(sns_wasm.clone()).unwrap();
        assert_eq!(stable_memory.read_wasm(offset, size).unwrap(), sns_wasm);
    }
}
