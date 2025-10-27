use std::{
    collections::BTreeSet,
    convert::TryFrom,
    fs::File,
    io::Write,
    os::{fd::AsRawFd, unix::fs::MetadataExt},
    path::Path,
    sync::Arc,
};

use ic_heap_bytes::DeterministicHeapBytes;
use ic_interfaces::execution_environment::{HypervisorError, HypervisorResult};
use ic_replicated_state::canister_state::execution_state::WasmMetadata;
use ic_types::{DiskBytes, NumInstructions, methods::WasmMethod};
use ic_wasm_types::WasmEngineError;
use nix::sys::mman::{MapFlags, ProtFlags, mmap};
use serde::{Deserialize, Serialize};
use wasmtime::Module;

use crate::wasm_utils::{
    InstrumentationOutput, Segments, WasmImportsDetails, WasmValidationDetails,
};

/// A `wasmtime::Module` that has been serialized.
#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
pub struct SerializedModuleBytes(#[serde(with = "serde_bytes")] Vec<u8>);

impl TryFrom<&Module> for SerializedModuleBytes {
    type Error = HypervisorError;

    fn try_from(module: &Module) -> Result<Self, Self::Error> {
        module.serialize().map(Self).map_err(|e| {
            HypervisorError::WasmEngineError(WasmEngineError::FailedToSerializeModule(format!(
                "{e:?}"
            )))
        })
    }
}

impl SerializedModuleBytes {
    pub fn empty() -> Self {
        Self(vec![])
    }

    /// It is guaranteed to be safe to deserialize this array into a `wasmtime::Module`.
    pub fn as_slice(&self) -> &[u8] {
        // Serializing a module always includes the header "wasmtime-aot", so
        // the array will be non-empty iff it was created by a call to
        // `wasmtime::Module::serialize` in the `TryFrom` impl. Otherwise it was
        // created by `empty` which should only happen when module sharing is
        // disabled.
        if self.0.is_empty() {
            panic!("Internal error: tried to deserialize Module from an empty arary.")
        } else {
            &self.0
        }
    }
}

/// Contains all data needed to construct a canister's execution state and
/// execute messages against it. If the execution state already exists, then
/// only the `bytes` field is needed to handle execution.
#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
pub struct SerializedModule {
    /// The serialized `wasmtime::Module`. This field is wrapped in an `Arc` so
    /// that it can be cheaply moved out of the `SerializedModule` in the cases
    /// when the other fields aren't needed.
    #[serde(serialize_with = "ic_utils::serde_arc::serialize_arc")]
    #[serde(deserialize_with = "ic_utils::serde_arc::deserialize_arc")]
    pub bytes: Arc<SerializedModuleBytes>,
    /// List of functions exported by the canister.
    pub exported_functions: BTreeSet<WasmMethod>,
    /// The initial state of the wasm heap.
    pub data_segments: Segments,
    /// The contents of the metadata custom section.
    pub wasm_metadata: WasmMetadata,
    /// Compiling the canister is equivalent to executing this many instructions.
    pub compilation_cost: NumInstructions,
    /// Imported System API functions that are deprecated, should become deprecated, or should only be used by NNS canisters.
    pub imports_details: WasmImportsDetails,
    /// Boolean value that indicates whether this is a Wasm64 module or not.
    pub is_wasm64: bool,
}

impl SerializedModule {
    pub(crate) fn new(
        module: &Module,
        instrumentation_output: InstrumentationOutput,
        validation_details: WasmValidationDetails,
        is_wasm64: bool,
    ) -> HypervisorResult<Self> {
        let bytes = SerializedModuleBytes::try_from(module)?;
        Ok(Self {
            bytes: Arc::new(bytes),
            exported_functions: instrumentation_output.exported_functions,
            data_segments: instrumentation_output.data,
            wasm_metadata: validation_details.wasm_metadata,
            compilation_cost: instrumentation_output.compilation_cost,
            imports_details: validation_details.imports_details,
            is_wasm64,
        })
    }

    pub fn take_data_segments(&mut self) -> Segments {
        std::mem::take(&mut self.data_segments)
    }
}

/// Parts of the serialized module which are only needed for creating the
/// initial state and can be stored together in a single file.
#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
pub struct InitialStateData {
    /// List of functions exported by the canister.
    pub exported_functions: BTreeSet<WasmMethod>,
    /// The initial state of the wasm heap.
    pub data_segments: Segments,
    /// The contents of the metadata custom section.
    pub wasm_metadata: WasmMetadata,
}

/// Contains all data needed to construct a canister's execution state and
/// execute messages against it. If the execution state already exists, then
/// only the `bytes` field is needed to handle execution.
///
/// All large fields should be stored in disk-backed files so this structure
/// doesn't take up much space in memory.
///
/// This structure owns all internal file descriptors and will close them when
/// dropped.
///
/// # File Safety
///
/// When creating an `OnDiskSerializedModule`, the caller passes in two paths.
/// The caller needs to guarantee that files can be created at these paths and
/// that afterwards the files will not be mutated.
///
/// The files will then be deleted and the resulting `OnDiskSerialisedModule`
/// will have exclusive ownership of file descriptors pointing to the files. The
/// descriptors are duplicated when passed to the sandbox for execution (this
/// happens implicitly when sending over the socket). The files should only be
/// accessed through mmap - otherwise seeks could interfere with each other.
#[derive(Debug, DeterministicHeapBytes)]
pub struct OnDiskSerializedModule {
    /// Bytes of the compilation artifact.
    pub bytes: File,
    /// Serialization of the other fields required for creating the initial state.
    pub initial_state_data: File,
    /// Compiling the canister is equivalent to executing this many instructions.
    pub compilation_cost: NumInstructions,
    /// Imported System API functions that are deprecated, should become deprecated, or should only be used by NNS canisters.
    pub imports_details: WasmImportsDetails,
    /// Boolean value that indicates whether this is a Wasm64 module or not.
    pub is_wasm64: bool,
}

impl DiskBytes for OnDiskSerializedModule {
    fn disk_bytes(&self) -> usize {
        (self.bytes.metadata().unwrap().len() + self.initial_state_data.metadata().unwrap().len())
            as usize
    }
}

impl OnDiskSerializedModule {
    /// Serializes data to disk and panics on error. The paths must not have
    /// existing files.  This treats failure to serialize the data the same as
    /// if we failed to allocate space for it in the first place.
    pub(crate) fn from_serialized_module(
        serialized_module: SerializedModule,
        bytes_path: &Path,
        initial_state_path: &Path,
    ) -> Self {
        let bytes = &serialized_module.bytes.0;
        let initial_state_data = InitialStateData {
            exported_functions: serialized_module.exported_functions,
            data_segments: serialized_module.data_segments,
            wasm_metadata: serialized_module.wasm_metadata,
        };
        let mut bytes_file = File::create_new(bytes_path).unwrap_or_else(|e| match e.kind() {
            std::io::ErrorKind::AlreadyExists => {
                panic!("Unable to serialize module: File {bytes_path:?} already exists.")
            }
            _ => panic!("Unable to serialize module: failed to create bytes file: {e}"),
        });
        bytes_file
            .write_all(bytes)
            .expect("Unable to serialize module: failed to write bytes file");
        let mut initial_state_file =
            File::create_new(initial_state_path).unwrap_or_else(|e| match e.kind() {
                std::io::ErrorKind::AlreadyExists => {
                    panic!(
                        "Unable to serialize module: File {initial_state_path:?} already exists."
                    )
                }
                _ => panic!("Unable to serialize module: failed to create initial state file: {e}"),
            });
        initial_state_file
            .write_all(
                &bincode::serialize(&initial_state_data)
                    .expect("Unable to serialize module: failed to serialize initial state"),
            )
            .expect("Unable to serialize module: failed to write initial state file");

        // Set file permissions to readonly and reopen with new permissions.
        let mut permissions = bytes_file
            .metadata()
            .expect("Unable to serialize module: failed to get bytes file permissions")
            .permissions();
        permissions.set_readonly(true);
        bytes_file
            .set_permissions(permissions.clone())
            .expect("Unable to serialize module: failed to set bytes file permissions");
        initial_state_file
            .set_permissions(permissions)
            .expect("Unable to serialize module: failed to set initial state file permissions");
        let bytes_file = File::open(bytes_path)
            .expect("Unable to serialize module: failed to reopen bytes file");
        let initial_state_file = File::open(initial_state_path)
            .expect("Unable to serialize module: failed to reopen initial state file");

        // Delete the files so that they are automatically cleaned up
        // when there are no more descriptors.
        std::fs::remove_file(bytes_path)
            .expect("Unable to serialize module: failed to delete bytes file");
        std::fs::remove_file(initial_state_path)
            .expect("Unable to serialize module: failed to delete initial state file");

        Self {
            bytes: bytes_file,
            initial_state_data: initial_state_file,
            compilation_cost: serialized_module.compilation_cost,
            imports_details: serialized_module.imports_details,
            is_wasm64: serialized_module.is_wasm64,
        }
    }

    /// Map the initial state file and deserialize its contents.
    pub fn initial_state_data(&self) -> InitialStateData {
        // Mmap the initial state file so that the file descriptor isn't mutated
        // (they might be shared).
        let mmap_size = self
            .initial_state_data
            .metadata()
            .expect("Unable to get size for initial state data file")
            .size() as usize;
        // Safety: Rust guarantees that the fd is valid and the null pointer
        // argument implies that this won't mess with any existing memory.
        let mmap_ptr = unsafe {
            mmap(
                std::ptr::null_mut(),
                mmap_size,
                ProtFlags::PROT_READ,
                MapFlags::MAP_PRIVATE,
                self.initial_state_data.as_raw_fd(),
                0,
            )
        }
        .unwrap_or_else(|err| {
            panic!("Reading OnDiskSerializedModule initial_state failed: {err:?}")
        }) as *mut u8;
        // Safety: allocation was made with length `mmap_size`.
        let data = unsafe { std::slice::from_raw_parts(mmap_ptr, mmap_size) };
        bincode::deserialize::<InitialStateData>(data)
            .expect("Error parsing initial state data file")
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use ic_replicated_state::canister_state::execution_state::{CustomSection, CustomSectionType};
    use ic_types::methods::SystemMethod;
    use proptest::prelude::*;
    use std::path::PathBuf;

    fn map_file_to_vec(file: &File) -> Vec<u8> {
        let mmap_size = file.metadata().unwrap().size() as usize;
        let mmap_ptr = unsafe {
            mmap(
                std::ptr::null_mut(),
                mmap_size,
                ProtFlags::PROT_READ,
                MapFlags::MAP_PRIVATE,
                file.as_raw_fd(),
                0,
            )
        }
        .unwrap_or_else(|err| panic!("Reading OnDiskSerializedModule failed: {err:?}"))
            as *mut u8;
        unsafe { std::slice::from_raw_parts(mmap_ptr, mmap_size) }.to_vec()
    }

    fn wasm_method() -> impl Strategy<Value = WasmMethod> {
        prop_oneof![
            (".*").prop_map(WasmMethod::Update),
            (".*").prop_map(WasmMethod::Query),
            (".*").prop_map(WasmMethod::CompositeQuery),
            Just(WasmMethod::System(SystemMethod::CanisterStart)),
            Just(WasmMethod::System(SystemMethod::CanisterInit)),
            Just(WasmMethod::System(SystemMethod::CanisterPreUpgrade)),
        ]
    }

    fn data_segment() -> impl Strategy<Value = (usize, Vec<u8>)> {
        let vec = prop::collection::vec(any::<u8>(), 0..4096 * 10);
        (any::<usize>(), vec)
    }

    prop_compose! {
        fn custom_section()(
            content in prop::collection::vec(any::<u8>(), 4096 * 10),
            visibility in prop_oneof![Just(CustomSectionType::Public), Just(CustomSectionType::Private)],
        ) -> CustomSection {
            CustomSection::new(visibility, content)
        }
    }

    proptest! {
        #[test]
        fn round_trip(
            bytes in prop::collection::vec(any::<u8>(), 0..4096 * 10),
            exported_functions in prop::collection::btree_set(wasm_method(), 0..100),
            data_segments in prop::collection::vec(data_segment(), 0..100),
            wasm_metadata in prop::collection::btree_map(".*", custom_section(), 30),
            num_instructions in 0..=u64::MAX,
            imports_call_cycles_add: bool,
            imports_canister_cycle_balance: bool,
            imports_msg_cycles_available: bool,
            imports_msg_cycles_refunded: bool,
            imports_msg_cycles_accept: bool,
            imports_mint_cycles: bool,
            is_wasm64: bool,
        ) {
            let bytes = Arc::new(SerializedModuleBytes(bytes));
            let data_segments = data_segments.into_iter().collect();
            let wasm_metadata = WasmMetadata::new(wasm_metadata);
            let compilation_cost = NumInstructions::from(num_instructions);
            let imports_details = WasmImportsDetails {
                imports_call_cycles_add,
                imports_canister_cycle_balance,
                imports_msg_cycles_available,
                imports_msg_cycles_refunded,
                imports_msg_cycles_accept,
                imports_mint_cycles,
            };
            let module = SerializedModule {
                bytes,
                exported_functions,
                data_segments,
                wasm_metadata,
                compilation_cost,
                imports_details,
                is_wasm64,
            };

            let dir = tempfile::tempdir().unwrap();
            let mut bytes_path: PathBuf = dir.path().into();
            let mut data_path: PathBuf = dir.path().into();
            bytes_path.push("bytes");
            data_path.push("data");

            let on_disk = OnDiskSerializedModule::from_serialized_module(module.clone(), &bytes_path, &data_path);

            let bytes_round_trip = map_file_to_vec(&on_disk.bytes);
            assert_eq!(module.bytes.0, bytes_round_trip);

            let initial_state_data = on_disk.initial_state_data();
            assert_eq!(module.exported_functions, initial_state_data.exported_functions);

            assert_eq!(module.data_segments, initial_state_data.data_segments);
            assert_eq!(module.wasm_metadata, initial_state_data.wasm_metadata);
            assert_eq!(module.compilation_cost, on_disk.compilation_cost);
            assert_eq!(module.imports_details, on_disk.imports_details);
            assert_eq!(module.is_wasm64, on_disk.is_wasm64);
        }

        // Check that multiple threads reading from an on disk serialized module
        // don't corrupt each other's data.
        fn read_in_parallel(
            bytes in prop::collection::vec(any::<u8>(), 0..4096 * 10),
            exported_functions in prop::collection::btree_set(wasm_method(), 0..100),
            data_segments in prop::collection::vec(data_segment(), 0..100),
            wasm_metadata in prop::collection::btree_map(".*", custom_section(), 30),
        ) {
            let bytes = Arc::new(SerializedModuleBytes(bytes));
            let data_segments = data_segments.into_iter().collect();
            let wasm_metadata = WasmMetadata::new(wasm_metadata);
            let compilation_cost = NumInstructions::from(0);
            let imports_details = WasmImportsDetails {
                imports_call_cycles_add: false,
                imports_canister_cycle_balance: false,
                imports_msg_cycles_available: false,
                imports_msg_cycles_refunded: false,
                imports_msg_cycles_accept: false,
                imports_mint_cycles: false,
            };
            let module = SerializedModule {
                bytes,
                exported_functions,
                data_segments,
                wasm_metadata,
                compilation_cost,
                imports_details,
                is_wasm64: false,
            };

            let dir = tempfile::tempdir().unwrap();
            let mut bytes_path: PathBuf = dir.path().into();
            let mut data_path: PathBuf = dir.path().into();
            bytes_path.push("bytes");
            data_path.push("data");

            let on_disk = OnDiskSerializedModule::from_serialized_module(module.clone(), &bytes_path, &data_path);

            std::thread::scope(|s| {
                let mut threads = vec![];
                for _ in 0..10 {
                    threads.push(s.spawn(|| {
                        (map_file_to_vec(&on_disk.bytes), on_disk.initial_state_data())
                    }));
                }
                let results: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();
                let (first_bytes, first_initial) = results[0].clone();
                for (bytes, initial) in results {
                    assert_eq!(first_bytes, bytes);
                    assert_eq!(first_initial, initial);
                }
            });
        }
    }
}
