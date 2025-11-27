//! Backwards-compatibility tests for the manifest.
//!
//! Any breakage of these tests likely means the encoding of the manifest
//! and/or the hashing of the manifest have changed, which means the root hash
//! is inconsistent for the same checkpoint between adjacent replica versions.

use crate::manifest::{
    DEFAULT_CHUNK_SIZE, manifest_hash, tests::computation::dummy_file_table_and_chunk_table,
};
use crate::state_sync::types::{
    ChunkInfo, FileInfo, MAX_SUPPORTED_STATE_SYNC_VERSION, Manifest, encode_manifest,
};
use ic_protobuf::state::sync::v1 as pb;
use ic_state_layout::{SUBNET_QUEUES_FILE, SYSTEM_METADATA_FILE};
use ic_types::state_sync::StateSyncVersion;
use proptest::prelude::*;

fn encode_file_info(file_info: &FileInfo) -> Vec<u8> {
    use prost::Message;

    let pb_file_info = pb::FileInfo::from(file_info.clone());
    pb_file_info.encode_to_vec()
}

fn encode_chunk_info(chunk_info: &ChunkInfo) -> Vec<u8> {
    use prost::Message;

    let pb_chunk_info = pb::ChunkInfo::from(chunk_info.clone());
    pb_chunk_info.encode_to_vec()
}

prop_compose! {
    /// Returns an arbitrary [`ChunkInfo`].
    pub fn arbitrary_chunk_info() (
        file_index in any::<u32>(),
        size_bytes in any::<u32>(),
        offset in any::<u64>(),
        hash in any::<[u8; 32]>(),
    ) -> ChunkInfo {
        ChunkInfo {
            file_index,
            size_bytes,
            offset,
            hash,
        }
    }
}

prop_compose! {
    /// Returns an arbitrary [`ChunkInfo`].
    pub fn arbitrary_file_info() (
        relative_path in any::<String>(),
        size_bytes in any::<u64>(),
        hash in any::<[u8; 32]>(),
    ) -> FileInfo {
        FileInfo {
            relative_path: std::path::PathBuf::from(relative_path),
            size_bytes,
            hash,
        }
    }
}

/// Implement the encoding of manifest according to the protobuf specification https://developers.google.com/protocol-buffers/docs/encoding.
/// The implementation is deterministic by its nature and can be used as the expected value
/// to check if the protobuf encoding is stable across replica versions.
const TAG_FILE_INFO_RELATIVE_PATH: [u8; 1] = [0x0au8];
const TAG_FILE_INFO_SIZE_BYTES: [u8; 1] = [0x10u8];
const TAG_FILE_INFO_HASH: [u8; 1] = [0x1au8];

const TAG_CHUNK_INFO_FILE_INDEX: [u8; 1] = [0x08u8];
const TAG_CHUNK_INFO_SIZE_BYTES: [u8; 1] = [0x10u8];
const TAG_CHUNK_INFO_OFFSET: [u8; 1] = [0x18u8];
const TAG_CHUNK_INFO_HASH: [u8; 1] = [0x22u8];

const TAG_MANIFEST_VERSION: [u8; 1] = [0x08u8];
const TAG_MANIFEST_FILE_INFO: [u8; 1] = [0x12u8];
const TAG_MANIFEST_CHUNK_INFO: [u8; 1] = [0x1au8];

fn encode_integer_expected(num: u64) -> Vec<u8> {
    let mut result = Vec::new();
    let mut num = num;
    while num >= 128 {
        let mut cur = (num & 0b01111111) as u8;
        cur |= 0b10000000;
        num >>= 7;
        result.push(cur);
    }
    result.push(num as u8);
    result
}

fn encode_file_info_expected(file_info: &FileInfo) -> Vec<u8> {
    let mut result = Vec::new();

    let relative_path = file_info
        .relative_path
        .to_string_lossy()
        .to_string()
        .into_bytes();

    if !relative_path.is_empty() {
        result.extend(TAG_FILE_INFO_RELATIVE_PATH);
        result.extend(encode_integer_expected(relative_path.len() as u64));
        result.extend(relative_path);
    }

    if file_info.size_bytes != 0 {
        result.extend(TAG_FILE_INFO_SIZE_BYTES);
        result.extend(encode_integer_expected(file_info.size_bytes));
    }

    result.extend(TAG_FILE_INFO_HASH);
    result.extend(encode_integer_expected(file_info.hash.len() as u64));
    result.extend(file_info.hash);

    result
}

fn encode_chunk_info_expected(chunk_info: &ChunkInfo) -> Vec<u8> {
    let mut result = Vec::new();

    if chunk_info.file_index != 0 {
        result.extend(TAG_CHUNK_INFO_FILE_INDEX);
        result.extend(encode_integer_expected(chunk_info.file_index as u64));
    }

    if chunk_info.size_bytes != 0 {
        result.extend(TAG_CHUNK_INFO_SIZE_BYTES);
        result.extend(encode_integer_expected(chunk_info.size_bytes as u64));
    }

    if chunk_info.offset != 0 {
        result.extend(TAG_CHUNK_INFO_OFFSET);
        result.extend(encode_integer_expected(chunk_info.offset));
    }

    result.extend(TAG_CHUNK_INFO_HASH);
    result.extend(encode_integer_expected(chunk_info.hash.len() as u64));
    result.extend(chunk_info.hash);

    result
}

fn encode_manifest_expected(manifest: &Manifest) -> Vec<u8> {
    let mut result = Vec::new();

    if manifest.version != StateSyncVersion::V0 {
        result.extend(TAG_MANIFEST_VERSION);
        result.extend(encode_integer_expected(manifest.version as u64));
    }

    for file_info in &manifest.file_table {
        result.extend(TAG_MANIFEST_FILE_INFO);
        let encoded_file_info = encode_file_info_expected(file_info);
        result.extend(encode_integer_expected(encoded_file_info.len() as u64));
        result.extend(encoded_file_info);
    }
    for chunk_info in &manifest.chunk_table {
        result.extend(TAG_MANIFEST_CHUNK_INFO);
        let encoded_chunk_info = encode_chunk_info_expected(chunk_info);
        result.extend(encode_integer_expected(encoded_chunk_info.len() as u64));
        result.extend(encoded_chunk_info);
    }
    result
}

/// Deterministic encoding of:
///
///```no_run
/// FileInfo {
///    relative_path: "canister_states/000000000010ffff0101/stable_memory.bin".into(),
///    size_bytes: 10_000_000_000,
///    hash: hex_to_hash("881305d7c0b2ace0f53fe822f4075278fa28511e8c34e70f37fd8425af659b36"),
/// }
/// ```
/// Expected protobuf encoding:
///
/// ```text
/// 0a              # field_number of `relative_path` = 1, wire_type = 2, tag = 1 << 3 | 2
///     36          # length of `relative_path` = 54
///     63616e69737465725f7374617465732f30303030303030303030313066666666303130312f737461626c655f6d656d6f72792e62696e # canister_states/000000000010ffff0101/stable_memory.bin
/// 10              # field_number of `size_bytes` = 2, wire_type = 0, tag = 2 << 3 | 0
///     80c8afa025  # value of size_bytes = 10_000_000_000 Note: refer to https://developers.google.com/protocol-buffers/docs/encoding#varints for the encoding of variable-width integers
/// 1a              # field_number of `hash` = 3, wire_type = 2, tag = 3 << 3 | 2
///     20          # length of `hash` = 32
///     881305d7c0b2ace0f53fe822f4075278fa28511e8c34e70f37fd8425af659b36 # value of hash
/// ```
const EXPECTED_ENCODED_FILE_INFO: &str = "0a3663616e69737465725f7374617465732f30303030303030303030313066666666303130312f737461626c655f6d656d6f72792e62696e1080c8afa0251a20881305d7c0b2ace0f53fe822f4075278fa28511e8c34e70f37fd8425af659b36";

#[test]
fn test_encoding_file_info() {
    let file_info = FileInfo {
        relative_path: "canister_states/000000000010ffff0101/stable_memory.bin".into(),
        size_bytes: 10_000_000_000,
        hash: hex_to_hash("881305d7c0b2ace0f53fe822f4075278fa28511e8c34e70f37fd8425af659b36"),
    };

    assert_eq!(
        hex::encode(encode_file_info_expected(&file_info)),
        EXPECTED_ENCODED_FILE_INFO.to_owned()
    );
    assert_eq!(
        hex::encode(encode_file_info(&file_info)),
        EXPECTED_ENCODED_FILE_INFO.to_owned()
    );
}

/// Deterministic encoding of:
///
///```no_run
/// ChunkInfo {
///    file_index: 1,
///    size_bytes: 192,
///    offset: 0,
///    hash: hex_to_hash("5cbaf08a21e06f3a359ec28b9a774eb79cf2c22164540ab4c37a9d6427b7b258"),
/// }
/// ```
/// Expected protobuf encoding:
///
/// ```text
/// 08              # field_number of `file_index` = 1, wire_type = 0, tag = 1 << 3 | 0
///     a08d06      # file_index = 100_000
/// 10              # field_number of `size_bytes` = 2, wire_type = 0, tag = 2 << 3 | 0
///     808040      # size_bytes = 1_048_576
/// 18              # field_number of `offset` = 3, wire_type = 0, tag = 3 << 3 | 0
///     808080f403  # offset = 1_048_576_000
/// 22              # field_number of `hash` = 4, wire_type = 2, tag = 4 << 3 | 2
///     20          # length = 32
///     5cbaf08a21e06f3a359ec28b9a774eb79cf2c22164540ab4c37a9d6427b7b258
/// ```
const EXPECTED_ENCODED_CHUNK_INFO: &str = "08a08d061080804018808080f40322205cbaf08a21e06f3a359ec28b9a774eb79cf2c22164540ab4c37a9d6427b7b258";

#[test]
fn test_encoding_chunk_info() {
    let chunk_info = ChunkInfo {
        file_index: 100_000,
        size_bytes: 1_048_576,
        offset: 1_048_576_000,
        hash: hex_to_hash("5cbaf08a21e06f3a359ec28b9a774eb79cf2c22164540ab4c37a9d6427b7b258"),
    };

    assert_eq!(
        hex::encode(encode_chunk_info_expected(&chunk_info)),
        EXPECTED_ENCODED_CHUNK_INFO.to_owned()
    );

    assert_eq!(
        hex::encode(encode_chunk_info(&chunk_info)),
        EXPECTED_ENCODED_CHUNK_INFO.to_owned()
    );
}

/// Deterministic encoding of the manifest:
///
/// The manifest below is computed from the checkpoint in a real subnet with 1 canister.
///
///```text
/// VERSION: 2
/// FILE TABLE
///     idx     |    size    |                               hash                               |                         path
/// ------------+------------+------------------------------------------------------------------+------------------------------------------------------
///           0 |          0 | 981305d7c0b2ace0f53fe822f4075278fa28511e8c34e70f37fd8425af659b36 | bitcoin/testnet/address_outpoints.bin
///           1 |        319 | 5b47e1fb48988925cecb65aa78b9af5191338b761d16285ad99d550e8f518225 | bitcoin/testnet/state.pbuf
///           2 |          0 | 981305d7c0b2ace0f53fe822f4075278fa28511e8c34e70f37fd8425af659b36 | bitcoin/testnet/utxos_medium.bin
///           3 |          0 | 981305d7c0b2ace0f53fe822f4075278fa28511e8c34e70f37fd8425af659b36 | bitcoin/testnet/utxos_small.bin
///           4 |        192 | 4c99cb3e6eb95d37a72345a79c78c58c3d3a193ad47789b29156e0245cc44a42 | canister_states/00000000001000000101/canister.pbuf
///           5 |          0 | 981305d7c0b2ace0f53fe822f4075278fa28511e8c34e70f37fd8425af659b36 | canister_states/00000000001000000101/queues.pbuf
///           6 |        218 | c790871526c7130487da1a88ce300074b50d1020f6368e043726af40535c3893 | canister_states/00000000001000000101/software.wasm
///           7 |          0 | 981305d7c0b2ace0f53fe822f4075278fa28511e8c34e70f37fd8425af659b36 | canister_states/00000000001000000101/stable_memory.bin
///           8 |          0 | 981305d7c0b2ace0f53fe822f4075278fa28511e8c34e70f37fd8425af659b36 | canister_states/00000000001000000101/vmemory_0.bin
///           9 |          0 | 981305d7c0b2ace0f53fe822f4075278fa28511e8c34e70f37fd8425af659b36 | subnet_queues.pbuf
///          10 |        887 | 1c134cd6a9d691d3ec74a81eec5462d5af8653be53beb61e26b884958ebd2d05 | system_metadata.pbuf
/// CHUNK TABLE
///     idx     |  file_idx  |   offset   |    size    |                               hash
/// ------------+------------+------------+------------+------------------------------------------------------------------
///           0 |          1 |          0 |        319 | 4cbaf08a21e06f3a359ec28b9a774eb79cf2c22164540ab4c37a9d6427b7b258
///           1 |          4 |          0 |        192 | 92b48865e4c666592080e97cf49f4bb18ea1b24811c754c52a391554a4be959c
///           2 |          6 |          0 |        218 | 66de6749199845f0fa41b0e0c944eb06ba1927197970674dd242895a82d359fe
///           3 |         10 |          0 |        887 | 2b71ffd247351b2918a1d64a5f019d79de950ff612efc8a4a1e81b5f6543f517
///```
///
/// Expected protobuf encoding:
///
/// ```text
/// 08              # field_number of `version` = 1, wire_type = 0, tag = 1 << 3 | 0 Note: refer to https://developers.google.com/protocol-buffers/docs/encoding#structure for the encoding of tags
///     02          # value of `version` = 2
///
/// 12              # field_number of `file_info` = 2, wire_type = 2, tag = 2 << 3 | 2
///     49          # length of `file_info` = 73
///     0a          # field_number of `relative_path` = 1, wire_type = 2, tag = 1 << 3 | 2
///         25      # length of `relative_path` = 37
///         626974636f696e2f746573746e65742f616464726573735f6f7574706f696e74732e62696e # bitcoin/testnet/address_outpoints.bin
///     1a          # field_number of `hash` = 3, wire_type = 2, tag = 3 << 3 | 2
///         20      # length of `hash` = 32
///         981305d7c0b2ace0f53fe822f4075278fa28511e8c34e70f37fd8425af659b36 # value of hash
///
/// 12              # file_info
///     41          # length = 65
///     0a          # relative_path
///         1a      # length = 26
///         626974636f696e2f746573746e65742f73746174652e70627566    # bitcoin/testnet/state.pbuf
///     10          # field_number of `size_bytes` = 2, wire_type = 0, tag = 2 << 3 | 0
///         bf02    # value of size_bytes = 319 Note: refer to https://developers.google.com/protocol-buffers/docs/encoding#varints for the encoding of variable-width integers
///     1a          # hash
///         20      # length = 32
///         5b47e1fb48988925cecb65aa78b9af5191338b761d16285ad99d550e8f518225
///
/// 12              # file_info
///     44          # length = 68
///     0a          # relative_path
///         20      # length = 32
///         626974636f696e2f746573746e65742f7574786f735f6d656469756d2e62696e # bitcoin/testnet/utxos_medium.bin
///     1a          # hash
///         20      # length = 32
///         981305d7c0b2ace0f53fe822f4075278fa28511e8c34e70f37fd8425af659b36
///
/// 12              # file_info
///     43          # length = 67
///     0a          # relative_path
///         1f      # length = 31
///         626974636f696e2f746573746e65742f7574786f735f736d616c6c2e62696e # bitcoin/testnet/utxos_small.bin
///     1a          # hash
///         20      # length = 32
///         981305d7c0b2ace0f53fe822f4075278fa28511e8c34e70f37fd8425af659b36
///
/// 12              # file_info
///     59          # length = 89
///     0a          # relative_path
///         32      # length = 50
///         63616e69737465725f7374617465732f30303030303030303030313030303030303130312f63616e69737465722e70627566 # canister_states/00000000001000000101/canister.pbuf
///     10          # size_bytes
///         c001    # 192
///     1a          # hash
///         20      # length = 32
///         4c99cb3e6eb95d37a72345a79c78c58c3d3a193ad47789b29156e0245cc44a42
///
/// 12              # file_info
///     54          # length = 84
///     0a          # relative_path
///         30      # length = 48
///         63616e69737465725f7374617465732f30303030303030303030313030303030303130312f7175657565732e70627566 # canister_states/00000000001000000101/queues.pbuf
///     1a          # hash
///         20      # length = 32
///         981305d7c0b2ace0f53fe822f4075278fa28511e8c34e70f37fd8425af659b36
///
/// 12              # file_info
///     59          # length = 89
///     0a          # relative_path
///         32      # length = 50
///         63616e69737465725f7374617465732f30303030303030303030313030303030303130312f736f6674776172652e7761736d # canister_states/00000000001000000101/software.wasm
///     10          # size_bytes
///         da01    # 218
///     1a          # hash
///         20      # length = 32
///         c790871526c7130487da1a88ce300074b50d1020f6368e043726af40535c3893
///
/// 12              # file_info
///     5a          # length = 90
///     0a          # relative_path
///         36      # length = 54
///         63616e69737465725f7374617465732f30303030303030303030313030303030303130312f737461626c655f6d656d6f72792e62696e # canister_states/00000000001000000101/stable_memory.bin
///     1a          # hash
///         20      # length = 32
///         981305d7c0b2ace0f53fe822f4075278fa28511e8c34e70f37fd8425af659b36
///
/// 12              # file_info
///     56          # length = 86
///     0a          # relative_path
///         32      # length = 50
///         63616e69737465725f7374617465732f30303030303030303030313030303030303130312f766d656d6f72795f302e62696e # canister_states/00000000001000000101/vmemory_0.bin
///     1a          # hash
///         20      # length = 32
///         981305d7c0b2ace0f53fe822f4075278fa28511e8c34e70f37fd8425af659b36
///
/// 12              # file_info
///     36          # length = 54
///     0a          # relative_path
///         12      # length = 18
///         7375626e65745f7175657565732e70627566 # subnet_queues.pbuf
///     1a          # hash
///         20      # length = 32
///         981305d7c0b2ace0f53fe822f4075278fa28511e8c34e70f37fd8425af659b36
///
/// 12              # file_info
///     3b          # length = 59
///     0a          # relative_path
///         14      # length = 20
///         73797374656d5f6d657461646174612e70627566 # system_metadata.pbuf
///     10          # size_bytes
///         f706    # 887
///     1a          # hash
///         20      # length = 32
///         1c134cd6a9d691d3ec74a81eec5462d5af8653be53beb61e26b884958ebd2d05
///
/// 1a              # field_number of `chunk_info` = 3, wire_type = 2, tag = 3 << 3 | 2
///     27          # length = 39
///     08          # field_number of `file_index` = 1, wire_type = 0, tag = 1 << 3 | 0
///         01      # file_index = 1
///     10          # field_number of `size_bytes` = 2, wire_type = 0, tag = 2 << 3 | 0
///         bf02        # size_bytes = 319
///     22          # field_number of `hash` = 4, wire_type = 2, tag = 4 << 3 | 2
///         20      # length = 32
///         4cbaf08a21e06f3a359ec28b9a774eb79cf2c22164540ab4c37a9d6427b7b258
///
/// 1a              # chunk_info
///     27          # length = 39
///     08          # file_index
///         04      # 4
///     10          # size_bytes
///         c001    # 192
///     22          # hash
///         20      # length = 32
///         92b48865e4c666592080e97cf49f4bb18ea1b24811c754c52a391554a4be959c
///
/// 1a              # chunk_info
///     27          # length = 39
///     08          # file_index
///         06      # 6
///     10          # size_bytes
///         da01    # 218
///     22          # hash
///         20      # length = 32
///         66de6749199845f0fa41b0e0c944eb06ba1927197970674dd242895a82d359fe
///
/// 1a              # chunk_info
///     27          # length = 39
///     08          # file_index
///         0a      # 10
///     10          # size_bytes
///         f706    # 887
///     22          # hash
///         20      # length = 32
///         2b71ffd247351b2918a1d64a5f019d79de950ff612efc8a4a1e81b5f6543f517
/// ```
/// Note that https://github.com/protocolbuffers/protoscope and https://protogen.marcgravell.com/decode are helpful to get well-printed protobuf encoding representation like above.
/// They can be useful to find which part of the encoded result changes when the deterministic encoding tests fail.
const EXPECTED_ENCODED_MANIFEST: &str = "080212490a25626974636f696e2f746573746e65742f616464726573735f6f7574706f696e74732e62696e1a20981305d7c0b2ace0f53fe822f4075278fa28511e8c34e70f37fd8425af659b3612410a1a626974636f696e2f746573746e65742f73746174652e7062756610bf021a205b47e1fb48988925cecb65aa78b9af5191338b761d16285ad99d550e8f51822512440a20626974636f696e2f746573746e65742f7574786f735f6d656469756d2e62696e1a20981305d7c0b2ace0f53fe822f4075278fa28511e8c34e70f37fd8425af659b3612430a1f626974636f696e2f746573746e65742f7574786f735f736d616c6c2e62696e1a20981305d7c0b2ace0f53fe822f4075278fa28511e8c34e70f37fd8425af659b3612590a3263616e69737465725f7374617465732f30303030303030303030313030303030303130312f63616e69737465722e7062756610c0011a204c99cb3e6eb95d37a72345a79c78c58c3d3a193ad47789b29156e0245cc44a4212540a3063616e69737465725f7374617465732f30303030303030303030313030303030303130312f7175657565732e706275661a20981305d7c0b2ace0f53fe822f4075278fa28511e8c34e70f37fd8425af659b3612590a3263616e69737465725f7374617465732f30303030303030303030313030303030303130312f736f6674776172652e7761736d10da011a20c790871526c7130487da1a88ce300074b50d1020f6368e043726af40535c3893125a0a3663616e69737465725f7374617465732f30303030303030303030313030303030303130312f737461626c655f6d656d6f72792e62696e1a20981305d7c0b2ace0f53fe822f4075278fa28511e8c34e70f37fd8425af659b3612560a3263616e69737465725f7374617465732f30303030303030303030313030303030303130312f766d656d6f72795f302e62696e1a20981305d7c0b2ace0f53fe822f4075278fa28511e8c34e70f37fd8425af659b3612360a127375626e65745f7175657565732e706275661a20981305d7c0b2ace0f53fe822f4075278fa28511e8c34e70f37fd8425af659b36123b0a1473797374656d5f6d657461646174612e7062756610f7061a201c134cd6a9d691d3ec74a81eec5462d5af8653be53beb61e26b884958ebd2d051a27080110bf0222204cbaf08a21e06f3a359ec28b9a774eb79cf2c22164540ab4c37a9d6427b7b2581a27080410c001222092b48865e4c666592080e97cf49f4bb18ea1b24811c754c52a391554a4be959c1a27080610da01222066de6749199845f0fa41b0e0c944eb06ba1927197970674dd242895a82d359fe1a27080a10f70622202b71ffd247351b2918a1d64a5f019d79de950ff612efc8a4a1e81b5f6543f517";

fn hex_to_hash(hex_str: &str) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    hex::decode_to_slice(hex_str, &mut bytes as &mut [u8])
        .expect("failed to convert hex string to hash of 32 bytes");
    bytes
}

fn testcase_file_table_and_chunk_table() -> (Vec<FileInfo>, Vec<ChunkInfo>) {
    let file_info_0 = FileInfo {
        relative_path: "bitcoin/testnet/address_outpoints.bin".into(),
        size_bytes: 0,
        hash: hex_to_hash("981305d7c0b2ace0f53fe822f4075278fa28511e8c34e70f37fd8425af659b36"),
    };
    let file_info_1 = FileInfo {
        relative_path: "bitcoin/testnet/state.pbuf".into(),
        size_bytes: 319,
        hash: hex_to_hash("5b47e1fb48988925cecb65aa78b9af5191338b761d16285ad99d550e8f518225"),
    };
    let file_info_2 = FileInfo {
        relative_path: "bitcoin/testnet/utxos_medium.bin".into(),
        size_bytes: 0,
        hash: hex_to_hash("981305d7c0b2ace0f53fe822f4075278fa28511e8c34e70f37fd8425af659b36"),
    };
    let file_info_3 = FileInfo {
        relative_path: "bitcoin/testnet/utxos_small.bin".into(),
        size_bytes: 0,
        hash: hex_to_hash("981305d7c0b2ace0f53fe822f4075278fa28511e8c34e70f37fd8425af659b36"),
    };
    let file_info_4 = FileInfo {
        relative_path: "canister_states/00000000001000000101/canister.pbuf".into(),
        size_bytes: 192,
        hash: hex_to_hash("4c99cb3e6eb95d37a72345a79c78c58c3d3a193ad47789b29156e0245cc44a42"),
    };
    let file_info_5 = FileInfo {
        relative_path: "canister_states/00000000001000000101/queues.pbuf".into(),
        size_bytes: 0,
        hash: hex_to_hash("981305d7c0b2ace0f53fe822f4075278fa28511e8c34e70f37fd8425af659b36"),
    };
    let file_info_6 = FileInfo {
        relative_path: "canister_states/00000000001000000101/software.wasm".into(),
        size_bytes: 218,
        hash: hex_to_hash("c790871526c7130487da1a88ce300074b50d1020f6368e043726af40535c3893"),
    };
    let file_info_7 = FileInfo {
        relative_path: "canister_states/00000000001000000101/stable_memory.bin".into(),
        size_bytes: 0,
        hash: hex_to_hash("981305d7c0b2ace0f53fe822f4075278fa28511e8c34e70f37fd8425af659b36"),
    };
    let file_info_8 = FileInfo {
        relative_path: "canister_states/00000000001000000101/vmemory_0.bin".into(),
        size_bytes: 0,
        hash: hex_to_hash("981305d7c0b2ace0f53fe822f4075278fa28511e8c34e70f37fd8425af659b36"),
    };
    let file_info_9 = FileInfo {
        relative_path: SUBNET_QUEUES_FILE.into(),
        size_bytes: 0,
        hash: hex_to_hash("981305d7c0b2ace0f53fe822f4075278fa28511e8c34e70f37fd8425af659b36"),
    };
    let file_info_10 = FileInfo {
        relative_path: SYSTEM_METADATA_FILE.into(),
        size_bytes: 887,
        hash: hex_to_hash("1c134cd6a9d691d3ec74a81eec5462d5af8653be53beb61e26b884958ebd2d05"),
    };

    let chunk_info_0 = ChunkInfo {
        file_index: 1,
        size_bytes: 319,
        offset: 0,
        hash: hex_to_hash("4cbaf08a21e06f3a359ec28b9a774eb79cf2c22164540ab4c37a9d6427b7b258"),
    };
    let chunk_info_1 = ChunkInfo {
        file_index: 4,
        size_bytes: 192,
        offset: 0,
        hash: hex_to_hash("92b48865e4c666592080e97cf49f4bb18ea1b24811c754c52a391554a4be959c"),
    };
    let chunk_info_2 = ChunkInfo {
        file_index: 6,
        size_bytes: 218,
        offset: 0,
        hash: hex_to_hash("66de6749199845f0fa41b0e0c944eb06ba1927197970674dd242895a82d359fe"),
    };
    let chunk_info_3 = ChunkInfo {
        file_index: 10,
        size_bytes: 887,
        offset: 0,
        hash: hex_to_hash("2b71ffd247351b2918a1d64a5f019d79de950ff612efc8a4a1e81b5f6543f517"),
    };
    (
        vec![
            file_info_0,
            file_info_1,
            file_info_2,
            file_info_3,
            file_info_4,
            file_info_5,
            file_info_6,
            file_info_7,
            file_info_8,
            file_info_9,
            file_info_10,
        ],
        vec![chunk_info_0, chunk_info_1, chunk_info_2, chunk_info_3],
    )
}

#[test]
fn test_encoding_manifest() {
    let (file_table, chunk_table) = testcase_file_table_and_chunk_table();
    let manifest = Manifest::new(StateSyncVersion::V2, file_table, chunk_table);

    assert_eq!(
        hex::encode(encode_manifest_expected(&manifest)),
        EXPECTED_ENCODED_MANIFEST.to_owned()
    );

    assert_eq!(
        hex::encode(encode_manifest(&manifest)),
        EXPECTED_ENCODED_MANIFEST.to_owned()
    );
}

#[test]
fn deterministic_manifest_hash() {
    let (file_table, chunk_table) = testcase_file_table_and_chunk_table();
    let manifest_v1 = Manifest::new(
        StateSyncVersion::V1,
        file_table.clone(),
        chunk_table.clone(),
    );
    assert_eq!(
        hex::encode(manifest_hash(&manifest_v1)),
        "7569c279f5054addc6949493293c8ad24f87b166fbff18a5bfe3908c23f8d3b5".to_owned()
    );
    let manifest_v2 = Manifest::new(StateSyncVersion::V2, file_table, chunk_table);
    assert_eq!(
        hex::encode(manifest_hash(&manifest_v2)),
        "24dad2a74373217053106e533da8fa2dc67560e0780df06bdd5ca9eb749d1242".to_owned()
    );

    // Ensure the hash is still stable when the manifest is larger than 100 MiB after encoding.
    let (file_table, chunk_table) = dummy_file_table_and_chunk_table();
    let manifest_v1 = Manifest::new(
        StateSyncVersion::V1,
        file_table.clone(),
        chunk_table.clone(),
    );
    assert_eq!(
        hex::encode(manifest_hash(&manifest_v1)),
        "18aabe0f8bc12b80bc232c02e0d6ca1b8a078980b7f8799ac992f06696fc1385".to_owned()
    );
    let manifest_v2 = Manifest::new(StateSyncVersion::V2, file_table, chunk_table);
    assert!(
        encode_manifest(&manifest_v2).len() > 100 * DEFAULT_CHUNK_SIZE as usize,
        "The encoded manifest is supposed to be larger than 100 MiB."
    );
    assert_eq!(
        hex::encode(manifest_hash(&manifest_v2)),
        "8df9274f839167037f02e7bd121a1c272c04d9363907f956b896e92ebd64aa06".to_owned()
    );
}

#[test_strategy::proptest]
fn chunk_info_deterministic_encoding(#[strategy(arbitrary_chunk_info())] chunk_info: ChunkInfo) {
    assert_eq!(
        encode_chunk_info(&chunk_info),
        encode_chunk_info_expected(&chunk_info)
    );
}

#[test_strategy::proptest]
fn file_info_deterministic_encoding(#[strategy(arbitrary_file_info())] file_info: FileInfo) {
    assert_eq!(
        encode_file_info(&file_info),
        encode_file_info_expected(&file_info)
    );
}

#[test_strategy::proptest]
fn manifest_deterministic_encoding(
    #[strategy(0..=MAX_SUPPORTED_STATE_SYNC_VERSION as u32)] version: u32,
    #[strategy(prop::collection::vec(arbitrary_file_info(), 0..=1000))] file_table: Vec<FileInfo>,
    #[strategy(prop::collection::vec(arbitrary_chunk_info(), 0..=1000))] chunk_table: Vec<
        ChunkInfo,
    >,
) {
    let manifest = Manifest::new(version.try_into().unwrap(), file_table, chunk_table);
    assert_eq!(
        encode_manifest(&manifest),
        encode_manifest_expected(&manifest)
    );
}
