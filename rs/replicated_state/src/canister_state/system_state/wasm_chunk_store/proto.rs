use super::*;
use ic_protobuf::{proxy::ProxyDecodeError, state::canister_state_bits::v1 as pb};

impl From<&WasmChunkStoreMetadata> for pb::WasmChunkStoreMetadata {
    fn from(item: &WasmChunkStoreMetadata) -> Self {
        let chunks = item
            .chunks
            .iter()
            .map(|(hash, ChunkInfo { index, length })| pb::WasmChunkData {
                hash: hash.to_vec(),
                index: *index,
                length: *length,
            })
            .collect::<Vec<_>>();
        let size = item.size.get();
        pb::WasmChunkStoreMetadata { chunks, size }
    }
}

impl TryFrom<pb::WasmChunkStoreMetadata> for WasmChunkStoreMetadata {
    type Error = ProxyDecodeError;

    fn try_from(value: pb::WasmChunkStoreMetadata) -> Result<Self, Self::Error> {
        let mut chunks = BTreeMap::new();
        for chunk in value.chunks {
            let hash: [u8; 32] =
                chunk
                    .hash
                    .try_into()
                    .map_err(|e| ProxyDecodeError::ValueOutOfRange {
                        typ: "[u8; 32]",
                        err: format!("Failed to convert vector to fixed size arrary: {e:?}"),
                    })?;
            chunks.insert(
                hash,
                ChunkInfo {
                    index: chunk.index,
                    length: chunk.length,
                },
            );
        }

        let size = value.size.into();
        Ok(Self { chunks, size })
    }
}
