use bitcoin::{
    hashes::Hash, Block, BlockHash, BlockHeader, OutPoint, Script, Transaction, TxIn, TxMerkleNode,
    TxOut, Txid,
};
use ic_protobuf::bitcoin::v1;

/// Converts a `Block` into a protobuf struct.
pub fn to_proto(block: &Block) -> v1::Block {
    v1::Block {
        header: Some(v1::BlockHeader {
            version: block.header.version,
            prev_blockhash: block.header.prev_blockhash.to_vec(),
            merkle_root: block.header.merkle_root.to_vec(),
            time: block.header.time,
            bits: block.header.bits,
            nonce: block.header.nonce,
        }),
        txdata: block
            .txdata
            .iter()
            .map(|t| v1::Transaction {
                version: t.version,
                lock_time: t.lock_time,
                input: t
                    .input
                    .iter()
                    .map(|i| v1::TxIn {
                        previous_output: Some(v1::OutPoint {
                            txid: i.previous_output.txid.to_vec(),
                            vout: i.previous_output.vout,
                        }),
                        script_sig: i.script_sig.to_bytes(),
                        sequence: i.sequence,
                        witness: i.witness.clone(),
                    })
                    .collect(),
                output: t
                    .output
                    .iter()
                    .map(|o| v1::TxOut {
                        value: o.value,
                        script_pubkey: o.script_pubkey.to_bytes(),
                    })
                    .collect(),
            })
            .collect(),
    }
}

/// Converts a protobuf block into a `Block`.
pub fn from_proto(block: &v1::Block) -> Block {
    let header = block.header.as_ref().expect("Block header must exist");

    Block {
        header: BlockHeader {
            version: header.version,
            prev_blockhash: BlockHash::from_hash(Hash::from_slice(&header.prev_blockhash).unwrap()),
            merkle_root: TxMerkleNode::from_hash(Hash::from_slice(&header.merkle_root).unwrap()),
            time: header.time,
            bits: header.bits,
            nonce: header.nonce,
        },
        txdata: block
            .txdata
            .iter()
            .map(|t| Transaction {
                version: t.version,
                lock_time: t.lock_time,
                input: t
                    .input
                    .iter()
                    .map(|i| {
                        let prev_output = i.previous_output.as_ref().unwrap();
                        TxIn {
                            previous_output: OutPoint::new(
                                Txid::from_hash(Hash::from_slice(&prev_output.txid).unwrap()),
                                prev_output.vout,
                            ),
                            script_sig: Script::from(i.script_sig.clone()),
                            sequence: i.sequence,
                            witness: i.witness.clone(),
                        }
                    })
                    .collect(),
                output: t
                    .output
                    .iter()
                    .map(|o| TxOut {
                        value: o.value,
                        script_pubkey: Script::from(o.script_pubkey.clone()),
                    })
                    .collect(),
            })
            .collect(),
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use ic_btc_test_utils::{BlockBuilder, TransactionBuilder};

    #[test]
    fn to_from_proto() {
        // Generate random blocks and verify that serializing/deserializing is a noop.
        let genesis = BlockBuilder::genesis()
            .with_transaction(TransactionBuilder::coinbase().build())
            .build();
        assert_eq!(genesis, from_proto(&to_proto(&genesis)));

        for _ in 0..100 {
            let block = BlockBuilder::with_prev_header(genesis.header)
                .with_transaction(TransactionBuilder::coinbase().build())
                .build();
            assert_eq!(block, from_proto(&to_proto(&block)));
        }
    }
}
