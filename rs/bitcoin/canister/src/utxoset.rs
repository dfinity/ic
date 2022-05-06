use crate::address_utxoset::AddressUtxoSet;
use crate::{state::UtxoSet, types::Storable, utxos::UtxosTrait};
use bitcoin::{Address, OutPoint, Transaction, TxOut, Txid};
use std::str::FromStr;

type Height = u32;

lazy_static::lazy_static! {
    static ref DUPLICATE_TX_IDS: [Txid; 2] = [
        Txid::from_str("d5d27987d2a3dfc724e359870c6644b40e497bdc0589a033220fe15429d88599").unwrap(),
        Txid::from_str("e3bf3d07d4b0375638d5f1db5255fe07ba2c4cb067cd81b84ee974b6585fb468").unwrap()
    ];
}

/// Returns the `UtxoSet` of a given bitcoin address.
pub fn get_utxos<'a>(utxo_set: &'a UtxoSet, address: &'a str) -> AddressUtxoSet<'a> {
    AddressUtxoSet::new(address.to_string(), utxo_set)
}

/// Inserts a transaction into the given UTXO set at the given height.
pub fn insert_tx(utxo_set: &mut UtxoSet, tx: &Transaction, height: Height) {
    remove_spent_txs(utxo_set, tx);
    insert_unspent_txs(utxo_set, tx, height);
}

// Iterates over transaction inputs and removes spent outputs.
fn remove_spent_txs(utxo_set: &mut UtxoSet, tx: &Transaction) {
    if tx.is_coin_base() {
        return;
    }

    for input in &tx.input {
        // Remove the input from the UTXOs. The input *must* exist in the UTXO set.
        match utxo_set.utxos.remove(&input.previous_output) {
            Some((txout, height)) => {
                if let Some(address) = Address::from_script(&txout.script_pubkey, utxo_set.network)
                {
                    let address = address.to_string();
                    let found = utxo_set
                        .address_to_outpoints
                        .remove(&(address, height, input.previous_output).to_bytes());

                    assert!(
                        found.is_some(),
                        "Outpoint {:?} not found in the index.",
                        input.previous_output
                    );
                }
            }
            None => {
                panic!("Outpoint {:?} not found.", input.previous_output);
            }
        }
    }
}

// Iterates over transaction outputs and adds unspents.
fn insert_unspent_txs(utxo_set: &mut UtxoSet, tx: &Transaction, height: Height) {
    for (vout, output) in tx.output.iter().enumerate() {
        if !(output.script_pubkey.is_provably_unspendable()) {
            insert_utxo(
                utxo_set,
                OutPoint::new(tx.txid(), vout as u32),
                output.clone(),
                height,
            );
        }
    }
}

// Inserts a UTXO at a given height into the given UTXO set.
// A UTXO is represented by the the tuple: (outpoint, output)
pub(crate) fn insert_utxo(
    utxo_set: &mut UtxoSet,
    outpoint: OutPoint,
    output: TxOut,
    height: Height,
) {
    // Verify that we haven't seen the outpoint before.
    // NOTE: There was a bug where there were duplicate transactions. These transactions
    // we overwrite.
    //
    // See: https://en.bitcoin.it/wiki/BIP_0030
    //      https://bitcoinexplorer.org/tx/d5d27987d2a3dfc724e359870c6644b40e497bdc0589a033220fe15429d88599
    //      https://bitcoinexplorer.org/tx/e3bf3d07d4b0375638d5f1db5255fe07ba2c4cb067cd81b84ee974b6585fb468
    if utxo_set.utxos.contains_key(&outpoint) && !DUPLICATE_TX_IDS.contains(&outpoint.txid) {
        panic!(
            "Cannot insert outpoint {:?} because it was already inserted. Block height: {}",
            outpoint, height
        );
    }

    // Insert the outpoint.
    if let Some(address) = Address::from_script(&output.script_pubkey, utxo_set.network) {
        // Add the address to the index if we can parse it.
        utxo_set
            .address_to_outpoints
            .insert((address.to_string(), height, outpoint).to_bytes(), vec![])
            .expect("insertion must succeed");
    }

    utxo_set.utxos.insert(outpoint, (output, height));
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{test_builder::TransactionBuilder, types::Address as AddressStr};
    use bitcoin::blockdata::{opcodes::all::OP_RETURN, script::Builder};
    use bitcoin::secp256k1::rand::rngs::OsRng;
    use bitcoin::secp256k1::Secp256k1;
    use bitcoin::{Address, Network, PublicKey, TxOut};
    use std::collections::BTreeSet;

    #[test]
    fn coinbase_tx() {
        for network in [Network::Bitcoin, Network::Regtest, Network::Testnet].iter() {
            let secp = Secp256k1::new();
            let mut rng = OsRng::new().unwrap();

            let address =
                Address::p2pkh(&PublicKey::new(secp.generate_keypair(&mut rng).1), *network);

            let coinbase_tx = TransactionBuilder::coinbase()
                .with_output(&address, 1000)
                .build();

            let mut utxo = UtxoSet::new(*network);
            insert_tx(&mut utxo, &coinbase_tx, 0);

            assert_eq!(utxo.utxos.len(), 1);
            assert_eq!(
                get_utxos(&utxo, &address.to_string()).into_vec(),
                vec![ic_btc_types::Utxo {
                    outpoint: ic_btc_types::OutPoint {
                        txid: coinbase_tx.txid().to_vec(),
                        vout: 0,
                    },
                    value: 1000,
                    height: 0,
                }]
            );
        }
    }

    #[test]
    fn tx_without_outputs_leaves_utxo_set_unchanged() {
        for network in [Network::Bitcoin, Network::Regtest, Network::Testnet].iter() {
            let mut utxo = UtxoSet::new(*network);

            // no output coinbase
            let mut coinbase_empty_tx = TransactionBuilder::coinbase().build();
            coinbase_empty_tx.output.clear();
            insert_tx(&mut utxo, &coinbase_empty_tx, 0);

            assert!(utxo.utxos.is_empty());
            assert!(utxo.address_to_outpoints.is_empty());
        }
    }

    #[test]
    fn filter_provably_unspendable_utxos() {
        for network in [Network::Bitcoin, Network::Regtest, Network::Testnet].iter() {
            let mut utxo = UtxoSet::new(*network);

            // op return coinbase
            let coinbase_op_return_tx = Transaction {
                output: vec![TxOut {
                    value: 50_0000_0000,
                    script_pubkey: Builder::new().push_opcode(OP_RETURN).into_script(),
                }],
                input: vec![],
                version: 1,
                lock_time: 0,
            };
            insert_tx(&mut utxo, &coinbase_op_return_tx, 0);

            assert!(utxo.utxos.is_empty());
            assert!(utxo.address_to_outpoints.is_empty());
        }
    }

    #[test]
    fn spending() {
        for network in [Network::Bitcoin, Network::Regtest, Network::Testnet].iter() {
            let secp = Secp256k1::new();
            let mut rng = OsRng::new().unwrap();
            let address_1 =
                Address::p2pkh(&PublicKey::new(secp.generate_keypair(&mut rng).1), *network);
            let address_2 =
                Address::p2pkh(&PublicKey::new(secp.generate_keypair(&mut rng).1), *network);

            let mut utxo = UtxoSet::new(*network);

            let coinbase_tx = TransactionBuilder::coinbase()
                .with_output(&address_1, 1000)
                .build();
            insert_tx(&mut utxo, &coinbase_tx, 0);

            let expected = vec![ic_btc_types::Utxo {
                outpoint: ic_btc_types::OutPoint {
                    txid: coinbase_tx.txid().to_vec(),
                    vout: 0,
                },
                value: 1000,
                height: 0,
            }];

            assert_eq!(
                get_utxos(&utxo, &address_1.to_string()).into_vec(),
                expected
            );
            assert_eq!(
                utxo.address_to_outpoints
                    .iter()
                    .map(|(k, _)| <(String, Height, OutPoint)>::from_bytes(k))
                    .collect::<BTreeSet<_>>(),
                maplit::btreeset! {
                    (address_1.to_string(), 0, OutPoint {
                        txid: coinbase_tx.txid(),
                        vout: 0
                    })
                }
            );

            // Spend the output to address 2.
            let tx = TransactionBuilder::with_input(OutPoint::new(coinbase_tx.txid(), 0))
                .with_output(&address_2, 1000)
                .build();
            insert_tx(&mut utxo, &tx, 1);

            assert_eq!(get_utxos(&utxo, &address_1.to_string()).into_vec(), vec![]);
            assert_eq!(
                get_utxos(&utxo, &address_2.to_string()).into_vec(),
                vec![ic_btc_types::Utxo {
                    outpoint: ic_btc_types::OutPoint {
                        txid: tx.txid().to_vec(),
                        vout: 0
                    },
                    value: 1000,
                    height: 1
                }]
            );
            assert_eq!(
                utxo.address_to_outpoints
                    .iter()
                    .map(|(k, _)| <(String, Height, OutPoint)>::from_bytes(k))
                    .collect::<BTreeSet<_>>(),
                maplit::btreeset! {
                    (address_2.to_string(), 1, OutPoint {
                        txid: tx.txid(),
                        vout: 0
                    })
                }
            );
        }
    }

    #[test]
    fn utxos_are_sorted_by_height() {
        let secp = Secp256k1::new();
        let mut rng = OsRng::new().unwrap();
        let address = Address::p2pkh(
            &PublicKey::new(secp.generate_keypair(&mut rng).1),
            Network::Testnet,
        )
        .to_string();

        let mut utxo = UtxoSet::new(Network::Testnet);

        // Insert some entries into the map with different heights in some random order.
        for height in [17u32, 0, 31, 4, 2].iter() {
            utxo.address_to_outpoints
                .insert(
                    (address.clone(), *height, OutPoint::null()).to_bytes(),
                    vec![],
                )
                .unwrap();
        }

        // Verify that the entries returned are sorted in descending height.
        assert_eq!(
            utxo.address_to_outpoints
                .range(address.to_bytes())
                .map(|(k, _)| {
                    let (_, height, _) = <(AddressStr, Height, OutPoint)>::from_bytes(k);
                    height
                })
                .collect::<Vec<_>>(),
            vec![31, 17, 4, 2, 0]
        );
    }
}
