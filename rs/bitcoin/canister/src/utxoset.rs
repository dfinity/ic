use crate::state::UtxoSet;
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
pub fn get_utxos(utxo_set: &UtxoSet, address: &str) -> UtxoSet {
    // Since we're returning a partial UTXO, we need not be strict.
    let mut utxos = UtxoSet::new(false, utxo_set.network);
    for outpoint in utxo_set
        .address_to_outpoints
        .get(address)
        .unwrap_or(&vec![])
    {
        let (tx_out, height) = utxo_set.utxos.get(outpoint).expect("outpoint must exist");
        insert_utxo(&mut utxos, *outpoint, tx_out.clone(), *height);
    }

    utxos
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
        // Verify that we've seen the outpoint before.
        match utxo_set.utxos.remove(&input.previous_output) {
            Some((txout, _)) => {
                if let Some(address) = Address::from_script(&txout.script_pubkey, utxo_set.network)
                {
                    let address = address.to_string();
                    let address_outpoints =
                        utxo_set.address_to_outpoints.get_mut(&address).unwrap();

                    let mut found = false;
                    for (index, outpoint) in address_outpoints.iter().enumerate() {
                        if outpoint == &input.previous_output {
                            address_outpoints.remove(index);
                            found = true;
                            break;
                        }
                    }

                    if !found && utxo_set.strict {
                        panic!("Outpoint {:?} not found in index.", input.previous_output);
                    }

                    if address_outpoints.is_empty() {
                        utxo_set.address_to_outpoints.remove(&address);
                    }
                }
            }
            None => {
                if utxo_set.strict {
                    panic!("Outpoint {:?} not found.", input.previous_output);
                }
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
            .entry(address.to_string())
            .or_insert_with(Vec::new)
            .push(outpoint);
    }

    utxo_set.utxos.insert(outpoint, (output, height));
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::test_builder::TransactionBuilder;
    use bitcoin::blockdata::{opcodes::all::OP_RETURN, script::Builder};
    use bitcoin::secp256k1::rand::rngs::OsRng;
    use bitcoin::secp256k1::Secp256k1;
    use bitcoin::{Address, Network, PublicKey, TxOut};
    use std::collections::HashMap;

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

            let mut utxo = UtxoSet::new(true, *network);
            insert_tx(&mut utxo, &coinbase_tx, 0);

            let expected = maplit::hashset! {
                (
                    OutPoint {
                        txid: coinbase_tx.txid(),
                        vout: 0
                    },
                    TxOut {
                        value: 1000,
                        script_pubkey: address.script_pubkey()
                    },
                    0
                )
            };

            assert_eq!(utxo.clone().into_set(), expected);
            assert_eq!(get_utxos(&utxo, &address.to_string()).into_set(), expected);
        }
    }

    #[test]
    fn tx_without_outputs_leaves_utxo_set_unchanged() {
        for network in [Network::Bitcoin, Network::Regtest, Network::Testnet].iter() {
            let mut utxo = UtxoSet::new(true, *network);

            // no output coinbase
            let mut coinbase_empty_tx = TransactionBuilder::coinbase().build();
            coinbase_empty_tx.output.clear();
            insert_tx(&mut utxo, &coinbase_empty_tx, 0);

            assert_eq!(utxo.utxos, HashMap::default());

            assert_eq!(utxo.address_to_outpoints, maplit::btreemap! {});
        }
    }

    #[test]
    fn filter_provably_unspendable_utxos() {
        for network in [Network::Bitcoin, Network::Regtest, Network::Testnet].iter() {
            let mut utxo = UtxoSet::new(true, *network);

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

            assert_eq!(utxo.utxos, HashMap::default());

            assert_eq!(utxo.address_to_outpoints, maplit::btreemap! {});
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

            let mut utxo = UtxoSet::new(true, *network);

            let coinbase_tx = TransactionBuilder::coinbase()
                .with_output(&address_1, 1000)
                .build();
            insert_tx(&mut utxo, &coinbase_tx, 0);
            let expected = maplit::hashset! {
                (
                    OutPoint {
                        txid: coinbase_tx.txid(),
                        vout: 0
                    },
                    TxOut {
                        value: 1000,
                        script_pubkey: address_1.script_pubkey()
                    },
                    0
                )
            };

            assert_eq!(
                get_utxos(&utxo, &address_1.to_string()).into_set(),
                expected
            );
            assert_eq!(
                utxo.address_to_outpoints,
                maplit::btreemap! {
                    address_1.to_string() => vec![OutPoint {
                        txid: coinbase_tx.txid(),
                        vout: 0
                    }]
                }
            );

            // Spend the output to address 2.
            let tx = TransactionBuilder::with_input(OutPoint::new(coinbase_tx.txid(), 0))
                .with_output(&address_2, 1000)
                .build();
            insert_tx(&mut utxo, &tx, 1);

            assert_eq!(
                get_utxos(&utxo, &address_1.to_string()).into_set(),
                maplit::hashset! {}
            );
            assert_eq!(
                get_utxos(&utxo, &address_2.to_string()).into_set(),
                maplit::hashset! {
                    (
                        OutPoint {
                            txid: tx.txid(),
                            vout: 0
                        },
                        TxOut {
                            value: 1000,
                            script_pubkey: address_2.script_pubkey()
                        },
                        1
                    )
                }
            );
            assert_eq!(
                utxo.address_to_outpoints,
                maplit::btreemap! {
                    address_2.to_string() => vec![OutPoint {
                        txid: tx.txid(),
                        vout: 0
                    }]
                }
            );
        }
    }
}
