use crate::proto;
use bitcoin::hashes::Hash;
use bitcoin::{Address, Network, OutPoint, Script, Transaction, TxOut, Txid};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::str::FromStr;

type Height = u32;

lazy_static::lazy_static! {
    static ref DUPLICATE_TX_IDS: [Txid; 2] = [
        Txid::from_str("d5d27987d2a3dfc724e359870c6644b40e497bdc0589a033220fe15429d88599").unwrap(),
        Txid::from_str("e3bf3d07d4b0375638d5f1db5255fe07ba2c4cb067cd81b84ee974b6585fb468").unwrap()
    ];
}

#[cfg_attr(test, derive(Clone, Debug, PartialEq))]
pub struct UtxoSet {
    utxos: HashMap<OutPoint, (TxOut, Height)>,
    network: Network,
    // An index for fast retrievals of an address's UTXOs.
    address_to_outpoints: BTreeMap<String, Vec<OutPoint>>,
    // If true, a transaction's inputs must all be present in the UTXO for it to be accepted.
    strict: bool,
}

impl UtxoSet {
    pub fn new(strict: bool, network: Network) -> Self {
        Self {
            utxos: HashMap::default(),
            address_to_outpoints: BTreeMap::default(),
            strict,
            network,
        }
    }

    /// Returns the `UtxoSet` of a given bitcoin address.
    pub fn get_utxos(&self, address: &str) -> UtxoSet {
        // Since we're returning a partial UTXO, we need not be strict.
        let mut utxos = Self::new(false, self.network);
        for outpoint in self.address_to_outpoints.get(address).unwrap_or(&vec![]) {
            let (tx_out, height) = self.utxos.get(outpoint).expect("outpoint must exist");
            utxos.insert_outpoint(*outpoint, tx_out.clone(), *height);
        }

        utxos
    }

    pub fn insert_tx(&mut self, tx: &Transaction, height: Height) {
        self.remove_spent_txs(tx);
        self.insert_unspent_txs(tx, height);
    }

    pub fn into_set(self) -> HashSet<(OutPoint, TxOut, Height)> {
        self.utxos.into_iter().map(|(k, v)| (k, v.0, v.1)).collect()
    }

    // Iterates over transaction inputs and removes spent outputs.
    fn remove_spent_txs(&mut self, tx: &Transaction) {
        if tx.is_coin_base() {
            return;
        }

        for input in &tx.input {
            // Verify that we've seen the outpoint before.
            match self.utxos.remove(&input.previous_output) {
                Some((txout, _)) => {
                    if let Some(address) = Address::from_script(&txout.script_pubkey, self.network)
                    {
                        let address = address.to_string();
                        let address_outpoints =
                            self.address_to_outpoints.get_mut(&address).unwrap();

                        let mut found = false;
                        for (index, outpoint) in address_outpoints.iter().enumerate() {
                            if outpoint == &input.previous_output {
                                address_outpoints.remove(index);
                                found = true;
                                break;
                            }
                        }

                        if !found && self.strict {
                            panic!("Outpoint {:?} not found in index.", input.previous_output);
                        }

                        if address_outpoints.is_empty() {
                            self.address_to_outpoints.remove(&address);
                        }
                    }
                }
                None => {
                    if self.strict {
                        panic!("Outpoint {:?} not found.", input.previous_output);
                    }
                }
            }
        }
    }

    // Iterates over transaction outputs and adds unspents.
    fn insert_unspent_txs(&mut self, tx: &Transaction, height: Height) {
        for (vout, output) in tx.output.iter().enumerate() {
            self.insert_outpoint(
                OutPoint::new(tx.txid(), vout as u32),
                output.clone(),
                height,
            );
        }
    }

    fn insert_outpoint(&mut self, outpoint: OutPoint, output: TxOut, height: Height) {
        // Verify that we haven't seen the outpoint before.
        // NOTE: There was a bug where there were duplicate transactions. These transactions
        // we overwrite.
        //
        // See: https://en.bitcoin.it/wiki/BIP_0030
        //      https://bitcoinexplorer.org/tx/d5d27987d2a3dfc724e359870c6644b40e497bdc0589a033220fe15429d88599
        //      https://bitcoinexplorer.org/tx/e3bf3d07d4b0375638d5f1db5255fe07ba2c4cb067cd81b84ee974b6585fb468
        if self.utxos.contains_key(&outpoint) && !DUPLICATE_TX_IDS.contains(&outpoint.txid) {
            panic!(
                "Cannot insert outpoint {:?} because it was already inserted. Block height: {}",
                outpoint, height
            );
        }

        // Insert the outpoint.
        if let Some(address) = Address::from_script(&output.script_pubkey, self.network) {
            // Add the address to the index if we can parse it.
            self.address_to_outpoints
                .entry(address.to_string())
                .or_insert_with(Vec::new)
                .push(outpoint);
        }

        self.utxos.insert(outpoint, (output, height));
    }

    pub fn to_proto(&self) -> proto::UtxoSet {
        proto::UtxoSet {
            utxos: self
                .utxos
                .iter()
                .map(|(outpoint, (txout, height))| proto::Utxo {
                    outpoint: Some(proto::OutPoint {
                        txid: outpoint.txid.to_vec(),
                        vout: outpoint.vout,
                    }),
                    txout: Some(proto::TxOut {
                        value: txout.value,
                        script_pubkey: txout.script_pubkey.to_bytes(),
                    }),
                    height: *height,
                })
                .collect(),
            strict: self.strict,
            network: match self.network {
                Network::Bitcoin => 0,
                Network::Testnet => 1,
                Network::Signet => 2,
                Network::Regtest => 3,
            },
        }
    }

    pub fn from_proto(utxos_proto: proto::UtxoSet) -> Self {
        let mut utxo_set = Self {
            utxos: HashMap::default(),
            address_to_outpoints: BTreeMap::default(),
            strict: utxos_proto.strict,
            network: match utxos_proto.network {
                0 => Network::Bitcoin,
                1 => Network::Testnet,
                2 => Network::Signet,
                3 => Network::Regtest,
                _ => panic!("Invalid network ID"),
            },
        };

        for utxo in utxos_proto.utxos.into_iter() {
            let outpoint = utxo
                .outpoint
                .map(|o| OutPoint::new(Txid::from_hash(Hash::from_slice(&o.txid).unwrap()), o.vout))
                .unwrap();

            let tx_out = utxo
                .txout
                .map(|t| TxOut {
                    value: t.value,
                    script_pubkey: Script::from(t.script_pubkey),
                })
                .unwrap();

            utxo_set.insert_outpoint(outpoint, tx_out, utxo.height);
        }

        utxo_set
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::test_builder::TransactionBuilder;
    use bitcoin::secp256k1::rand::rngs::OsRng;
    use bitcoin::secp256k1::Secp256k1;
    use bitcoin::{Address, PublicKey, TxOut};

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
            utxo.insert_tx(&coinbase_tx, 0);

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
            assert_eq!(utxo.get_utxos(&address.to_string()).into_set(), expected);
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
            utxo.insert_tx(&coinbase_tx, 0);
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

            assert_eq!(utxo.get_utxos(&address_1.to_string()).into_set(), expected);
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
            utxo.insert_tx(&tx, 1);

            assert_eq!(
                utxo.get_utxos(&address_1.to_string()).into_set(),
                maplit::hashset! {}
            );
            assert_eq!(
                utxo.get_utxos(&address_2.to_string()).into_set(),
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
