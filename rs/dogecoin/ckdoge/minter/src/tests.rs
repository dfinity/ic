use crate::Network;
use crate::address::DogecoinAddress;
use crate::dogecoin_canister::get_dogecoin_canister_id;
use bitcoin::consensus::Encodable;
use ic_ckbtc_minter::address::BitcoinAddress;
use ic_ckbtc_minter::signature::EncodedSignature;
use ic_ckbtc_minter::tx::{
    OutPoint, SignedInput, SignedTransaction, TxOut, UnsignedInput, UnsignedTransaction,
};

#[test]
fn should_have_correct_dogecoin_canister_id() {
    assert_eq!(
        get_dogecoin_canister_id(&Network::Mainnet).to_string(),
        "gordg-fyaaa-aaaan-aaadq-cai"
    );

    assert_eq!(
        get_dogecoin_canister_id(&Network::Testnet).to_string(),
        "hd7hi-kqaaa-aaaan-aaaea-cai"
    );

    assert_eq!(
        get_dogecoin_canister_id(&Network::Regtest).to_string(),
        "hd7hi-kqaaa-aaaan-aaaea-cai"
    );
}

#[test]
fn should_use_p2pkh() {
    use bitcoin::{consensus::Decodable, hashes::Hash};

    let unsigned_input = UnsignedInput {
        previous_output: OutPoint {
            txid: "a7612af24cd57190c18d1e5daa0e401754ab5ae41daf8f200ffc29408e1ae491"
                .parse()
                .unwrap(),
            vout: 0,
        },
        value: 13_785_800_000,
        sequence: 4294967293,
    };
    let receiver_address =
        DogecoinAddress::parse("D9Boe5MMx93BdZW1T94L4dyUUTfJqx8NFT", &Network::Mainnet).unwrap();
    let minter_address =
        DogecoinAddress::parse("DJsTUj3DPhJG3GMDr66mqxnQGL7dF8N9eU", &Network::Mainnet).unwrap();
    let unsigned_tx = UnsignedTransaction {
        inputs: vec![unsigned_input.clone()],
        outputs: vec![
            TxOut {
                value: 4_819_746_746,
                address: dogecoin_address_to_bitcoin(receiver_address.clone()),
            },
            TxOut {
                value: 8_965_800_000,
                address: dogecoin_address_to_bitcoin(minter_address.clone()),
            },
        ],
        lock_time: 0,
    };
    let public_key: [u8; 33] =
        hex::decode("03fe0e8ca9d0e8cd52715b153cf83f5c1915cfdb9d0046cd46ad72ea2b60cc6444")
            .unwrap()
            .try_into()
            .unwrap();
    let signature: [u8; 72] = hex::decode("3045022100a56244d8c7fafcabf69bbfac3288a8f88e918ff200a0ed7304fa4bcfecac203d02207604f23a2430391dec2fc1b31f4db6ff70ae53227accad2ad339703b241a0fa801").unwrap().try_into().unwrap();
    let signed_tx = SignedTransaction {
        inputs: vec![SignedInput {
            previous_output: unsigned_input.previous_output,
            sequence: unsigned_input.sequence,
            signature: EncodedSignature::try_from_slice(&signature).unwrap(),
            pubkey: public_key.to_vec().into(),
            uses_segwit: false,
        }],
        outputs: unsigned_tx.outputs,
        lock_time: unsigned_tx.lock_time,
    };
    let signed_tx_bytes = signed_tx.serialize();

    let dogecoin_tx =
        bitcoin::Transaction::consensus_decode(&mut signed_tx_bytes.as_slice()).unwrap();
    let mut dogecoin_tx_bytes = Vec::new();
    dogecoin_tx
        .consensus_encode(&mut dogecoin_tx_bytes)
        .unwrap();
    assert_eq!(signed_tx_bytes, dogecoin_tx_bytes);

    assert_eq!(
        dogecoin_tx,
        bitcoin::Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn {
                previous_output:
                    "a7612af24cd57190c18d1e5daa0e401754ab5ae41daf8f200ffc29408e1ae491:0"
                        .parse()
                        .unwrap(),
                script_sig: bitcoin::script::Builder::new()
                    .push_slice(signature)
                    .push_slice(public_key)
                    .into_script(),
                sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Default::default(),
            }],
            output: vec![
                bitcoin::TxOut {
                    value: bitcoin::Amount::from_sat(4_819_746_746),
                    script_pubkey: bitcoin::ScriptBuf::new_p2pkh(
                        &bitcoin::PubkeyHash::from_byte_array(*receiver_address.as_array())
                    ),
                },
                bitcoin::TxOut {
                    value: bitcoin::Amount::from_sat(8_965_800_000),
                    script_pubkey: bitcoin::ScriptBuf::new_p2pkh(
                        &bitcoin::PubkeyHash::from_byte_array(*minter_address.as_array())
                    ),
                }
            ],
        }
    );
    assert_eq!(
        dogecoin_tx.compute_txid().as_byte_array(),
        &signed_tx.wtxid()
    );
}

fn dogecoin_address_to_bitcoin(address: DogecoinAddress) -> BitcoinAddress {
    match address {
        DogecoinAddress::P2pkh(p2pkh) => BitcoinAddress::P2pkh(p2pkh),
        DogecoinAddress::P2sh(p2sh) => BitcoinAddress::P2sh(p2sh),
    }
}
