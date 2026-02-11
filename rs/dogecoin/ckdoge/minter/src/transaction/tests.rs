use crate::OutPoint;
use crate::address::DogecoinAddress;
use crate::lifecycle::init::Network;
use crate::test_fixtures::{dogecoin_address_to_bitcoin, mock::MockCanisterRuntime};
use crate::transaction::DogecoinTransactionSigner;
use bitcoin::hashes::Hash;
use candid::Principal;
use ic_ckbtc_minter::Txid;
use ic_ckbtc_minter::tx::{TxOut, UnsignedInput, UnsignedTransaction};
use icrc_ledger_types::icrc1::account::Account;

#[tokio::test]
async fn should_be_noop_when_no_transactions() {
    let runtime = MockCanisterRuntime::new();
    let (signer, _canister_private_key) = signer();
    let result = signer
        .sign_transaction(
            UnsignedTransaction {
                inputs: vec![],
                outputs: vec![],
                lock_time: 0,
            },
            vec![],
            &runtime,
        )
        .await
        .unwrap();

    let transaction: bitcoin::Transaction =
        bitcoin::consensus::deserialize(result.as_ref()).unwrap();

    assert_eq!(
        transaction,
        bitcoin::Transaction {
            version: bitcoin::transaction::Version::ONE,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![],
        }
    );
}

#[tokio::test]
async fn should_verify_signed_transaction() {
    let (signer, canister_private_key) = signer();
    let chain_code: [u8; 32] = signer
        .ecdsa_public_key
        .chain_code
        .clone()
        .try_into()
        .unwrap();
    let depositor = Account {
        owner: Principal::from_text(
            "2oyh2-miczk-rzcqm-zbkes-q3kyi-lmen7-slvvl-byown-zz6v6-razzx-vae",
        )
        .unwrap(),
        subaccount: Some([42_u8; 32]),
    };
    let mut runtime = MockCanisterRuntime::new();
    runtime.expect_time().return_const(0_u64);
    runtime
        .expect_sign_with_ecdsa()
        .times(1)
        .withf(move |key_name, derivation_path, _message_hash| {
            key_name == "key_1"
                && derivation_path == &crate::updates::get_doge_address::derivation_path(&depositor)
        })
        .returning(move |_key_name, derivation_path, message_hash| {
            let account_private_key = canister_private_key
                .derive_subkey_with_chain_code(
                    &ic_secp256k1::DerivationPath::new(
                        derivation_path
                            .into_iter()
                            .map(ic_secp256k1::DerivationIndex)
                            .collect(),
                    ),
                    &chain_code,
                )
                .0;
            Ok(account_private_key
                .sign_digest_with_ecdsa(&message_hash)
                .to_vec())
        });

    let receiver =
        DogecoinAddress::parse("D9Boe5MMx93BdZW1T94L4dyUUTfJqx8NFT", &Network::Mainnet).unwrap();
    let minter =
        DogecoinAddress::parse("DJsTUj3DPhJG3GMDr66mqxnQGL7dF8N9eU", &Network::Mainnet).unwrap();
    let result = signer
        .sign_transaction(
            UnsignedTransaction {
                inputs: vec![UnsignedInput {
                    previous_output: OutPoint {
                        txid: "a7612af24cd57190c18d1e5daa0e401754ab5ae41daf8f200ffc29408e1ae491"
                            .parse()
                            .unwrap(),
                        vout: 0,
                    },
                    value: 13_785_800_000,
                    sequence: 0xFFFFFFFD,
                }],
                outputs: vec![
                    TxOut {
                        value: 4_808_463_200,
                        address: dogecoin_address_to_bitcoin(receiver.clone()),
                    },
                    TxOut {
                        value: 8_965_800_000,
                        address: dogecoin_address_to_bitcoin(minter.clone()),
                    },
                ],
                lock_time: 0,
            },
            vec![depositor],
            &runtime,
        )
        .await
        .unwrap();

    let transaction: bitcoin::Transaction =
        bitcoin::consensus::deserialize(result.as_ref()).unwrap();

    let public_key =
        crate::updates::get_doge_address::derive_public_key(&signer.ecdsa_public_key, &depositor);
    let signature: [u8; 72] = hex::decode("30450221008417fdd626ba643bc3300b7b2f77eced97cdcae4e93800d07a302711cd48e0b702204a211955b3eb5f60c8bcd82b1c3d8d003c1d2497a07d1d58898afbe67a4a916d01").unwrap().try_into().unwrap();
    assert_eq!(
        transaction,
        bitcoin::Transaction {
            version: bitcoin::transaction::Version::ONE,
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
                witness: Default::default(), //no segwit
            }],
            output: vec![
                bitcoin::TxOut {
                    value: bitcoin::Amount::from_sat(4_808_463_200),
                    script_pubkey: bitcoin::ScriptBuf::new_p2pkh(
                        &bitcoin::PubkeyHash::from_byte_array(*receiver.as_array())
                    ),
                },
                bitcoin::TxOut {
                    value: bitcoin::Amount::from_sat(8_965_800_000),
                    script_pubkey: bitcoin::ScriptBuf::new_p2pkh(
                        &bitcoin::PubkeyHash::from_byte_array(*minter.as_array())
                    ),
                },
            ],
        }
    );

    // Signature is DER-encoded.
    // See BIP-0066: https://github.com/bitcoin/bips/blob/master/bip-0066.mediawiki
    let sec1_signature: [u8; 64] = [&signature[5..=36], &signature[39..=70]]
        .concat()
        .try_into()
        .unwrap();
    assert_eq!(
        signature,
        ic_ckbtc_minter::signature::EncodedSignature::from_sec1(&sec1_signature).as_slice()
    );
    assert_eq!(
        *signature.last().unwrap(),
        bitcoin::EcdsaSighashType::All as u8
    );

    // Verify signature is correct.
    let depositor_address = DogecoinAddress::p2pkh_from_public_key(&public_key);
    let cache = bitcoin::sighash::SighashCache::new(&transaction);
    let sighash = cache
        .legacy_signature_hash(
            0,
            &bitcoin::ScriptBuf::new_p2pkh(&bitcoin::PubkeyHash::from_byte_array(
                *depositor_address.as_array(),
            )),
            bitcoin::EcdsaSighashType::All.to_u32(),
        )
        .expect("BUG: sighash should not error")
        .to_byte_array();
    let account_public_key = ic_secp256k1::PublicKey::deserialize_sec1(&public_key).unwrap();
    assert!(account_public_key.verify_ecdsa_signature_prehashed(&sighash, &sec1_signature))
}

#[tokio::test]
async fn should_be_similar_to_fake_sign() {
    // DOGE mainnet transaction [32d24dcb68fae3cac41caa55c9f9ed39eb4ee21689ba4d989c53df243b3b7364](https://chain.so/tx/DOGE/32d24dcb68fae3cac41caa55c9f9ed39eb4ee21689ba4d989c53df243b3b7364).
    let signed_transaction: bitcoin::Transaction = bitcoin::consensus::deserialize(&hex::decode("010000000191e41a8e4029fc0f208faf1de45aab5417400eaa5d1e8dc19071d54cf22a61a7000000006b483045022100921b10e76fdb449fad2518ff321b9072842775f020a1fc3713283bc1bf94f2ff02200f51a76a40c0d2778c44e89ed56d757feac8231db9668631366ba385606adf35012103c0ba3fcf0ac8219fef80d979dcc5bacf6a77be5637191364bb1b70f0275d4275fdffffff0260539b1e010000001976a9142c63a4d417d41515cf1f6de60831d578ad8a0f9588ac40406716020000001976a914969c95abfe91b2019cc64be25920830ce516558688ac00000000").unwrap()).unwrap();
    let unsigned_transaction = UnsignedTransaction {
        inputs: signed_transaction
            .input
            .clone()
            .into_iter()
            .map(|input| UnsignedInput {
                previous_output: OutPoint {
                    txid: Txid::from(input.previous_output.txid.to_byte_array()),
                    vout: input.previous_output.vout,
                },
                value: 0, //not relevant
                sequence: input.sequence.0,
            })
            .collect(),
        outputs: signed_transaction
            .output
            .clone()
            .into_iter()
            .map(|output| TxOut {
                value: output.value.to_sat(),
                address: ic_ckbtc_minter::address::BitcoinAddress::parse(
                    &bitcoin::Address::from_script(
                        &output.script_pubkey,
                        bitcoin::Network::Bitcoin,
                    )
                    .unwrap()
                    .to_string(),
                    ic_ckbtc_minter::Network::Mainnet,
                )
                .unwrap(),
            })
            .collect(),
        lock_time: 0,
    };

    let fake_signed_transaction: bitcoin::Transaction = bitcoin::consensus::deserialize(
        &DogecoinTransactionSigner::fake_sign(&unsigned_transaction),
    )
    .unwrap();

    assert_eq!(
        signed_transaction.compute_ntxid(),
        fake_signed_transaction.compute_ntxid()
    );
    let signed_tx_len = bitcoin::consensus::encode::serialize(&signed_transaction).len();
    let fake_signed_tx_len = bitcoin::consensus::encode::serialize(&fake_signed_transaction).len();
    let error_margin = signed_tx_len / 20; // 5%
    assert!(
        signed_tx_len <= fake_signed_tx_len && fake_signed_tx_len <= signed_tx_len + error_margin
    );
}

fn signer() -> (DogecoinTransactionSigner, ic_secp256k1::PrivateKey) {
    let (canister_public_key, canister_private_key) =
        crate::test_fixtures::canister_public_key_pair();
    let signer = DogecoinTransactionSigner::new("key_1".to_string(), canister_public_key);
    (signer, canister_private_key)
}
