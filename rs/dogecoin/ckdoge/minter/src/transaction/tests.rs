use crate::OutPoint;
use crate::address::DogecoinAddress;
use crate::lifecycle::init::Network;
use crate::test_fixtures::{dogecoin_address_to_bitcoin, mock::MockCanisterRuntime};
use crate::transaction::DogecoinTransactionSigner;
use bitcoin::hashes::Hash;
use candid::Principal;
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
    let depositor_address = DogecoinAddress::from_compressed_public_key(&public_key);
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

fn signer() -> (DogecoinTransactionSigner, ic_secp256k1::PrivateKey) {
    let (canister_public_key, canister_private_key) =
        crate::test_fixtures::canister_public_key_pair();
    let signer = DogecoinTransactionSigner::new("key_1".to_string(), canister_public_key);
    (signer, canister_private_key)
}
