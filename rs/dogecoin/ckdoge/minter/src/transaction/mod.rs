use crate::address::DogecoinAddress;
use ic_ckbtc_minter::{CanisterRuntime, ECDSAPublicKey, management};
use icrc_ledger_types::icrc1::account::Account;

pub struct DogecoinTransactionSigner {
    key_name: String,
    ecdsa_public_key: ECDSAPublicKey,
}

impl DogecoinTransactionSigner {
    pub async fn sign_transaction<R: CanisterRuntime>(
        &self,
        unsigned_tx: ic_ckbtc_minter::tx::UnsignedTransaction,
        accounts: Vec<Account>,
        runtime: &R,
    ) -> Result<bitcoin::Transaction, management::CallError> {
        use bitcoin::hashes::Hash;

        assert_eq!(
            unsigned_tx.inputs.len(),
            accounts.len(),
            "BUG: expected on account per input"
        );

        let dogecoin_tx = bitcoin::Transaction {
            // Dogecoin does not support BIP-68.
            version: bitcoin::transaction::Version::ONE,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: unsigned_tx
                .inputs
                .into_iter()
                .map(|input| bitcoin::transaction::TxIn {
                    previous_output: bitcoin::transaction::OutPoint {
                        txid: bitcoin::Txid::from_byte_array(input.previous_output.txid.into()),
                        vout: input.previous_output.vout,
                    },
                    script_sig: bitcoin::ScriptBuf::new(),
                    sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
                    witness: bitcoin::Witness::default(),
                })
                .collect(),
            output: unsigned_tx
                .outputs
                .into_iter()
                .map(|output| bitcoin::TxOut {
                    value: bitcoin::Amount::from_sat(output.value),
                    script_pubkey: match output.address {
                        ic_ckbtc_minter::address::BitcoinAddress::P2pkh(hash) => {
                            bitcoin::ScriptBuf::new_p2pkh(&bitcoin::PubkeyHash::from_byte_array(
                                hash,
                            ))
                        }
                        ic_ckbtc_minter::address::BitcoinAddress::P2sh(hash) => {
                            bitcoin::ScriptBuf::new_p2sh(&bitcoin::ScriptHash::from_byte_array(
                                hash,
                            ))
                        }
                        _ => panic!("BUG: Dogecoin does not support other address types"),
                    },
                })
                .collect(),
        };

        let cache = bitcoin::sighash::SighashCache::new(&dogecoin_tx);
        let mut script_sigs = Vec::with_capacity(accounts.len());
        let sighash_type = bitcoin::EcdsaSighashType::All;

        for (input_index, account) in accounts.into_iter().enumerate() {
            let derivation_path = crate::updates::get_doge_address::derivation_path(&account);
            let public_key = crate::updates::get_doge_address::derive_public_key(
                &self.ecdsa_public_key,
                &account,
            );
            let address = DogecoinAddress::from_compressed_public_key(&public_key);
            let script_pubkey = match address {
                DogecoinAddress::P2pkh(hash) => {
                    bitcoin::ScriptBuf::new_p2pkh(&bitcoin::PubkeyHash::from_byte_array(hash))
                }
                DogecoinAddress::P2sh(hash) => {
                    bitcoin::ScriptBuf::new_p2sh(&bitcoin::ScriptHash::from_byte_array(hash))
                }
            };
            let sighash = cache
                .legacy_signature_hash(input_index, &script_pubkey, sighash_type.to_u32())
                .expect("BUG: sighash should not error");
            let sec1_signature = ic_ckbtc_minter::management::sign_with_ecdsa(
                self.key_name.clone(),
                derivation_path,
                sighash.to_byte_array(),
                runtime,
            )
            .await?;
            let signature = ic_ckbtc_minter::signature::sec1_to_der(&sec1_signature);
            debug_assert_eq!(
                Ok(()),
                ic_ckbtc_minter::signature::validate_encoded_signature(&signature)
            );
            let sig_push_bytes: &bitcoin::script::PushBytes = signature
                .as_slice()
                .try_into()
                .expect("BUG: validity check ensures signature contains at most 73 bytes");
            let script_sig = bitcoin::Script::builder()
                .push_slice(sig_push_bytes)
                .push_int(sighash_type.to_u32() as i64)
                .push_key(
                    &bitcoin::PublicKey::from_slice(&public_key)
                        .expect("BUG: public key should be valid"),
                )
                .into_script();
            script_sigs.push(script_sig);
        }

        let mut signed_tx = dogecoin_tx;
        signed_tx
            .input
            .iter_mut()
            .zip(script_sigs)
            .for_each(|(input, script_sig)| {
                input.script_sig = script_sig;
            });

        Ok(signed_tx)
    }
}
