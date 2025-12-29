#[cfg(test)]
mod tests;

use crate::address::DogecoinAddress;
use ic_ckbtc_minter::{CanisterRuntime, ECDSAPublicKey, management, tx::SignedRawTransaction};
use icrc_ledger_types::icrc1::account::Account;

pub struct DogecoinTransactionSigner {
    key_name: String,
    ecdsa_public_key: ECDSAPublicKey,
}

impl DogecoinTransactionSigner {
    pub fn new(key_name: String, ecdsa_public_key: ECDSAPublicKey) -> Self {
        Self {
            key_name,
            ecdsa_public_key,
        }
    }

    pub async fn sign_transaction<R: CanisterRuntime>(
        &self,
        unsigned_tx: ic_ckbtc_minter::tx::UnsignedTransaction,
        accounts: Vec<Account>,
        runtime: &R,
    ) -> Result<SignedRawTransaction, management::CallError> {
        use bitcoin::hashes::Hash;

        assert_eq!(
            unsigned_tx.inputs.len(),
            accounts.len(),
            "BUG: expected one account per input"
        );

        let dogecoin_tx = into_bitcoin_transaction(unsigned_tx);
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
            let mut signature = ic_ckbtc_minter::signature::sec1_to_der(&sec1_signature);
            // The signature must end with a single byte indicating the SIGHASH type.
            signature.push(sighash_type as u8);
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
                .push_slice(public_key)
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
        let txid = ic_ckbtc_minter::Txid::from(signed_tx.compute_txid().to_byte_array());

        Ok(SignedRawTransaction::new(
            bitcoin::consensus::encode::serialize(&signed_tx),
            txid,
        ))
    }

    pub fn fake_sign(unsigned_tx: &ic_ckbtc_minter::tx::UnsignedTransaction) -> Vec<u8> {
        const FAKE_PUBKEY: [u8; 33] = [0_u8; ic_ckbtc_minter::tx::PUBKEY_LEN];

        let mut dogecoin_tx = into_bitcoin_transaction(unsigned_tx.clone());
        let max_size_script_sig = bitcoin::Script::builder()
            .push_slice(ic_ckbtc_minter::signature::FAKE_SIG)
            .push_slice(FAKE_PUBKEY)
            .into_script();
        dogecoin_tx.input.iter_mut().for_each(|input| {
            input.script_sig = max_size_script_sig.clone();
        });

        bitcoin::consensus::encode::serialize(&dogecoin_tx)
    }
}

fn into_bitcoin_transaction(
    unsigned_tx: ic_ckbtc_minter::tx::UnsignedTransaction,
) -> bitcoin::Transaction {
    use bitcoin::hashes::Hash;

    bitcoin::Transaction {
        // Dogecoin transactions use Version 1 (BIP-68 is not supported)"
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
                        bitcoin::ScriptBuf::new_p2pkh(&bitcoin::PubkeyHash::from_byte_array(hash))
                    }
                    ic_ckbtc_minter::address::BitcoinAddress::P2sh(hash) => {
                        bitcoin::ScriptBuf::new_p2sh(&bitcoin::ScriptHash::from_byte_array(hash))
                    }
                    _ => panic!("BUG: Dogecoin does not support other address types"),
                },
            })
            .collect(),
    }
}
