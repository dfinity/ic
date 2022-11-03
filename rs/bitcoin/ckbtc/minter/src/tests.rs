use crate::{build_unsigned_transaction, greedy, signed_transaction_length, tx, BuildTxError};
use bitcoin::util::psbt::serialize::{Deserialize, Serialize};
use ic_base_types::{CanisterId, PrincipalId};
use ic_btc_types::{Network, OutPoint, Satoshi, Utxo};
use ic_icrc1::Account;
use proptest::proptest;
use proptest::{
    array::uniform32,
    collection::{btree_set, vec as pvec},
    option,
    prelude::{any, Strategy},
};
use proptest::{prop_assert, prop_assert_eq};
use serde_bytes::ByteBuf;
use std::collections::{BTreeSet, HashMap};

fn dummy_utxo_from_value(v: u64) -> Utxo {
    Utxo {
        outpoint: OutPoint {
            txid: v.to_be_bytes().to_vec(),
            vout: 0,
        },
        value: v,
        height: 0,
    }
}

fn as_txid(hash: &[u8]) -> bitcoin::Txid {
    bitcoin::Txid::from_hash(bitcoin::hashes::Hash::from_slice(hash).unwrap())
}

fn wpk_hash(pk: &[u8]) -> bitcoin::WPubkeyHash {
    bitcoin::WPubkeyHash::from_hash(bitcoin::hashes::Hash::from_slice(&tx::hash160(pk)).unwrap())
}

fn unsigned_tx_to_bitcoin_tx(tx: &tx::UnsignedTransaction) -> bitcoin::Transaction {
    bitcoin::Transaction {
        version: tx::TX_VERSION as i32,
        lock_time: tx.lock_time,
        input: tx
            .inputs
            .iter()
            .map(|txin| bitcoin::TxIn {
                previous_output: bitcoin::OutPoint {
                    txid: as_txid(&txin.previous_output.txid),
                    vout: txin.previous_output.vout,
                },
                sequence: txin.sequence,
                script_sig: bitcoin::Script::default(),
                witness: bitcoin::Witness::default(),
            })
            .collect(),
        output: tx
            .outputs
            .iter()
            .map(|txout| bitcoin::TxOut {
                value: txout.value,
                script_pubkey: bitcoin::Script::from(tx::script_from_pubkey(&txout.pubkey)),
            })
            .collect(),
    }
}

fn signed_tx_to_bitcoin_tx(tx: &tx::SignedTransaction) -> bitcoin::Transaction {
    bitcoin::Transaction {
        version: tx::TX_VERSION as i32,
        lock_time: tx.lock_time,
        input: tx
            .inputs
            .iter()
            .map(|txin| bitcoin::TxIn {
                previous_output: bitcoin::OutPoint {
                    txid: as_txid(&txin.previous_output.txid),
                    vout: txin.previous_output.vout,
                },
                sequence: txin.sequence,
                script_sig: bitcoin::Script::new_v0_p2wpkh(&wpk_hash(&txin.pubkey)),
                witness: bitcoin::Witness::from_vec(vec![
                    txin.signature.to_vec(),
                    txin.pubkey.to_vec(),
                ]),
            })
            .collect(),
        output: tx
            .outputs
            .iter()
            .map(|txout| bitcoin::TxOut {
                value: txout.value,
                script_pubkey: bitcoin::Script::from(tx::script_from_pubkey(&txout.pubkey)),
            })
            .collect(),
    }
}

#[test]
fn greedy_smoke_test() {
    let mut utxos: BTreeSet<Utxo> = (1..10u64).map(dummy_utxo_from_value).collect();
    assert_eq!(utxos.len(), 9_usize);

    let res = greedy(15, &mut utxos);

    assert_eq!(res[0].value, 9_u64);
    assert_eq!(res[1].value, 6_u64);
}

fn arb_amount() -> impl Strategy<Value = Satoshi> {
    1..10_000_000_000u64
}

fn arb_out_point() -> impl Strategy<Value = tx::OutPoint> {
    (pvec(any::<u8>(), 32), any::<u32>()).prop_map(|(txid, vout)| tx::OutPoint { txid, vout })
}

fn arb_unsigned_input() -> impl Strategy<Value = tx::UnsignedInput> {
    (arb_out_point(), any::<u32>()).prop_map(|(previous_output, sequence)| tx::UnsignedInput {
        previous_output,
        sequence,
    })
}

fn arb_signed_input() -> impl Strategy<Value = tx::SignedInput> {
    (
        arb_out_point(),
        any::<u32>(),
        pvec(any::<u8>(), 72),
        pvec(any::<u8>(), 32),
    )
        .prop_map(
            |(previous_output, sequence, signature, pubkey)| tx::SignedInput {
                previous_output,
                sequence,
                signature: ByteBuf::from(signature),
                pubkey: ByteBuf::from(pubkey),
            },
        )
}

fn arb_tx_out() -> impl Strategy<Value = tx::TxOut> {
    (arb_amount(), pvec(any::<u8>(), 32)).prop_map(|(value, pubkey)| tx::TxOut { value, pubkey })
}

fn arb_utxo(amount: impl Strategy<Value = Satoshi>) -> impl Strategy<Value = Utxo> {
    (amount, pvec(any::<u8>(), 32), 0..5u32).prop_map(|(value, txid, vout)| Utxo {
        outpoint: OutPoint { txid, vout },
        value,
        height: 0,
    })
}

fn arb_account() -> impl Strategy<Value = Account> {
    (pvec(any::<u8>(), 32), option::of(uniform32(any::<u8>()))).prop_map(|(pk, subaccount)| {
        Account {
            owner: PrincipalId::new_self_authenticating(&pk),
            subaccount,
        }
    })
}

proptest! {
    #[test]
    fn greedy_solution_properties(
        values in pvec(1u64..1_000_000_000, 1..10),
        target in 1u64..1_000_000_000,
    ) {
        let mut utxos: BTreeSet<Utxo> = values
            .into_iter()
            .map(dummy_utxo_from_value)
            .collect();

        let total = utxos.iter().map(|u| u.value).sum::<u64>();

        if total < target {
            utxos.insert(dummy_utxo_from_value(target - total));
        }

        let original_utxos = utxos.clone();

        let solution = greedy(target, &mut utxos);

        prop_assert!(
            !solution.is_empty(),
            "greedy() must always find a solution given enough available UTXOs"
        );

        prop_assert!(
            solution.iter().map(|u| u.value).sum::<u64>() >= target,
            "greedy() must reach the specified target amount"
        );

        prop_assert!(
            solution.iter().all(|u| original_utxos.contains(u)),
            "greedy() must select utxos from the available set"
        );

        prop_assert!(
            solution.iter().all(|u| !utxos.contains(u)),
            "greedy() must remove found UTXOs from the available set"
        );
    }

    #[test]
    fn greedy_does_not_modify_input_when_fails(
        values in pvec(1u64..1_000_000_000, 1..10),
    ) {
        let mut utxos: BTreeSet<Utxo> = values
            .into_iter()
            .map(dummy_utxo_from_value)
            .collect();

        let total = utxos.iter().map(|u| u.value).sum::<u64>();

        let original_utxos = utxos.clone();
        let solution = greedy(total + 1, &mut utxos);

        prop_assert!(solution.is_empty());
        prop_assert_eq!(utxos, original_utxos);
    }

    #[test]
    fn unsigned_tx_encoding_model(
        inputs in pvec(arb_unsigned_input(), 1..20),
        outputs in pvec(arb_tx_out(), 1..20),
        lock_time in any::<u32>(),
    ) {
        let arb_tx = tx::UnsignedTransaction { inputs, outputs, lock_time };
        println!("{:?}", arb_tx);
        let btc_tx = unsigned_tx_to_bitcoin_tx(&arb_tx);
        println!("{:?}", btc_tx.serialize());

        let tx_bytes = tx::encode_into(&arb_tx, Vec::<u8>::new());
        println!("{:?}", tx_bytes);
        let decoded_btc_tx = bitcoin::Transaction::deserialize(&tx_bytes).expect("failed to deserialize an unsigned transaction");

        prop_assert_eq!(btc_tx.serialize(), tx_bytes);
        prop_assert_eq!(&decoded_btc_tx, &btc_tx);
        prop_assert_eq!(&arb_tx.txid(), &*btc_tx.txid());
    }

    #[test]
    fn signed_tx_encoding_model(
        inputs in pvec(arb_signed_input(), 1..20),
        outputs in pvec(arb_tx_out(), 1..20),
        lock_time in any::<u32>(),
    ) {
        let arb_tx = tx::SignedTransaction { inputs, outputs, lock_time };
        println!("{:?}", arb_tx);
        let btc_tx = signed_tx_to_bitcoin_tx(&arb_tx);
        println!("{:?}", btc_tx.serialize());

        let tx_bytes = tx::encode_into(&arb_tx, Vec::<u8>::new());
        println!("{:?}", tx_bytes);
        let decoded_btc_tx = bitcoin::Transaction::deserialize(&tx_bytes).expect("failed to deserialize a signed transaction");

        prop_assert_eq!(btc_tx.serialize(), tx_bytes);
        prop_assert_eq!(&decoded_btc_tx, &btc_tx);
        prop_assert_eq!(&arb_tx.wtxid(), &*btc_tx.wtxid());
    }

    #[test]
    fn build_tx_splits_utxos(
        mut utxos in btree_set(arb_utxo(5_000u64..1_000_000_000), 1..20),
        dst_pubkey in pvec(any::<u8>(), 32),
        main_pubkey in pvec(any::<u8>(), 32),
        fee_per_vbyte in 1000..2000u64,
    ) {
        let value_by_outpoint: HashMap<_, _> = utxos
            .iter()
            .map(|utxo| (utxo.outpoint.clone(), utxo.value))
            .collect();

        let utxo_count = utxos.len();
        let total_value = utxos.iter().map(|u| u.value).sum::<u64>();

        let target = total_value / 2;
        let unsigned_tx = build_unsigned_transaction(&mut utxos, dst_pubkey, main_pubkey, target, None, fee_per_vbyte)
            .expect("failed to build transaction");

        let fee = signed_transaction_length(&unsigned_tx) as u64 * fee_per_vbyte / 1000;

        let inputs_value = unsigned_tx.inputs
            .iter()
            .map(|input| value_by_outpoint.get(&input.previous_output).unwrap())
            .sum::<u64>();

        prop_assert!(inputs_value >= target);
        prop_assert!(fee < target);
        prop_assert_eq!(utxo_count, unsigned_tx.inputs.len() + utxos.len());
        prop_assert_eq!(utxos.iter().map(|u| u.value).sum::<u64>(), total_value - inputs_value);
    }

    #[test]
    fn build_tx_handles_change_from_inputs(
        mut utxos in btree_set(arb_utxo(1_000_000u64..1_000_000_000), 1..20),
        dst_pubkey in pvec(any::<u8>(), 32),
        main_pubkey in pvec(any::<u8>(), 32),
        target in 10000..50000u64,
        fee_per_vbyte in 1000..2000u64,
    ) {
        let value_by_outpoint: HashMap<_, _> = utxos
            .iter()
            .map(|utxo| (utxo.outpoint.clone(), utxo.value))
            .collect();

        let user_fee = 5000u64;
        let unsigned_tx = build_unsigned_transaction(&mut utxos, dst_pubkey.clone(), main_pubkey.clone(), target, Some(user_fee), fee_per_vbyte)
            .expect("failed to build transaction");

        let fee = signed_transaction_length(&unsigned_tx) as u64 * fee_per_vbyte / 1000;

        prop_assert!(fee <= user_fee);

        let inputs_value = unsigned_tx.inputs
            .iter()
            .map(|input| value_by_outpoint.get(&input.previous_output).unwrap())
            .sum::<u64>();

        prop_assert_eq!(
            &unsigned_tx.outputs,
            &vec![
                tx::TxOut { pubkey: dst_pubkey, value: target - user_fee },
                tx::TxOut { pubkey: main_pubkey, value: inputs_value - target },
            ]
        );
    }

    #[test]
    fn build_tx_does_not_modify_utxos_on_error(
        mut utxos in btree_set(arb_utxo(5_000u64..1_000_000_000), 1..20),
        dst_pubkey in pvec(any::<u8>(), 32),
        main_pubkey in pvec(any::<u8>(), 32),
        fee_per_vbyte in 1000..2000u64,
    ) {
        let utxos_copy = utxos.clone();

        let total_value = utxos.iter().map(|u| u.value).sum::<u64>();

        prop_assert_eq!(
            build_unsigned_transaction(&mut utxos, dst_pubkey.clone(), main_pubkey.clone(), total_value * 2, None, fee_per_vbyte)
                .expect_err("build transaction should fail because the amount is too high"),
            BuildTxError::NotEnoughFunds
        );
        prop_assert_eq!(&utxos_copy, &utxos);

        prop_assert_eq!(
            build_unsigned_transaction(&mut utxos, dst_pubkey.clone(), main_pubkey.clone(), 1000, Some(1), fee_per_vbyte)
                .expect_err("build transaction should fail because max fee is too low"),
            BuildTxError::UserFeeTooLow
        );
        prop_assert_eq!(&utxos_copy, &utxos);

        prop_assert_eq!(
            build_unsigned_transaction(&mut utxos, dst_pubkey, main_pubkey, 1, None, fee_per_vbyte)
                .expect_err("build transaction should fail because the amount is too low to pay the fee"),
            BuildTxError::AmountTooLow
        );
        prop_assert_eq!(&utxos_copy, &utxos);
    }

    #[test]
    fn add_utxos_maintains_invariants(
        utxos_acc_idx in pvec((arb_utxo(5_000u64..1_000_000_000), 0..5usize), 10..20),
        accounts in pvec(arb_account(), 5),
    ) {
        use crate::{lifecycle::init::InitArgs, state::CkBtcMinterState};

        let mut state = CkBtcMinterState::from(InitArgs {
            btc_network: Network::Regtest,
            ecdsa_key_name: "".to_string(),
            retrieve_btc_min_fee: 0,
            retrieve_btc_min_amount: 0,
            ledger_id: CanisterId::from_u64(42),
        });
        for (utxo, acc_idx) in utxos_acc_idx {
            state.add_utxos(accounts[acc_idx].clone(), vec![utxo]);
            state.check_invariants();
        }
    }
}
