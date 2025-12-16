use crate::{OutPoint, Txid, Utxo};
use ic_ckbtc_minter::Satoshi;
use ic_ckbtc_minter::state::utxos::UtxoSet;
use proptest::collection::SizeRange;
use proptest::prelude::Just;
use proptest::{arbitrary::any, array::uniform32, prelude::Strategy};

pub fn utxo(amount: impl Strategy<Value = Satoshi>) -> impl Strategy<Value = Utxo> {
    (outpoint(), amount, any::<u32>()).prop_map(|(outpoint, value, height)| Utxo {
        outpoint,
        value,
        height,
    })
}

pub fn utxo_set(
    amount: impl Strategy<Value = Satoshi> + Clone,
    size: impl Into<SizeRange>,
) -> impl Strategy<Value = UtxoSet> {
    (proptest::collection::btree_set(outpoint(), size))
        .prop_flat_map(move |outpoints| {
            let num_utxos = outpoints.len();
            (
                Just(outpoints),
                proptest::collection::vec(amount.clone(), num_utxos),
                proptest::collection::vec(any::<u32>(), num_utxos),
            )
        })
        .prop_map(|(outpoints, amounts, heights)| {
            outpoints
                .into_iter()
                .zip(amounts)
                .zip(heights)
                .map(|((outpoint, amount), height)| Utxo {
                    outpoint,
                    value: amount,
                    height,
                })
                .collect::<UtxoSet>()
        })
}

fn txid() -> impl Strategy<Value = Txid> {
    uniform32(any::<u8>()).prop_map(Txid::from)
}

fn outpoint() -> impl Strategy<Value = OutPoint> {
    (txid(), any::<u32>()).prop_map(|(txid, vout)| OutPoint { txid, vout })
}
