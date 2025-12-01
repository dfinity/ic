use crate::fees::DogecoinFeeEstimator;
use crate::lifecycle::init::Network;

pub fn dogecoin_fee_estimator() -> DogecoinFeeEstimator {
    const RETRIEVE_DOGE_MIN_AMOUNT: u64 = 50 * 100_000_000;
    DogecoinFeeEstimator::new(Network::Mainnet, RETRIEVE_DOGE_MIN_AMOUNT)
}

pub mod arbitrary {
    use crate::{OutPoint, Txid, Utxo};
    use ic_ckbtc_minter::Satoshi;
    use proptest::{arbitrary::any, array::uniform32, prelude::Strategy};

    pub fn utxo(amount: impl Strategy<Value = Satoshi>) -> impl Strategy<Value = Utxo> {
        (outpoint(), amount, any::<u32>()).prop_map(|(outpoint, value, height)| Utxo {
            outpoint,
            value,
            height,
        })
    }

    fn txid() -> impl Strategy<Value = Txid> {
        uniform32(any::<u8>()).prop_map(Txid::from)
    }

    fn outpoint() -> impl Strategy<Value = OutPoint> {
        (txid(), any::<u32>()).prop_map(|(txid, vout)| OutPoint { txid, vout })
    }
}
