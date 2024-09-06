use minicbor::Encoder;
use minicbor::{Decode, Encode};

/// Encodes minter memo as a binary blob.
pub fn encode<T: minicbor::Encode<()>>(t: &T) -> Vec<u8> {
    let mut encoder = Encoder::new(Vec::new());
    encoder.encode(t).expect("minicbor encoding failed");
    encoder.into_writer()
}

#[derive(Eq, PartialEq, Debug, Decode, Encode)]
#[cbor(index_only)]
pub enum Status {
    #[n(0)]
    /// The minter accepted a retrieve_btc request.
    Accepted,
    /// The minter rejected a retrieve_btc due to a failed KYT check.
    #[n(1)]
    Rejected,
    #[n(2)]
    CallFailed,
}

#[derive(Eq, PartialEq, Debug, Decode, Encode)]
pub enum MintMemo<'a> {
    #[n(0)]
    /// The minter converted a single UTXO to ckBTC.
    Convert {
        #[cbor(n(0), with = "minicbor::bytes")]
        /// The transaction ID of the accepted UTXO.
        txid: Option<&'a [u8]>,
        #[n(1)]
        /// UTXO's output index within the BTC transaction.
        vout: Option<u32>,
        #[n(2)]
        /// The KYT check fee.
        kyt_fee: Option<u64>,
    },
    #[n(1)]
    /// The minter minted accumulated KYT fees to the KYT provider.
    Kyt,
    #[n(2)]
    /// The minter failed to check retrieve btc destination address
    /// or the destination address is tainted.
    KytFail {
        #[n(0)]
        /// The KYT check fee.
        kyt_fee: Option<u64>,
        #[n(1)]
        /// The status of the KYT check.
        status: Option<Status>,
        #[n(2)]
        associated_burn_index: Option<u64>,
    },
}

#[derive(Eq, PartialEq, Debug, Decode, Encode)]
pub enum BurnMemo<'a> {
    #[n(0)]
    /// The minter processed a retrieve_btc request.
    Convert {
        #[n(0)]
        /// The destination of the retrieve BTC request.
        address: Option<&'a str>,
        #[n(1)]
        /// The KYT fee for the burn.
        kyt_fee: Option<u64>,
        #[n(2)]
        /// The status of the KYT check.
        status: Option<Status>,
    },
}
