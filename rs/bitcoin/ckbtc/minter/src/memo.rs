#![allow(deprecated)]
use crate::state::LedgerBurnIndex;
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
    /// The minter rejected a retrieve_btc due to a failed Bitcoin check.
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
        /// The Bitcoin check fee.
        kyt_fee: Option<u64>,
    },
    #[n(1)]
    #[deprecated]
    /// The minter minted accumulated check fees to the KYT provider.
    Kyt,
    #[n(2)]
    #[deprecated]
    /// The minter failed to check retrieve btc destination address
    /// or the destination address is tainted.
    KytFail {
        #[n(0)]
        /// The Bitcoin check fee.
        kyt_fee: Option<u64>,
        #[n(1)]
        /// The status of the Bitcoin check.
        status: Option<Status>,
        #[n(2)]
        associated_burn_index: Option<u64>,
    },
    #[n(3)]
    ReimburseWithdrawal {
        #[n(0)]
        /// The id corresponding to the withdrawal request,
        /// which corresponds to the ledger burn index.
        withdrawal_id: LedgerBurnIndex,
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
        /// The check fee for the burn.
        kyt_fee: Option<u64>,
        #[n(2)]
        /// The status of the Bitcoin check.
        status: Option<Status>,
    },
    #[n(1)]
    Consolidate {
        #[n(0)]
        /// The total value of conslidated UTXOs.
        value: u64,
        /// Number of consolidated UTXOs.
        #[n(1)]
        inputs: u64,
    },
}
