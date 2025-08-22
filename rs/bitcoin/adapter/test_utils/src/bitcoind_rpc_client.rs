use bitcoin::{
    address::{NetworkUnchecked, ParseError as AddressParseError},
    amount::ParseAmountError,
    consensus::encode,
    Address, Amount, BlockHash, Network, Transaction, Txid,
};
use bitcoincore_rpc::{
    bitcoincore_rpc_json as json, Client as BtcClient, Error as BtcRpcError, RpcApi as BtcRpcApi,
};
use std::collections::HashMap;
use std::sync::Arc;

pub use bitcoincore_rpc::{Auth, RawTx};
pub use json::{
    CreateRawTransactionInput, EstimateMode, GetBalancesResult, GetBlockchainInfoResult,
    ListUnspentResultEntry, SignRawTransactionInput,
};

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    RpcError(BtcRpcError),
    InvalidAddress(AddressParseError),
}

impl From<AddressParseError> for Error {
    fn from(e: AddressParseError) -> Error {
        Error::InvalidAddress(e)
    }
}

impl From<ParseAmountError> for Error {
    fn from(e: ParseAmountError) -> Error {
        Error::RpcError(e.into())
    }
}

impl From<serde_json::error::Error> for Error {
    fn from(e: serde_json::error::Error) -> Error {
        Error::RpcError(e.into())
    }
}

impl From<encode::FromHexError> for Error {
    fn from(e: encode::FromHexError) -> Error {
        Error::RpcError(e.into())
    }
}

impl From<BtcRpcError> for Error {
    fn from(e: BtcRpcError) -> Error {
        Error::RpcError(e)
    }
}

pub trait RpcApi {
    fn get_blockchain_info(&self) -> Result<json::GetBlockchainInfoResult>;
    fn get_connection_count(&self) -> Result<usize>;
    fn get_block_hash(&self, height: u64) -> Result<BlockHash>;
    fn get_best_block_hash(&self) -> Result<BlockHash>;
    fn generate_to_address(&self, block_num: u64, address: &Address) -> Result<Vec<BlockHash>>;
    fn send_to_address(
        &self,
        address: &Address,
        amount: Amount,
        subtract_fee: Option<bool>,
        replaceable: Option<bool>,
        estimate_mode: Option<json::EstimateMode>,
    ) -> Result<Txid>;
    fn get_balance(
        &self,
        minconf: Option<usize>,
        include_watchonly: Option<bool>,
    ) -> Result<Amount>;
    fn balance_of(
        &self,
        account: Option<&str>,
        minconf: Option<usize>,
        include_watchonly: Option<bool>,
    ) -> Result<Amount>;
    fn get_balances(&self) -> Result<json::GetBalancesResult>;
    fn create_raw_transaction(
        &self,
        utxos: &[json::CreateRawTransactionInput],
        outs: &HashMap<String, Amount>,
    ) -> Result<Transaction>;
    fn sign_raw_transaction<R: RawTx>(
        &self,
        tx: R,
        utxos: Option<&[json::SignRawTransactionInput]>,
    ) -> Result<json::SignRawTransactionResult>;
    fn get_received_by_address(&self, address: &Address, minconf: Option<u32>) -> Result<Amount>;
    fn list_unspent(
        &self,
        minconf: Option<usize>,
        addresses: Option<&[&Address]>,
    ) -> Result<Vec<json::ListUnspentResultEntry>>;
    fn get_raw_mempool(&self) -> Result<Vec<Txid>>;
    fn get_address(&self) -> &Address;
    fn add_node(&self, addr: &str) -> Result<()>;
    fn onetry_node(&self, addr: &str) -> Result<()>;
    fn disconnect_node(&self, addr: &str) -> Result<()>;
}

pub struct RpcClient {
    network: Network,
    client: Arc<BtcClient>,
    address: Address,
    account: Option<String>,
}

fn get_new_address(client: &BtcClient, network: Network, label: Option<&str>) -> Result<Address> {
    let address: Address<NetworkUnchecked> =
        client.call("getnewaddress", &opt_into_vec_json(label)?)?;
    let address = address.require_network(network)?;
    Ok(address)
}

impl RpcClient {
    pub fn new(network: Network, url: &str, auth: Auth) -> Result<Self> {
        let client = Arc::new(BtcClient::new(url, auth)?);
        let address = get_new_address(&client, network, None)?;
        Ok(RpcClient {
            network,
            client,
            address,
            account: None,
        })
    }

    pub fn with_account(&self, account: &str) -> Result<Self> {
        let address = get_new_address(&self.client, self.network, Some(account))?;
        Ok(RpcClient {
            network: self.network,
            client: self.client.clone(),
            address,
            account: Some(account.to_string()),
        })
    }
}

impl RpcApi for RpcClient {
    fn get_address(&self) -> &Address {
        &self.address
    }

    fn get_blockchain_info(&self) -> Result<json::GetBlockchainInfoResult> {
        Ok(self.client.get_blockchain_info()?)
    }

    fn get_connection_count(&self) -> Result<usize> {
        Ok(self.client.call("getconnectioncount", &[])?)
    }

    fn get_block_hash(&self, height: u64) -> Result<BlockHash> {
        Ok(self.client.call("getblockhash", &[height.into()])?)
    }

    fn get_best_block_hash(&self) -> Result<BlockHash> {
        Ok(self.client.call("getbestblockhash", &[])?)
    }

    fn generate_to_address(&self, block_num: u64, address: &Address) -> Result<Vec<BlockHash>> {
        Ok(self.client.call(
            "generatetoaddress",
            &[block_num.into(), address.to_string().into()],
        )?)
    }

    fn send_to_address(
        &self,
        address: &Address,
        amount: Amount,
        subtract_fee: Option<bool>,
        replaceable: Option<bool>,
        estimate_mode: Option<json::EstimateMode>,
    ) -> Result<Txid> {
        let args = [
            address.to_string().into(),
            into_json(amount.to_btc())?,
            into_json("")?,
            into_json("")?,
            opt_into_json(subtract_fee, false)?,
            opt_into_json(replaceable, false)?,
            into_json(6)?,
            opt_into_json_with_default(estimate_mode, null())?,
        ];
        Ok(self.client.call("sendtoaddress", &args)?)
    }

    fn get_balance(
        &self,
        minconf: Option<usize>,
        include_watchonly: Option<bool>,
    ) -> Result<Amount> {
        let account = self.account.as_deref();
        self.balance_of(account, minconf, include_watchonly)
    }

    fn balance_of(
        &self,
        account: Option<&str>,
        minconf: Option<usize>,
        include_watchonly: Option<bool>,
    ) -> Result<Amount> {
        let args = [
            opt_into_json(account, "*")?,
            opt_into_json(minconf, 0)?,
            opt_into_json_with_default(include_watchonly, null())?,
        ];
        Ok(Amount::from_btc(self.client.call("getbalance", &args)?)?)
    }

    fn get_balances(&self) -> Result<json::GetBalancesResult> {
        Ok(self.client.call("getbalances", &[])?)
    }

    fn create_raw_transaction(
        &self,
        utxos: &[json::CreateRawTransactionInput],
        outs: &HashMap<String, Amount>,
    ) -> Result<Transaction> {
        let hex: String = self
            .client
            .create_raw_transaction_hex(utxos, outs, None, Some(true))?;
        Ok(encode::deserialize_hex(&hex)?)
    }

    fn sign_raw_transaction<R: RawTx>(
        &self,
        tx: R,
        utxos: Option<&[json::SignRawTransactionInput]>,
    ) -> Result<json::SignRawTransactionResult> {
        let args = [
            tx.raw_hex().into(),
            opt_into_json(utxos, &[])?,
            empty_arr(),
            null(),
        ];
        Ok(self.client.call("signrawtransaction", &args)?)
    }

    fn get_received_by_address(&self, address: &Address, minconf: Option<u32>) -> Result<Amount> {
        let args = [
            address.to_string().into(),
            opt_into_json_with_default(minconf, null())?,
        ];
        Ok(Amount::from_btc(
            self.client.call("getreceivedbyaddress", &args)?,
        )?)
    }

    fn list_unspent(
        &self,
        minconf: Option<usize>,
        addresses: Option<&[&Address]>,
    ) -> Result<Vec<json::ListUnspentResultEntry>> {
        let args = [
            opt_into_json(minconf, 0)?,
            into_json(9999999)?,
            opt_into_json_with_default(addresses, empty_arr())?,
            into_json(true)?,
            null(),
        ];
        Ok(self.client.call("listunspent", &args)?)
    }

    fn get_raw_mempool(&self) -> Result<Vec<Txid>> {
        Ok(self.client.call("getrawmempool", &[])?)
    }

    fn add_node(&self, addr: &str) -> Result<()> {
        Ok(self
            .client
            .call("addnode", &[into_json(addr)?, into_json("add")?])?)
    }

    fn onetry_node(&self, addr: &str) -> Result<()> {
        Ok(self
            .client
            .call("addnode", &[into_json(addr)?, into_json("onetry")?])?)
    }

    fn disconnect_node(&self, addr: &str) -> Result<()> {
        Ok(self.client.call("disconnectnode", &[into_json(addr)?])?)
    }
}

fn opt_into_vec_json<T>(opt: Option<T>) -> Result<Vec<serde_json::Value>>
where
    T: serde::ser::Serialize,
{
    match opt {
        Some(val) => Ok(vec![into_json(val)?]),
        None => Ok(vec![]),
    }
}

/// Shorthand for converting an Option into an Option<serde_json::Value>.
fn opt_into_json<T>(opt: Option<T>, default: T) -> Result<serde_json::Value>
where
    T: serde::ser::Serialize,
{
    opt_into_json_with_default(opt, into_json(default)?)
}

/// Shorthand for converting an Option into an Option<serde_json::Value>.
fn opt_into_json_with_default<T>(
    opt: Option<T>,
    default: serde_json::Value,
) -> Result<serde_json::Value>
where
    T: serde::ser::Serialize,
{
    match opt {
        Some(val) => Ok(into_json(val)?),
        None => Ok(default),
    }
}

/// Shorthand for converting a variable into a serde_json::Value.
fn into_json<T>(val: T) -> Result<serde_json::Value>
where
    T: serde::ser::Serialize,
{
    Ok(serde_json::to_value(val)?)
}

/// Shorthand for `serde_json::Value::Null`.
fn null() -> serde_json::Value {
    serde_json::Value::Null
}

/// Shorthand for an empty serde_json::Value array.
fn empty_arr() -> serde_json::Value {
    serde_json::Value::Array(vec![])
}
