use bitcoin::{
    address::{NetworkUnchecked, ParseError as AddressParseError},
    amount::ParseAmountError,
    consensus::encode,
    hex::DisplayHex,
    Address, Amount, BlockHash, Network, Transaction, Txid,
};
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::sync::Arc;

pub use crate::rpc_json::{
    CreateRawTransactionInput, GetBalancesResult, GetBlockchainInfoResult, GetMempoolEntryResult,
    ListUnspentResultEntry, LoadWalletResult, SignRawTransactionInput, SignRawTransactionResult,
};

pub type Result<T> = std::result::Result<T, RpcError>;

/// The different authentication methods for the client.
#[derive(Clone, Debug, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub enum Auth {
    None,
    UserPass(String, String),
    CookieFile(PathBuf),
}

impl Auth {
    /// Convert into the arguments that jsonrpc::Client needs.
    pub fn get_user_pass(self) -> Result<(Option<String>, Option<String>)> {
        match self {
            Auth::None => Ok((None, None)),
            Auth::UserPass(u, p) => Ok((Some(u), Some(p))),
            Auth::CookieFile(path) => {
                let line = BufReader::new(File::open(path)?)
                    .lines()
                    .next()
                    .ok_or(RpcError::InvalidCookieFile)??;
                let colon = line.find(':').ok_or(RpcError::InvalidCookieFile)?;
                Ok((Some(line[..colon].into()), Some(line[colon + 1..].into())))
            }
        }
    }
}
/// Used to pass raw txs into the API.
pub trait RawTx: Sized + Clone {
    fn raw_hex(self) -> String;
}

impl RawTx for &Transaction {
    fn raw_hex(self) -> String {
        encode::serialize_hex(self)
    }
}

impl RawTx for &[u8] {
    fn raw_hex(self) -> String {
        self.to_lower_hex_string()
    }
}

impl RawTx for &Vec<u8> {
    fn raw_hex(self) -> String {
        self.to_lower_hex_string()
    }
}

#[derive(Debug)]
pub enum RpcError {
    Amount(ParseAmountError),
    Json(serde_json::error::Error),
    JsonRpc(jsonrpc::error::Error),
    FromHex(encode::FromHexError),
    IO(std::io::Error),
    InvalidAddress(AddressParseError),
    InvalidCookieFile,
    AddressNotAvailable,
}

impl From<AddressParseError> for RpcError {
    fn from(e: AddressParseError) -> Self {
        Self::InvalidAddress(e)
    }
}

impl From<ParseAmountError> for RpcError {
    fn from(e: ParseAmountError) -> Self {
        Self::Amount(e)
    }
}

impl From<serde_json::error::Error> for RpcError {
    fn from(e: serde_json::error::Error) -> Self {
        Self::Json(e)
    }
}

impl From<jsonrpc::error::Error> for RpcError {
    fn from(e: jsonrpc::error::Error) -> Self {
        Self::JsonRpc(e)
    }
}

impl From<encode::FromHexError> for RpcError {
    fn from(e: encode::FromHexError) -> Self {
        Self::FromHex(e)
    }
}

impl From<std::io::Error> for RpcError {
    fn from(e: std::io::Error) -> Self {
        Self::IO(e)
    }
}

/// The RPC interface of Bitcoin daemon. It is only a subnet of the
/// supported API and tailored for our own testing purpose.
pub trait RpcApi {
    fn call<T: for<'a> serde::de::Deserialize<'a>>(
        &self,
        cmd: &str,
        args: &[serde_json::Value],
    ) -> Result<T>;

    fn stop(&self) -> Result<String>;
    fn get_blockchain_info(&self) -> Result<GetBlockchainInfoResult>;
    fn get_connection_count(&self) -> Result<usize>;
    fn get_block_hash(&self, height: u64) -> Result<BlockHash>;
    fn get_best_block_hash(&self) -> Result<BlockHash>;
    fn generate_to_address(&self, block_num: u64, address: &Address) -> Result<Vec<BlockHash>>;
    fn get_balance_of(&self, minconf: Option<usize>, address: &Address) -> Result<Amount>;
    fn create_raw_transaction(
        &self,
        utxos: &[CreateRawTransactionInput],
        outs: &HashMap<String, Amount>,
    ) -> Result<Transaction>;
    fn create_raw_transaction_hex(
        &self,
        utxos: &[CreateRawTransactionInput],
        outs: &HashMap<String, Amount>,
        locktime: Option<i64>,
        _replaceable: Option<bool>,
    ) -> Result<String>;
    fn sign_raw_transaction<R: RawTx>(
        &self,
        tx: R,
        utxos: Option<&[SignRawTransactionInput]>,
    ) -> Result<SignRawTransactionResult>;
    fn send_raw_transaction<R: RawTx>(&self, tx: R) -> Result<Txid>;
    fn get_received_by_address(&self, address: &Address, minconf: Option<u32>) -> Result<Amount>;
    fn list_unspent(
        &self,
        minconf: Option<usize>,
        addresses: Option<&[&Address]>,
    ) -> Result<Vec<ListUnspentResultEntry>>;
    fn get_raw_mempool(&self) -> Result<Vec<Txid>>;
    fn get_mempool_entry(&self, txid: &Txid) -> Result<GetMempoolEntryResult>;
    fn get_new_address(&self) -> Result<Address>;
    fn add_node(&self, addr: &str) -> Result<()>;
    fn onetry_node(&self, addr: &str) -> Result<()>;
    fn disconnect_node(&self, addr: &str) -> Result<()>;
}

/// RPC client that sends RPC commands to a Bitcoin daemon.
pub struct RpcClient {
    network: Network,
    client: Arc<jsonrpc::client::Client>,
    address: Option<Address>,
}

fn get_new_address(client: &RpcClient, network: Network, label: Option<&str>) -> Result<Address> {
    let address: Address<NetworkUnchecked> =
        client.call("getnewaddress", &opt_into_vec_json(label)?)?;
    let address = address.require_network(network)?;
    Ok(address)
}

/*
impl Drop for RpcClient {
    fn drop(&mut self) {
        if self.address.is_some() {
            let _ = self.client.unload_wallet(Some("default"));
        }
    }
}
*/

impl RpcClient {
    /// Create a RPC client using the given [Network], url and [Auth].
    pub fn new(network: Network, url: &str, auth: Auth) -> Result<Self> {
        let (user, pass) = auth.get_user_pass()?;
        let client = jsonrpc::client::Client::simple_http(url, user, pass)
            .map_err(|e| RpcError::JsonRpc(e.into()))?;
        let client = Arc::new(client);
        Ok(RpcClient {
            network,
            client,
            address: None,
        })
    }

    /// Return a new RPC client that shares the same connect by using a different
    /// account name and default address.
    /// This is different than the wallet feature supported by the Bitcoin daemon
    /// because all accounts will share the same wallet.
    /// We cann't rely on the wallet feature because Dogecoin does not support it.
    pub fn with_account(&self, account: &str) -> Result<Self> {
        let address = get_new_address(self, self.network, Some(account))?;
        Ok(RpcClient {
            network: self.network,
            client: self.client.clone(),
            address: Some(address),
        })
    }

    /// Ensure the default wallet exists by either creating or loading it.
    pub fn ensure_wallet(mut self) -> Result<Self> {
        loop {
            if self
                .call::<serde_json::Value>("getblockchaininfo", &[])
                .is_ok()
            {
                // Try creating new wallet, if fails due to already existing wallet file
                // try loading the same. Return if still errors.
                if self
                    .create_wallet("default", None, None, None, None)
                    .is_err()
                {
                    self.load_wallet("default")?;
                }
                break;
            }
        }
        self.address = Some(get_new_address(&self, self.network, None)?);
        Ok(self)
    }

    /// Return the default address of the client, which is only created
    /// after wallet exists.
    ///
    /// To change the default address one has to create a new [RpcClient]
    /// by calling [with_account].
    pub fn get_address(&self) -> Result<&Address> {
        self.address.as_ref().ok_or(RpcError::AddressNotAvailable)
    }

    /// Return the balance available at the default address.
    pub fn get_balance(&self, minconf: Option<usize>) -> Result<Amount> {
        self.get_balance_of(minconf, self.get_address()?)
    }

    /// Send bitcoin from the default address.
    pub fn send_to(&self, to_address: &Address, amount: Amount, fee: Amount) -> Result<Txid> {
        self.send(self.get_address()?, to_address, amount, fee)
    }

    /// Send bitcoin from the given [from_address].
    pub fn send(
        &self,
        from_address: &Address,
        to_address: &Address,
        amount: Amount,
        fee: Amount,
    ) -> Result<Txid> {
        let unspent = self.list_unspent(Some(0), Some(&[from_address]))?;
        let total: Amount = unspent.iter().map(|x| x.amount).sum();
        let inputs = unspent
            .iter()
            .map(|x| CreateRawTransactionInput {
                txid: x.txid,
                vout: x.vout,
                sequence: None,
            })
            .collect::<Vec<_>>();
        let mut outputs = HashMap::new();
        outputs.insert(to_address.to_string(), amount);
        if total > amount + fee {
            outputs.insert(from_address.to_string(), total - amount - fee);
        }
        let raw_tx = self.create_raw_transaction(&inputs, &outputs)?;
        let tx = self.sign_raw_transaction(&raw_tx, None)?;
        self.send_raw_transaction::<&[u8]>(tx.hex.as_ref())
    }

    fn create_wallet(
        &self,
        wallet: &str,
        disable_private_keys: Option<bool>,
        blank: Option<bool>,
        passphrase: Option<&str>,
        avoid_reuse: Option<bool>,
    ) -> Result<LoadWalletResult> {
        let args = [
            wallet.into(),
            opt_into_json(disable_private_keys, into_json(false)?)?,
            opt_into_json(blank, into_json(false)?)?,
            opt_into_json(passphrase, into_json("")?)?,
            opt_into_json(avoid_reuse, into_json(false)?)?,
        ];
        self.call("createwallet", &args)
    }

    fn load_wallet(&self, wallet: &str) -> Result<LoadWalletResult> {
        self.call("loadwallet", &[wallet.into()])
    }
}

impl RpcApi for RpcClient {
    /// Call an `cmd` rpc with given `args` list
    fn call<T: for<'a> serde::de::Deserialize<'a>>(
        &self,
        cmd: &str,
        args: &[serde_json::Value],
    ) -> Result<T> {
        let raw = serde_json::value::to_raw_value(args)?;
        let req = self.client.build_request(cmd, Some(&raw));
        let resp = self.client.send_request(req).map_err(RpcError::from);
        Ok(resp?.result()?)
    }

    fn stop(&self) -> Result<String> {
        self.call("stop", &[])
    }

    fn get_new_address(&self) -> Result<Address> {
        get_new_address(self, self.network, None)
    }

    fn get_blockchain_info(&self) -> Result<GetBlockchainInfoResult> {
        self.call("getblockchaininfo", &[])
    }

    fn get_connection_count(&self) -> Result<usize> {
        self.call("getconnectioncount", &[])
    }

    fn get_block_hash(&self, height: u64) -> Result<BlockHash> {
        self.call("getblockhash", &[height.into()])
    }

    fn get_best_block_hash(&self) -> Result<BlockHash> {
        self.call("getbestblockhash", &[])
    }

    fn generate_to_address(&self, block_num: u64, address: &Address) -> Result<Vec<BlockHash>> {
        self.call(
            "generatetoaddress",
            &[block_num.into(), address.to_string().into()],
        )
    }

    fn get_balance_of(&self, minconf: Option<usize>, address: &Address) -> Result<Amount> {
        let unspent = self.list_unspent(minconf, Some(&[address]))?;
        Ok(unspent.iter().map(|x| x.amount).sum())
    }

    fn create_raw_transaction(
        &self,
        utxos: &[CreateRawTransactionInput],
        outs: &HashMap<String, Amount>,
    ) -> Result<Transaction> {
        let hex: String = self.create_raw_transaction_hex(utxos, outs, None, Some(true))?;
        Ok(encode::deserialize_hex(&hex)?)
    }

    fn create_raw_transaction_hex(
        &self,
        utxos: &[CreateRawTransactionInput],
        outs: &HashMap<String, Amount>,
        locktime: Option<i64>,
        _replaceable: Option<bool>,
    ) -> Result<String> {
        let outs_converted = serde_json::Map::from_iter(
            outs.iter()
                .map(|(k, v)| (k.clone(), serde_json::Value::from(v.to_btc()))),
        );
        let args = [
            into_json(utxos)?,
            into_json(outs_converted)?,
            opt_into_json(locktime, null())?,
        ];
        self.call("createrawtransaction", &args)
    }

    fn sign_raw_transaction<R: RawTx>(
        &self,
        tx: R,
        utxos: Option<&[SignRawTransactionInput]>,
    ) -> Result<SignRawTransactionResult> {
        let args = [tx.raw_hex().into(), opt_into_json(utxos, empty_arr())?];
        self.call("signrawtransactionwithwallet", &args)
    }

    fn send_raw_transaction<R: RawTx>(&self, tx: R) -> Result<Txid> {
        self.call("sendrawtransaction", &[tx.raw_hex().into()])
    }

    fn get_received_by_address(&self, address: &Address, minconf: Option<u32>) -> Result<Amount> {
        let args = [address.to_string().into(), opt_into_json(minconf, null())?];
        Ok(Amount::from_btc(self.call("getreceivedbyaddress", &args)?)?)
    }

    fn list_unspent(
        &self,
        minconf: Option<usize>,
        addresses: Option<&[&Address]>,
    ) -> Result<Vec<ListUnspentResultEntry>> {
        let args = [
            opt_into_json(minconf, into_json(0)?)?,
            into_json(9999999)?,
            opt_into_json(addresses, empty_arr())?,
            into_json(true)?,
            null(),
        ];
        self.call("listunspent", &args)
    }

    fn get_raw_mempool(&self) -> Result<Vec<Txid>> {
        self.call("getrawmempool", &[])
    }

    fn get_mempool_entry(&self, txid: &Txid) -> Result<GetMempoolEntryResult> {
        self.call("getmempoolentry", &[into_json(txid)?])
    }

    fn add_node(&self, addr: &str) -> Result<()> {
        self.call("addnode", &[into_json(addr)?, into_json("add")?])
    }

    fn onetry_node(&self, addr: &str) -> Result<()> {
        self.call("addnode", &[into_json(addr)?, into_json("onetry")?])
    }

    fn disconnect_node(&self, addr: &str) -> Result<()> {
        self.call("disconnectnode", &[into_json(addr)?])
    }
}

// Shorthand for converting an Option into a JSON array.
fn opt_into_vec_json<T>(opt: Option<T>) -> Result<Vec<serde_json::Value>>
where
    T: serde::ser::Serialize,
{
    match opt {
        Some(val) => Ok(vec![into_json(val)?]),
        None => Ok(vec![]),
    }
}

// Shorthand for converting an Option into a JSON value.
fn opt_into_json<T>(opt: Option<T>, default: serde_json::Value) -> Result<serde_json::Value>
where
    T: serde::ser::Serialize,
{
    match opt {
        Some(val) => Ok(into_json(val)?),
        None => Ok(default),
    }
}

// Shorthand for converting a variable into a JSON value.
fn into_json<T>(val: T) -> Result<serde_json::Value>
where
    T: serde::ser::Serialize,
{
    Ok(serde_json::to_value(val)?)
}

// Shorthand for JSON value null.
fn null() -> serde_json::Value {
    serde_json::Value::Null
}

// Shorthand for an empty JSON array.
fn empty_arr() -> serde_json::Value {
    serde_json::Value::Array(vec![])
}
