use bitcoin::{
    Amount, Block as BtcBlock, BlockHash, Network as BtcNetwork, Transaction, Txid,
    address::{Address as BtcAddress, NetworkUnchecked, ParseError as BtcAddressParseError},
    amount::ParseAmountError,
    block::Header,
    consensus::{Decodable, encode},
    dogecoin::{
        Address as DogeAddress, Block as DogeBlock, Network as DogeNetwork,
        address::ParseError as DogeAddressParseError,
    },
    hex::DisplayHex,
};
use ic_config::adapters::AdaptersConfig;
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;

pub use crate::rpc_json::{
    BtcGetMempoolEntryResult, CreateRawTransactionInput, DogeGetMempoolEntryResult,
    GetBalancesResult, GetBlockchainInfoResult, ListUnspentResultEntry, LoadWalletResult,
    SignRawTransactionInput, SignRawTransactionResult, UnloadWalletResult,
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
    InvalidDogeAddress(DogeAddressParseError),
    InvalidBtcAddress(BtcAddressParseError),
    InvalidCookieFile,
    AddressNotAvailable,
}

impl From<BtcAddressParseError> for RpcError {
    fn from(e: BtcAddressParseError) -> Self {
        Self::InvalidBtcAddress(e)
    }
}

impl From<DogeAddressParseError> for RpcError {
    fn from(e: DogeAddressParseError) -> Self {
        Self::InvalidDogeAddress(e)
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

pub trait RpcClientType: Copy + std::fmt::Display {
    type Header: Decodable;
    type Block: Decodable;
    type Address: serde::Serialize + std::fmt::Display;
    type AddressUnchecked: for<'a> serde::Deserialize<'a>;
    type AddressParseError;
    type GetMempoolEntryResult: for<'a> serde::Deserialize<'a>;

    const REGTEST: Self;
    const NAME: &str;
    const RPC_WALLET_SUPPORT: bool;
    /// Initial block reward for regtest network.
    const REGTEST_INITIAL_BLOCK_REWARDS: Amount;
    /// Number of blocks for coinbase maturity
    const REGTEST_COINBASE_MATURITY: u64;
    fn require_network(address: Self::AddressUnchecked, network: Self) -> Result<Self::Address>;
    fn assume_checked(address: Self::AddressUnchecked) -> Self::Address;
    fn block_hash(block: &Self::Block) -> BlockHash;
    fn iter_transactions(block: &Self::Block) -> impl Iterator<Item = &Transaction>;
    fn new_adapters_config_with_mainnet_uds_path(mainnet_uds_path: &Path) -> AdaptersConfig;
}

impl RpcClientType for BtcNetwork {
    type Header = Header;
    type Block = BtcBlock;
    type Address = BtcAddress;
    type AddressUnchecked = BtcAddress<NetworkUnchecked>;
    type AddressParseError = BtcAddressParseError;
    type GetMempoolEntryResult = BtcGetMempoolEntryResult;

    const REGTEST: Self = BtcNetwork::Regtest;
    const NAME: &str = "Bitcoin";
    const RPC_WALLET_SUPPORT: bool = true;
    const REGTEST_INITIAL_BLOCK_REWARDS: Amount = Amount::from_sat(5_000_000_000);
    const REGTEST_COINBASE_MATURITY: u64 = 100;

    fn require_network(address: Self::AddressUnchecked, network: Self) -> Result<Self::Address> {
        Ok(address.require_network(network)?)
    }
    fn assume_checked(address: Self::AddressUnchecked) -> Self::Address {
        address.assume_checked()
    }
    fn block_hash(block: &Self::Block) -> BlockHash {
        block.block_hash()
    }
    fn iter_transactions(block: &Self::Block) -> impl Iterator<Item = &Transaction> {
        block.txdata.iter()
    }
    fn new_adapters_config_with_mainnet_uds_path(mainnet_uds_path: &Path) -> AdaptersConfig {
        AdaptersConfig {
            bitcoin_mainnet_uds_path: Some(mainnet_uds_path.into()),
            ..Default::default()
        }
    }
}

impl RpcClientType for DogeNetwork {
    type Header = Header;
    type Block = DogeBlock;
    type Address = DogeAddress;
    type AddressUnchecked = DogeAddress<NetworkUnchecked>;
    type AddressParseError = DogeAddressParseError;
    type GetMempoolEntryResult = DogeGetMempoolEntryResult;

    const REGTEST: Self = DogeNetwork::Regtest;
    const NAME: &str = "Dogecoin";
    const RPC_WALLET_SUPPORT: bool = false;
    const REGTEST_INITIAL_BLOCK_REWARDS: Amount = Amount::from_sat(50_000_000_000_000);
    const REGTEST_COINBASE_MATURITY: u64 = 60;

    fn require_network(address: Self::AddressUnchecked, network: Self) -> Result<Self::Address> {
        Ok(address.require_network(network)?)
    }
    fn assume_checked(address: Self::AddressUnchecked) -> Self::Address {
        address.assume_checked()
    }
    fn block_hash(block: &Self::Block) -> BlockHash {
        block.block_hash()
    }
    fn iter_transactions(block: &Self::Block) -> impl Iterator<Item = &Transaction> {
        block.txdata.iter()
    }
    fn new_adapters_config_with_mainnet_uds_path(mainnet_uds_path: &Path) -> AdaptersConfig {
        AdaptersConfig {
            dogecoin_mainnet_uds_path: Some(mainnet_uds_path.into()),
            ..Default::default()
        }
    }
}

/// RPC client that sends RPC commands to a Bitcoin daemon.
pub struct RpcClient<T: RpcClientType> {
    network: T,
    client: Arc<jsonrpc::client::Client>,
    address: Option<T::Address>,
}

impl<T: RpcClientType> Drop for RpcClient<T> {
    fn drop(&mut self) {
        if self.address.is_some() {
            let _ = self.unload_wallet(Some("default"));
        }
    }
}

impl<T: RpcClientType> RpcClient<T> {
    /// Create a RPC client using the given [Network], url and [Auth].
    pub fn new(network: T, url: &str, auth: Auth) -> Result<Self> {
        let (user, pass) = auth.get_user_pass()?;
        let transport = jsonrpc::simple_http::Builder::new()
            .timeout(std::time::Duration::from_secs(60))
            .url(url)
            .map_err(|e| RpcError::JsonRpc(e.into()))?;
        let transport = if let Some(user) = user {
            transport.auth(user, pass)
        } else {
            transport
        };
        let client = jsonrpc::client::Client::with_transport(transport.build());
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
    /// We can't rely on the wallet feature because Dogecoin does not support it.
    pub fn with_account(&self, account: &str) -> Result<Self> {
        let address = self.get_new_address_with_label(Some(account))?;
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
                    match self.load_wallet("default") {
                        // Wait a second if it says "Wallet already loading."
                        Err(RpcError::JsonRpc(jsonrpc::error::Error::Rpc(
                            jsonrpc::error::RpcError { code, message, .. },
                        ))) if code == -4 && message == "Wallet already loading." => {
                            std::thread::sleep(std::time::Duration::from_secs(1));
                        }
                        Err(err) => return Err(err),
                        Ok(_) => {}
                    }
                }
                break;
            }
        }
        self.address = Some(self.get_new_address()?);
        Ok(self)
    }

    /// Return the default address of the client, which is only created
    /// after wallet exists.
    ///
    /// To change the default address one has to create a new [RpcClient]
    /// by calling [with_account].
    pub fn get_address(&self) -> Result<&T::Address> {
        self.address.as_ref().ok_or(RpcError::AddressNotAvailable)
    }

    /// Return the balance available at the default address.
    pub fn get_balance(&self, minconf: Option<usize>) -> Result<Amount> {
        self.get_balance_of(minconf, self.get_address()?)
    }

    /// Send bitcoin from the default address.
    pub fn send_to(&self, to_address: &T::Address, amount: Amount, fee: Amount) -> Result<Txid> {
        self.send(self.get_address()?, to_address, amount, fee)
    }

    /// Send bitcoin from the given [from_address].
    pub fn send(
        &self,
        from_address: &T::Address,
        to_address: &T::Address,
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

    /// Adds a private key (as returned by `dumpprivkey`) to your wallet.
    pub fn import_private_key(&self, private_key: &str, label: &str) -> Result<()> {
        let args = [into_json(private_key)?, into_json(label)?];
        self.call("importprivkey", &args)
    }

    fn create_wallet(
        &self,
        wallet: &str,
        disable_private_keys: Option<bool>,
        blank: Option<bool>,
        passphrase: Option<&str>,
        avoid_reuse: Option<bool>,
    ) -> Result<LoadWalletResult> {
        if !T::RPC_WALLET_SUPPORT {
            return Ok(LoadWalletResult {
                name: wallet.to_string(),
                warning: None,
            });
        }
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
        if !T::RPC_WALLET_SUPPORT {
            return Ok(LoadWalletResult {
                name: wallet.to_string(),
                warning: None,
            });
        }
        self.call("loadwallet", &[wallet.into()])
    }

    fn unload_wallet(&self, wallet: Option<&str>) -> Result<UnloadWalletResult> {
        if !T::RPC_WALLET_SUPPORT {
            return Ok(UnloadWalletResult { warning: None });
        }
        let args = [opt_into_json(wallet, null())?];
        self.call("unloadwallet", &args)
    }

    /// Call an `cmd` rpc with given `args` list
    fn call<V: for<'a> serde::de::Deserialize<'a>>(
        &self,
        cmd: &str,
        args: &[serde_json::Value],
    ) -> Result<V> {
        let raw = serde_json::value::to_raw_value(args)?;
        let req = self.client.build_request(cmd, Some(&raw));
        let resp = self.client.send_request(req).map_err(RpcError::from);
        Ok(resp?.result()?)
    }

    pub fn stop(&self) -> Result<String> {
        self.call("stop", &[])
    }

    pub fn get_new_address_with_label(&self, label: Option<&str>) -> Result<T::Address> {
        let address: T::AddressUnchecked =
            self.call("getnewaddress", &opt_into_vec_json(label)?)?;
        let address = T::require_network(address, self.network)?;
        Ok(address)
    }

    pub fn get_new_address(&self) -> Result<T::Address> {
        self.get_new_address_with_label(None)
    }

    pub fn get_blockchain_info(&self) -> Result<GetBlockchainInfoResult> {
        self.call("getblockchaininfo", &[])
    }

    pub fn get_connection_count(&self) -> Result<usize> {
        self.call("getconnectioncount", &[])
    }

    pub fn get_block_hash(&self, height: u64) -> Result<BlockHash> {
        self.call("getblockhash", &[height.into()])
    }

    pub fn get_best_block_hash(&self) -> Result<BlockHash> {
        self.call("getbestblockhash", &[])
    }

    pub fn generate_to_address(
        &self,
        block_num: u64,
        address: &T::Address,
    ) -> Result<Vec<BlockHash>> {
        self.call(
            "generatetoaddress",
            &[block_num.into(), address.to_string().into()],
        )
    }

    pub fn get_balance_of(&self, minconf: Option<usize>, address: &T::Address) -> Result<Amount> {
        let unspent = self.list_unspent(minconf, Some(&[address]))?;
        Ok(unspent.iter().map(|x| x.amount).sum())
    }

    pub fn create_raw_transaction(
        &self,
        utxos: &[CreateRawTransactionInput],
        outs: &HashMap<String, Amount>,
    ) -> Result<Transaction> {
        let hex: String = self.create_raw_transaction_hex(utxos, outs, None, Some(true))?;
        Ok(encode::deserialize_hex(&hex)?)
    }

    pub fn create_raw_transaction_hex(
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

    pub fn sign_raw_transaction<R: RawTx>(
        &self,
        tx: R,
        utxos: Option<&[SignRawTransactionInput]>,
    ) -> Result<SignRawTransactionResult> {
        let args = [tx.raw_hex().into(), opt_into_json(utxos, empty_arr())?];
        if T::RPC_WALLET_SUPPORT {
            self.call("signrawtransactionwithwallet", &args)
        } else {
            self.call("signrawtransaction", &args)
        }
    }

    pub fn send_raw_transaction<R: RawTx>(&self, tx: R) -> Result<Txid> {
        self.call("sendrawtransaction", &[tx.raw_hex().into()])
    }

    pub fn list_unspent(
        &self,
        minconf: Option<usize>,
        addresses: Option<&[&T::Address]>,
    ) -> Result<Vec<ListUnspentResultEntry>> {
        let args = [
            opt_into_json(minconf, into_json(0)?)?,
            into_json(9999999)?,
            opt_into_json(addresses, empty_arr())?,
            into_json(true)?,
        ];
        self.call("listunspent", &args)
    }

    pub fn get_raw_mempool(&self) -> Result<Vec<Txid>> {
        self.call("getrawmempool", &[])
    }

    pub fn get_mempool_entry(&self, txid: &Txid) -> Result<T::GetMempoolEntryResult> {
        self.call("getmempoolentry", &[into_json(txid)?])
    }

    pub fn add_node(&self, addr: &str) -> Result<()> {
        self.call("addnode", &[into_json(addr)?, into_json("add")?])
    }

    pub fn onetry_node(&self, addr: &str) -> Result<()> {
        self.call("addnode", &[into_json(addr)?, into_json("onetry")?])
    }

    pub fn disconnect_node(&self, addr: &str) -> Result<()> {
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
