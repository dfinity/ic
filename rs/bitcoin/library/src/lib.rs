//! # Internet Computer Rust Bitcoin Library
//!
//! Please read the [library's README](https://github.com/dfinity/bitcoin-library/blob/main/README.adoc) first for an overview of its current features.
//!
//! The core component of the library is the stateful [BitcoinAgent]. It can be used for the following tasks:
//!
//! * It can derive and manage Bitcoin addresses, handling the associated unspent transaction outputs (UTXOs).
//! * It can provide information about account balances of Bitcoin addresses.
// * It can be used to transfer bitcoins from a managed address to any other address.
//!
//! A step-by-step tutorial is presented in [Section 1](#1-step-by-step-tutorial).
//!
//! Snippets of sample code to illustrate its usage are provided in [Section 2](#2-sample-code).
//!
//! As mentioned above, the [BitcoinAgent] is stateful. Therefore, it is important to store and load the agent’s state properly in the canister’s life cycle management. This aspect is discussed in detail in [Section 3](#3-life-cycle-management).
//!
//! While working on the Internet Computer does not require more configuration, working locally does. The additional instructions are provided in [Section 4](#4-testing-locally).

//! # 1. Step-by-step tutorial

//! Make sure that [Rust](https://www.rust-lang.org/tools/install) and [dfx](https://github.com/dfinity/sdk#getting-started) are installed.
//!
//! Create a Rust example dfx project.

//! ```bash
//! dfx new --type rust example_rust
//! ```

//! Move into the `example_rust/` project directory.

//! ```bash
//! cd example_rust/
//! ```

//! Add the most recent version of the `ic-btc-library` and its dependency to your `src/example_rust/Cargo.toml` dependencies.

//! ```toml
//! ic-btc-library = "0.1.0"
//! bitcoin = "0.28.1"
//! ```

//! Replace the content of `src/example_rust/src/lib.rs` with the sample code from [Section 2](#2-sample-code).
//!
//! While working on the Internet Computer does not require more configuration, working locally does. The additional instructions are provided in [Section 4](#4-testing-locally).
//!
//! Replace the content of `src/example_rust/example_rust.did` with:

//! ```candid
//! service : {
//!     "main": () -> (text, nat64, text);
//! }
//! ```

//! Install `ic-cdk-optimizer` to optimize the output WASM module.

//! ```bash
//! cargo install ic-cdk-optimizer
//! ```

//! Deploy (or redeploy by adding `--mode=reinstall`) your canister using the `ic-btc-library`.
//!
//! Note: On macOS a specific version of llvm-ar and clang need to be set, otherwise the WASM compilation of rust-secp256k1 will fail. To this end, Mac users first need to run the following command:

//! ```bash
//! AR="/usr/local/opt/llvm/bin/llvm-ar" CC="/usr/local/opt/llvm/bin/clang" cargo build --target "wasm32-unknown-unknown" --release
//! ```

//! To deploy the canister locally.

//! ```bash
//! dfx deploy example_rust
//! ```

//! To deploy the canister on the Internet Computer.

//! ```bash
//! dfx deploy --network ic
//! ```

//! Execute the `main` function locally.

//! ```bash
//! dfx canister call example_rust main
//! ```

//! Execute the `main` function on the Internet Computer.

//! ```bash
//! dfx canister --network ic call example_rust main
//! ```

//! If you are running the code locally then the output of `ic_cdk::print` is displayed on the terminal running dfx.
//!
//! If you are interested in sending bitcoins to the canister you created, [see these instructions](#sending-bitcoin-to-the-example-canister).

//! # 2. Sample Code

//! The following code shows how to create a [BitcoinAgent] instance, add a managed address derived from the canister’s public key and get its current balance.
//! ```ignore
//! use ic_btc_library::{AddressType, Network};
//! use ic_cdk::print;
//! # use ic_btc_library::{BitcoinAgent, BitcoinCanister, BitcoinCanisterMock};
//! # /*
//! use ic_cdk_macros::update;
//! use ic_btc_library::{BitcoinAgent, BitcoinCanister, BitcoinCanisterImpl, Satoshi};
//! # */
//!
//! # #[tokio::main]
//! # async fn main() -> () {
//! # /*
//! #[update]
//! pub async fn main() -> (String, Satoshi, String) {
//! # */
//!     let num_confirmations = 6;
//!
//!     let mut agent = BitcoinAgent::new(
//!         // Choose the Bitcoin network your `BitcoinAgent` will use: mainnet, testnet, or regtest.
//!         # /*
//!         BitcoinCanisterImpl::new(Network::Regtest),
//!         # */
//!         # BitcoinCanisterMock::new(Network::Regtest),
//!         &AddressType::P2pkh,
//!         num_confirmations,
//!     ).unwrap();
//!
//!     // Print the address of the main account and its balance:
//!     let main_address = agent.get_main_address();
//!     # /*
//!     print(&format!("Main account address: {}", main_address));
//!     let balance = agent.get_balance(&main_address, num_confirmations).await.unwrap();
//!     print(&format!("Main account balance: {}", balance));
//!     # */
//!     # println!("Main account address: {}", main_address);
//!     # let balance = agent.get_balance(&main_address, num_confirmations).await.unwrap();
//!     # println!("Main account balance: {}", balance);
//!
//!     // Derive an address and print it:
//!     let derivation_path: Vec<u8> = vec![1];
//!     let new_address = agent.add_address(&derivation_path).unwrap();
//!     # /*
//!     print(&format!("Derived address: {}", new_address));
//!
//!     // If running on the Internet Computer, then `ic_cdk::print` doesn't print anywhere.
//!     // So to get the output, we return the printed variables.
//!     (main_address.to_string(), balance, new_address.to_string())
//!     # */
//!     # println!("Derived address: {}", new_address);
//! }
//! ```

/*
    Send bitcoin to a derived address:
    let amount: Satoshi = 1000000;
    let payouts = HashMap::from([(new_address, amount)]);

    agent.transfer(payouts, Fee::Standard, num_confirmations, false);
*/

//! Given a [BitcoinAgent] instance, it is possible to get updates for a particular address using the function [`get_balance_update`](BitcoinAgent::get_balance_update):

//! ```ignore
//! # use ic_btc_library::{AddressType, Network, BitcoinAgent, BitcoinCanister, BitcoinCanisterMock};
//! #
//! # #[tokio::main]
//! # async fn main() {
//! # let mut agent = BitcoinAgent::new(
//! #     BitcoinCanisterMock::new(Network::Regtest),
//! #     &AddressType::P2pkh,
//! #     0,
//! # ).unwrap();
//! # let address = agent.get_main_address();
//! #
//! let balance_update = agent.get_balance_update(&address).await.unwrap();
//! if balance_update.added_balance > 0 {
//!     // ...
//! }
//! # }
//! ```

//! Note that the [`get_balance_update`](BitcoinAgent::get_balance_update) call changes the state of the agent. If the function is called again before any other balance change is recorded, the return value will indicate no balance changes, i.e., `balance_update.added_balance == 0`.
//! In a more complex example, asynchronous actions may be triggered based on the update. If these actions fail, the library state should not change in order to avoid inconsistencies.
//! This case can be handled using [`peek_balance_update`](BitcoinAgent::peek_balance_update) and [`update_state`](BitcoinAgent::update_state) as follows.

//! ```ignore
//! # use ic_btc_library::{AddressType, Network, BitcoinAgent, BitcoinCanister, BitcoinCanisterMock};
//! #
//! # #[tokio::main]
//! # async fn main() {
//! # let mut agent = BitcoinAgent::new(
//! #     BitcoinCanisterMock::new(Network::Regtest),
//! #     &AddressType::P2pkh,
//! #     0,
//! # ).unwrap();
//! # let address = agent.get_main_address();
//! #
//! // ...
//! // NOTE: A guard must be in place to prevent access to the given
//! // address until the end of the code snippet!
//! let balance_update = agent.peek_balance_update(&address).await.unwrap();
//! if balance_update.added_balance > 0 {
//!     // async_call(balance_update.added_balance).await.unwrap();
//!     // The state is updated after completing the asynchronous call.
//!     agent.update_state(&address);
//! }
//! // Access to the address can be made available again here.
//! # }
//! ```

//! Calling [`peek_balance_update`](BitcoinAgent::peek_balance_update) followed by [`update_state`](BitcoinAgent::update_state) is equivalent to calling [`get_balance_update`](BitcoinAgent::get_balance_update).
//!
//! As noted in the code snippet, care needs to be taken not to call [`peek_balance_update`](BitcoinAgent::peek_balance_update) multiple times for concurrent requests when waiting for a response for the asynchronous call.
//! The simplest approach is to keep a data structure with all addresses that are currently being served. The code snippet must not be executed for any address currently found in the data structure.
//!
//! Moreover, it is important to ensure that the same address is never managed by multiple [BitcoinAgent]s.

//! # 3. Life Cycle Management

//! The canister developer has the responsability to store and restore the [BitcoinAgent]s' states during canister upgrades.
//! The following sample code manages this aspect for a single [BitcoinAgent] instance.

//! ```
//! use ic_cdk::storage;
//! use std::cell::RefCell;
//! use ic_btc_library::{BitcoinAgentState, AddressType, Network, BitcoinAgent, BitcoinCanister, BitcoinCanisterImpl};
//! use ic_cdk_macros::{post_upgrade, pre_upgrade};
//!
//! thread_local! {
//!     static BITCOIN_AGENT: RefCell<BitcoinAgent<BitcoinCanisterImpl>> =
//!         RefCell::new(BitcoinAgent::new(BitcoinCanisterImpl::new(Network::Regtest), &AddressType::P2pkh, 0).unwrap());
//! }
//!
//! #[pre_upgrade]
//! fn pre_upgrade() {
//!     BITCOIN_AGENT
//!         .with(|bitcoin_agent| storage::stable_save((bitcoin_agent.borrow().get_state(),)).unwrap());
//! }
//!
//! #[post_upgrade]
//! fn post_upgrade() {
//!     let (old_bitcoin_agent_state,): (BitcoinAgentState,) = storage::stable_restore().unwrap();
//!     BITCOIN_AGENT.with(|bitcoin_agent| {
//!         *bitcoin_agent.borrow_mut() = BitcoinAgent::from_state(old_bitcoin_agent_state)
//!     });
//! }
//! ```

//! Note that the functions must be annotated with `#[init]`, `#[pre_upgrade]` and `#[post_upgrade]`.

//! Furthermore the canister developer must enforce that no address is managed by multiple [BitcoinAgent]s.

//! # 4. Testing locally

//! The [BitcoinAgent] invokes the Bitcoin integration API through the management canister. In order to test the `ic-btc-library` locally, you have to follow the following instructions.

//! # Prerequisites

//! - [Bitcoin Core](https://bitcoin.org/en/download). Mac users are recommended to download the `.tar.gz` version.
//!
//! The first step would be to setup a local Bitcoin network.

//! # Setting up a local Bitcoin network

//! 1. Unpack the `.tar.gz` file.

//! 2. Create a directory named `data` inside the unpacked folder.

//! 3. Create a file called `bitcoin.conf` at the root of the unpacked folder and add the following contents:
//! ```conf
//! ## Enable regtest mode. This is required to setup a private Bitcoin network.
//! regtest=1
//!
//! ## Dummy credentials that are required by `bitcoin-cli`.
//! rpcuser=btc-library
//! rpcpassword=Wjh4u6SAjT4UMJKxPmoZ0AN2r9qbE-ksXQ5I2_-Hm4w=
//! rpcauth=btc-library:8555f1162d473af8e1f744aa056fd728$afaf9cb17b8cf0e8e65994d1195e4b3a4348963b08897b4084d210e5ee588bcb
//! ```

//! 4. Run bitcoind to start the Bitcoin client using the following command:
//! ```bash
//! ./bin/bitcoind -conf=$(pwd)/bitcoin.conf -datadir=$(pwd)/data
//! ```

//! 5. Create a wallet:
//! ```bash
//! ./bin/bitcoin-cli -conf=$(pwd)/bitcoin.conf createwallet mywallet
//! ```
//! If everything is setup correctly, you should see the following output:
//! ```bash
//! {
//!   "name": "mywallet",
//!   "warning": ""
//! }

//! ```
//! 6. Generate a Bitcoin address and save it in variable for later reuse:
//! ```bash
//! export BTC_ADDRESS=$(./bin/bitcoin-cli -conf=$(pwd)/bitcoin.conf getnewaddress)
//! ```
//! This will generate a Bitcoin address for your wallet to receive funds.
//!
//! 7. Mine blocks to receive some bitcoins as a reward.
//! ```bash
//! ./bin/bitcoin-cli -conf=$(pwd)/bitcoin.conf generatetoaddress 101 $BTC_ADDRESS
//! ```
//! You should see an output that looks similar to, but not exactly like, the following:
//! ```bash
//! [
//!   "1625281b2595b77276903868a0fe2fc31cb0c624e9bdc269e74a3f319ceb48de",
//!   "1cc5ba7e86fc313333c5448af6c7af44ff249eca3c8b681edc3c275efd3a2d38",
//!   "1d3c85b674497ba08a48d1b955bee5b4dc4505ffe4e9f49b428153e02e3e0764",
//!   ...
//!   "0dfd066985dc001ccc1fe6d7bfa53b7ad4944285dc173615792653bbd52151f1",
//!   "65975f1cd5809164f73b0702cf326204d8fee8b9669bc6bd510cb221cf09db5c",
//! ]
//! ```

//! # Synchronize blocks from bitcoind and create the canister

//! Synchronize blocks from bitcoind with the adapter and replica by executing in `example_rust` folder:

//! ```bash
//! dfx start --enable-bitcoin --bitcoin-node 127.0.0.1:18444
//! ```

//! Create the example Rust canister.

//! ```bash
//! dfx canister create example_rust
//! ```

//! # Sending bitcoin to the example canister

//! To top up the example canister with bitcoins, run the following:

//! ```bash
//! ## The canister's BTC address (if using P2PKH address type on regtest Bitcoin network).
//! export CANISTER_BTC_ADDRESS=mmdoAzumgjbvAJjVGg7fkQmtvDNFd2wjjH
//!
//! ## Send a transaction that transfers 10 BTC to the canister.
//! ./bin/bitcoin-cli -conf=$(pwd)/bitcoin.conf -datadir=$(pwd)/data sendtoaddress $CANISTER_BTC_ADDRESS 10 "" "" true true null "unset" null 1.1
//!
//! ## Mine 6 blocks that contains the transaction in order to reach provided `min_confirmations`.
//! ./bin/bitcoin-cli -conf=$(pwd)/bitcoin.conf generatetoaddress 6 $BTC_ADDRESS
//! ```

pub mod address_management;
mod agent;
mod canister_common;
mod canister_implementation;
#[cfg(test)]
mod canister_mock;
mod types;
mod upgrade_management;
mod utxo_management;

pub use ic_btc_types::{GetUtxosError, OutPoint, Satoshi, Utxo};
pub use types::{
    AddAddressWithParametersError, AddressNotTracked, AddressType, AddressUsingPrimitives,
    BalanceUpdate, BitcoinAgentState, DerivationPathTooLong, EcdsaPubKey, MinConfirmationsTooHigh,
    Network, UtxosState, UtxosUpdate, STABILITY_THRESHOLD,
};

pub use agent::BitcoinAgent;
pub use canister_common::BitcoinCanister;
pub use canister_implementation::BitcoinCanisterImpl;

/*
    To run documentation tests:
    1. uncomment the `use` line below.
    2. comment `#[cfg(test)]` above.
    3. remove the three `ignore` documentation test attribute above.
    4. comment `(crate)` in `pub(crate) struct BitcoinCanisterMock` in `canister_mock.rs`.
*/
//pub use canister_mock::BitcoinCanisterMock;
