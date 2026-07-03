//! Demo of the "deposit from CEX" flow designed in ../deposit_from_cex.md,
//! with the minter simulated by a plain EOA controlling a family of EOAs
//! (stand-in for threshold ECDSA key derivation on the IC).
//!
//!   0) minter EOA + CEX hot-wallet EOA; CkSweeper delegate and a USDT-like
//!      ERC-20 are deployed.
//!   1) the minter derives user-specific deposit addresses.
//!   2) those addresses are unfunded: 0 ETH, 0 USDT, no code.
//!   3) users withdraw USDT from the CEX: plain ERC-20 transfers to the
//!      deposit addresses (the CEX pays that gas).
//!   4) the minter sweeps a deposit address in ONE type-0x04 (EIP-7702)
//!      transaction: authorization signed by the deposit EOA + call to
//!      sweepErc20, gas paid by the minter (variant A: direct sweep).
//!   5) batched sweep: ONE transaction targets several deposit EOAs at once
//!      via CkSweeper.sweepErc20Batch, their authorizations riding in the same
//!      transaction's authorization list.
//!   6) variant B setup: the REAL helper contract (CkDeposit, compiled from
//!      minter/DepositHelperWithSubaccount.sol) and the CkSweeperViaHelper
//!      delegate are deployed; the CEX sends a second round of deposits.
//!   7) variant B sweeps: the deposit EOAs are re-delegated (new
//!      authorizations) to CkSweeperViaHelper, which sweeps by calling the
//!      helper's depositErc20, so each sweep emits the canonical
//!      ReceivedEthOrErc20 event (with the right IC principal) that the
//!      minter's existing deposit pipeline already scrapes and mints from.
//!   8) attack: someone other than the minter tries to sweep (passing their
//!      own principal) and is rejected; the deposit is then swept correctly.
//!
//! Requires a dev node supporting EIP-7702 (Ethereum mainnet since the Pectra
//! upgrade, May 2025), e.g.
//!   anvil
//! or, without foundry installed:
//!   docker run --rm -p 8545:8545 ghcr.io/foundry-rs/foundry:v1.7.1 \
//!       "anvil --host 0.0.0.0"

use alloy::{
    consensus::{Transaction, TxEnvelope},
    eips::{eip2718::Encodable2718, eip7702::Authorization, eip7702::SignedAuthorization},
    network::{EthereumWallet, TransactionBuilder, TransactionBuilder7702},
    primitives::{Address, FixedBytes, U256, keccak256},
    providers::{DynProvider, Provider, ProviderBuilder},
    rpc::types::{TransactionReceipt, TransactionRequest},
    signers::{SignerSync, local::PrivateKeySigner},
    sol,
    sol_types::{SolCall, SolConstructor, SolEvent},
};
use anyhow::{Context, Result, ensure};
use candid::Principal;

sol! {
    #[sol(rpc)]
    contract CkSweeper {
        constructor(address minter);
        function sweepErc20(address[] calldata tokens) external;
        function sweepErc20Batch(address[] calldata depositAddresses, address[] calldata tokens) external;
    }

    #[sol(rpc)]
    contract CkSweeperViaHelper {
        constructor(address minter, address helper);
        function sweepErc20(address[] calldata tokens, bytes32 principal, bytes32 subaccount) external;
        function sweepErc20Batch(address[] calldata depositAddresses, bytes32[] calldata principals, bytes32[] calldata subaccounts, address[] calldata tokens) external;
    }

    /// The existing ckETH helper smart contract
    /// (minter/DepositHelperWithSubaccount.sol).
    #[sol(rpc)]
    contract CkDeposit {
        constructor(address _minterAddress);
        function getMinterAddress() public view returns (address);
        event ReceivedEthOrErc20(
            address indexed erc20ContractAddress,
            address indexed owner,
            uint256 amount,
            bytes32 indexed principal,
            bytes32 subaccount
        );
    }

    #[sol(rpc)]
    contract MockUSDT {
        constructor(address initialHolder, uint256 initialSupply);
        function balanceOf(address account) external view returns (uint256);
        function transfer(address to, uint256 value) external;
        event Transfer(address indexed from, address indexed to, uint256 value);
    }
}

const CKSWEEPER_BYTECODE: &str = include_str!("../artifacts/CkSweeper.bin.hex");
const CKSWEEPER_VIA_HELPER_BYTECODE: &str = include_str!("../artifacts/CkSweeperViaHelper.bin.hex");
const CKDEPOSIT_BYTECODE: &str = include_str!("../artifacts/CkDeposit.bin.hex");
const MOCKUSDT_BYTECODE: &str = include_str!("../artifacts/MockUSDT.bin.hex");

// Anvil's first three well-known dev accounts.
const MINTER_PRIVATE_KEY: &str =
    "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const CEX_PRIVATE_KEY: &str = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
const ATTACKER_PRIVATE_KEY: &str =
    "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a";

const USDT_SUPPLY: u64 = 1_000_000_000_000; // 1M USDT (6 decimals)

// The demo is fully deterministic (fixed keys, fixed contracts, fresh chain),
// so the gas used by each sweep transaction is a constant.
const SINGLE_SWEEP_GAS_USED: u64 = 66_854;
const BATCH_SWEEP_GAS_USED: u64 = 118_876;
const SINGLE_SWEEP_VIA_HELPER_GAS_USED: u64 = 82_207;
const BATCH_SWEEP_VIA_HELPER_GAS_USED: u64 = 164_746;

fn step(title: &str) {
    println!("\n== {title}");
}

fn show(label: &str, value: impl std::fmt::Display) {
    println!("   {label:<46} {value}");
}

fn ok(what: &str) {
    println!("   OK: {what}");
}

/// Demo stand-in for threshold ECDSA derivation: the "minter master key"
/// deterministically derives one child key per IC account. On the IC the
/// private key never exists anywhere; sign_with_ecdsa produces the signatures.
fn derive_deposit_signer(principal: &str) -> PrivateKeySigner {
    let seed = keccak256(format!(
        "cketh-deposit-address|{MINTER_PRIVATE_KEY}|{principal}"
    ));
    PrivateKeySigner::from_bytes(&seed).expect("valid derived key")
}

/// Encodes an IC principal as the bytes32 expected by the helper contract:
/// byte 0 is the principal length, followed by the principal bytes.
fn encode_principal(principal_text: &str) -> FixedBytes<32> {
    let principal = Principal::from_text(principal_text).expect("valid principal");
    let bytes = principal.as_slice();
    let mut encoded = [0u8; 32];
    encoded[0] = bytes.len() as u8;
    encoded[1..=bytes.len()].copy_from_slice(bytes);
    FixedBytes::from(encoded)
}

/// Fills chain id, nonce, fees and gas, then signs with the given wallet,
/// without sending. An explicit gas limit skips estimation (needed for
/// transactions that are expected to revert).
async fn fill_and_sign(
    provider: &DynProvider,
    wallet: &EthereumWallet,
    from: Address,
    tx: TransactionRequest,
    gas_limit: Option<u64>,
) -> Result<TxEnvelope> {
    let fees = provider.estimate_eip1559_fees().await?;
    let mut tx = tx
        .with_from(from)
        .with_chain_id(provider.get_chain_id().await?)
        .with_nonce(provider.get_transaction_count(from).await?)
        .with_max_fee_per_gas(fees.max_fee_per_gas)
        .with_max_priority_fee_per_gas(fees.max_priority_fee_per_gas);
    let gas_limit = match gas_limit {
        Some(gas_limit) => gas_limit,
        None => provider.estimate_gas(tx.clone()).await?,
    };
    tx = tx.with_gas_limit(gas_limit);
    Ok(tx.build(wallet).await?)
}

async fn deploy(
    provider: &DynProvider,
    wallet: &EthereumWallet,
    deployer: &str,
    deployer_address: Address,
    bytecode_hex: &str,
    constructor_args: Vec<u8>,
) -> Result<Address> {
    let mut code = hex::decode(bytecode_hex.trim().trim_start_matches("0x"))?;
    code.extend(constructor_args);
    let envelope = fill_and_sign(
        provider,
        wallet,
        deployer_address,
        TransactionRequest::default().with_deploy_code(code),
        None,
    )
    .await?;
    show(&format!("{deployer} nonce (deploy):"), envelope.nonce());
    let receipt = provider
        .send_tx_envelope(envelope)
        .await?
        .get_receipt()
        .await?;
    receipt.contract_address.context("no contract address")
}

fn sign_delegation(
    deposit_signer: &PrivateKeySigner,
    sweeper: Address,
    chain_id: u64,
    nonce: u64,
) -> Result<SignedAuthorization> {
    let authorization = Authorization {
        chain_id: U256::from(chain_id),
        address: sweeper,
        nonce,
    };
    let signature = deposit_signer.sign_hash_sync(&authorization.signature_hash())?;
    Ok(authorization.into_signed(signature))
}

/// Signs a sweep transaction with the minter's wallet, prints it in full
/// (including the minter's nonce and the raw signed transaction hex), sends it
/// and prints the resulting receipt.
async fn send_and_print_sweep_transaction(
    minter_provider: &DynProvider,
    minter_wallet: &EthereumWallet,
    minter: Address,
    tx: TransactionRequest,
    authorizations: &[SignedAuthorization],
) -> Result<TransactionReceipt> {
    let envelope = fill_and_sign(minter_provider, minter_wallet, minter, tx, None).await?;
    show("minter nonce (sweep):", envelope.nonce());
    show(
        "raw signed transaction:",
        alloy::hex::encode_prefixed(envelope.encoded_2718()),
    );
    let receipt = minter_provider
        .send_tx_envelope(envelope)
        .await?
        .get_receipt()
        .await?;

    show("transaction hash:", receipt.transaction_hash);
    let transaction_type = receipt.transaction_type() as u8;
    show(
        "transaction type:",
        format!(
            "{transaction_type}{}",
            match transaction_type {
                4 => " (EIP-7702 SetCode)",
                2 => " (EIP-1559, no authorization needed anymore)",
                _ => "",
            }
        ),
    );
    show("from (pays gas):", receipt.from);
    show("to:", receipt.to.expect("call, not create"));
    show("gas used:", receipt.gas_used);
    show(
        "effective gas price:",
        format!("{} wei", receipt.effective_gas_price),
    );
    for auth in authorizations {
        show(
            "authorization:",
            format!(
                "EOA {} -> delegate {} (nonce {})",
                auth.recover_authority().expect("valid signature"),
                auth.address,
                auth.nonce
            ),
        );
    }
    for log in receipt.logs() {
        if let Ok(transfer) = MockUSDT::Transfer::decode_log(&log.inner) {
            show(
                "Transfer event:",
                format!(
                    "{} -> {}: {} USDT",
                    transfer.from,
                    transfer.to,
                    transfer.value / U256::from(1_000_000)
                ),
            );
        }
        if let Ok(received) = CkDeposit::ReceivedEthOrErc20::decode_log(&log.inner) {
            show(
                "ReceivedEthOrErc20 event:",
                format!(
                    "token {}, owner {}, amount {}, principal {}, subaccount {}",
                    received.erc20ContractAddress,
                    received.owner,
                    received.amount / U256::from(1_000_000),
                    received.principal,
                    received.subaccount
                ),
            );
        }
    }
    Ok(receipt)
}

#[tokio::main]
async fn main() -> Result<()> {
    let rpc_url =
        std::env::var("ETH_RPC_URL").unwrap_or_else(|_| "http://127.0.0.1:8545".to_string());

    let minter_signer: PrivateKeySigner = MINTER_PRIVATE_KEY.parse()?;
    let cex_signer: PrivateKeySigner = CEX_PRIVATE_KEY.parse()?;
    let minter = minter_signer.address();
    let cex = cex_signer.address();
    // The minter and the CEX are unrelated parties: two separate wallets.
    let minter_wallet = EthereumWallet::from(minter_signer);
    let cex_wallet = EthereumWallet::from(cex_signer);
    let minter_provider = ProviderBuilder::new()
        .wallet(minter_wallet.clone())
        .connect_http(rpc_url.parse()?)
        .erased();
    let cex_provider = ProviderBuilder::new()
        .wallet(cex_wallet.clone())
        .connect_http(rpc_url.parse()?)
        .erased();
    let chain_id = minter_provider.get_chain_id().await?;

    step("0) Setup: minter EOA, CEX hot wallet, contracts");
    let sweeper_address = deploy(
        &minter_provider,
        &minter_wallet,
        "minter",
        minter,
        CKSWEEPER_BYTECODE,
        CkSweeper::constructorCall { minter }.abi_encode(),
    )
    .await?;
    let usdt_address = deploy(
        &cex_provider,
        &cex_wallet,
        "CEX",
        cex,
        MOCKUSDT_BYTECODE,
        MockUSDT::constructorCall {
            initialHolder: cex,
            initialSupply: U256::from(USDT_SUPPLY),
        }
        .abi_encode(),
    )
    .await?;
    let usdt = MockUSDT::new(usdt_address, minter_provider.clone());
    let usdt_as_cex = MockUSDT::new(usdt_address, cex_provider.clone());
    show("minter (EOA, pays all sweep gas):", minter);
    show("CEX hot wallet (EOA):", cex);
    show("CkSweeper delegate + batcher:", sweeper_address);
    show("MockUSDT (USDT-style ERC-20, 6 decimals):", usdt_address);

    step("1) Minter derives user-specific deposit addresses");
    let principals: Vec<String> = (0u8..4)
        .map(|i| Principal::self_authenticating([i]).to_text())
        .collect();
    let deposit_signers: Vec<PrivateKeySigner> = principals
        .iter()
        .map(|p| derive_deposit_signer(p))
        .collect();
    let deposit_addresses: Vec<Address> = deposit_signers.iter().map(|s| s.address()).collect();
    for (principal, address) in principals.iter().zip(&deposit_addresses) {
        show(&format!("{}...:", &principal[..20]), address);
    }

    step("2) Deposit addresses are unfunded: no ETH, no token, no code");
    for address in &deposit_addresses {
        ensure!(minter_provider.get_balance(*address).await?.is_zero());
        ensure!(usdt.balanceOf(*address).call().await?.is_zero());
        ensure!(minter_provider.get_code_at(*address).await?.is_empty());
    }
    ok("every deposit address has 0 ETH, 0 USDT and no code");

    step("3) Users withdraw USDT from the CEX (plain ERC-20 transfers)");
    let amounts: [u64; 4] = [250_000_000, 100_000_000, 75_000_000, 50_000_000];
    for (address, amount) in deposit_addresses.iter().zip(amounts) {
        usdt_as_cex
            .transfer(*address, U256::from(amount))
            .send()
            .await?
            .get_receipt()
            .await?;
        show(
            &format!("CEX -> {address}:"),
            format!("{} USDT", amount / 1_000_000),
        );
    }
    for address in &deposit_addresses {
        ensure!(minter_provider.get_balance(*address).await?.is_zero());
    }
    ok("deposit addresses still have 0 ETH (cannot pay gas themselves)");

    step("4) Variant A: minter sweeps ONE deposit address in ONE EIP-7702 transaction");
    let single_authorization = sign_delegation(&deposit_signers[0], sweeper_address, chain_id, 0)?;
    let single_sweep = TransactionRequest::default()
        .with_to(deposit_addresses[0])
        .with_input(
            CkSweeper::sweepErc20Call {
                tokens: vec![usdt_address],
            }
            .abi_encode(),
        )
        .with_authorization_list(vec![single_authorization.clone()]);
    let single_receipt = send_and_print_sweep_transaction(
        &minter_provider,
        &minter_wallet,
        minter,
        single_sweep,
        &[single_authorization],
    )
    .await?;

    ensure!(single_receipt.status(), "single sweep reverted");
    ensure!(usdt.balanceOf(deposit_addresses[0]).call().await?.is_zero());
    ensure!(usdt.balanceOf(minter).call().await? == U256::from(amounts[0]));
    ok("250 USDT swept to the minter; deposit address needed 0 ETH throughout");
    let single_gas = single_receipt.gas_used;
    ensure!(
        single_gas == SINGLE_SWEEP_GAS_USED,
        "unexpected single-sweep gas: {single_gas}, expected {SINGLE_SWEEP_GAS_USED}"
    );
    ok(&format!(
        "gas used is exactly {SINGLE_SWEEP_GAS_USED} \
         (21000 base + 25000 authorization + ~21000 delegated ERC-20 sweep)"
    ));

    step("5) Variant A batched: ONE transaction targets the 3 remaining deposit EOAs");
    let batch_authorizations: Vec<SignedAuthorization> = deposit_signers[1..]
        .iter()
        .map(|signer| sign_delegation(signer, sweeper_address, chain_id, 0))
        .collect::<Result<_>>()?;
    let batch_targets = deposit_addresses[1..].to_vec();
    let batch_sweep = TransactionRequest::default()
        .with_to(sweeper_address)
        .with_input(
            CkSweeper::sweepErc20BatchCall {
                depositAddresses: batch_targets.clone(),
                tokens: vec![usdt_address],
            }
            .abi_encode(),
        )
        .with_authorization_list(batch_authorizations.clone());
    let batch_receipt = send_and_print_sweep_transaction(
        &minter_provider,
        &minter_wallet,
        minter,
        batch_sweep,
        &batch_authorizations,
    )
    .await?;

    ensure!(batch_receipt.status(), "batched sweep reverted");
    for address in &batch_targets {
        ensure!(usdt.balanceOf(*address).call().await?.is_zero());
    }
    let expected_total: u64 = amounts.iter().sum();
    ensure!(usdt.balanceOf(minter).call().await? == U256::from(expected_total));
    ok("all deposit addresses swept; minter now holds all 475 USDT");

    let batch_gas = batch_receipt.gas_used;
    ensure!(
        batch_gas == BATCH_SWEEP_GAS_USED,
        "unexpected batch-sweep gas: {batch_gas}, expected {BATCH_SWEEP_GAS_USED}"
    );
    let marginal = (batch_gas - single_gas) / 2;
    ok(&format!(
        "gas used is exactly {BATCH_SWEEP_GAS_USED} for 3 EOAs < 3 x {single_gas} \
         (3 separate sweeps); ~{marginal} gas per additional EOA"
    ));

    step("6) Variant B setup: the existing helper contract and its sweeper delegate");
    let helper_address = deploy(
        &minter_provider,
        &minter_wallet,
        "minter",
        minter,
        CKDEPOSIT_BYTECODE,
        CkDeposit::constructorCall {
            _minterAddress: minter,
        }
        .abi_encode(),
    )
    .await?;
    let via_helper_address = deploy(
        &minter_provider,
        &minter_wallet,
        "minter",
        minter,
        CKSWEEPER_VIA_HELPER_BYTECODE,
        CkSweeperViaHelper::constructorCall {
            minter,
            helper: helper_address,
        }
        .abi_encode(),
    )
    .await?;
    let helper = CkDeposit::new(helper_address, minter_provider.clone());
    ensure!(helper.getMinterAddress().call().await? == minter);
    show(
        "CkDeposit helper (DepositHelperWithSubaccount):",
        helper_address,
    );
    show("CkSweeperViaHelper delegate + batcher:", via_helper_address);
    let amounts_b: [u64; 4] = [150_000_000, 80_000_000, 60_000_000, 40_000_000];
    for (address, amount) in deposit_addresses.iter().zip(amounts_b) {
        usdt_as_cex
            .transfer(*address, U256::from(amount))
            .send()
            .await?
            .get_receipt()
            .await?;
        show(
            &format!("CEX -> {address}:"),
            format!("{} USDT", amount / 1_000_000),
        );
    }

    step("7) Variant B: sweeps go through the helper, emitting ReceivedEthOrErc20");
    // Each deposit EOA re-delegates to CkSweeperViaHelper: the applied variant-A
    // authorization incremented its nonce to 1.
    let re_delegation = sign_delegation(&deposit_signers[0], via_helper_address, chain_id, 1)?;
    let via_helper_sweep = TransactionRequest::default()
        .with_to(deposit_addresses[0])
        .with_input(
            CkSweeperViaHelper::sweepErc20Call {
                tokens: vec![usdt_address],
                principal: encode_principal(&principals[0]),
                subaccount: FixedBytes::ZERO,
            }
            .abi_encode(),
        )
        .with_authorization_list(vec![re_delegation.clone()]);
    let via_helper_receipt = send_and_print_sweep_transaction(
        &minter_provider,
        &minter_wallet,
        minter,
        via_helper_sweep,
        &[re_delegation],
    )
    .await?;

    ensure!(via_helper_receipt.status(), "sweep via helper reverted");
    ensure!(usdt.balanceOf(deposit_addresses[0]).call().await?.is_zero());
    let received = via_helper_receipt
        .logs()
        .iter()
        .find_map(|log| CkDeposit::ReceivedEthOrErc20::decode_log(&log.inner).ok())
        .context("no ReceivedEthOrErc20 event")?;
    ensure!(received.address == helper_address);
    ensure!(received.erc20ContractAddress == usdt_address);
    ensure!(received.owner == deposit_addresses[0]);
    ensure!(received.amount == U256::from(amounts_b[0]));
    ensure!(received.principal == encode_principal(&principals[0]));
    ensure!(received.subaccount == FixedBytes::ZERO);
    ok(
        "the sweep emitted the canonical ReceivedEthOrErc20 event from the helper, \
         carrying the right IC principal: the minter's existing deposit pipeline \
         scrapes and mints from it unchanged",
    );
    let via_helper_gas = via_helper_receipt.gas_used;
    ensure!(
        via_helper_gas == SINGLE_SWEEP_VIA_HELPER_GAS_USED,
        "unexpected sweep-via-helper gas: {via_helper_gas}, \
         expected {SINGLE_SWEEP_VIA_HELPER_GAS_USED}"
    );
    ok(&format!(
        "gas used is exactly {SINGLE_SWEEP_VIA_HELPER_GAS_USED} \
         (+{} vs the direct sweep: approve + transferFrom + event)",
        SINGLE_SWEEP_VIA_HELPER_GAS_USED - SINGLE_SWEEP_GAS_USED
    ));

    // Batched variant B: re-delegate the 3 remaining EOAs in one transaction;
    // EOAs 1 and 2 are swept, EOA 3 is only re-delegated (swept in step 8).
    let re_delegations: Vec<SignedAuthorization> = deposit_signers[1..]
        .iter()
        .map(|signer| sign_delegation(signer, via_helper_address, chain_id, 1))
        .collect::<Result<_>>()?;
    let via_helper_batch = TransactionRequest::default()
        .with_to(via_helper_address)
        .with_input(
            CkSweeperViaHelper::sweepErc20BatchCall {
                depositAddresses: deposit_addresses[1..3].to_vec(),
                principals: principals[1..3]
                    .iter()
                    .map(|p| encode_principal(p))
                    .collect(),
                subaccounts: vec![FixedBytes::ZERO; 2],
                tokens: vec![usdt_address],
            }
            .abi_encode(),
        )
        .with_authorization_list(re_delegations.clone());
    let via_helper_batch_receipt = send_and_print_sweep_transaction(
        &minter_provider,
        &minter_wallet,
        minter,
        via_helper_batch,
        &re_delegations,
    )
    .await?;
    ensure!(
        via_helper_batch_receipt.status(),
        "batched sweep via helper reverted"
    );
    let received_events: Vec<_> = via_helper_batch_receipt
        .logs()
        .iter()
        .filter_map(|log| CkDeposit::ReceivedEthOrErc20::decode_log(&log.inner).ok())
        .collect();
    ensure!(received_events.len() == 2);
    for (i, event) in received_events.iter().enumerate() {
        ensure!(event.owner == deposit_addresses[i + 1]);
        ensure!(event.principal == encode_principal(&principals[i + 1]));
    }
    let via_helper_batch_gas = via_helper_batch_receipt.gas_used;
    ensure!(
        via_helper_batch_gas == BATCH_SWEEP_VIA_HELPER_GAS_USED,
        "unexpected batched sweep-via-helper gas: {via_helper_batch_gas}, \
         expected {BATCH_SWEEP_VIA_HELPER_GAS_USED}"
    );
    ok(&format!(
        "batched sweep through the helper: 2 canonical deposit events, \
         gas used is exactly {BATCH_SWEEP_VIA_HELPER_GAS_USED} \
         (incl. the deferred re-delegation of the 4th deposit address)"
    ));

    step("8) Attack: someone other than the minter tries to sweep");
    // Deposit EOA 3 is already delegated to CkSweeperViaHelper (step 7) but not
    // yet swept: it still holds 40 USDT. The attacker tries to credit that
    // deposit to their own IC principal.
    let attacker_signer: PrivateKeySigner = ATTACKER_PRIVATE_KEY.parse()?;
    let attacker = attacker_signer.address();
    let attacker_wallet = EthereumWallet::from(attacker_signer);
    let attacker_provider = ProviderBuilder::new()
        .wallet(attacker_wallet.clone())
        .connect_http(rpc_url.parse()?)
        .erased();
    let attacker_principal = "2vxsx-fae";
    show("attacker (EOA):", attacker);
    let attack = TransactionRequest::default()
        .with_to(deposit_addresses[3])
        .with_input(
            CkSweeperViaHelper::sweepErc20Call {
                tokens: vec![usdt_address],
                principal: encode_principal(attacker_principal),
                subaccount: FixedBytes::ZERO,
            }
            .abi_encode(),
        );
    // Gas estimation would already fail with "caller is not the minter", so the
    // attacker forces an explicit gas limit to get the transaction on chain.
    let attack_envelope = fill_and_sign(
        &attacker_provider,
        &attacker_wallet,
        attacker,
        attack,
        Some(300_000),
    )
    .await?;
    let attack_receipt = attacker_provider
        .send_tx_envelope(attack_envelope)
        .await?
        .get_receipt()
        .await?;
    ensure!(
        !attack_receipt.status(),
        "attacker's sweep should have reverted"
    );
    ensure!(usdt.balanceOf(deposit_addresses[3]).call().await? == U256::from(amounts_b[3]));
    ok("the attacker's sweep reverted (caller is not the minter); funds untouched");

    // The minter sweeps it correctly: the delegation is already installed, so no
    // authorization is needed anymore.
    let final_sweep = TransactionRequest::default()
        .with_to(deposit_addresses[3])
        .with_input(
            CkSweeperViaHelper::sweepErc20Call {
                tokens: vec![usdt_address],
                principal: encode_principal(&principals[3]),
                subaccount: FixedBytes::ZERO,
            }
            .abi_encode(),
        );
    let final_receipt = send_and_print_sweep_transaction(
        &minter_provider,
        &minter_wallet,
        minter,
        final_sweep,
        &[],
    )
    .await?;
    ensure!(final_receipt.status(), "final sweep reverted");
    let grand_total: u64 = amounts.iter().sum::<u64>() + amounts_b.iter().sum::<u64>();
    ensure!(usdt.balanceOf(minter).call().await? == U256::from(grand_total));
    ok("the minter swept it with the right principal; it now holds all 805 USDT");

    println!("\nDemo completed successfully.");
    Ok(())
}
