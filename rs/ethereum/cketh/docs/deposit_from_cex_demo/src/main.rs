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
//!      sweepErc20, gas paid by the minter.
//!   5) batched sweep: ONE transaction targets several deposit EOAs at once
//!      via CkSweeper.sweepErc20Batch, their authorizations riding in the same
//!      transaction's authorization list.
//!
//! Requires a dev node supporting EIP-7702 (Ethereum mainnet since the Pectra
//! upgrade, May 2025), e.g.
//!   anvil
//! or, without foundry installed:
//!   docker run --rm -p 8545:8545 ghcr.io/foundry-rs/foundry:v1.7.1 \
//!       "anvil --host 0.0.0.0"

use alloy::{
    eips::eip7702::{Authorization, SignedAuthorization},
    network::{EthereumWallet, TransactionBuilder, TransactionBuilder7702},
    primitives::{Address, U256, keccak256},
    providers::{DynProvider, Provider, ProviderBuilder},
    rpc::types::{TransactionReceipt, TransactionRequest},
    signers::{SignerSync, local::PrivateKeySigner},
    sol,
    sol_types::{SolCall, SolConstructor, SolEvent},
};
use anyhow::{Context, Result, ensure};

sol! {
    #[sol(rpc)]
    contract CkSweeper {
        constructor(address minter);
        function sweepErc20(address[] calldata tokens) external;
        function sweepErc20Batch(address[] calldata depositAddresses, address[] calldata tokens) external;
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
const MOCKUSDT_BYTECODE: &str = include_str!("../artifacts/MockUSDT.bin.hex");

// Anvil's first two well-known dev accounts.
const MINTER_PK: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const CEX_PK: &str = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";

const USDT_SUPPLY: u64 = 1_000_000_000_000; // 1M USDT (6 decimals)

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
    let seed = keccak256(format!("cketh-deposit-address|{MINTER_PK}|{principal}"));
    PrivateKeySigner::from_bytes(&seed).expect("valid derived key")
}

async fn deploy(
    provider: &DynProvider,
    from: Address,
    bytecode_hex: &str,
    constructor_args: Vec<u8>,
) -> Result<Address> {
    let mut code = hex::decode(bytecode_hex.trim().trim_start_matches("0x"))?;
    code.extend(constructor_args);
    let tx = TransactionRequest::default()
        .with_from(from)
        .with_deploy_code(code);
    let receipt = provider.send_transaction(tx).await?.get_receipt().await?;
    receipt.contract_address.context("no contract address")
}

fn sign_delegation(
    deposit_signer: &PrivateKeySigner,
    sweeper: Address,
    chain_id: u64,
) -> Result<SignedAuthorization> {
    let authorization = Authorization {
        chain_id: U256::from(chain_id),
        address: sweeper,
        nonce: 0,
    };
    let signature = deposit_signer.sign_hash_sync(&authorization.signature_hash())?;
    Ok(authorization.into_signed(signature))
}

fn print_sweep_transaction(receipt: &TransactionReceipt, authorizations: &[SignedAuthorization]) {
    show("transaction hash:", receipt.transaction_hash);
    show(
        "transaction type:",
        format!(
            "{} (4 = EIP-7702 SetCode)",
            receipt.transaction_type() as u8
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
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let rpc_url =
        std::env::var("ETH_RPC_URL").unwrap_or_else(|_| "http://127.0.0.1:8545".to_string());

    let minter_signer: PrivateKeySigner = MINTER_PK.parse()?;
    let cex_signer: PrivateKeySigner = CEX_PK.parse()?;
    let minter = minter_signer.address();
    let cex = cex_signer.address();
    let mut wallet = EthereumWallet::from(minter_signer);
    wallet.register_signer(cex_signer);
    let provider = ProviderBuilder::new()
        .wallet(wallet)
        .connect_http(rpc_url.parse()?)
        .erased();
    let chain_id = provider.get_chain_id().await?;

    step("0) Setup: minter EOA, CEX hot wallet, contracts");
    let sweeper_address = deploy(
        &provider,
        minter,
        CKSWEEPER_BYTECODE,
        CkSweeper::constructorCall { minter }.abi_encode(),
    )
    .await?;
    let usdt_address = deploy(
        &provider,
        cex,
        MOCKUSDT_BYTECODE,
        MockUSDT::constructorCall {
            initialHolder: cex,
            initialSupply: U256::from(USDT_SUPPLY),
        }
        .abi_encode(),
    )
    .await?;
    let usdt = MockUSDT::new(usdt_address, provider.clone());
    show("minter (EOA, pays all sweep gas):", minter);
    show("CEX hot wallet (EOA):", cex);
    show("CkSweeper delegate + batcher:", sweeper_address);
    show("MockUSDT (USDT-style ERC-20, 6 decimals):", usdt_address);

    step("1) Minter derives user-specific deposit addresses");
    let principals = [
        "k2t6j-2nvnp-4zjm3-25dtz-6xhaa-c7boj-5gayf-oj3xs-i43lp-teztq-6ae",
        "hkroy-sm7vs-yyjs7-ekppe-qqnwx-hm4zf-n7ybs-titsi-k6e3k-ucuiu-uqe",
        "6b4pv-sbpcm-4nsnw-4iplt-t46wy-hbdla-vhemq-lvhlv-tghdk-k6gao-mae",
        "5nl2b-p6c6f-h4o7v-erwra-ceapp-ai4fw-ze2cs-6xsyq-mnhwq-kkwoa-yqe",
    ];
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
        ensure!(provider.get_balance(*address).await?.is_zero());
        ensure!(usdt.balanceOf(*address).call().await?.is_zero());
        ensure!(provider.get_code_at(*address).await?.is_empty());
    }
    ok("every deposit address has 0 ETH, 0 USDT and no code");

    step("3) Users withdraw USDT from the CEX (plain ERC-20 transfers)");
    let amounts: [u64; 4] = [250_000_000, 100_000_000, 75_000_000, 50_000_000];
    for (address, amount) in deposit_addresses.iter().zip(amounts) {
        usdt.transfer(*address, U256::from(amount))
            .from(cex)
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
        ensure!(provider.get_balance(*address).await?.is_zero());
    }
    ok("deposit addresses still have 0 ETH (cannot pay gas themselves)");

    step("4) Minter sweeps ONE deposit address in ONE EIP-7702 transaction");
    let single_authorization = sign_delegation(&deposit_signers[0], sweeper_address, chain_id)?;
    let single_sweep = TransactionRequest::default()
        .with_from(minter)
        .with_to(deposit_addresses[0])
        .with_input(
            CkSweeper::sweepErc20Call {
                tokens: vec![usdt_address],
            }
            .abi_encode(),
        )
        .with_authorization_list(vec![single_authorization.clone()]);
    let single_receipt = provider
        .send_transaction(single_sweep)
        .await?
        .get_receipt()
        .await?;
    print_sweep_transaction(&single_receipt, &[single_authorization]);

    ensure!(single_receipt.status(), "single sweep reverted");
    ensure!(usdt.balanceOf(deposit_addresses[0]).call().await?.is_zero());
    ensure!(usdt.balanceOf(minter).call().await? == U256::from(amounts[0]));
    ok("250 USDT swept to the minter; deposit address needed 0 ETH throughout");
    let single_gas = single_receipt.gas_used;
    ensure!(
        (60_000..=90_000).contains(&single_gas),
        "unexpected single-sweep gas: {single_gas}"
    );
    ok(&format!(
        "gas used {single_gas} within expected bounds [60000, 90000] \
         (21000 base + 25000 authorization + ~21000 delegated ERC-20 sweep)"
    ));

    step("5) Batched sweep: ONE transaction targets the 3 remaining deposit EOAs");
    let batch_authorizations: Vec<SignedAuthorization> = deposit_signers[1..]
        .iter()
        .map(|signer| sign_delegation(signer, sweeper_address, chain_id))
        .collect::<Result<_>>()?;
    let batch_targets = deposit_addresses[1..].to_vec();
    let batch_sweep = TransactionRequest::default()
        .with_from(minter)
        .with_to(sweeper_address)
        .with_input(
            CkSweeper::sweepErc20BatchCall {
                depositAddresses: batch_targets.clone(),
                tokens: vec![usdt_address],
            }
            .abi_encode(),
        )
        .with_authorization_list(batch_authorizations.clone());
    let batch_receipt = provider
        .send_transaction(batch_sweep)
        .await?
        .get_receipt()
        .await?;
    print_sweep_transaction(&batch_receipt, &batch_authorizations);

    ensure!(batch_receipt.status(), "batched sweep reverted");
    for address in &batch_targets {
        ensure!(usdt.balanceOf(*address).call().await?.is_zero());
    }
    let expected_total: u64 = amounts.iter().sum();
    ensure!(usdt.balanceOf(minter).call().await? == U256::from(expected_total));
    ok("all deposit addresses swept; minter now holds all 475 USDT");

    let batch_gas = batch_receipt.gas_used;
    ensure!(
        batch_gas < 3 * single_gas,
        "batching brought no amortization: {batch_gas} vs 3 x {single_gas}"
    );
    let marginal = (batch_gas - single_gas) / 2;
    ok(&format!(
        "gas used {batch_gas} for 3 EOAs < 3 x {single_gas} (3 separate sweeps); \
         ~{marginal} gas per additional EOA"
    ));

    println!("\nDemo completed successfully.");
    Ok(())
}
