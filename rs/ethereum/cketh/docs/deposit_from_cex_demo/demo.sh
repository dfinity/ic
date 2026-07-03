#!/usr/bin/env bash
#
# Demo of the "deposit from CEX" flow designed in ../deposit_from_cex.md,
# with the minter simulated by a plain EOA controlling a family of EOAs
# (stand-in for threshold ECDSA key derivation on the IC).
#
#   0) minter EOA + CEX hot-wallet EOA; CkSweeper delegate and a USDT-like
#      ERC-20 are deployed.
#   1) the minter derives a user-specific deposit address.
#   2) that address is unfunded: 0 ETH, 0 USDT, no code.
#   3) the user withdraws USDT from the CEX: a plain ERC-20 transfer to the
#      deposit address (the CEX pays that gas; the deposit address still has 0 ETH).
#   4) the minter sweeps the tokens in ONE type-0x04 (EIP-7702) transaction:
#      authorization signed by the deposit EOA + call to sweepErc20, gas paid
#      by the minter. The deposit address never holds any ETH.
#
# Requires foundry (anvil/forge/cast). If not installed locally, the script
# re-executes itself inside the official foundry Docker image.

set -euo pipefail
cd "$(dirname "$0")"

if ! command -v anvil >/dev/null 2>&1; then
    if command -v docker >/dev/null 2>&1; then
        echo "foundry not found locally; re-running inside ghcr.io/foundry-rs/foundry"
        exec docker run --rm --user "$(id -u):$(id -g)" -e HOME=/tmp/foundry-home \
            -v "$PWD":/demo -w /demo --entrypoint /demo/demo.sh \
            ghcr.io/foundry-rs/foundry:latest
    fi
    echo "error: neither foundry (anvil/forge/cast) nor docker is available" >&2
    exit 1
fi

RPC="http://127.0.0.1:8545"
CHAIN_ID=31337

# Anvil's first two well-known dev accounts.
MINTER_PK="0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
CEX_PK="0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
MINTER=$(cast wallet address --private-key "$MINTER_PK")
CEX=$(cast wallet address --private-key "$CEX_PK")

step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
show() { printf '   %-42s %s\n' "$1" "$2"; }
assert_eq() {
    if [ "$1" != "$2" ]; then
        echo "ASSERTION FAILED: expected '$2', got '$1' ($3)" >&2
        exit 1
    fi
    echo "   OK: $3"
}

eth_balance() { cast balance "$1" --rpc-url "$RPC"; }
usdt_balance() { cast call "$USDT" "balanceOf(address)(uint256)" "$1" --rpc-url "$RPC" | awk '{print $1}'; }

step "0) Setup: anvil (Prague), minter EOA, CEX hot wallet, contracts"
anvil --hardfork prague --silent &
ANVIL_PID=$!
trap 'kill "$ANVIL_PID" 2>/dev/null' EXIT
for _ in $(seq 1 50); do
    cast block-number --rpc-url "$RPC" >/dev/null 2>&1 && break
    sleep 0.2
done

SWEEPER=$(forge create contracts/CkSweeper.sol:CkSweeper --broadcast \
    --private-key "$MINTER_PK" --rpc-url "$RPC" --constructor-args "$MINTER" \
    | awk '/Deployed to:/ {print $3}')
USDT=$(forge create contracts/MockUSDT.sol:MockUSDT --broadcast \
    --private-key "$CEX_PK" --rpc-url "$RPC" --constructor-args "$CEX" 1000000000000 \
    | awk '/Deployed to:/ {print $3}')
show "minter (EOA, pays all sweep gas):" "$MINTER"
show "CEX hot wallet (EOA):" "$CEX"
show "CkSweeper delegate (sweeps only to minter):" "$SWEEPER"
show "MockUSDT (USDT-style ERC-20, 6 decimals):" "$USDT"

step "1) Minter derives the user's deposit address"
# Demo stand-in for threshold ECDSA derivation: the "minter master key"
# deterministically derives one child key per IC account. On the IC the private
# key never exists anywhere; sign_with_ecdsa produces the signatures instead.
PRINCIPAL="k2t6j-2nvnp-4zjm3-25dtz-6xhaa-c7boj-5gayf-oj3xs-i43lp-teztq-6ae"
DEPOSIT_PK=$(cast keccak "cketh-deposit-address|${MINTER_PK}|${PRINCIPAL}")
DEPOSIT=$(cast wallet address --private-key "$DEPOSIT_PK")
show "IC principal:" "$PRINCIPAL"
show "deposit address:" "$DEPOSIT"

step "2) Deposit address is unfunded: no ETH, no token, no code"
assert_eq "$(eth_balance "$DEPOSIT")" "0" "deposit address has 0 ETH"
assert_eq "$(usdt_balance "$DEPOSIT")" "0" "deposit address has 0 USDT"
assert_eq "$(cast code "$DEPOSIT" --rpc-url "$RPC")" "0x" "deposit address has no code"

step "3) User withdraws 250 USDT from the CEX to the deposit address (plain ERC-20 transfer)"
cast send "$USDT" "transfer(address,uint256)" "$DEPOSIT" 250000000 \
    --private-key "$CEX_PK" --rpc-url "$RPC" >/dev/null
assert_eq "$(usdt_balance "$DEPOSIT")" "250000000" "deposit address received 250 USDT"
assert_eq "$(eth_balance "$DEPOSIT")" "0" "deposit address still has 0 ETH (cannot pay gas itself)"

step "4) Minter sweeps in ONE EIP-7702 transaction (gas paid by the minter)"
# The deposit EOA signs an authorization (nonce 0, one-time) delegating its
# code to CkSweeper; the minter submits a single type-0x04 transaction carrying
# that authorization and calling sweepErc20 on the deposit address.
MINTER_USDT_BEFORE=$(usdt_balance "$MINTER")
AUTH=$(cast wallet sign-auth "$SWEEPER" --private-key "$DEPOSIT_PK" --nonce 0 --chain "$CHAIN_ID")
TX=$(cast send "$DEPOSIT" "sweepErc20(address[])" "[$USDT]" \
    --private-key "$MINTER_PK" --auth "$AUTH" --rpc-url "$RPC" --json)
show "sweep tx:" "$(echo "$TX" | grep -o '"transactionHash":"[^"]*"' | head -1 | cut -d'"' -f4)"
show "sweep tx type:" "$(echo "$TX" | grep -o '"type":"[^"]*"' | head -1 | cut -d'"' -f4) (0x4 = EIP-7702 SetCode)"

assert_eq "$(usdt_balance "$DEPOSIT")" "0" "deposit address swept"
assert_eq "$(usdt_balance "$MINTER")" "$((MINTER_USDT_BEFORE + 250000000))" "minter received 250 USDT"
assert_eq "$(eth_balance "$DEPOSIT")" "0" "deposit address needed 0 ETH throughout"
DELEGATION="0xef0100$(echo "${SWEEPER#0x}" | tr '[:upper:]' '[:lower:]')"
assert_eq "$(cast code "$DEPOSIT" --rpc-url "$RPC")" "$DELEGATION" "deposit address now delegates to CkSweeper"

step "Bonus) Next deposit needs no new authorization: delegation persists"
cast send "$USDT" "transfer(address,uint256)" "$DEPOSIT" 100000000 \
    --private-key "$CEX_PK" --rpc-url "$RPC" >/dev/null
cast send "$DEPOSIT" "sweepErc20(address[])" "[$USDT]" \
    --private-key "$MINTER_PK" --rpc-url "$RPC" >/dev/null
assert_eq "$(usdt_balance "$MINTER")" "$((MINTER_USDT_BEFORE + 350000000))" "second sweep via plain call, no authorization"

printf '\n\033[1mDemo completed successfully.\033[0m\n'
