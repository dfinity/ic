# Token Faucet

A token faucet service for the Internet Computer (IC) that provides test tokens for development and testing purposes. This faucet supports both ICP and ICRC1 token standards.

## Overview

This project consists of multiple canisters that work together to provide a token faucet service:

- **Test Ledger Canisters**: Simulate real ledger canisters for testing
  - `testicp-ledger`: Test ICP ledger canister
  - `ticrc1-ledger`: Test ICRC1 ledger canister

- **Faucet Backend Canisters**: Handle token distribution requests
  - `testicp-backend`: Faucet for ICP tokens
  - `ticrc1-backend`: Faucet for ICRC1 tokens

## Quick Start

### 1. Start Local IC Replica

```bash
dfx start --background
```

### 2. Deploy Canisters

Choose which token type you want to deploy:

#### For ICP Token Faucet
```bash
just deploy-icp
```

#### For ICRC1 Token Faucet  
```bash
just deploy-icrc1
```

This will deploy:
- Test ledger canisters with the faucet backend set as the minting account.
- Faucet backend canisters connected to their respective ledgers

### 3. Using the Web UI

After deployment, you can use the web interface to request tokens:

Open your browser to `http://nqoci-rqaaa-aaaap-qp53q-cai.localhost:4943/` to access the ICP token faucet interface.

Open your browser to `http://pwwqf-yaaaa-aaaap-qp5wq-cai.localhost:4943/` to access the ICRC1 token faucet interface.

### 4. Command Line Usage (Alternative)

If you prefer using the command line instead of the web UI:

#### For ICRC1 Tokens

```bash
# Replace the principal with the principal you want the tokens to be sent to.
dfx canister call ticrc1-backend transfer_icrc1 '(principal "uqqxf-5h777-77774-qaaaa-cai")'
```

Checking the balance:

```bash
# Replace the principal with the principal you want the tokens to be sent to.
dfx canister call ticrc1-ledger icrc1_balance_of '(record { owner = principal "uqqxf-5h777-77774-qaaaa-cai"})'
```

#### For ICP Tokens

```bash
# Replace the account identifier with the account identifier you want the tokens to be sent to.
dfx canister call testicp-backend transfer_icp '("f0da8debe354b98d21be4fe41f0d5fbe403763f22cc6f6b6850cc390d8b33e77")'
```

Checking the balance:

```bash
# Replace the account identifier with the account identifier you want the tokens to be sent to.
dfx canister call testicp-ledger account_balance_dfx '(record { account = "f0da8debe354b98d21be4fe41f0d5fbe403763f22cc6f6b6850cc390d8b33e77"})'
```
