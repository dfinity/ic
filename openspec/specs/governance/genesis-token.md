# Genesis Token Canister (GTC)

**Crates**: `ic-nns-gtc`, `ic-nns-gtc-accounts`

The Genesis Token Canister manages the claiming, donation, and forwarding of genesis token accounts. These are accounts created at IC genesis for early contributors, each associated with neurons in the governance canister.

## Requirements

### Requirement: Canister Identity
The GTC is installed at index 6 on the NNS subnet with canister ID `renrk-eyaaa-aaaaa-aaada-cai`.

#### Scenario: GTC has a fixed canister ID
- **WHEN** the GTC is deployed
- **THEN** it is assigned index 6 on the NNS subnet

### Requirement: Claim GTC Neurons
Genesis token holders can claim their neurons by proving ownership of their genesis key.

#### Scenario: Successful neuron claim
- **WHEN** a user calls claim_neurons with their public key hex
- **AND** the current time is at least SECONDS_UNTIL_CLAIM_NEURONS_CAN_BE_CALLED (3 days) after genesis
- **AND** the public key validates against the caller's principal
- **AND** the account has not been donated or forwarded
- **THEN** the governance canister's claim_gtc_neurons is called with the caller and neuron IDs
- **AND** the account is marked as claimed
- **AND** the neuron IDs are returned

#### Scenario: Claim fails before allowed time
- **WHEN** claim_neurons is called before 3 days after genesis
- **THEN** the call fails with "claim_neurons cannot be called yet"

#### Scenario: Claim after donation fails
- **WHEN** claim_neurons is called on an account that has been donated
- **THEN** the call fails with "Account has previously donated its funds"

#### Scenario: Claim after forwarding fails
- **WHEN** claim_neurons is called on an account that has been forwarded
- **THEN** the call fails with "Account has previously forwarded its funds"

#### Scenario: Re-claiming returns existing neuron IDs
- **WHEN** claim_neurons is called on an already-claimed account
- **THEN** the existing neuron IDs are returned without calling governance again

### Requirement: Account Donation
Genesis token holders can donate their unclaimed neuron stakes to a custodian neuron.

#### Scenario: Successful donation
- **WHEN** a user calls donate_account with their public key hex
- **AND** the public key validates against the caller
- **AND** the account has not been claimed, donated, or forwarded
- **THEN** the neuron stakes are transferred to the donate_account_recipient_neuron_id
- **AND** the account is marked as donated

#### Scenario: Donation after claiming fails
- **WHEN** donate_account is called on an already-claimed account
- **THEN** the call fails with "Neurons already claimed"

### Requirement: Forward Whitelisted Unclaimed Accounts
After a waiting period, whitelisted unclaimed accounts can be forwarded to a custodian neuron by anyone.

#### Scenario: Forward unclaimed accounts
- **WHEN** forward_whitelisted_unclaimed_accounts is called
- **AND** at least SECONDS_UNTIL_FORWARD_WHITELISTED_UNCLAIMED_ACCOUNTS_CAN_BE_CALLED (188 days) have elapsed since genesis
- **THEN** for each whitelisted account that is not claimed, donated, or forwarded
- **AND** the neuron stakes are transferred to the forward_whitelisted_unclaimed_accounts_recipient_neuron_id
- **AND** the account is marked as forwarded

#### Scenario: Forward fails before allowed time
- **WHEN** forward_whitelisted_unclaimed_accounts is called before 188 days after genesis
- **THEN** the call fails with "forward_all_unclaimed_accounts cannot be called yet"

#### Scenario: Forward continues on individual transfer errors
- **WHEN** a transfer fails for one account during forwarding
- **THEN** the error is logged
- **AND** forwarding continues for remaining accounts

### Requirement: Account State Transfer
Transferring an account's neuron stakes involves calling the governance canister for each neuron.

#### Scenario: Transfer neuron stakes
- **WHEN** an account transfer is initiated
- **AND** the account has not been claimed, donated, forwarded, and a custodian neuron exists
- **THEN** for each neuron ID in the account, transfer_gtc_neuron is called on governance
- **AND** transferred neurons are recorded with timestamps and any error messages
- **AND** the neuron ID is removed from the account's list

### Requirement: Public Key Validation
The GTC validates that the caller's principal matches the provided public key.

#### Scenario: Public key decoded and validated
- **WHEN** a public key hex is provided
- **THEN** it is decoded from hex format
- **AND** the derived address matches the caller's GTC address
- **AND** the principal derived from the key matches the caller

### Requirement: Account Lookup
GTC accounts can be looked up by their address.

#### Scenario: Account found
- **WHEN** get_account is called with a valid address
- **THEN** the account state is returned

#### Scenario: Account not found
- **WHEN** get_account is called with an unknown address
- **THEN** an error "Account not found" is returned
