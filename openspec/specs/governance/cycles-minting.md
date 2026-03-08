# Cycles Minting Canister (CMC)

**Crates**: `cycles_minting`, `cycles-minting-canister`

The Cycles Minting Canister (CMC) is responsible for converting ICP tokens into cycles, which are the computational resource unit of the Internet Computer. It maintains the ICP/XDR conversion rate and handles canister creation with cycles.

## Requirements

### Requirement: Canister Identity
The CMC is installed at index 4 on the NNS subnet with canister ID `rkp4c-7iaaa-aaaaa-aaaca-cai`.

#### Scenario: CMC has a fixed canister ID
- **WHEN** the CMC is deployed
- **THEN** it is assigned index 4 on the NNS subnet
- **AND** its canister ID is `rkp4c-7iaaa-aaaaa-aaaca-cai`

### Requirement: ICP/XDR Conversion Rate
The CMC maintains both the current and average ICP/XDR conversion rates.

#### Scenario: Average rate calculation
- **WHEN** the ICP/XDR rate is queried
- **THEN** the average of the past NUM_DAYS_FOR_ICP_XDR_AVERAGE (30) days' start-of-day rates is used
- **AND** the cache holds ICP_XDR_CONVERSION_RATE_CACHE_SIZE (60) days of rates

#### Scenario: Rate certified data
- **WHEN** the conversion rate is updated
- **THEN** certified data is set for both ICP_XDR_CONVERSION_RATE and AVERAGE_ICP_XDR_CONVERSION_RATE labels
- **AND** the data is available via the certified data tree

### Requirement: Conversion Rate Update
The ICP/XDR conversion rate is updated via governance proposals.

#### Scenario: Rate update payload
- **WHEN** an UpdateIcpXdrConversionRatePayload is received
- **THEN** the new rate is stored in the rate cache
- **AND** the average rate is recalculated
- **AND** the certified data is updated

### Requirement: Canister Creation with Cycles
Users can create canisters by sending ICP to the CMC, which converts it to cycles.

#### Scenario: Create canister from ICP
- **WHEN** a user sends ICP to the CMC with a canister-creation memo
- **AND** the equivalent cycles meet CREATE_CANISTER_MIN_CYCLES (100 billion cycles) minimum
- **THEN** a new canister is created on a target subnet
- **AND** the canister receives cycles converted from the ICP

#### Scenario: Create canister rejected with too few cycles
- **WHEN** a create canister request results in fewer cycles than CREATE_CANISTER_MIN_CYCLES
- **THEN** the request is rejected

### Requirement: Cycles Minting Limits
The CMC enforces monthly limits on cycles minting to prevent abuse.

#### Scenario: Default cycles limit
- **WHEN** a non-privileged principal mints cycles
- **THEN** the total cycles minted in the current month must not exceed DEFAULT_CYCLES_LIMIT (150 * 10^15 cycles)

#### Scenario: Subnet Rental cycles limit
- **WHEN** the Subnet Rental Canister mints cycles
- **THEN** the total cycles minted in the current month must not exceed SUBNET_RENTAL_DEFAULT_CYCLES_LIMIT (500 * 10^15 cycles)

### Requirement: Notification Processing
The CMC processes notifications from the ledger about ICP transfers and caches results.

#### Scenario: Notification status tracking
- **WHEN** a ledger notification is received
- **THEN** it transitions through states: Processing -> (NotifiedTopUp | NotifiedCreateCanister | NotifiedMint | NotMeaningfulMemo)
- **AND** at most MAX_NOTIFY_HISTORY (1,000,000) statuses are stored
- **AND** the oldest statuses are purged in batches of MAX_NOTIFY_PURGE (100,000)

#### Scenario: Duplicate notification handling
- **WHEN** a notification for an already-processed block is received
- **THEN** the cached result is returned

#### Scenario: Non-meaningful memo refund
- **WHEN** a transfer is received with a memo that does not match any supported operation
- **THEN** the ICP is refunded to the sender (minus transfer fee)
- **AND** the status is recorded as NotMeaningfulMemo

### Requirement: Canister Top-Up
Existing canisters can be topped up with cycles by sending ICP to the CMC.

#### Scenario: Top up canister with cycles
- **WHEN** ICP is sent to the CMC with a top-up memo containing a canister ID
- **THEN** the ICP is converted to cycles at the current rate
- **AND** the cycles are deposited into the target canister

### Requirement: Exchange Rate Integration
The CMC integrates with an external exchange rate canister for ICP/XDR rate data.

#### Scenario: Exchange rate canister client
- **WHEN** the CMC needs to update the exchange rate
- **THEN** it queries the RealExchangeRateCanisterClient
- **AND** handles UpdateExchangeRateError and UpdateExchangeRateState appropriately

### Requirement: State Versioning
The CMC uses a versioned state migration system for backward-compatible upgrades.

#### Scenario: State version migration
- **WHEN** the CMC is upgraded
- **AND** the stored state version is one less than the expected version
- **THEN** the old state is decoded and migrated to the new format
- **WHEN** the stored version matches the expected version
- **THEN** the state is decoded directly
- **WHEN** the stored version is greater than the expected version (rollback)
- **THEN** the canister panics to prevent data corruption

### Requirement: Maturity Modulation Bounds
The CMC provides maturity modulation parameters used by the governance canister.

#### Scenario: Modulation within bounds
- **WHEN** maturity modulation is computed
- **THEN** it is within MIN_MATURITY_MODULATION_PERMYRIAD and MAX_MATURITY_MODULATION_PERMYRIAD bounds

### Requirement: Memo Length Limit
Transfer memos processed by the CMC have a maximum length.

#### Scenario: Memo length enforced
- **WHEN** a transfer memo exceeds MAX_MEMO_LENGTH (32 bytes)
- **THEN** the memo is not recognized as meaningful
