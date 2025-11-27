use candid::{Nat, Principal};
use ic_ledger_core::tokens::TokensType;
use icrc_ledger_types::icrc::generic_value::{ICRC3Value, Value};
use icrc_ledger_types::icrc1::account::Account;
use serde_bytes::ByteBuf;
use std::collections::BTreeMap;

/// Helper function to convert Account to ICRC3Value array format
fn account_to_icrc3_value(account: &Account) -> ICRC3Value {
    let mut account_array = vec![ICRC3Value::Blob(ByteBuf::from(account.owner.as_slice()))];
    if let Some(subaccount) = account.subaccount {
        account_array.push(ICRC3Value::Blob(ByteBuf::from(subaccount)));
    }
    ICRC3Value::Array(account_array)
}

pub struct BlockBuilder<Tokens: TokensType> {
    block_id: u64,
    timestamp: u64,
    fee_collector: Option<Account>,
    fee_collector_block: Option<u64>,
    fee: Option<Tokens>,
    parent_hash: Option<Vec<u8>>,
    btype: Option<String>,
}

impl<Tokens: TokensType> BlockBuilder<Tokens> {
    /// Create a new BlockBuilder with the specified block ID and timestamp
    pub fn new(block_id: u64, timestamp: u64) -> Self {
        Self {
            block_id,
            timestamp,
            fee_collector: None,
            fee_collector_block: None,
            fee: None,
            parent_hash: None,
            btype: None,
        }
    }

    /// Set the fee collector
    pub fn with_fee_collector(mut self, fee_collector: Account) -> Self {
        self.fee_collector = Some(fee_collector);
        self
    }

    /// Set the fee collector block
    pub fn with_fee_collector_block(mut self, fee_collector_block: u64) -> Self {
        self.fee_collector_block = Some(fee_collector_block);
        self
    }

    /// Set the fee
    pub fn with_fee(mut self, fee: Tokens) -> Self {
        self.fee = Some(fee);
        self
    }

    /// Set a custom parent hash (default is simplified hash for testing)
    pub fn with_parent_hash(mut self, parent_hash: Vec<u8>) -> Self {
        self.parent_hash = Some(parent_hash);
        self
    }

    /// Set the block type
    pub fn with_btype(mut self, btype: String) -> Self {
        self.btype = Some(btype);
        self
    }

    /// Create a transfer operation
    pub fn transfer(self, from: Account, to: Account, amount: Tokens) -> TransferBuilder<Tokens> {
        TransferBuilder {
            builder: self,
            from,
            to,
            amount,
            spender: None,
        }
    }

    /// Create a transfer_from operation
    pub fn transfer_from(
        self,
        from: Account,
        to: Account,
        spender: Account,
        amount: Tokens,
    ) -> TransferBuilder<Tokens> {
        TransferBuilder {
            builder: self,
            from,
            to,
            amount,
            spender: Some(spender),
        }
    }

    /// Create a mint operation
    pub fn mint(self, to: Account, amount: Tokens) -> MintBuilder<Tokens> {
        MintBuilder {
            builder: self,
            to,
            amount,
        }
    }

    /// Create a burn operation
    pub fn burn(self, from: Account, amount: Tokens) -> BurnBuilder<Tokens> {
        BurnBuilder {
            builder: self,
            from,
            amount,
            spender: None,
        }
    }

    /// Create an approve operation
    pub fn approve(
        self,
        from: Account,
        spender: Account,
        allowance: Tokens,
    ) -> ApproveBuilder<Tokens> {
        ApproveBuilder {
            builder: self,
            from,
            spender,
            allowance,
            expected_allowance: None,
            expires_at: None,
        }
    }

    /// Create a fee collector block
    pub fn fee_collector(
        self,
        fee_collector: Option<Account>,
        caller: Option<Principal>,
        ts: Option<u64>,
    ) -> FeeCollectorBuilder<Tokens> {
        FeeCollectorBuilder {
            builder: self,
            fee_collector,
            caller,
            ts,
        }
    }

    /// Build the final ICRC3Value block
    fn build_with_operation(
        self,
        op_name: &str,
        tx_fields: BTreeMap<String, ICRC3Value>,
    ) -> ICRC3Value {
        let mut block_map = BTreeMap::new();

        // Add timestamp
        block_map.insert("ts".to_string(), ICRC3Value::Nat(Nat::from(self.timestamp)));

        // Create transaction
        let mut tx_map = BTreeMap::new();
        tx_map.insert("op".to_string(), ICRC3Value::Text(op_name.to_string()));

        // Add operation-specific fields
        for (key, value) in tx_fields {
            tx_map.insert(key, value);
        }

        block_map.insert("tx".to_string(), ICRC3Value::Map(tx_map));

        // Add fee if specified
        if let Some(fee) = self.fee {
            block_map.insert("fee".to_string(), ICRC3Value::Nat(fee.into()));
        }

        // Add fee collector if specified
        if let Some(fee_collector) = &self.fee_collector {
            block_map.insert("fee_col".to_string(), account_to_icrc3_value(fee_collector));
        }

        // Add fee collector block if specified
        if let Some(fee_collector_block) = self.fee_collector_block {
            block_map.insert(
                "fee_col_block".to_string(),
                ICRC3Value::Nat(Nat::from(fee_collector_block)),
            );
        }

        // Add parent hash for blocks after the first
        if self.block_id > 0 {
            let parent_hash = self.parent_hash.unwrap_or_else(|| vec![0u8; 32]); // Simplified parent hash for testing
            block_map.insert(
                "phash".to_string(),
                ICRC3Value::Blob(ByteBuf::from(parent_hash)),
            );
        }

        // Add fee collector block if specified
        if let Some(btype) = self.btype {
            block_map.insert("btype".to_string(), ICRC3Value::Text(btype));
        }

        ICRC3Value::Map(block_map)
    }
}

/// Builder for transfer operations
pub struct TransferBuilder<Tokens: TokensType> {
    builder: BlockBuilder<Tokens>,
    from: Account,
    to: Account,
    amount: Tokens,
    spender: Option<Account>,
}

impl<Tokens: TokensType> TransferBuilder<Tokens> {
    /// Set the spender for the transfer
    pub fn with_spender(mut self, spender: Account) -> Self {
        self.spender = Some(spender);
        self
    }

    /// Build the transfer block
    pub fn build(self) -> ICRC3Value {
        let mut tx_fields = BTreeMap::new();
        tx_fields.insert("from".to_string(), account_to_icrc3_value(&self.from));
        tx_fields.insert("to".to_string(), account_to_icrc3_value(&self.to));
        tx_fields.insert("amt".to_string(), ICRC3Value::Nat(self.amount.into()));

        if let Some(spender) = &self.spender {
            tx_fields.insert("spender".to_string(), account_to_icrc3_value(spender));
        }

        self.builder.build_with_operation("xfer", tx_fields)
    }
}

/// Builder for mint operations
pub struct MintBuilder<Tokens: TokensType> {
    builder: BlockBuilder<Tokens>,
    to: Account,
    amount: Tokens,
}

impl<Tokens: TokensType> MintBuilder<Tokens> {
    /// Build the mint block
    pub fn build(self) -> ICRC3Value {
        let mut tx_fields = BTreeMap::new();
        tx_fields.insert("to".to_string(), account_to_icrc3_value(&self.to));
        tx_fields.insert("amt".to_string(), ICRC3Value::Nat(self.amount.into()));

        self.builder.build_with_operation("mint", tx_fields)
    }
}

/// Builder for burn operations
pub struct BurnBuilder<Tokens: TokensType> {
    builder: BlockBuilder<Tokens>,
    from: Account,
    amount: Tokens,
    spender: Option<Account>,
}

impl<Tokens: TokensType> BurnBuilder<Tokens> {
    /// Set the spender for the burn
    pub fn with_spender(mut self, spender: Account) -> Self {
        self.spender = Some(spender);
        self
    }

    /// Build the burn block
    pub fn build(self) -> ICRC3Value {
        let mut tx_fields = BTreeMap::new();
        tx_fields.insert("from".to_string(), account_to_icrc3_value(&self.from));
        tx_fields.insert("amt".to_string(), ICRC3Value::Nat(self.amount.into()));

        if let Some(spender) = &self.spender {
            tx_fields.insert("spender".to_string(), account_to_icrc3_value(spender));
        }

        self.builder.build_with_operation("burn", tx_fields)
    }
}

/// Builder for approve operations
pub struct ApproveBuilder<Tokens: TokensType> {
    builder: BlockBuilder<Tokens>,
    from: Account,
    spender: Account,
    allowance: Tokens,
    expected_allowance: Option<Tokens>,
    expires_at: Option<u64>,
}

impl<Tokens: TokensType> ApproveBuilder<Tokens> {
    /// Set the expected allowance
    pub fn with_expected_allowance(mut self, expected_allowance: Tokens) -> Self {
        self.expected_allowance = Some(expected_allowance);
        self
    }

    /// Set the expiration timestamp
    pub fn with_expires_at(mut self, expires_at: u64) -> Self {
        self.expires_at = Some(expires_at);
        self
    }

    /// Build the approve block
    pub fn build(self) -> ICRC3Value {
        let mut tx_fields = BTreeMap::new();
        tx_fields.insert("from".to_string(), account_to_icrc3_value(&self.from));
        tx_fields.insert("spender".to_string(), account_to_icrc3_value(&self.spender));
        tx_fields.insert("amt".to_string(), ICRC3Value::Nat(self.allowance.into()));

        if let Some(expected_allowance) = self.expected_allowance {
            tx_fields.insert(
                "expected_allowance".to_string(),
                ICRC3Value::Nat(expected_allowance.into()),
            );
        }

        if let Some(expires_at) = self.expires_at {
            tx_fields.insert(
                "expires_at".to_string(),
                ICRC3Value::Nat(Nat::from(expires_at)),
            );
        }

        self.builder.build_with_operation("approve", tx_fields)
    }
}

/// Builder for fee collector operations
pub struct FeeCollectorBuilder<Tokens: TokensType> {
    builder: BlockBuilder<Tokens>,
    fee_collector: Option<Account>,
    caller: Option<Principal>,
    ts: Option<u64>,
}

impl<Tokens: TokensType> FeeCollectorBuilder<Tokens> {
    /// Build the fee collector block
    pub fn build(self) -> ICRC3Value {
        let mut tx_fields = BTreeMap::new();
        if let Some(fee_collector) = &self.fee_collector {
            tx_fields.insert(
                "fee_collector".to_string(),
                account_to_icrc3_value(fee_collector),
            );
        }
        if let Some(caller) = &self.caller {
            tx_fields.insert("caller".to_string(), ICRC3Value::from(Value::from(*caller)));
        }
        if let Some(ts) = self.ts {
            tx_fields.insert("ts".to_string(), ICRC3Value::Nat(Nat::from(ts)));
        }
        self.builder
            .build_with_operation("107set_fee_collector", tx_fields)
    }
}

#[cfg(test)]
mod builder_tests {
    use super::*;
    use candid::Principal;
    use ic_ledger_core::tokens::Tokens;
    use ic_types::PrincipalId;

    fn tokens(n: u64) -> Tokens {
        Tokens::from(n)
    }

    fn test_account(n: u64) -> Account {
        Account::from(Principal::from(PrincipalId::new_user_test_id(n)))
    }

    #[test]
    fn test_transfer_builder() {
        let block = BlockBuilder::<Tokens>::new(1, 1609459200)
            .with_fee(tokens(10))
            .transfer(test_account(1), test_account(2), tokens(1000))
            .with_spender(test_account(3))
            .build();

        if let ICRC3Value::Map(block_map) = block {
            assert!(block_map.contains_key("ts"));
            assert!(block_map.contains_key("tx"));
            assert!(block_map.contains_key("fee"));
            assert!(block_map.contains_key("phash")); // block_id > 0
        } else {
            panic!("Expected ICRC3Value::Map");
        }
    }

    #[test]
    fn test_mint_builder() {
        let block = BlockBuilder::<Tokens>::new(0, 1609459200)
            .with_fee_collector(test_account(99))
            .mint(test_account(1), tokens(5000))
            .build();

        if let ICRC3Value::Map(block_map) = block {
            assert!(block_map.contains_key("ts"));
            assert!(block_map.contains_key("tx"));
            assert!(block_map.contains_key("fee_col"));
            assert!(!block_map.contains_key("phash")); // block_id == 0
        } else {
            panic!("Expected ICRC3Value::Map");
        }
    }

    #[test]
    fn test_burn_builder() {
        let block = BlockBuilder::<Tokens>::new(2, 1609459200)
            .burn(test_account(1), tokens(500))
            .with_spender(test_account(3))
            .build();

        if let ICRC3Value::Map(block_map) = block {
            assert!(block_map.contains_key("ts"));
            assert!(block_map.contains_key("tx"));
            assert!(block_map.contains_key("phash"));
        } else {
            panic!("Expected ICRC3Value::Map");
        }
    }

    #[test]
    fn test_approve_builder() {
        let block = BlockBuilder::<Tokens>::new(3, 1609459200)
            .approve(test_account(1), test_account(2), tokens(2000))
            .with_expected_allowance(tokens(1000))
            .with_expires_at(1609459300)
            .build();

        if let ICRC3Value::Map(block_map) = block {
            assert!(block_map.contains_key("ts"));
            assert!(block_map.contains_key("tx"));
            assert!(block_map.contains_key("phash"));
        } else {
            panic!("Expected ICRC3Value::Map");
        }
    }
}
