use candid::Nat;
use ic_ledger_core::tokens::TokensType;
use icrc_ledger_types::icrc::generic_value::ICRC3Value;
use serde_bytes::ByteBuf;
use std::collections::BTreeMap;

pub struct BlockBuilder<Tokens: TokensType, FeeCollector: Into<Vec<u8>>> {
    block_id: u64,
    timestamp: u64,
    fee_collector: Option<FeeCollector>,
    fee_collector_block: Option<u64>,
    fee: Option<Tokens>,
    parent_hash: Option<Vec<u8>>,
}

impl<Tokens: TokensType, FeeCollector: Into<Vec<u8>>> BlockBuilder<Tokens, FeeCollector> {
    /// Create a new BlockBuilder with the specified block ID and timestamp
    pub fn new(block_id: u64, timestamp: u64) -> Self {
        Self {
            block_id,
            timestamp,
            fee_collector: None,
            fee_collector_block: None,
            fee: None,
            parent_hash: None,
        }
    }

    /// Set the fee collector
    pub fn with_fee_collector(mut self, fee_collector: FeeCollector) -> Self {
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

    /// Create a transfer operation
    pub fn transfer(
        self,
        from: impl Into<Vec<u8>>,
        to: impl Into<Vec<u8>>,
        amount: Tokens,
    ) -> TransferBuilder<Tokens, FeeCollector> {
        TransferBuilder {
            builder: self,
            from: from.into(),
            to: to.into(),
            amount,
            spender: None,
        }
    }

    /// Create a mint operation
    pub fn mint(
        self,
        to: impl Into<Vec<u8>>,
        amount: Tokens,
    ) -> MintBuilder<Tokens, FeeCollector> {
        MintBuilder {
            builder: self,
            to: to.into(),
            amount,
        }
    }

    /// Create a burn operation
    pub fn burn(
        self,
        from: impl Into<Vec<u8>>,
        amount: Tokens,
    ) -> BurnBuilder<Tokens, FeeCollector> {
        BurnBuilder {
            builder: self,
            from: from.into(),
            amount,
            spender: None,
        }
    }

    /// Create an approve operation
    pub fn approve(
        self,
        from: impl Into<Vec<u8>>,
        spender: impl Into<Vec<u8>>,
        allowance: Tokens,
    ) -> ApproveBuilder<Tokens, FeeCollector> {
        ApproveBuilder {
            builder: self,
            from: from.into(),
            spender: spender.into(),
            allowance,
            expected_allowance: None,
            expires_at: None,
        }
    }

    /// Build the final ICRC3Value block
    fn build_with_operation(self, op_name: &str, tx_fields: BTreeMap<String, ICRC3Value>) -> ICRC3Value {
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
        if let Some(fee_collector) = self.fee_collector {
            block_map.insert(
                "fee_col".to_string(),
                ICRC3Value::Array(vec![ICRC3Value::Blob(ByteBuf::from(fee_collector))]),
            );
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

        ICRC3Value::Map(block_map)
    }
}

/// Builder for transfer operations
pub struct TransferBuilder<Tokens: TokensType, FeeCollector: Into<Vec<u8>>> {
    builder: BlockBuilder<Tokens, FeeCollector>,
    from: Vec<u8>,
    to: Vec<u8>,
    amount: Tokens,
    spender: Option<Vec<u8>>,
}

impl<Tokens: TokensType, FeeCollector: Into<Vec<u8>>> TransferBuilder<Tokens, FeeCollector> {
    /// Set the spender for the transfer
    pub fn with_spender(mut self, spender: impl Into<Vec<u8>>) -> Self {
        self.spender = Some(spender.into());
        self
    }

    /// Build the transfer block
    pub fn build(self) -> ICRC3Value {
        let mut tx_fields = BTreeMap::new();
        tx_fields.insert(
            "from".to_string(),
            ICRC3Value::Array(vec![ICRC3Value::Blob(ByteBuf::from(self.from))]),
        );
        tx_fields.insert(
            "to".to_string(),
            ICRC3Value::Array(vec![ICRC3Value::Blob(ByteBuf::from(self.to))]),
        );
        tx_fields.insert("amt".to_string(), ICRC3Value::Nat(self.amount.into()));

        if let Some(spender) = self.spender {
            tx_fields.insert(
                "spender".to_string(),
                ICRC3Value::Array(vec![ICRC3Value::Blob(ByteBuf::from(spender))]),
            );
        }

        self.builder.build_with_operation("xfer", tx_fields)
    }
}

/// Builder for mint operations
pub struct MintBuilder<Tokens: TokensType, FeeCollector: Into<Vec<u8>>> {
    builder: BlockBuilder<Tokens, FeeCollector>,
    to: Vec<u8>,
    amount: Tokens,
}

impl<Tokens: TokensType, FeeCollector: Into<Vec<u8>>> MintBuilder<Tokens, FeeCollector> {
    /// Build the mint block
    pub fn build(self) -> ICRC3Value {
        let mut tx_fields = BTreeMap::new();
        tx_fields.insert(
            "to".to_string(),
            ICRC3Value::Array(vec![ICRC3Value::Blob(ByteBuf::from(self.to))]),
        );
        tx_fields.insert("amt".to_string(), ICRC3Value::Nat(self.amount.into()));

        self.builder.build_with_operation("mint", tx_fields)
    }
}

/// Builder for burn operations
pub struct BurnBuilder<Tokens: TokensType, FeeCollector: Into<Vec<u8>>> {
    builder: BlockBuilder<Tokens, FeeCollector>,
    from: Vec<u8>,
    amount: Tokens,
    spender: Option<Vec<u8>>,
}

impl<Tokens: TokensType, FeeCollector: Into<Vec<u8>>> BurnBuilder<Tokens, FeeCollector> {
    /// Set the spender for the burn
    pub fn with_spender(mut self, spender: impl Into<Vec<u8>>) -> Self {
        self.spender = Some(spender.into());
        self
    }

    /// Build the burn block
    pub fn build(self) -> ICRC3Value {
        let mut tx_fields = BTreeMap::new();
        tx_fields.insert(
            "from".to_string(),
            ICRC3Value::Array(vec![ICRC3Value::Blob(ByteBuf::from(self.from))]),
        );
        tx_fields.insert("amt".to_string(), ICRC3Value::Nat(self.amount.into()));

        if let Some(spender) = self.spender {
            tx_fields.insert(
                "spender".to_string(),
                ICRC3Value::Array(vec![ICRC3Value::Blob(ByteBuf::from(spender))]),
            );
        }

        self.builder.build_with_operation("burn", tx_fields)
    }
}

/// Builder for approve operations
pub struct ApproveBuilder<Tokens: TokensType, FeeCollector: Into<Vec<u8>>> {
    builder: BlockBuilder<Tokens, FeeCollector>,
    from: Vec<u8>,
    spender: Vec<u8>,
    allowance: Tokens,
    expected_allowance: Option<Tokens>,
    expires_at: Option<u64>,
}

impl<Tokens: TokensType, FeeCollector: Into<Vec<u8>>> ApproveBuilder<Tokens, FeeCollector> {
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
        tx_fields.insert(
            "from".to_string(),
            ICRC3Value::Array(vec![ICRC3Value::Blob(ByteBuf::from(self.from))]),
        );
        tx_fields.insert(
            "spender".to_string(),
            ICRC3Value::Array(vec![ICRC3Value::Blob(ByteBuf::from(self.spender))]),
        );
        tx_fields.insert("allowance".to_string(), ICRC3Value::Nat(self.allowance.into()));

        if let Some(expected_allowance) = self.expected_allowance {
            tx_fields.insert("expected_allowance".to_string(), ICRC3Value::Nat(expected_allowance.into()));
        }

        if let Some(expires_at) = self.expires_at {
            tx_fields.insert("expires_at".to_string(), ICRC3Value::Nat(Nat::from(expires_at)));
        }

        self.builder.build_with_operation("approve", tx_fields)
    }
}

pub fn transfer_block<F: Into<Vec<u8>>, T: Into<Vec<u8>>>(
    block_id: u64,
    from: F,
    to: T,
    amount: u64,
    timestamp: u64,
) -> ICRC3Value {
    let mut block_map = BTreeMap::new();

    // Add timestamp
    block_map.insert("ts".to_string(), ICRC3Value::Nat(Nat::from(timestamp)));

    // Create transaction
    let mut tx_map = BTreeMap::new();
    tx_map.insert("op".to_string(), ICRC3Value::Text("xfer".to_string()));

    tx_map.insert(
        "from".to_string(),
        ICRC3Value::Array(vec![ICRC3Value::Blob(ByteBuf::from(from))]),
    );
    tx_map.insert(
        "to".to_string(),
        ICRC3Value::Array(vec![ICRC3Value::Blob(ByteBuf::from(to))]),
    );
    tx_map.insert("amt".to_string(), ICRC3Value::Nat(Nat::from(amount)));

    block_map.insert("tx".to_string(), ICRC3Value::Map(tx_map));

    // Add parent hash for blocks after the first
    if block_id > 0 {
        let parent_hash = vec![0u8; 32]; // Simplified parent hash for testing
        block_map.insert(
            "phash".to_string(),
            ICRC3Value::Blob(ByteBuf::from(parent_hash)),
        );
    }

    ICRC3Value::Map(block_map)
}

pub fn mint_block<T: Into<Vec<u8>>, F: Into<Vec<u8>>>(
    block_id: u64,
    to: T,
    amount: u64,
    timestamp: u64,
    fee_collector: Option<F>,
) -> ICRC3Value {
    let mut block_map = BTreeMap::new();

    // Add timestamp
    block_map.insert("ts".to_string(), ICRC3Value::Nat(Nat::from(timestamp)));

    // Create transaction
    let mut tx_map = BTreeMap::new();
    tx_map.insert("op".to_string(), ICRC3Value::Text("mint".to_string()));

    tx_map.insert(
        "to".to_string(),
        ICRC3Value::Array(vec![ICRC3Value::Blob(ByteBuf::from(to))]),
    );
    tx_map.insert("amt".to_string(), ICRC3Value::Nat(Nat::from(amount)));

    block_map.insert("tx".to_string(), ICRC3Value::Map(tx_map));

    if let Some(fee_collector) = fee_collector {
        block_map.insert(
            "fee_col".to_string(),
            ICRC3Value::Array(vec![ICRC3Value::Blob(ByteBuf::from(fee_collector))]),
        );
    }

    // Add parent hash for blocks after the first
    if block_id > 0 {
        let parent_hash = vec![0u8; 32]; // Simplified parent hash for testing
        block_map.insert(
            "phash".to_string(),
            ICRC3Value::Blob(ByteBuf::from(parent_hash)),
        );
    }

    ICRC3Value::Map(block_map)
}

pub fn burn_block<F: Into<Vec<u8>>>(
    block_id: u64,
    from: F,
    amount: u64,
    timestamp: u64,
    fee: Option<u64>,
    fee_col_block: Option<u64>,
) -> ICRC3Value {
    let mut block_map = BTreeMap::new();

    // Add timestamp
    block_map.insert("ts".to_string(), ICRC3Value::Nat(Nat::from(timestamp)));

    // Create transaction
    let mut tx_map = BTreeMap::new();
    tx_map.insert("op".to_string(), ICRC3Value::Text("burn".to_string()));

    tx_map.insert(
        "from".to_string(),
        ICRC3Value::Array(vec![ICRC3Value::Blob(ByteBuf::from(from))]),
    );
    tx_map.insert("amt".to_string(), ICRC3Value::Nat(Nat::from(amount)));

    block_map.insert("tx".to_string(), ICRC3Value::Map(tx_map));

    if let Some(fee) = fee {
        block_map.insert("fee".to_string(), ICRC3Value::Nat(Nat::from(fee)));
    }

    if let Some(fee_col_block) = fee_col_block {
        block_map.insert(
            "fee_col_block".to_string(),
            ICRC3Value::Nat(Nat::from(fee_col_block)),
        );
    }

    // Add parent hash for blocks after the first
    if block_id > 0 {
        let parent_hash = vec![0u8; 32]; // Simplified parent hash for testing
        block_map.insert(
            "phash".to_string(),
            ICRC3Value::Blob(ByteBuf::from(parent_hash)),
        );
    }

    ICRC3Value::Map(block_map)
}

#[cfg(test)]
mod builder_tests {
    use super::*;
    use ic_ledger_core::tokens::Tokens;

    fn tokens(n: u64) -> Tokens {
        Tokens::from(n)
    }

    #[test]
    fn test_transfer_builder() {
        let block = BlockBuilder::<Tokens, Vec<u8>>::new(1, 1609459200)
            .with_fee(tokens(10))
            .transfer(b"sender".to_vec(), b"receiver".to_vec(), tokens(1000))
            .with_spender(b"spender".to_vec())
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
        let block = BlockBuilder::<Tokens, Vec<u8>>::new(0, 1609459200)
            .with_fee_collector(b"fee_collector".to_vec())
            .mint(b"recipient".to_vec(), tokens(5000))
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
        let block = BlockBuilder::<Tokens, Vec<u8>>::new(2, 1609459200)
            .burn(b"burner".to_vec(), tokens(500))
            .with_spender(b"spender".to_vec())
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
        let block = BlockBuilder::<Tokens, Vec<u8>>::new(3, 1609459200)
            .approve(b"owner".to_vec(), b"spender".to_vec(), tokens(2000))
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