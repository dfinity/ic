//! Tests for AuxPoW behavior, adapted from the original Dogecoin C++ test suite.
//!
//! These tests are based on:
//! <https://github.com/dogecoin/dogecoin/blob/51cbc1fd5d0d045dda2ad84f53572bbf524c6a8e/src/test/auxpow_tests.cpp#L358>
//!
//! The goal is to verify correctness of merged mining validation logic, particularly around
//! version number and chain ID rules, and child/parent PoW validation.
use crate::doge::{AuxPowHeaderValidator, ValidateAuxPowHeaderError};
use crate::doge::{DogecoinHeaderValidator, HeaderValidator, ValidateHeaderError};
use crate::tests::doge::utils::{AuxPowBuilder, DOGECOIN_CHAIN_ID, HeaderBuilder};
use crate::tests::utils::{SimpleHeaderStore, build_header_chain};
use bitcoin::block::Header;
use bitcoin::dogecoin::Header as DogecoinHeader;
use bitcoin::dogecoin::constants::genesis_block;

const BASE_VERSION: i32 = 5;

/// Helper to create a header chain before AuxPow activation in regtest
fn create_header_store_before_auxpow_activation_regtest() -> (SimpleHeaderStore, Header) {
    let validator = DogecoinHeaderValidator::regtest();
    let genesis_header = genesis_block(validator.network()).header;
    // Build chain up to height 15 - next block will be at height 16 (before AuxPow activation at height 20)
    let (store, last_header) = build_header_chain(&validator, *genesis_header, 16);
    (store, last_header)
}

/// Helper to create a header chain that extends beyond AuxPow activation in regtest
fn create_header_store_after_auxpow_activation_regtest() -> (SimpleHeaderStore, Header) {
    let validator = DogecoinHeaderValidator::regtest();
    let genesis_header = genesis_block(validator.network()).header;
    // Build chain up to height 25 - next block will be at height 26 (after AuxPow activation at height 20)
    let (store, last_header) = build_header_chain(&validator, *genesis_header, 26);
    (store, last_header)
}

#[test]
fn test_auxpow_version() {
    let validator = DogecoinHeaderValidator::regtest();
    let (store_legacy, prev_header_legacy) = create_header_store_before_auxpow_activation_regtest();
    let (store_auxpow, prev_header_auxpow) = create_header_store_after_auxpow_activation_regtest();

    // Version 1 (legacy) - should pass (before AuxPow activation)
    let dogecoin_header = HeaderBuilder::default()
        .with_prev_header(prev_header_legacy)
        .with_version(1)
        .with_chain_id(0)
        .with_auxpow_bit(false)
        .with_valid_pow(true)
        .build()
        .into();
    assert!(
        validator
            .validate_auxpow_header(&store_legacy, &dogecoin_header)
            .is_ok()
    );

    // Version 3 (with no chain ID) - should fail (before AuxPow activation)
    // This should fail because version 3 is not legacy but doesn't have chain ID
    let dogecoin_header = HeaderBuilder::default()
        .with_prev_header(prev_header_legacy)
        .with_version(3)
        .with_chain_id(0)
        .with_auxpow_bit(false)
        .with_valid_pow(true)
        .build()
        .into();
    assert_eq!(
        validator.validate_auxpow_header(&store_legacy, &dogecoin_header),
        Err(ValidateAuxPowHeaderError::InvalidChainId)
    );

    // Version 2 (with no chain ID) - should pass (before AuxPow activation)
    let dogecoin_header = HeaderBuilder::default()
        .with_prev_header(prev_header_legacy)
        .with_version(2)
        .with_chain_id(0)
        .with_auxpow_bit(false)
        .with_valid_pow(true)
        .build()
        .into();
    assert!(
        validator
            .validate_auxpow_header(&store_legacy, &dogecoin_header)
            .is_ok()
    );

    // Version 2 (with correct chain ID) - should pass (after AuxPow activation)
    let dogecoin_header = HeaderBuilder::default()
        .with_prev_header(prev_header_auxpow)
        .with_version(2)
        .with_chain_id(DOGECOIN_CHAIN_ID)
        .with_auxpow_bit(false)
        .with_valid_pow(true)
        .build()
        .into();
    assert!(
        validator
            .validate_auxpow_header(&store_auxpow, &dogecoin_header)
            .is_ok()
    );

    // AuxPow bit set (with correct chain ID) - should fail (before AuxPow activation)
    let pure_header = HeaderBuilder::default()
        .with_prev_header(prev_header_legacy)
        .with_version(BASE_VERSION)
        .with_chain_id(DOGECOIN_CHAIN_ID)
        .with_auxpow_bit(true)
        .with_valid_pow(false)
        .build();
    let aux_pow = AuxPowBuilder::new(pure_header.block_hash())
        .with_valid_pow(true)
        .build();
    let dogecoin_header = DogecoinHeader {
        pure_header,
        aux_pow: Some(aux_pow),
    };
    assert_eq!(
        validator.validate_auxpow_header(&store_legacy, &dogecoin_header),
        Err(ValidateAuxPowHeaderError::AuxPowBlockNotAllowed)
    );

    // AuxPow bit set (with correct chain ID) - should pass (after AuxPow activation)
    let pure_header = HeaderBuilder::default()
        .with_prev_header(prev_header_auxpow)
        .with_version(BASE_VERSION)
        .with_chain_id(DOGECOIN_CHAIN_ID)
        .with_auxpow_bit(true)
        .with_valid_pow(false)
        .build();
    let aux_pow = AuxPowBuilder::new(pure_header.block_hash())
        .with_valid_pow(true)
        .build();
    let dogecoin_header = DogecoinHeader {
        pure_header,
        aux_pow: Some(aux_pow),
    };
    assert!(
        validator
            .validate_auxpow_header(&store_auxpow, &dogecoin_header)
            .is_ok()
    );

    // AuxPow bit set (with wrong chain ID) - should fail (after AuxPow activation)
    let dogecoin_header = HeaderBuilder::default()
        .with_prev_header(prev_header_auxpow)
        .with_version(BASE_VERSION)
        .with_chain_id(DOGECOIN_CHAIN_ID + 1)
        .with_auxpow_bit(false)
        .with_valid_pow(true)
        .build()
        .into();
    assert_eq!(
        validator.validate_auxpow_header(&store_auxpow, &dogecoin_header),
        Err(ValidateAuxPowHeaderError::InvalidChainId)
    );
}

#[test]
fn test_without_auxpow_data() {
    let validator = DogecoinHeaderValidator::regtest();
    let (legacy_store, prev_header_legacy) = create_header_store_before_auxpow_activation_regtest();

    // AuxPow flag unset and no AuxPow data with correct PoW - should pass
    let dogecoin_header = HeaderBuilder::default()
        .with_prev_header(prev_header_legacy)
        .with_version(BASE_VERSION)
        .with_chain_id(DOGECOIN_CHAIN_ID)
        .with_auxpow_bit(false)
        .with_valid_pow(true)
        .build()
        .into();
    assert!(
        validator
            .validate_auxpow_header(&legacy_store, &dogecoin_header)
            .is_ok()
    );

    // AuxPow flag unset and no AuxPow data but bad PoW - should fail
    let dogecoin_header = HeaderBuilder::default()
        .with_prev_header(prev_header_legacy)
        .with_version(BASE_VERSION)
        .with_chain_id(DOGECOIN_CHAIN_ID)
        .with_auxpow_bit(false)
        .with_valid_pow(false)
        .build()
        .into();
    assert_eq!(
        validator.validate_auxpow_header(&legacy_store, &dogecoin_header),
        Err(ValidateHeaderError::InvalidPoWForComputedTarget.into())
    );

    // AuxPow flag set but no AuxPow data - should fail
    let dogecoin_header = HeaderBuilder::default()
        .with_prev_header(prev_header_legacy)
        .with_version(BASE_VERSION)
        .with_chain_id(DOGECOIN_CHAIN_ID)
        .with_auxpow_bit(true)
        .with_valid_pow(true)
        .build()
        .into();
    assert_eq!(
        validator.validate_auxpow_header(&legacy_store, &dogecoin_header),
        Err(ValidateAuxPowHeaderError::InconsistentAuxPowBitSet)
    );
}

#[test]
fn test_with_auxpow_data() {
    let validator = DogecoinHeaderValidator::regtest();
    let (store_auxpow, prev_header_auxpow) = create_header_store_after_auxpow_activation_regtest();

    // Parent block with valid PoW - should pass
    let pure_header = HeaderBuilder::default()
        .with_prev_header(prev_header_auxpow)
        .with_version(BASE_VERSION)
        .with_chain_id(DOGECOIN_CHAIN_ID)
        .with_auxpow_bit(true)
        .with_valid_pow(false)
        .build();
    let aux_pow = AuxPowBuilder::new(pure_header.block_hash())
        .with_valid_pow(true)
        .build();
    let dogecoin_header = DogecoinHeader {
        pure_header,
        aux_pow: Some(aux_pow),
    };
    assert!(
        validator
            .validate_auxpow_header(&store_auxpow, &dogecoin_header)
            .is_ok()
    );

    // Parent block with invalid PoW - should fail
    let pure_header = HeaderBuilder::default()
        .with_prev_header(prev_header_auxpow)
        .with_version(BASE_VERSION)
        .with_chain_id(DOGECOIN_CHAIN_ID)
        .with_auxpow_bit(true)
        .with_valid_pow(false)
        .build();
    let aux_pow = AuxPowBuilder::new(pure_header.block_hash())
        .with_valid_pow(false)
        .build();
    let dogecoin_header = DogecoinHeader {
        pure_header,
        aux_pow: Some(aux_pow),
    };
    assert_eq!(
        validator.validate_auxpow_header(&store_auxpow, &dogecoin_header),
        Err(ValidateAuxPowHeaderError::InvalidParentPoW)
    );

    // Parent block with invalid PoW and block with valid PoW - should fail
    let pure_header = HeaderBuilder::default()
        .with_prev_header(prev_header_auxpow)
        .with_version(BASE_VERSION)
        .with_chain_id(DOGECOIN_CHAIN_ID)
        .with_auxpow_bit(true)
        .with_valid_pow(true)
        .build();
    let aux_pow = AuxPowBuilder::new(pure_header.block_hash())
        .with_valid_pow(false)
        .build();
    let dogecoin_header = DogecoinHeader {
        pure_header,
        aux_pow: Some(aux_pow),
    };
    assert_eq!(
        validator.validate_auxpow_header(&store_auxpow, &dogecoin_header),
        Err(ValidateAuxPowHeaderError::InvalidParentPoW)
    );

    // AuxPow flag unset but with AuxPow data - should fail
    let pure_header = HeaderBuilder::default()
        .with_prev_header(prev_header_auxpow)
        .with_version(BASE_VERSION)
        .with_chain_id(DOGECOIN_CHAIN_ID)
        .with_auxpow_bit(false)
        .with_valid_pow(false)
        .build();
    let aux_pow = AuxPowBuilder::new(pure_header.block_hash())
        .with_valid_pow(true)
        .build();
    let dogecoin_header = DogecoinHeader {
        pure_header,
        aux_pow: Some(aux_pow),
    };
    assert_eq!(
        validator.validate_auxpow_header(&store_auxpow, &dogecoin_header),
        Err(ValidateAuxPowHeaderError::InconsistentAuxPowBitSet)
    );
}

#[test]
fn test_header_modification_invalidates_auxpow_proof() {
    let validator = DogecoinHeaderValidator::regtest();
    let (store_auxpow, prev_header_auxpow) = create_header_store_after_auxpow_activation_regtest();

    let pure_header = HeaderBuilder::default()
        .with_prev_header(prev_header_auxpow)
        .with_version(BASE_VERSION)
        .with_chain_id(DOGECOIN_CHAIN_ID)
        .with_auxpow_bit(true)
        .with_valid_pow(false)
        .build();
    let aux_pow = AuxPowBuilder::new(pure_header.block_hash())
        .with_valid_pow(true)
        .build();
    let mut dogecoin_header = DogecoinHeader {
        pure_header,
        aux_pow: Some(aux_pow),
    };

    // Should pass initially
    assert!(
        validator
            .validate_auxpow_header(&store_auxpow, &dogecoin_header)
            .is_ok()
    );

    // Modify the block header
    dogecoin_header.pure_header.time += 1;

    // Should fail after modification because AuxPow references old block header
    assert_eq!(
        validator.validate_auxpow_header(&store_auxpow, &dogecoin_header),
        Err(ValidateAuxPowHeaderError::InvalidAuxPoW)
    );
}
