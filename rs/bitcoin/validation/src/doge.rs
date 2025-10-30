use crate::BlockHeight;
use crate::constants::SECONDS_IN_ONE_YEAR;
pub(crate) use crate::header::{
    AuxPowHeaderValidator, HeaderStore, HeaderValidator, ValidateAuxPowHeaderError,
    ValidateHeaderError, is_timestamp_valid,
};
use bitcoin::dogecoin::Network as DogecoinNetwork;
use bitcoin::{
    BlockHash, CompactTarget, Target, block::Header as PureHeader,
    dogecoin::Header as DogecoinHeader,
};
use std::str::FromStr;
use std::time::Duration;

/// Height after which the allow_min_difficulty_blocks parameter becomes active for Digishield blocks.
/// Ref: <https://github.com/dogecoin/dogecoin/blob/51cbc1fd5d0d045dda2ad84f53572bbf524c6a8e/src/dogecoin.cpp#L33>
pub(crate) const ALLOW_DIGISHIELD_MIN_DIFFICULTY_HEIGHT: u32 = 157_500;

pub struct DogecoinHeaderValidator {
    network: DogecoinNetwork,
}

impl DogecoinHeaderValidator {
    pub fn new(network: DogecoinNetwork) -> Self {
        Self { network }
    }

    pub fn mainnet() -> Self {
        Self::new(DogecoinNetwork::Dogecoin)
    }

    pub fn testnet() -> Self {
        Self::new(DogecoinNetwork::Testnet)
    }

    pub fn regtest() -> Self {
        Self::new(DogecoinNetwork::Regtest)
    }

    /// Context-dependent header validity checks
    /// Ref: <https://github.com/dogecoin/dogecoin/blob/215fc33d08ef55cdb52a639bb2d8ce0af502c126/src/validation.cpp#L3065>
    fn contextual_check_header(
        &self,
        store: &impl HeaderStore,
        header: &PureHeader,
    ) -> Result<(Target, BlockHeight), ValidateHeaderError> {
        let chain_height = store.get_height();
        let (prev_header, prev_height) = match store.get_header(&header.prev_blockhash) {
            Some(result) => result,
            None => {
                return Err(ValidateHeaderError::PrevHeaderNotFound);
            }
        };

        if !self.is_header_within_one_year_of_tip(prev_height, chain_height) {
            return Err(ValidateHeaderError::HeightTooLow);
        }

        if !is_timestamp_valid(store, header) {
            return Err(ValidateHeaderError::HeaderIsOld);
        }

        if !self.is_checkpoint_valid(prev_height, header, chain_height) {
            return Err(ValidateHeaderError::DoesNotMatchCheckpoint);
        }

        let header_target = header.target();
        if header_target > self.max_target() {
            return Err(ValidateHeaderError::TargetDifficultyAboveMax);
        }

        let target = self.get_next_target(store, &prev_header, prev_height, header.time);

        let header_target = header.target();
        if target != header_target {
            println!("bad target");
            return Err(ValidateHeaderError::InvalidPoWForComputedTarget);
        }

        Ok((target, prev_height + 1))
    }
}

impl HeaderValidator for DogecoinHeaderValidator {
    type Network = DogecoinNetwork;

    fn network(&self) -> &Self::Network {
        &self.network
    }

    fn max_target(&self) -> Target {
        self.network().params().max_attainable_target
    }

    fn no_pow_retargeting(&self) -> bool {
        self.network().params().no_pow_retargeting
    }

    fn pow_limit_bits(&self) -> CompactTarget {
        self.network()
            .params()
            .max_attainable_target
            .to_compact_lossy()
    }

    fn pow_target_spacing(&self) -> Duration {
        Duration::from_secs(self.network().params().pow_target_spacing as u64)
    }

    fn difficulty_adjustment_interval(&self, height: u32) -> u32 {
        (self.network().params().pow_target_timespan(height)
            / self.network().params().pow_target_spacing) as u32
    }

    fn allow_min_difficulty_blocks(&self, height: u32) -> bool {
        self.network().params().allow_min_difficulty_blocks(height)
    }

    fn checkpoints(&self) -> &[(BlockHeight, &str)] {
        match self.network() {
            Self::Network::Dogecoin => crate::constants::DOGECOIN_MAINNET,
            Self::Network::Testnet => crate::constants::DOGECOIN_TESTNET,
            Self::Network::Regtest => &[],
            _ => &[],
        }
    }

    fn is_checkpoint_valid(
        &self,
        prev_height: BlockHeight,
        header: &PureHeader,
        chain_height: BlockHeight,
    ) -> bool {
        let checkpoints = self.checkpoints();
        if prev_height == u32::MAX {
            return false;
        }
        let next_height = prev_height + 1;

        if let Some((_, expected_hash_str)) =
            self.checkpoints().iter().find(|(h, _)| *h == next_height)
        {
            let expected_hash = BlockHash::from_str(expected_hash_str)
                .expect("Programmer error: invalid hash in checkpoints");
            return expected_hash == header.block_hash();
        }

        let latest_checkpoint_height = checkpoints
            .iter()
            .rev()
            .find(|(height, _)| *height <= chain_height)
            .map_or(0, |(height, _)| *height);

        next_height > latest_checkpoint_height
    }

    fn validate_header(
        &self,
        store: &impl HeaderStore,
        header: &PureHeader,
    ) -> Result<(), ValidateHeaderError> {
        let (target, _) = self.contextual_check_header(store, header)?;

        if let Err(err) = header.validate_pow_with_scrypt(target) {
            match err {
                bitcoin::block::ValidationError::BadProofOfWork => println!("bad proof of work"),
                bitcoin::block::ValidationError::BadTarget => println!("bad target"),
                _ => {}
            };
            return Err(ValidateHeaderError::InvalidPoWForComputedTarget);
        }

        Ok(())
    }

    fn get_next_target(
        &self,
        store: &impl HeaderStore,
        prev_header: &PureHeader,
        prev_height: BlockHeight,
        timestamp: u32,
    ) -> Target {
        // Dogecoin core ref: <https://github.com/dogecoin/dogecoin/blob/1be681a1b97b686f838af90682a57f2030d26015/src/pow.cpp#L32>
        let height = prev_height + 1;

        if height >= ALLOW_DIGISHIELD_MIN_DIFFICULTY_HEIGHT
            && self.allow_min_difficulty_blocks(height)
            && timestamp > prev_header.time + (self.pow_target_spacing() * 2).as_secs() as u32
        {
            // If no block has been found in `pow_target_spacing * 2` minutes, then use
            // the maximum difficulty target
            return self.max_target();
        }

        if !height.is_multiple_of(self.difficulty_adjustment_interval(height)) {
            if self.allow_min_difficulty_blocks(height) {
                if timestamp > prev_header.time + (self.pow_target_spacing() * 2).as_secs() as u32 {
                    // If no block has been found in `pow_target_spacing * 2` minutes, then use
                    // the maximum difficulty target
                    return self.max_target();
                } else {
                    // If the block has been found within `pow_target_spacing * 2` minutes, then
                    // use the previous difficulty target that is not equal to the maximum
                    // difficulty target
                    return Target::from_compact(self.find_next_difficulty_in_chain(
                        store,
                        prev_header,
                        prev_height,
                    ));
                };
            }
            return Target::from_compact(prev_header.bits);
        };

        Target::from_compact(self.compute_next_difficulty(store, prev_header, prev_height))
    }

    fn find_next_difficulty_in_chain(
        &self,
        store: &impl HeaderStore,
        prev_header: &PureHeader,
        prev_height: BlockHeight,
    ) -> CompactTarget {
        // This is the maximum difficulty target for the network
        let pow_limit_bits = self.pow_limit_bits();
        match self.network() {
            DogecoinNetwork::Testnet | DogecoinNetwork::Regtest => {
                let mut current_header = *prev_header;
                let mut current_height = prev_height;
                let mut current_hash = current_header.block_hash();
                let initial_header_hash = store.get_initial_hash();

                // Keep traversing the blockchain backwards from the recent block to initial
                // header hash.
                loop {
                    // Check if non-limit PoW found or it's time to adjust difficulty.
                    if current_header.bits != pow_limit_bits
                        || current_height
                            .is_multiple_of(self.difficulty_adjustment_interval(prev_height + 1))
                    {
                        return current_header.bits;
                    }

                    // Stop if we reach the initial header.
                    if current_hash == initial_header_hash {
                        break;
                    }

                    // Traverse to the previous header.
                    let prev_blockhash = current_header.prev_blockhash;
                    (current_header, _) = store
                        .get_header(&prev_blockhash)
                        .expect("previous header should be in the header store");
                    // Update the current height and hash.
                    current_height -= 1;
                    current_hash = prev_blockhash;
                }
                pow_limit_bits
            }
            DogecoinNetwork::Dogecoin => pow_limit_bits,
            &other => unreachable!("Unsupported network: {:?}", other),
        }
    }

    fn compute_next_difficulty(
        &self,
        store: &impl HeaderStore,
        prev_header: &PureHeader,
        prev_height: BlockHeight,
    ) -> CompactTarget {
        // Pre-Digishield: difficulty is adjusted every 240 blocks.
        // If an interval boundary is not reached, then previous difficulty target is
        // returned. Regtest network doesn't adjust PoW difficulty levels. For
        // regtest, simply return the previous difficulty target.
        // Digishield: difficulty is adjusted every block.

        let height = prev_height + 1;
        let difficulty_adjustment_interval = self.difficulty_adjustment_interval(height);

        // Computing the `last_adjustment_header`.
        // `last_adjustment_header` is the header before the previous difficulty adjustment point.
        // Dogecoin solves the "off-by-one" or Time Wrap bug in Bitcoin by going back to the full
        // retarget period.
        // See: <https://litecoin.info/docs/history/time-warp-attack>
        let mut current_header = *prev_header;
        for _ in 0..difficulty_adjustment_interval {
            if let Some((header, _)) = store.get_header(&current_header.prev_blockhash) {
                current_header = header;
            }
        }
        let last_adjustment_header = current_header;

        // Computing the timespan between the last adjustment header time and
        // current time. Our goal is to readjust the difficulty target so that the
        // timespan taken for the next interval is equal to the `pow_target_timespan`
        // of the network.
        //
        // IMPORTANT: With the Median Time Past (MTP) rule, a block's timestamp
        // is only required to be greater than the median of the previous 11 blocks.
        // This allows individual block timestamps to decrease relative to their
        // predecessor, which can result in a negative timespan.
        let last_adjustment_time = last_adjustment_header.time;
        let timespan = (prev_header.time as i64) - (last_adjustment_time as i64);

        CompactTarget::from_next_work_required_dogecoin(
            prev_header.bits,
            timespan,
            self.network,
            height,
        )
    }

    fn is_header_within_one_year_of_tip(
        &self,
        prev_height: BlockHeight,
        chain_height: BlockHeight,
    ) -> bool {
        let header_height = prev_height
            .checked_add(1)
            .expect("next height causes an overflow");

        let height_one_year_ago = chain_height.saturating_sub(
            (SECONDS_IN_ONE_YEAR / self.network().params().pow_target_spacing) as u32,
        );
        header_height >= height_one_year_ago
    }
}

impl AuxPowHeaderValidator for DogecoinHeaderValidator {
    fn strict_chain_id(&self) -> bool {
        self.network().params().strict_chain_id
    }

    fn auxpow_chain_id(&self) -> i32 {
        self.network().params().auxpow_chain_id
    }

    fn allow_legacy_blocks(&self, height: u32) -> bool {
        self.network.params().allow_legacy_blocks(height)
    }

    fn contextual_check_header_auxpow(
        &self,
        header: &PureHeader,
        height: BlockHeight,
    ) -> Result<(), ValidateAuxPowHeaderError> {
        if !self.allow_legacy_blocks(height) && header.is_legacy() {
            return Err(ValidateAuxPowHeaderError::LegacyBlockNotAllowed);
        }

        if self.allow_legacy_blocks(height) && header.has_auxpow_bit() {
            return Err(ValidateAuxPowHeaderError::AuxPowBlockNotAllowed);
        }

        if (header.extract_base_version() < 3 && height >= self.network().params().bip66_height)
            || (header.extract_base_version() < 4 && height >= self.network().params().bip65_height)
        {
            return Err(ValidateAuxPowHeaderError::VersionObsolete);
        }

        Ok(())
    }

    /// AuxPow header validation
    /// Ref: <https://github.com/dogecoin/dogecoin/blob/51cbc1fd5d0d045dda2ad84f53572bbf524c6a8e/src/dogecoin.cpp#L89>
    fn validate_auxpow_header(
        &self,
        store: &impl HeaderStore,
        header: &DogecoinHeader,
    ) -> Result<(), ValidateAuxPowHeaderError> {
        if !header.is_legacy()
            && self.strict_chain_id()
            && header.extract_chain_id() != self.auxpow_chain_id()
        {
            return Err(ValidateAuxPowHeaderError::InvalidChainId);
        }

        if let Some(aux_pow) = header.aux_pow.as_ref() {
            if !header.has_auxpow_bit() {
                return Err(ValidateAuxPowHeaderError::InconsistentAuxPowBitSet);
            }

            let (target, height) = self.contextual_check_header(store, &header.pure_header)?;

            self.contextual_check_header_auxpow(&header.pure_header, height)?;

            if !target.is_met_by(aux_pow.parent_block_header.block_hash_with_scrypt()) {
                return Err(ValidateAuxPowHeaderError::InvalidParentPoW);
            }
            if aux_pow
                .check(
                    header.block_hash(),
                    header.extract_chain_id(),
                    self.strict_chain_id(),
                )
                .is_err()
            {
                return Err(ValidateAuxPowHeaderError::InvalidAuxPoW);
            }
        } else {
            if header.has_auxpow_bit() {
                return Err(ValidateAuxPowHeaderError::InconsistentAuxPowBitSet);
            }

            self.validate_header(store, &header.pure_header)?;
        }

        Ok(())
    }
}
