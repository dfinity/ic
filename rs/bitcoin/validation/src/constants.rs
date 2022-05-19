use std::collections::HashMap;

use bitcoin::{hashes::hex::FromHex, util::uint::Uint256, BlockHash, Network};

use crate::BlockHeight;

/// Expected number of blocks for 2 weeks (2_016).
pub const DIFFICULTY_ADJUSTMENT_INTERVAL: BlockHeight = 6 * 24 * 14;

/// Needed to help test check for the 20 minute testnet/regtest rule
pub const TEN_MINUTES: u32 = 60 * 10;

/// Represents approximately the number of blocks that will be created within one year.
///
/// This number is determine by the following formula. A year approximately has 356.25 days. Assuming the
/// Bitcoin network produces a new block every 10 minutes on average, `6 * 24 * 365.25 = 52,596`.
pub const BLOCKS_IN_ONE_YEAR: BlockHeight = 52_596;

/// Bitcoin mainnet checkpoints
#[rustfmt::skip]
const BITCOIN: &[(BlockHeight, &str)] = &[
    (11_111, "0000000069e244f73d78e8fd29ba2fd2ed618bd6fa2ee92559f542fdb26e7c1d",),
    (33_333, "000000002dd5588a74784eaa7ab0507a18ad16a236e7b1ce69f00d7ddfb5d0a6",),
    (74_000, "0000000000573993a3c9e41ce34471c079dcf5f52a0e824a81e7f953b8661a20",),
    (105_000, "00000000000291ce28027faea320c8d2b054b2e0fe44a773f3eefb151d6bdc97",),
    (134_444, "00000000000005b12ffd4cd315cd34ffd4a594f430ac814c91184a0d42d2b0fe",),
    (168_000, "000000000000099e61ea72015e79632f216fe6cb33d7899acb35b75c8303b763",),
    (193_000, "000000000000059f452a5f7340de6682a977387c17010ff6e6c3bd83ca8b1317",),
    (210_000, "000000000000048b95347e83192f69cf0366076336c639f9b7228e9ba171342e",),
    (216_116, "00000000000001b4f4b433e81ee46494af945cf96014816a4e2370f11b23df4e",),
    (225_430, "00000000000001c108384350f74090433e7fcf79a606b8e797f065b130575932",),
    (250_000, "000000000000003887df1f29024b06fc2200b55f8af8f35453d7be294df2d214",),
    (279_000, "0000000000000001ae8c72a0b0c301f67e3afca10e819efa9041e458e9bd7e40",),
    (295_000, "00000000000000004d9b4ef50f0f9d686fd69db2e03af35a100370c64632a983",),
    (393_216, "00000000000000000390df7d2bdc06b9fcb260b39e3fb15b4bc9f62572553924"),
    (421_888, "000000000000000004b232ad9492d0729d7f9d6737399ffcdaac1c8160db5ef6"),
    (438_784, "0000000000000000040d6ef667d7a52caf93d8e0d1e40fd7155c787b42667179"),
    (451_840, "0000000000000000029103c8ade7786e7379623465c72d71d84624eb9c159bea"),
    (469_766, "000000000000000000130b2bd812c6a7ae9c02a74fc111806b1dd11e8975da45"),
    (481_824, "0000000000000000001c8018d9cb3b742ef25114f27563e3fc4a1902167f9893"),
    (514_048, "00000000000000000022fe630be397a62c58972bb81f0a2d1ae8c968511a4659"),
    (553_472, "0000000000000000000e06b6698a4f65ab9915f24b23ca2f9d1abf30cc3e9173"),
    (571_392, "00000000000000000019c18b43077775fc299a6646ab0e9dbbd5770bf6ca392d"),
    (596_000, "0000000000000000000706f93dc673ca366c810f317e7cfe8d951c0107b65223"),
    (601_723, "000000000000000000009837f74796532b21d8ccf7def3dcfcb45aa92cd86b9e"),
    (617_056, "0000000000000000000ca51b293fb2be2fbaf1acc76dcbbbff7e4d7796380b9e"),
    (632_549, "00000000000000000001bae1b2b73ec3fde475c1ed7fdd382c2c49860ec19920"),
    (643_700, "00000000000000000002959e9b44507120453344794df09bd1276eb325ed7110"),
    (667_811, "00000000000000000007888a9d01313d69d6335df46ea33e875ee6832670c596"),
    (688_888, "0000000000000000000e1e3bd783ce0de7b0cdabf2034723595dbcd5a28cf831"),
    (704_256, "0000000000000000000465f5acfcd603337994261a4d67a647cb49866c98b538"),
];

/// Bitcoin testnet checkpoints
#[rustfmt::skip]
const TESTNET: &[(BlockHeight, &str)] = &[
    (546, "000000002a936ca763904c3c35fce2f3556c559c0214345d31b1bcebf76acb70")
];

/// Bitcoin mainnet maximum target value
const BITCOIN_MAX_TARGET: Uint256 = Uint256([
    0x0000000000000000,
    0x0000000000000000,
    0x0000000000000000,
    0x00000000ffff0000,
]);

/// Bitcoin testnet maximum target value
const TESTNET_MAX_TARGET: Uint256 = Uint256([
    0x0000000000000000,
    0x0000000000000000,
    0x0000000000000000,
    0x00000000ffff0000,
]);

/// Bitcoin regtest maximum target value
const REGTEST_MAX_TARGET: Uint256 = Uint256([
    0x0000000000000000,
    0x0000000000000000,
    0x0000000000000000,
    0x7fffff0000000000,
]);

/// Bitcoin signet maximum target value
const SIGNET_MAX_TARGET: Uint256 = Uint256([
    0x0000000000000000u64,
    0x0000000000000000u64,
    0x0000000000000000u64,
    0x00000377ae000000u64,
]);

/// Returns the maximum difficulty target depending on the network
pub fn max_target(network: &Network) -> Uint256 {
    match network {
        Network::Bitcoin => BITCOIN_MAX_TARGET,
        Network::Testnet => TESTNET_MAX_TARGET,
        Network::Regtest => REGTEST_MAX_TARGET,
        Network::Signet => SIGNET_MAX_TARGET,
    }
}

/// Returns false iff PoW difficulty level of blocks can be
/// readjusted in the network after a fixed time interval.
pub fn no_pow_retargeting(network: &Network) -> bool {
    match network {
        Network::Bitcoin | Network::Testnet | Network::Signet => false,
        Network::Regtest => true,
    }
}

/// Returns the PoW limit bits of the bitcoin network
pub fn pow_limit_bits(network: &Network) -> u32 {
    match network {
        Network::Bitcoin => 0x1d00ffff,
        Network::Testnet => 0x1d00ffff,
        Network::Regtest => 0x207fffff,
        Network::Signet => 0x1e0377ae,
    }
}

/// Checkpoints used to validate blocks at certain heights.
pub fn checkpoints(network: &Network) -> HashMap<BlockHeight, BlockHash> {
    let points = match network {
        Network::Bitcoin => BITCOIN,
        Network::Testnet => TESTNET,
        Network::Signet => &[],
        Network::Regtest => &[],
    };
    points
        .iter()
        .cloned()
        .map(|(height, hash)| {
            let hash = BlockHash::from_hex(hash).expect("Programmer error: invalid hash");
            (height, hash)
        })
        .collect()
}

pub fn latest_checkpoint_height(network: &Network, current_height: BlockHeight) -> BlockHeight {
    let points = match network {
        Network::Bitcoin => BITCOIN,
        Network::Testnet => TESTNET,
        Network::Signet => &[],
        Network::Regtest => &[],
    };

    points
        .iter()
        .rev()
        .find(|(height, _)| *height <= current_height)
        .map_or(0, |(height, _)| *height)
}

#[cfg(test)]
pub mod test {

    use super::*;

    /// Mainnet 00000000bcb3c8ff4e3e243ad47832d75bb81e922efdc05be63f2696c5dfad09
    pub const MAINNET_HEADER_11109: &str = "0100000027e37046713f768e57bd9c613f70657048320cab3e016c6ad437dadd00000000a12e0863a26054892799db694b8ccd9f44ad062b4d6ef09d2be12e994d50649b9ca2e649ffff001d2823bacb";
    /// Mainnet 00000000deaa3a36d8531844fd1cb11faff6a1171d5228d42131d1b302c56271
    pub const MAINNET_HEADER_11110: &str = "0100000009addfc596263fe65bc0fd2e921eb85bd73278d43a243e4effc8b3bc0000000006413a83ca2d3fbf6b1ac332976043152e0093f17e29fef68c3eb736d379d7365aa3e649ffff001da44e7f02";
    /// Mainnet 0000000069e244f73d78e8fd29ba2fd2ed618bd6fa2ee92559f542fdb26e7c1d
    pub const MAINNET_HEADER_11111: &str = "010000007162c502b3d13121d428521d17a1f6af1fb11cfd441853d8363aaade000000007adf7b53a9dc840a210766054aa8a1b2076fd30dadcc3f757c23318a8c8be55213a4e649ffff001d05d9428b";

    /// Mainnet 000000000000000000063108ecc1f03f7fd1481eb20f97307d532a612bc97f04
    pub const MAINNET_HEADER_586656: &str ="00008020cff0e07ab39db0f31d4ded81ba2339173155b9c57839110000000000000000007a2d75dce5981ec421a54df706d3d407f66dc9170f1e0d6e48ed1e8a1cad7724e9ed365d083a1f17bc43b10a";
    /// Mainnet 0000000000000000000d37dfef7fe1c7bd22c893dbe4a94272c8cf556e40be99
    pub const MAINNET_HEADER_705600: &str = "0400a0205849eed80b320273a73d39933c0360e127d15036a69d020000000000000000006cc2504814505bb6863d960599c1d1f76a4768090ac15b0ad5172f5a5cd918a155d86d6108040e175daab79e";
    /// Mainnet 0000000000000000000567617f2101a979d04cff2572a081aa5f29e30800ab75
    pub const MAINNET_HEADER_705601: &str = "04e0002099be406e55cfc87242a9e4db93c822bdc7e17fefdf370d000000000000000000eba036bca22654014f363f3019d0f08b3cdf6b2747ab57eff2e6dc1da266bc0392d96d6108040e176c6624cd";
    /// Mainnet 00000000000000000001eea12c0de75000c2546da22f7bf42d805c1d2769b6ef
    pub const MAINNET_HEADER_705602: &str = "0400202075ab0008e3295faa81a07225ff4cd079a901217f616705000000000000000000c027a2615b11b4c75afc9e42d1db135d7124338c1f556f6a14d1257a3bd103a5f4dd6d6108040e1745d26934";

    /// Testnet 00000000000000e23bb091a0046e6c73160db0a71aa052c20b10ff7de7554f97
    pub const TESTNET_HEADER_2132555: &str = "004000200e1ff99438666c67c649def743fb82117537c2017bcc6ad617000000000000007fa40cf82bf224909e3174281a57af2eb3a4a2a961d33f50ec0772c1221c9e61ddfdc061ffff001a64526636";
    /// Testnet 00000000383cd7fff4692410ccd9bd6201790043bb41b93bacb21e9b85620767
    pub const TESTNET_HEADER_2132556: &str = "00000020974f55e77dff100bc252a01aa7b00d16736c6e04a091b03be200000000000000c44f2d69fc200c4a2211885000b6b67512f42c1bec550f3754e103b6c4046e05a202c161ffff001d09ec1bc4";

    #[test]
    fn test_latest_checkpoint_height() {
        let height = latest_checkpoint_height(&Network::Bitcoin, 1_000_000);
        assert_eq!(height, 704_256);

        let height = latest_checkpoint_height(&Network::Bitcoin, 40_000);
        assert_eq!(height, 33_333);

        let height = latest_checkpoint_height(&Network::Testnet, 1_000_000);
        assert_eq!(height, 546);
    }
}
