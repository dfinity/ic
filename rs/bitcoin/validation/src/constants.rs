use bitcoin::{CompactTarget, Network, Target};

use crate::BlockHeight;

/// Expected number of blocks for 2 weeks (2_016).
pub const DIFFICULTY_ADJUSTMENT_INTERVAL: BlockHeight = 6 * 24 * 14;

/// Needed to help test check for the 20 minute testnet/regtest rule
pub const TEN_MINUTES: u32 = 60 * 10;

/// Returns the maximum difficulty target depending on the network
pub fn max_target(network: &Network) -> Target {
    match network {
        Network::Bitcoin => Target::MAX_ATTAINABLE_MAINNET,
        Network::Testnet => Target::MAX_ATTAINABLE_TESTNET,
        Network::Regtest => Target::MAX_ATTAINABLE_REGTEST,
        Network::Signet => Target::MAX_ATTAINABLE_SIGNET,
        _ => unreachable!(),
    }
}

/// Returns false iff PoW difficulty level of blocks can be
/// readjusted in the network after a fixed time interval.
pub fn no_pow_retargeting(network: &Network) -> bool {
    match network {
        Network::Bitcoin | Network::Testnet | Network::Signet => false,
        Network::Regtest => true,
        _ => unreachable!(),
    }
}

/// Returns the PoW limit bits of the bitcoin network
pub fn pow_limit_bits(network: &Network) -> CompactTarget {
    CompactTarget::from_consensus(match network {
        Network::Bitcoin => 0x1d00ffff,
        Network::Testnet => 0x1d00ffff,
        Network::Regtest => 0x207fffff,
        Network::Signet => 0x1e0377ae,
        _ => unreachable!(),
    })
}

#[cfg(test)]
pub mod test {
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
}
