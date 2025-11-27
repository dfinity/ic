use std::{collections::HashMap, str::FromStr};

use bitcoin::{BlockHash, CompactTarget, Network, Target};

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

/// Average number of seconds in a year (365.25 days) `60 * 60 * 24 * 365.25 = 31,557,600`
pub const SECONDS_IN_ONE_YEAR: i64 = 31_557_600;

/// Bitcoin mainnet checkpoints
#[rustfmt::skip]
const BITCOIN_MAINNET: &[(BlockHeight, &str)] = &[
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
const BITCOIN_TESTNET: &[(BlockHeight, &str)] = &[
    (546, "000000002a936ca763904c3c35fce2f3556c559c0214345d31b1bcebf76acb70")
];

/// Bitcoin testnet checkpoints
#[rustfmt::skip]
const BITCOIN_TESTNET4: &[(BlockHeight, &str)] = &[
    (64000, "000000000deb369dca3115f66e208733066f44c8cc177edd4b5f86869e6355b5")
];

/// Dogecoin mainnet checkpoints
#[rustfmt::skip]
pub(crate) const DOGECOIN_MAINNET: &[(BlockHeight, &str)] = &[
    (0, "1a91e3dace36e2be3bf030a65679fe821aa1d6ef92e7c9902eb318182c355691"),
    (104679, "35eb87ae90d44b98898fec8c39577b76cb1eb08e1261cfc10706c8ce9a1d01cf"),
    (145000, "cc47cae70d7c5c92828d3214a266331dde59087d4a39071fa76ddfff9b7bde72"),
    (371337, "60323982f9c5ff1b5a954eac9dc1269352835f47c2c5222691d80f0d50dcf053"),
    (450000, "d279277f8f846a224d776450aa04da3cf978991a182c6f3075db4c48b173bbd7"),
    (771275, "1b7d789ed82cbdc640952e7e7a54966c6488a32eaad54fc39dff83f310dbaaed"),
    (1000000, "6aae55bea74235f0c80bd066349d4440c31f2d0f27d54265ecd484d8c1d11b47"),
    (1250000, "00c7a442055c1a990e11eea5371ca5c1c02a0677b33cc88ec728c45edc4ec060"),
    (1500000, "f1d32d6920de7b617d51e74bdf4e58adccaa582ffdc8657464454f16a952fca6"),
    (1750000, "5c8e7327984f0d6f59447d89d143e5f6eafc524c82ad95d176c5cec082ae2001"),
    (2000000, "9914f0e82e39bbf21950792e8816620d71b9965bdbbc14e72a95e3ab9618fea8"),
    (2031142, "893297d89afb7599a3c571ca31a3b80e8353f4cf39872400ad0f57d26c4c5d42"),
    (2250000, "0a87a8d4e40dca52763f93812a288741806380cd569537039ee927045c6bc338"),
    (2510150, "77e3f4a4bcb4a2c15e8015525e3d15b466f6c022f6ca82698f329edef7d9777e"),
    (2750000, "d4f8abb835930d3c4f92ca718aaa09bef545076bd872354e0b2b85deefacf2e3"),
    (3000000, "195a83b091fb3ee7ecb56f2e63d01709293f57f971ccf373d93890c8dc1033db"),
    (3250000, "7f3e28bf9e309c4b57a4b70aa64d3b2ea5250ae797af84976ddc420d49684034"),
    (3500000, "eaa303b93c1c64d2b3a2cdcf6ccf21b10cc36626965cc2619661e8e1879abdfb"),
    (3606083, "954c7c66dee51f0a3fb1edb26200b735f5275fe54d9505c76ebd2bcabac36f1e"),
    (3854173, "e4b4ecda4c022406c502a247c0525480268ce7abbbef632796e8ca1646425e75"),
    (3963597, "2b6927cfaa5e82353d45f02be8aadd3bfd165ece5ce24b9bfa4db20432befb5d"),
    (4303965, "ed7d266dcbd8bb8af80f9ccb8deb3e18f9cc3f6972912680feeb37b090f8cee0"),
    (5050000, "e7d4577405223918491477db725a393bcfc349d8ee63b0a4fde23cbfbfd81dea"),
];

/// Dogecoin testnet checkpoints
#[rustfmt::skip]
pub(crate) const DOGECOIN_TESTNET: &[(BlockHeight, &str)] = &[
    (0, "bb0a78264637406b6360aad926284d544d7049f45189db5664f3c4d07350559e"),
    (483173, "a804201ca0aceb7e937ef7a3c613a9b7589245b10cc095148c4ce4965b0b73b5"),
    (591117, "5f6b93b2c28cedf32467d900369b8be6700f0649388a7dbfd3ebd4a01b1ffad8"),
    (658924, "ed6c8324d9a77195ee080f225a0fca6346495e08ded99bcda47a8eea5a8a620b"),
    (703635, "839fa54617adcd582d53030a37455c14a87a806f6615aa8213f13e196230ff7f"),
    (1000000, "1fe4d44ea4d1edb031f52f0d7c635db8190dc871a190654c41d2450086b8ef0e"),
    (1202214, "a2179767a87ee4e95944703976fee63578ec04fa3ac2fc1c9c2c83587d096977"),
    (1250000, "b46affb421872ca8efa30366b09694e2f9bf077f7258213be14adb05a9f41883"),
    (1500000, "0caa041b47b4d18a4f44bdc05cef1a96d5196ce7b2e32ad3e4eb9ba505144917"),
    (1750000, "8042462366d854ad39b8b95ed2ca12e89a526ceee5a90042d55ebb24d5aab7e9"),
    (2000000, "d6acde73e1b42fc17f29dcc76f63946d378ae1bd4eafab44d801a25be784103c"),
    (2250000, "c4342ae6d9a522a02e5607411df1b00e9329563ef844a758d762d601d42c86dc"),
    (2500000, "3a66ec4933fbb348c9b1889aaf2f732fe429fd9a8f74fee6895eae061ac897e2"),
    (2750000, "473ea9f625d59f534ffcc9738ffc58f7b7b1e0e993078614f5484a9505885563"),
    (3062910, "113c41c00934f940a41f99d18b2ad9aefd183a4b7fe80527e1e6c12779bd0246"),
    (3286675, "07fef07a255d510297c9189dc96da5f4e41a8184bc979df8294487f07fee1cf3"),
    (3445426, "70574db7856bd685abe7b0a8a3e79b29882620645bd763b01459176bceb58cd1"),
    (3976284, "af23c3e750bb4f2ce091235f006e7e4e2af453d4c866282e7870471dcfeb4382"),
    (5900000, "199bea6a442310589cbb50a193a30b097c228bd5a0f21af21e4e53dd57c382d3"),
];

/// Returns the maximum difficulty target depending on the network
pub fn max_target(network: &Network) -> Target {
    match network {
        Network::Bitcoin => Target::MAX_ATTAINABLE_MAINNET,
        Network::Testnet => Target::MAX_ATTAINABLE_TESTNET,
        Network::Testnet4 => Target::MAX_ATTAINABLE_TESTNET,
        Network::Regtest => Target::MAX_ATTAINABLE_REGTEST,
        Network::Signet => Target::MAX_ATTAINABLE_SIGNET,
        &other => unreachable!("Unsupported network: {:?}", other),
    }
}

/// Returns false iff PoW difficulty level of blocks can be
/// readjusted in the network after a fixed time interval.
pub fn no_pow_retargeting(network: &Network) -> bool {
    match network {
        Network::Bitcoin | Network::Testnet | Network::Signet | Network::Testnet4 => false,
        Network::Regtest => true,
        &other => unreachable!("Unsupported network: {:?}", other),
    }
}

/// Returns the PoW limit bits of the bitcoin network
pub fn pow_limit_bits(network: &Network) -> CompactTarget {
    CompactTarget::from_consensus(match network {
        Network::Bitcoin => 0x1d00ffff,
        Network::Testnet => 0x1d00ffff,
        Network::Testnet4 => 0x1d00ffff,
        Network::Regtest => 0x207fffff,
        Network::Signet => 0x1e0377ae,
        &other => unreachable!("Unsupported network: {:?}", other),
    })
}

/// Checkpoints used to validate blocks at certain heights.
pub fn checkpoints(network: &Network) -> HashMap<BlockHeight, BlockHash> {
    let points = match network {
        Network::Bitcoin => BITCOIN_MAINNET,
        Network::Testnet => BITCOIN_TESTNET,
        Network::Testnet4 => BITCOIN_TESTNET4,
        Network::Signet => &[],
        Network::Regtest => &[],
        _ => &[],
    };
    points
        .iter()
        .cloned()
        .map(|(height, hash)| {
            //TODO: handle this unwrap without crashing
            let hash = BlockHash::from_str(hash).expect("Programmer error: invalid hash");
            (height, hash)
        })
        .collect()
}

pub fn latest_checkpoint_height(network: &Network, current_height: BlockHeight) -> BlockHeight {
    let points = match network {
        Network::Bitcoin => BITCOIN_MAINNET,
        Network::Testnet => BITCOIN_TESTNET,
        Network::Testnet4 => BITCOIN_TESTNET4,
        Network::Signet => &[],
        Network::Regtest => &[],
        _ => &[],
    };

    points
        .iter()
        .rev()
        .find(|(height, _)| *height <= current_height)
        .map_or(0, |(height, _)| *height)
}

#[cfg(test)]
pub mod test {
    /// Mainnet 000000000000000000063108ecc1f03f7fd1481eb20f97307d532a612bc97f04
    pub const MAINNET_HEADER_586656: &str = "00008020cff0e07ab39db0f31d4ded81ba2339173155b9c57839110000000000000000007a2d75dce5981ec421a54df706d3d407f66dc9170f1e0d6e48ed1e8a1cad7724e9ed365d083a1f17bc43b10a";
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
