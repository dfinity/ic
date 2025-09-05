mod auxpow;
mod utils;

use crate::doge::ALLOW_DIGISHIELD_MIN_DIFFICULTY_HEIGHT;
use crate::doge::{DogecoinHeaderValidator, HeaderValidator};
use crate::tests::utils::dogecoin_genesis_header;
use crate::tests::{
    verify_backdated_block_difficulty, verify_consecutive_headers,
    verify_consecutive_headers_auxpow, verify_regtest_difficulty_calculation,
    verify_timestamp_rules, verify_with_excessive_target, verify_with_invalid_pow,
    verify_with_invalid_pow_with_computed_target, verify_with_missing_parent,
};
use bitcoin::dogecoin::Network as DogecoinNetwork;
use bitcoin::{CompactTarget, Target};

/// Mainnet 0c120ab190655673a709bc92ad86f80dc1cd9f11f9e0f09ebc5e6a3058b73002
const MAINNET_HEADER_DOGE_17: &str = "01000000fbc172c83b7e535390cfd7807118a7fc799cdbda9da0cbd390f4b70c0f62c2fb155fa2e0ad11cfd91cd0f47049c0fcf5dfabd2fe1a3a406c0350e89f14618bb1f4eda352f0ff0f1e00067505";
/// Mainnet da0e2362cc1d1cd48c8eb70e578c97f00d9a530985ba36027eb7e3fba98c74ae
const MAINNET_HEADER_DOGE_18: &str = "010000000230b758306a5ebc9ef0e0f9119fcdc10df886ad92bc09a773566590b10a120ca96ac7b3a8ef18a68f1044aef152724403bb6bb6e2e44bdb26395a6f00ec858df6eda352f0ff0f1e0002c935";
/// Mainnet 3b595392744d34544c300a886577f0bd839aeb788e3e8e19138e6092eb5c2ad6
const MAINNET_HEADER_DOGE_151556: &str = "02000000c145aa6d9acdbeb6d3196e1dd4a21fd976cbbaf10d520f1e67f933ebc669b7f0748f9b1f40c1a60740c8f47d506c6de6b9f415d00c8a9c4484ef36abe593a39fe4e72d5301cf241b00220241";
/// Mainnet d3b4205b9cab0c969d0e96ff924ab4e3acd8779c2ce1669b94c98d6f2f0365f4
const MAINNET_HEADER_DOGE_151557: &str = "02000000d62a5ceb92608e13198e3e8e78eb9a83bdf07765880a304c54344d749253593b9debfe3e9ead5f19238f3ec5bb321de36acf69f0680d0231c4612961fd2e0fa91ae82d53b4652d1b00adb73b";
/// Mainnet 82553d56341549dd67e3acc0ad77d22e92f043f51a8a2f014dc5b3aac7e32a0d
const MAINNET_HEADER_DOGE_151558: &str = "02000000f465032f6f8dc9949b66e12c9c77d8ace3b44a92ff960e9d960cab9c5b20b4d3f58c2f6492ca38883a4e2335bd67e117a2a86f14907f2c3bb7d3181fb4ccffb243e82d53b4652d1b0006be14";
/// Mainnet 4378cee85115fe9014b53a0b1d0a58b6c5677b26d8efddddcd590d129694e7a7 (Contains AuxPow)
const MAINNET_HEADER_DOGE_400000: &str = "02016200b047cc94ef6886e3e2e79226703a58841619d8fab0de523c1664517310c12818704bc78ff28bf8f7fb20a9901e2ace59db1ab634fbd41a4a74e064a29e6dd315965c2d548a20071b0000000001000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4f03e1ef09fabe6d6d4378cee85115fe9014b53a0b1d0a58b6c5677b26d8efddddcd590d129694e7a70100000000000000062f503253482f04785c2d54080800200402000000092f7374726174756d2f000000000100f2052a010000001976a914f332ec6f1729495e7edcd8ce9d887742567fe60988ac00000000ed94aa029449a3fa7684d707d04fcd11d6e0d42c2db0d1b5392a135b0b0987060000000000000000000002000000e6816ca65e5c4ae73186cea2ee263cb69e86f311fcbe07d41908f3b170bb33804bf55dc3db4f3228ca5122eef35ea1c7bdd521bc80aa496033103e8d983fccec9d5c2d5431cf011b0cd75567";
/// Mainnet 70587d814ddc1c813a00df96854c5fb8f95e357a92f97fb616ad5d1301e48769 (Contains AuxPow)
const MAINNET_HEADER_DOGE_400001: &str = "02016200a7e79496120d59cdddddefd8267b67c5b6580a1d0b3ab51490fe1551e8ce78435d0e49e5c8a6d81f296ff057e959c81fb5f89b4bb3f7a800ae0eae6915f19e0e785c2d54c47b071b0000000001000000010000000000000000000000000000000000000000000000000000000000000000ffffffff5803e1ef09062f503253482f04795c2d5408fabe6d6d70587d814ddc1c813a00df96854c5fb8f95e357a92f97fb616ad5d1301e487690100000000000000700701ab17000000122f434d73666972653231353839373830342f000000000100f2052a010000001976a91411fde3131d4a59d9de9d6d9390f8baeebf50396088ac000000003301a7df3f1be4c495becbf61203d925e8b10225d753975ed3bb5b1843b13f170000000000000000000002000000e6816ca65e5c4ae73186cea2ee263cb69e86f311fcbe07d41908f3b170bb3380c4df46c9f92ee0c12ab954ed4dadb47b018d2aaf91a360d821b5fd8bd6f6e10d6a5c2d5431cf011b8f021906";
/// Mainnet a5021d69a83f39aef10f3f24f932068d6ff322c654d20562def3fac5703ce3aa (Contains AuxPow)
const MAINNET_HEADER_DOGE_400002: &str = "020162006987e401135dad16b67ff9927a355ef9b85f4c8596df003a811cdc4d817d5870f3a110dab57e109c3af2e4a527f6fe6e05dde4e2c4f2d099af22a41cc6868fc7d85c2d548a1c061b0000000001000000010000000000000000000000000000000000000000000000000000000000000000ffffffff5003e1ef09fabe6d6d0b1f5ecfb132faabac9804974dc560e0697163c5089b47beea817cb2495c51254000000000000000d0e38502000004003acc03004d696e65642062792073666d696e65722e636f6dffffffff01800c0c2a010000001976a914fc5e3afa7a0fa01df5a6dc8e28576309075d45d888ac00000000910cc6e411fe82307ae2d6613359ea76cd06f3129103e8830b4e04000000000003502af177348c5424a4271a0d75533cd2a6a62725c96ba81b524264a2cc8135588998f5045fd590d6f39cf301e86e2291878001e3d32fd0128d992146942d154a9349d3bab05ec1f3e494c6f2bed35eb18e809e008fe7dd9b0c659a7482332b83000000000649a466c7a55fac7adae0fa7fbdac228919af6a2a0968ac4d5fd77417444031ee6c4127661ba7d68c453b449868e6135a6ac0d9351a3e40d7dd58767531de67ee31284c19194806e9c00943e05a9d1a79e17fa0c9b79bef9027ad2ca0bdf99eabfe2d8f99be8b35640357d1af6ec9884840d0a9d91dbac1a8334df680016151ffc584b8039a3eff688f0839d232def7c24dd3b9ed8eb8fc4b3cf6e201ea28f3321bd90e6de9c74dcb2186558963cf9463ba7500f8bed05fc1ad197ea4fa218a0a3800000002000000e6816ca65e5c4ae73186cea2ee263cb69e86f311fcbe07d41908f3b170bb3380a106ab427e1cff3aadbd4b492d84c5a7713e5c56532638725bd13b98973abd56d85c2d5431cf011ba8253717";

/// Testnet 7214c118466d8e2d63e7c50ede083816fbf4e0d75e3e8ec7c3ce1312ae7e77ab
const TESTNET_HEADER_DOGE_88: &str = "0200000052208696e97fb9cc8088399db53791fe668a401f549eb949d5cd16dec5190809bc987206bfe6ee60efab462316a5d127b8697cc3f75cf859c96b480819e46e0f880afb52f0ff0f1e00141ed2";
/// Testnet 4fc5fc1a5e5db47ab33f3626c4456c0cbcf69dc4db6cd64ef5917d703db45a27
const TESTNET_HEADER_DOGE_89: &str = "02000000ab777eae1213cec3c78e3e5ed7e0f4fb163808de0ec5e7632d8e6d4618c114729053d47099f1b595cc742f80a1164520eff7284cd0be18d9bbc5d265f04766e9970afb52f0ff0f1e00021648";
/// Testnet 5ed64a826fa09f20aaf6fcd20bc17ab2c4053d1c10a30a13e54cb5aca786b15e
const TESTNET_HEADER_DOGE_158378: &str = "020062001d79428d80cda680f8e52e886a3746fd6c8295abce89787035eabd31d5acc88391f163f370d83ca96b39d551a93b2c1cfee103a54a49da26b7de388e94ad099ca598e053e1eb061e000a85b3";
/// Testnet ab0d367b677f3e0569563c3ae86c3b2f91c45f79ba1c6654b1d894cac35cacb7
const TESTNET_HEADER_DOGE_158379: &str = "020062005eb186a7acb54ce5130aa3101c3d05c4b27ac10bd2fcf6aa209fa06f824ad65e5e6448eee4d53b1750840c2aea3160cb91344fdb108ed732c89247dcb104b781b098e053c075061e00371be8";
/// Testnet 1561d36f48fbc6799d803b94768e317c25b5aec6150c61ef7276f317af9ecf47 (Contains AuxPow)
const TESTNET_HEADER_DOGE_158380: &str = "02016200b7ac5cc3ca94d8b154661cba795fc4912f3b6ce83a3c5669053e7f677b360dab5433333435a7c5f5b0f02601d8108970360bc806ce28a50747a68090785c5dd5f698e05360d0051e0000000002000000010000000000000000000000000000000000000000000000000000000000000000ffffffff3d037827022cfabe6d6db4106f06d051743d737eb7a6dbefdc008940c62d3f5d6453551dd20d8e7fb6f0040000000000000001000000000000000000000000000000012e016af1b20000001976a9149628aabe802c3f6f67946f70c300321d7110bc4388ac00000000f0550a4183f7eabaaeaff72d876115573148c79b4972d34085c2b4de07a2608600000000000257a668057a41b9aa2c6d44c32e9141ac291a2587fbc9384eca0ebc743b696f235c6a0f13f6429bd555d08e4b17007468fd10d52250a0de605c927d745197ba3900000000020000007042a116c81e3cfb6a5681cde48703a895a3a6fba717317090111400aeccfb968b756e0cf7c1f5b638a1b2b804d7d022ee39fab0fef4e2e67f4e303a189990472499e053caee011c000eb60a";

#[test]
fn test_basic_header_validation_mainnet() {
    verify_consecutive_headers(
        &DogecoinHeaderValidator::mainnet(),
        MAINNET_HEADER_DOGE_17,
        17,
        MAINNET_HEADER_DOGE_18,
    );
}

#[test]
fn test_basic_header_validation_testnet() {
    verify_consecutive_headers(
        &DogecoinHeaderValidator::testnet(),
        TESTNET_HEADER_DOGE_88,
        88,
        TESTNET_HEADER_DOGE_89,
    );
}

#[test]
fn test_basic_header_validation_auxpow_mainnet() {
    verify_consecutive_headers_auxpow(
        DogecoinHeaderValidator::mainnet(),
        MAINNET_HEADER_DOGE_400000,
        400_000,
        MAINNET_HEADER_DOGE_400001,
        MAINNET_HEADER_DOGE_400002,
    );
}

#[test]
fn test_basic_header_validation_auxpow_testnet() {
    verify_consecutive_headers_auxpow(
        DogecoinHeaderValidator::testnet(),
        TESTNET_HEADER_DOGE_158378,
        158_378,
        TESTNET_HEADER_DOGE_158379,
        TESTNET_HEADER_DOGE_158380,
    );
}

#[test]
fn test_missing_previous_header() {
    verify_with_missing_parent(
        &DogecoinHeaderValidator::mainnet(),
        MAINNET_HEADER_DOGE_151556,
        151_556,
        MAINNET_HEADER_DOGE_151558,
    );
}

#[test]
fn test_invalid_pow_mainnet() {
    verify_with_invalid_pow(
        &DogecoinHeaderValidator::mainnet(),
        MAINNET_HEADER_DOGE_17,
        17,
        MAINNET_HEADER_DOGE_18,
    );
}

#[test]
fn test_invalid_pow_with_computed_target_regtest() {
    let dogecoin_genesis_header = dogecoin_genesis_header(
        &DogecoinNetwork::Dogecoin,
        CompactTarget::from_consensus(0x000ffff0), // Put a low target
    );
    verify_with_invalid_pow_with_computed_target(
        &DogecoinHeaderValidator::regtest(),
        dogecoin_genesis_header,
    );
}

#[test]
fn test_target_exceeds_maximum_mainnet() {
    verify_with_excessive_target(
        &DogecoinHeaderValidator::mainnet(),
        &DogecoinHeaderValidator::regtest(),
        MAINNET_HEADER_DOGE_151556,
        151_556,
        MAINNET_HEADER_DOGE_151557,
    );
}

#[test]
fn test_difficulty_regtest() {
    let initial_pow = CompactTarget::from_consensus(0x1d0000ff); // Some non-limit PoW, the actual value is not important.
    let genesis_header = dogecoin_genesis_header(&DogecoinNetwork::Regtest, initial_pow);
    verify_regtest_difficulty_calculation(
        &DogecoinHeaderValidator::regtest(),
        genesis_header,
        initial_pow,
    );
}

#[test]
fn test_backdated_difficulty_adjustment_testnet() {
    let validator = DogecoinHeaderValidator::testnet();
    let genesis_target = CompactTarget::from_consensus(0x1e0ffff0);
    let genesis_header = dogecoin_genesis_header(validator.network(), genesis_target);
    let expected_target = Target::from(genesis_target)
        .min_transition_threshold_dogecoin(validator.network(), 0)
        .to_compact_lossy(); // Target is expected to reach the minimum valid Target threshold allowed in a difficulty adjustment.
    verify_backdated_block_difficulty(
        &validator,
        validator.difficulty_adjustment_interval(0),
        genesis_header,
        expected_target,
    );
}

#[test]
fn test_timestamp_validation_mainnet() {
    verify_timestamp_rules(
        &DogecoinHeaderValidator::mainnet(),
        MAINNET_HEADER_DOGE_151556,
        151_556,
        MAINNET_HEADER_DOGE_151557,
        MAINNET_HEADER_DOGE_151558,
    );
}

#[test]
fn test_digishield_with_min_difficulty_height() {
    let networks = [DogecoinNetwork::Testnet, DogecoinNetwork::Regtest];
    for network in networks.iter() {
        assert!(network
            .params()
            .is_digishield_activated(ALLOW_DIGISHIELD_MIN_DIFFICULTY_HEIGHT));
    }
}
