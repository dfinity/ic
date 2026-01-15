mod auxpow;
mod utils;

use crate::doge::ALLOW_DIGISHIELD_MIN_DIFFICULTY_HEIGHT;
use crate::doge::{DogecoinHeaderValidator, HeaderValidator};
use crate::tests::utils::{deserialize_auxpow_header, dogecoin_genesis_header};
use crate::tests::{
    verify_backdated_block_difficulty, verify_consecutive_headers,
    verify_consecutive_headers_auxpow, verify_difficulty_adjustment, verify_header_sequence,
    verify_header_sequence_auxpow, verify_regtest_difficulty_calculation, verify_timestamp_rules,
    verify_with_excessive_target, verify_with_invalid_pow,
    verify_with_invalid_pow_with_computed_target, verify_with_missing_parent,
};
use bitcoin::dogecoin::Network as DogecoinNetwork;
use bitcoin::dogecoin::constants::genesis_block as dogecoin_genesis_block;
use bitcoin::{CompactTarget, Target};

/// Mainnet 0c120ab190655673a709bc92ad86f80dc1cd9f11f9e0f09ebc5e6a3058b73002
const DOGE_MAINNET_HEADER_17: &str = "01000000fbc172c83b7e535390cfd7807118a7fc799cdbda9da0cbd390f4b70c0f62c2fb155fa2e0ad11cfd91cd0f47049c0fcf5dfabd2fe1a3a406c0350e89f14618bb1f4eda352f0ff0f1e00067505";
/// Mainnet da0e2362cc1d1cd48c8eb70e578c97f00d9a530985ba36027eb7e3fba98c74ae
const DOGE_MAINNET_HEADER_18: &str = "010000000230b758306a5ebc9ef0e0f9119fcdc10df886ad92bc09a773566590b10a120ca96ac7b3a8ef18a68f1044aef152724403bb6bb6e2e44bdb26395a6f00ec858df6eda352f0ff0f1e0002c935";
/// Mainnet 3b595392744d34544c300a886577f0bd839aeb788e3e8e19138e6092eb5c2ad6
const DOGE_MAINNET_HEADER_151556: &str = "02000000c145aa6d9acdbeb6d3196e1dd4a21fd976cbbaf10d520f1e67f933ebc669b7f0748f9b1f40c1a60740c8f47d506c6de6b9f415d00c8a9c4484ef36abe593a39fe4e72d5301cf241b00220241";
/// Mainnet d3b4205b9cab0c969d0e96ff924ab4e3acd8779c2ce1669b94c98d6f2f0365f4
const DOGE_MAINNET_HEADER_151557: &str = "02000000d62a5ceb92608e13198e3e8e78eb9a83bdf07765880a304c54344d749253593b9debfe3e9ead5f19238f3ec5bb321de36acf69f0680d0231c4612961fd2e0fa91ae82d53b4652d1b00adb73b";
/// Mainnet 82553d56341549dd67e3acc0ad77d22e92f043f51a8a2f014dc5b3aac7e32a0d
const DOGE_MAINNET_HEADER_151558: &str = "02000000f465032f6f8dc9949b66e12c9c77d8ace3b44a92ff960e9d960cab9c5b20b4d3f58c2f6492ca38883a4e2335bd67e117a2a86f14907f2c3bb7d3181fb4ccffb243e82d53b4652d1b0006be14";
/// Mainnet 4378cee85115fe9014b53a0b1d0a58b6c5677b26d8efddddcd590d129694e7a7 (Contains AuxPow)
const DOGE_MAINNET_HEADER_400000: &str = "02016200b047cc94ef6886e3e2e79226703a58841619d8fab0de523c1664517310c12818704bc78ff28bf8f7fb20a9901e2ace59db1ab634fbd41a4a74e064a29e6dd315965c2d548a20071b0000000001000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4f03e1ef09fabe6d6d4378cee85115fe9014b53a0b1d0a58b6c5677b26d8efddddcd590d129694e7a70100000000000000062f503253482f04785c2d54080800200402000000092f7374726174756d2f000000000100f2052a010000001976a914f332ec6f1729495e7edcd8ce9d887742567fe60988ac00000000ed94aa029449a3fa7684d707d04fcd11d6e0d42c2db0d1b5392a135b0b0987060000000000000000000002000000e6816ca65e5c4ae73186cea2ee263cb69e86f311fcbe07d41908f3b170bb33804bf55dc3db4f3228ca5122eef35ea1c7bdd521bc80aa496033103e8d983fccec9d5c2d5431cf011b0cd75567";
/// Mainnet 70587d814ddc1c813a00df96854c5fb8f95e357a92f97fb616ad5d1301e48769 (Contains AuxPow)
const DOGE_MAINNET_HEADER_400001: &str = "02016200a7e79496120d59cdddddefd8267b67c5b6580a1d0b3ab51490fe1551e8ce78435d0e49e5c8a6d81f296ff057e959c81fb5f89b4bb3f7a800ae0eae6915f19e0e785c2d54c47b071b0000000001000000010000000000000000000000000000000000000000000000000000000000000000ffffffff5803e1ef09062f503253482f04795c2d5408fabe6d6d70587d814ddc1c813a00df96854c5fb8f95e357a92f97fb616ad5d1301e487690100000000000000700701ab17000000122f434d73666972653231353839373830342f000000000100f2052a010000001976a91411fde3131d4a59d9de9d6d9390f8baeebf50396088ac000000003301a7df3f1be4c495becbf61203d925e8b10225d753975ed3bb5b1843b13f170000000000000000000002000000e6816ca65e5c4ae73186cea2ee263cb69e86f311fcbe07d41908f3b170bb3380c4df46c9f92ee0c12ab954ed4dadb47b018d2aaf91a360d821b5fd8bd6f6e10d6a5c2d5431cf011b8f021906";
/// Mainnet a5021d69a83f39aef10f3f24f932068d6ff322c654d20562def3fac5703ce3aa (Contains AuxPow)
const DOGE_MAINNET_HEADER_400002: &str = "020162006987e401135dad16b67ff9927a355ef9b85f4c8596df003a811cdc4d817d5870f3a110dab57e109c3af2e4a527f6fe6e05dde4e2c4f2d099af22a41cc6868fc7d85c2d548a1c061b0000000001000000010000000000000000000000000000000000000000000000000000000000000000ffffffff5003e1ef09fabe6d6d0b1f5ecfb132faabac9804974dc560e0697163c5089b47beea817cb2495c51254000000000000000d0e38502000004003acc03004d696e65642062792073666d696e65722e636f6dffffffff01800c0c2a010000001976a914fc5e3afa7a0fa01df5a6dc8e28576309075d45d888ac00000000910cc6e411fe82307ae2d6613359ea76cd06f3129103e8830b4e04000000000003502af177348c5424a4271a0d75533cd2a6a62725c96ba81b524264a2cc8135588998f5045fd590d6f39cf301e86e2291878001e3d32fd0128d992146942d154a9349d3bab05ec1f3e494c6f2bed35eb18e809e008fe7dd9b0c659a7482332b83000000000649a466c7a55fac7adae0fa7fbdac228919af6a2a0968ac4d5fd77417444031ee6c4127661ba7d68c453b449868e6135a6ac0d9351a3e40d7dd58767531de67ee31284c19194806e9c00943e05a9d1a79e17fa0c9b79bef9027ad2ca0bdf99eabfe2d8f99be8b35640357d1af6ec9884840d0a9d91dbac1a8334df680016151ffc584b8039a3eff688f0839d232def7c24dd3b9ed8eb8fc4b3cf6e201ea28f3321bd90e6de9c74dcb2186558963cf9463ba7500f8bed05fc1ad197ea4fa218a0a3800000002000000e6816ca65e5c4ae73186cea2ee263cb69e86f311fcbe07d41908f3b170bb3380a106ab427e1cff3aadbd4b492d84c5a7713e5c56532638725bd13b98973abd56d85c2d5431cf011ba8253717";
/// Mainnet 836b17a6e9d869b32c8f3c3718f46564ce6aa03267f7f5dd120c5e47ba92ff17 (Contains AuxPow)
const DOGE_MAINNET_HEADER_521335: &str = "02016200f74b00b615b0f885790ad03977e36a9245991b0367a7d841c27f2eac3b516fada5a6aedefb0506274e13aa4540c4f40ff5b9b790aa99b1f55f441faac1502aa9ab42a254953e021b0000000001000000010000000000000000000000000000000000000000000000000000000000000000ffffffff590388ba0ae4b883e5bda9e7a59ee4bb99e9b1bcfabe6d6dfeba5b94f1b5db0469abced74ec4c6b3e4a364ad7954e206012f91dab4ad00b3200000000000000000ff1375090000004d696e65642062792065617379326d696e65ffffffff0100f2052a010000001976a914aa3750aa18b8a0f3f0590731e1fab934856680cf88ac0000000058374fe2d3198dcf12a6a6ecfb4db156e60c56f2b02e84ff65c80000000000000000000000052e1c21738814115e1ee29aca32b85b33e703ce77a2575f18a4910567bafaa1e29673f696e5825601a920ad8c0059c7c80893bcb6d0234f8011426f7bc33ab6e710f48ac60cdfce087415a93f24255b52d7d8a0131450d97d197642f78692568dc9ca22b7ea52e2f70c10f1f0f2e1a08fe2fe70ab3e87fcc24114bd7e6e269ea40c694b9adcfaa58f9872e8f98dd941bd0a42e0506888b1ce59218b8444f041b31800000002000000608ef24128e360853e7b45ebeba86ddd3ba4a77c993b43eb76fd1533fadfda73b75988381dc727b5c64e47c0b272fa07f2aadee40ba3f9fb36b61fc48a809ab7ac42a254841c011b54ac5302";
/// Mainnet 1e2eb7de8933b2cebd0e262ff4a694e73bbfa22fe4429539107e3974cf05d3b2 (Contains AuxPow)
const DOGE_MAINNET_HEADER_521336: &str = "0201620017ff92ba475e0c12ddf5f76732a06ace6465f418373c8f2cb369d8e9a6176b83c4d96ac32bd47e0f84ba407b86df6591ab2cc29be1e8bf4f64861e2cab0da0d10043a254bc51021b0000000001000000010000000000000000000000000000000000000000000000000000000000000000ffffffff570389ba0ae4b883e5bda9e7a59ee4bb99e9b1bcfabe6d6d16fc266fdccc98cfd8473aa0c9ca61238b9f9f3b56d8277069bda02d52cffd052000000000000000011a49e9230000004d696e656420627920736779616e7969ffffffff01e0850a2a010000001976a914aa3750aa18b8a0f3f0590731e1fab934856680cf88ac0000000016d0eaf773968e3f85b244cc6a76575c02bafc3f2d0d8429c8d7000000000000033b0205e2b3e160d2dac12e3b02791ae75d5f6ac5ada24aa26eb013d85a56b7a6b8f2232a5b68bf0d21979bdffa150b46137d33ff4be86bf650674918da9f1370b804389de5beac34145c5a7b9fa5f5ebca97500e381fab6d47976b38ffd662e3000000000556f133be1b493fb899d8dafc36e506bb75209e76f636752ef88e3864a4ae23699673f696e5825601a920ad8c0059c7c80893bcb6d0234f8011426f7bc33ab6e72dcd7e31475334e158abd41c8dd1a0b4271d53a421dc06dd9584308e4337c20cc9ca22b7ea52e2f70c10f1f0f2e1a08fe2fe70ab3e87fcc24114bd7e6e269ea4ff1639be5c267e82a3f653459ff8cf3077a0eae67f59813ea06960840b503e07180000000200000093ea9e10eeb0b396a85393df75ed1139145786cd0bc0d1b7e12488ea90e7134f879170858389c03cc78288fbd23b27aee5d62075abb7a9c042cc8f49b6dc51192d43a254841c011b7b0eef43";

/// Testnet 7214c118466d8e2d63e7c50ede083816fbf4e0d75e3e8ec7c3ce1312ae7e77ab
const DOGE_TESTNET_HEADER_88: &str = "0200000052208696e97fb9cc8088399db53791fe668a401f549eb949d5cd16dec5190809bc987206bfe6ee60efab462316a5d127b8697cc3f75cf859c96b480819e46e0f880afb52f0ff0f1e00141ed2";
/// Testnet 4fc5fc1a5e5db47ab33f3626c4456c0cbcf69dc4db6cd64ef5917d703db45a27
const DOGE_TESTNET_HEADER_89: &str = "02000000ab777eae1213cec3c78e3e5ed7e0f4fb163808de0ec5e7632d8e6d4618c114729053d47099f1b595cc742f80a1164520eff7284cd0be18d9bbc5d265f04766e9970afb52f0ff0f1e00021648";
/// Testnet 5ed64a826fa09f20aaf6fcd20bc17ab2c4053d1c10a30a13e54cb5aca786b15e
const DOGE_TESTNET_HEADER_158378: &str = "020062001d79428d80cda680f8e52e886a3746fd6c8295abce89787035eabd31d5acc88391f163f370d83ca96b39d551a93b2c1cfee103a54a49da26b7de388e94ad099ca598e053e1eb061e000a85b3";
/// Testnet ab0d367b677f3e0569563c3ae86c3b2f91c45f79ba1c6654b1d894cac35cacb7
const DOGE_TESTNET_HEADER_158379: &str = "020062005eb186a7acb54ce5130aa3101c3d05c4b27ac10bd2fcf6aa209fa06f824ad65e5e6448eee4d53b1750840c2aea3160cb91344fdb108ed732c89247dcb104b781b098e053c075061e00371be8";
/// Testnet 1561d36f48fbc6799d803b94768e317c25b5aec6150c61ef7276f317af9ecf47 (Contains AuxPow)
const DOGE_TESTNET_HEADER_158380: &str = "02016200b7ac5cc3ca94d8b154661cba795fc4912f3b6ce83a3c5669053e7f677b360dab5433333435a7c5f5b0f02601d8108970360bc806ce28a50747a68090785c5dd5f698e05360d0051e0000000002000000010000000000000000000000000000000000000000000000000000000000000000ffffffff3d037827022cfabe6d6db4106f06d051743d737eb7a6dbefdc008940c62d3f5d6453551dd20d8e7fb6f0040000000000000001000000000000000000000000000000012e016af1b20000001976a9149628aabe802c3f6f67946f70c300321d7110bc4388ac00000000f0550a4183f7eabaaeaff72d876115573148c79b4972d34085c2b4de07a2608600000000000257a668057a41b9aa2c6d44c32e9141ac291a2587fbc9384eca0ebc743b696f235c6a0f13f6429bd555d08e4b17007468fd10d52250a0de605c927d745197ba3900000000020000007042a116c81e3cfb6a5681cde48703a895a3a6fba717317090111400aeccfb968b756e0cf7c1f5b638a1b2b804d7d022ee39fab0fef4e2e67f4e303a189990472499e053caee011c000eb60a";
/// Testnet ee48b7f2a5fd55c6bdc22e646b7948533985e80e9ed6b6d225a71672cef86746 (Contains AuxPow)
const DOGE_TESTNET_HEADER_293098: &str = "02016200b71a126ea7370cc8edd9688cc42e6038081819ddc265252ce58e6a1fc0b2ead4743d33f7f090670ee46347c4f91b3b1d3333d33247cd5aedd5495620587d0450bd869e54cb91001e0000000002000000010000000000000000000000000000000000000000000000000000000000000000ffffffff3903fd36072cfabe6d6dee48b7f2a5fd55c6bdc22e646b7948533985e80e9ed6b6d225a71672cef8674601000000000000001398fc0100000000000000000100f2052a010000001976a914d5c6ab987d68dfbadc3fba5103787d061de9ce5288ac0000000014955ce052b4d87d3ae4629cab6b764a35c2e73b93090ff4405e19492e0fe97c000000000000000000000200000005116c087d14a65744e57b664dcc9db4abbdd938a8c4c60a97b3ea5de80581541431363db860e8e810e9f04870f30a6c7415a547cb3d2ab12b541f4a921b39ce8e869e54c0f74c1d8001d83d";
/// Testnet 2c01cd0ff4e898779efe4ad50ac2dff982190b7e347ede9bfa97bd66052eb631 (Contains AuxPow)
const DOGE_TESTNET_HEADER_293099: &str = "020162004667f8ce7216a725d2b6d69e0ee885395348796b642ec2bdc655fda5f2b748ee0dfff4d766359c5d544820f24f947c6d14fc981f62da3ee3fb628ec9befdc4fbc7869e54a485001e0000000002000000010000000000000000000000000000000000000000000000000000000000000000ffffffff39030037072cfabe6d6d2c01cd0ff4e898779efe4ad50ac2dff982190b7e347ede9bfa97bd66052eb63101000000000000001298fc0100000000000000000100f2052a010000001976a914d5c6ab987d68dfbadc3fba5103787d061de9ce5288ac00000000c5c1e7ade9cc87127d0c6ed16484b5c82646db3efd1b6c378883e0d6c773bc1c0000000000000000000002000000bceac3fa006816f11ce1e2d2e5210d60d2f29635b5f1f371b2d3af31914d2a084c702759e5712dbc1ead5c8db62af0c5c6c12e3dbbb70ed80fd13099704acd42ac869e54c0f74c1decd8c4de";

#[test]
fn test_basic_header_validation_mainnet() {
    verify_consecutive_headers(
        &DogecoinHeaderValidator::mainnet(),
        DOGE_MAINNET_HEADER_17,
        17,
        DOGE_MAINNET_HEADER_18,
    );
}

#[test]
fn test_basic_header_validation_testnet() {
    verify_consecutive_headers(
        &DogecoinHeaderValidator::testnet(),
        DOGE_TESTNET_HEADER_88,
        88,
        DOGE_TESTNET_HEADER_89,
    );
}

#[test]
fn test_basic_header_validation_auxpow_mainnet() {
    verify_consecutive_headers_auxpow(
        DogecoinHeaderValidator::mainnet(),
        DOGE_MAINNET_HEADER_400000,
        400_000,
        DOGE_MAINNET_HEADER_400001,
        DOGE_MAINNET_HEADER_400002,
    );
}

#[test]
fn test_basic_header_validation_auxpow_testnet() {
    verify_consecutive_headers_auxpow(
        DogecoinHeaderValidator::testnet(),
        DOGE_TESTNET_HEADER_158378,
        158_378,
        DOGE_TESTNET_HEADER_158379,
        DOGE_TESTNET_HEADER_158380,
    );
}

#[test]
fn test_sequential_header_validation_mainnet() {
    let mainnet_headers_1_15000_parsed =
        std::env::var("DOGE_MAINNET_HEADERS_1_15000_PARSED_DATA_PATH")
            .expect("Failed to get test data path env variable");
    verify_header_sequence(
        &DogecoinHeaderValidator::mainnet(),
        mainnet_headers_1_15000_parsed.as_str(),
        *dogecoin_genesis_block(DogecoinNetwork::Dogecoin).header,
        0,
    );
}

#[test]
fn test_sequential_header_validation_testnet() {
    let testnet_headers_1_15000_parsed =
        std::env::var("DOGE_TESTNET_HEADERS_1_15000_PARSED_DATA_PATH")
            .expect("Failed to get test data path env variable");
    verify_header_sequence(
        &DogecoinHeaderValidator::testnet(),
        testnet_headers_1_15000_parsed.as_str(),
        *dogecoin_genesis_block(DogecoinNetwork::Testnet).header,
        0,
    );
}

#[test]
fn test_sequential_header_validation_mainnet_auxpow() {
    let mainnet_headers_521337_522336_auxpow_parsed =
        std::env::var("DOGE_MAINNET_HEADERS_521337_536336_AUXPOW_PARSED_DATA_PATH")
            .expect("Failed to get test data path env variable");
    verify_header_sequence_auxpow(
        DogecoinHeaderValidator::mainnet(),
        mainnet_headers_521337_522336_auxpow_parsed.as_str(),
        *deserialize_auxpow_header(DOGE_MAINNET_HEADER_521335),
        521335,
        *deserialize_auxpow_header(DOGE_MAINNET_HEADER_521336),
    );
}

#[test]
fn test_sequential_header_validation_testnet_auxpow() {
    let testnet_headers_293100_308099_auxpow_parsed =
        std::env::var("DOGE_TESTNET_HEADERS_293100_308099_AUXPOW_PARSED_DATA_PATH")
            .expect("Failed to get test data path env variable");
    verify_header_sequence_auxpow(
        DogecoinHeaderValidator::testnet(),
        testnet_headers_293100_308099_auxpow_parsed.as_str(),
        *deserialize_auxpow_header(DOGE_TESTNET_HEADER_293098),
        293098,
        *deserialize_auxpow_header(DOGE_TESTNET_HEADER_293099),
    );
}

#[test]
fn test_missing_previous_header() {
    verify_with_missing_parent(
        &DogecoinHeaderValidator::mainnet(),
        DOGE_MAINNET_HEADER_151556,
        151_556,
        DOGE_MAINNET_HEADER_151558,
    );
}

#[test]
fn test_invalid_pow_mainnet() {
    verify_with_invalid_pow(
        &DogecoinHeaderValidator::mainnet(),
        DOGE_MAINNET_HEADER_17,
        17,
        DOGE_MAINNET_HEADER_18,
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
        DOGE_MAINNET_HEADER_151556,
        151_556,
        DOGE_MAINNET_HEADER_151557,
    );
}

#[test]
fn test_difficulty_adjustments_mainnet() {
    let mainnet_headers_0_700000_raw = std::env::var("DOGE_MAINNET_HEADERS_0_700000_RAW_DATA_PATH")
        .expect("Failed to get test data path env variable");
    verify_difficulty_adjustment(
        &DogecoinHeaderValidator::mainnet(),
        mainnet_headers_0_700000_raw.as_str(),
        700_000,
    );
}

#[test]
fn test_difficulty_adjustments_testnet() {
    let mainnet_headers_0_2000000_raw =
        std::env::var("DOGE_TESTNET_HEADERS_0_2000000_RAW_DATA_PATH")
            .expect("Failed to get test data path env variable");
    verify_difficulty_adjustment(
        &DogecoinHeaderValidator::testnet(),
        mainnet_headers_0_2000000_raw.as_str(),
        2_000_000,
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
        DOGE_MAINNET_HEADER_151556,
        151_556,
        DOGE_MAINNET_HEADER_151557,
        DOGE_MAINNET_HEADER_151558,
    );
}

#[test]
fn test_digishield_with_min_difficulty_height() {
    let networks = [DogecoinNetwork::Testnet, DogecoinNetwork::Regtest];
    for network in networks.iter() {
        assert!(
            network
                .params()
                .is_digishield_activated(ALLOW_DIGISHIELD_MIN_DIFFICULTY_HEIGHT)
        );
    }
}
