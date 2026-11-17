use super::*;

#[test]
fn test_fetch_guard() {
    use super::*;
    let txid = Txid::from([0_u8; 32]);
    let max = MAX_CONCURRENT;
    {
        let _guard = FetchGuard::new(txid).unwrap();
        assert_eq!(OUTCALL_CAPACITY.with(|c| *c.borrow()), max - 1);
        assert!(matches!(
            get_fetch_status(txid),
            Some(FetchTxStatus::PendingOutcall)
        ));
    }
    assert!(get_fetch_status(txid).is_none());
    assert_eq!(OUTCALL_CAPACITY.with(|c| *c.borrow()), max);

    {
        let mut guards = Vec::new();
        for i in 0..max {
            assert_eq!(OUTCALL_CAPACITY.with(|c| *c.borrow()), max - i);
            let txid = Txid::from([(i + 1) as u8; 32]);
            guards.push(FetchGuard::new(txid).unwrap());
        }
        assert!(FetchGuard::new(txid).is_err());
        assert_eq!(OUTCALL_CAPACITY.with(|c| *c.borrow()), 0);
    }
    assert_eq!(OUTCALL_CAPACITY.with(|c| *c.borrow()), max);
}

#[test]
fn test_fetch_status() {
    let txid_0 = Txid::from([0_u8; 32]);
    assert!(get_fetch_status(txid_0).is_none());
    set_fetch_status(txid_0, FetchTxStatus::PendingOutcall);
    assert!(matches!(
        get_fetch_status(txid_0),
        Some(FetchTxStatus::PendingOutcall)
    ));

    let bytes = b"\
\x02\x00\x00\x00\x01\x17\x34\x3a\xab\xa9\x67\x67\x2f\x17\xef\x0a\xbf\x4b\xb1\x14\xad\x19\x63\xe0\
\x7d\xd2\xf2\x05\xaa\x25\xa4\xda\x50\x3e\xdb\x01\xab\x01\x00\x00\x00\x6a\x47\x30\x44\x02\x20\x21\
\x81\xb5\x9c\xa7\xed\x7e\x2c\x8e\x06\x96\x52\xb0\x7e\xd2\x10\x24\x9e\x83\x37\xec\xc5\x35\xca\x6b\
\x75\x3c\x02\x44\x89\xe4\x5d\x02\x20\x2a\xc7\x55\xcb\x55\x97\xf1\xcc\x2c\xad\x32\xb8\xa4\x33\xf1\
\x79\x6b\x5f\x51\x76\x71\x6d\xa9\x22\x2c\x65\xf9\x44\xaf\xd1\x3d\xa8\x01\x21\x02\xc4\xc6\x9e\x4d\
\x36\x4b\x3e\xdf\x84\xb5\x20\xa0\x18\xd5\x7e\x71\xfa\xce\x19\x7e\xc8\xf9\x46\x43\x60\x7e\x4a\xca\
\x70\xdc\x82\xc1\xfd\xff\xff\xff\x02\x10\x27\x00\x00\x00\x00\x00\x00\x19\x76\xa9\x14\x11\xb3\x66\
\xed\xfc\x0a\x8b\x66\xfe\xeb\xae\x5c\x2e\x25\xa7\xb6\xa5\xd1\xcf\x31\x88\xac\x7c\x2e\x00\x00\x00\
\x00\x00\x00\x19\x76\xa9\x14\xb9\x73\x68\xd8\xbf\x0a\x37\x69\x00\x85\x16\x57\xf3\x7f\xbe\x73\xa6\
\x56\x61\x33\x88\xac\x14\xa4\x0c\x00";
    use bitcoin::Network;
    use bitcoin::consensus::Decodable;
    let tx = Transaction::consensus_decode(&mut bytes.to_vec().as_slice()).unwrap();
    let txid_1 = Txid::from(*(tx.compute_txid().as_ref() as &[u8; 32]));
    let from_tx = |tx: &bitcoin::Transaction| {
        TransactionCheckData::from_transaction(&BtcNetwork::Mainnet, tx.clone())
    };
    set_fetch_status(
        txid_1,
        FetchTxStatus::Fetched(FetchedTx {
            tx: from_tx(&tx),
            input_addresses: vec![None; 2],
        }),
    );
    assert!(matches!(
        get_fetch_status(txid_1),
        Some(FetchTxStatus::Fetched(_))
    ));
    let address = Address::from_script(&tx.output[0].script_pubkey, Network::Bitcoin).unwrap();
    assert_eq!(
        get_fetched_output_addresses(txid_1, 0),
        Some(Ok(vec![address.clone()]))
    );
    assert_eq!(
        get_fetched_output_addresses(txid_1, 2),
        Some(Err(SpentOutputError::MissingOutput))
    );
    assert_eq!(get_fetched_output_addresses(txid_0, 0), None);
    set_fetched_addresses(txid_1, 0, vec![address.clone()]);
    match get_fetch_status(txid_1) {
        Some(FetchTxStatus::Fetched(fetched)) => {
            assert_eq!(fetched.input_addresses[0], Some(vec![address]))
        }
        _ => {
            panic!("txid {txid_1} is not found")
        }
    }
    clear_fetch_status(txid_1);
    assert!(get_fetch_status(txid_1).is_none());
}

#[test]
fn test_fetch_tx_cache_bounds() {
    let txid_0 = Txid::from([0_u8; 32]);
    let txid_1 = Txid::from([1_u8; 32]);
    let txid_2 = Txid::from([2_u8; 32]);
    let txid_3 = Txid::from([3_u8; 32]);
    let max_entries = 3;
    let mut cache = FetchTxCache::new(max_entries);
    assert_eq!(cache.set_status_with(txid_0, (), 0), None);
    assert_eq!(cache.set_status_with(txid_1, (), 100), None);
    assert_eq!(cache.set_status_with(txid_2, (), 200), None);
    assert_eq!(
        cache.iter().collect::<Vec<_>>(),
        vec![(txid_0, 0, &()), (txid_1, 100, &()), (txid_2, 200, &())]
    );

    assert_eq!(
        cache.set_status_with(txid_3, (), 300),
        Some((txid_0, 0, ()))
    );
    assert_eq!(
        cache.iter().collect::<Vec<_>>(),
        vec![(txid_1, 100, &()), (txid_2, 200, &()), (txid_3, 300, &())]
    );

    // setting status of an existing entry will not change its creation
    // time, neither will it purge any existing entry.
    assert_eq!(cache.set_status_with(txid_2, (), 400), None);
    assert_eq!(
        cache.iter().collect::<Vec<_>>(),
        vec![(txid_1, 100, &()), (txid_2, 200, &()), (txid_3, 300, &())]
    );

    // clear_status should make room for one more entry
    cache.clear_status(txid_2);
    assert_eq!(
        cache.iter().collect::<Vec<_>>(),
        vec![(txid_1, 100, &()), (txid_3, 300, &())]
    );
    assert_eq!(cache.set_status_with(txid_0, (), 500), None);
    assert_eq!(
        cache.iter().collect::<Vec<_>>(),
        vec![(txid_1, 100, &()), (txid_3, 300, &()), (txid_0, 500, &())]
    );
}

#[test]
fn cache_should_have_same_size() {
    enum Status {
        Status0,
        Status1,
        Status2,
    }

    let txid_0 = Txid::from([0_u8; 32]);
    let max_entries = 3;
    let mut cache = FetchTxCache::new(max_entries);
    assert_eq!(cache.status.len(), 0);
    assert_eq!(cache.created.len(), 0);

    cache.set_status_with(txid_0, Status::Status0, 0);
    assert_eq!(cache.status.len(), 1);
    assert_eq!(cache.created.len(), 1);

    cache.set_status_with(txid_0, Status::Status1, 1);
    assert_eq!(cache.status.len(), 1);
    assert_eq!(cache.created.len(), 1);

    cache.set_status_with(txid_0, Status::Status2, 2);
    assert_eq!(cache.status.len(), 1);
    assert_eq!(cache.created.len(), 1);
}

mod output_addresses {
    use crate::state::{output_addresses, script_num};
    use bitcoin::{
        Address, Network, PublicKey, ScriptBuf, opcodes::all::*, script::Builder,
        script::Instruction, script::PushBytesBuf,
    };
    use ic_btc_checker::blocklist;
    use std::str::FromStr;

    // The public key of the private key 1, i.e. the generator point G.
    const COMPRESSED_PUBLIC_KEY: &str =
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    const UNCOMPRESSED_PUBLIC_KEY: &str = "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8";
    // The same key in hybrid encoding, as used in Bitcoin Core's `script_tests.json`
    // ("P2PK with hybrid pubkey but no STRICTENC").
    const HYBRID_PUBLIC_KEY: &str = "0679be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8";
    const PUBLIC_KEY_ADDRESSES: [&str; 4] = [
        "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH",
        "1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm",
        "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
        "3JvL6Ymt8MVWiCNHC7oWU6nLeHNJKLZGLN",
    ];
    // The public key of the private key 2.
    const OTHER_PUBLIC_KEY: &str =
        "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
    const OTHER_PUBLIC_KEY_ADDRESSES: [&str; 4] = [
        "1cMh228HTCiwS8ZsaakH8A8wze1JR5ZsP",
        "1LagHJk2FyCV2VzrNHVqg3gYG4TSYwDV4m",
        "bc1qq6hag67dl53wl99vzg42z8eyzfz2xlkvxechjp",
        "3FWHHE3RVgyv5vYmMrcoRdA25uugWvQbso",
    ];
    // Encoded like a compressed public key, but not a point on the curve.
    const INVALID_PUBLIC_KEY: [u8; 33] = [
        0x02, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff,
    ];
    const MALFORMED_PUBLIC_KEY: [u8; 33] = [0x05; 33];
    // The hybrid encoding of the generator point with the prefix for an odd y-coordinate,
    // although its y-coordinate is even.
    const HYBRID_PUBLIC_KEY_WITH_WRONG_PARITY: &str = "0779be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8";

    fn key(hex: &str) -> PushBytesBuf {
        PushBytesBuf::try_from(hex::decode(hex).unwrap()).unwrap()
    }

    fn addresses(addresses: &[&str]) -> Vec<Address> {
        addresses
            .iter()
            .map(|address| Address::from_str(address).unwrap().assume_checked())
            .collect()
    }

    fn p2pk(key: PushBytesBuf) -> ScriptBuf {
        Builder::new()
            .push_slice(key)
            .push_opcode(OP_CHECKSIG)
            .into_script()
    }

    fn multisig(m: i64, keys: &[PushBytesBuf], n: i64) -> ScriptBuf {
        let mut builder = Builder::new().push_int(m);
        for key in keys {
            builder = builder.push_slice(key);
        }
        builder
            .push_int(n)
            .push_opcode(OP_CHECKMULTISIG)
            .into_script()
    }

    #[test]
    fn should_return_standard_address() {
        let expected = addresses(&["bc1q6xmv92ujqs2szzlpz4hhtn8dfzvpev72zv8zv7"]);

        assert_eq!(
            output_addresses(&expected[0].script_pubkey(), Network::Bitcoin),
            Some(expected)
        );
    }

    #[test]
    fn should_return_all_addresses_of_p2pk_key_in_any_encoding() {
        for public_key in [
            COMPRESSED_PUBLIC_KEY,
            UNCOMPRESSED_PUBLIC_KEY,
            HYBRID_PUBLIC_KEY,
        ] {
            let script = p2pk(key(public_key));
            assert!(script.is_p2pk());
            assert!(Address::from_script(&script, Network::Bitcoin).is_err());

            assert_eq!(
                output_addresses(&script, Network::Bitcoin),
                Some(addresses(&PUBLIC_KEY_ADDRESSES)),
                "{public_key}"
            );
        }
        // The P2PKH addresses match the ones derived by the `bitcoin` crate.
        for public_key in [COMPRESSED_PUBLIC_KEY, UNCOMPRESSED_PUBLIC_KEY] {
            let address =
                Address::p2pkh(PublicKey::from_str(public_key).unwrap(), Network::Bitcoin);
            assert!(PUBLIC_KEY_ADDRESSES.contains(&address.to_string().as_str()));
        }
    }

    #[test]
    fn should_return_addresses_of_all_keys_of_bare_multisig() {
        let script = multisig(
            1,
            &[
                key(COMPRESSED_PUBLIC_KEY),
                PushBytesBuf::from(INVALID_PUBLIC_KEY),
                PushBytesBuf::from(MALFORMED_PUBLIC_KEY),
                key(HYBRID_PUBLIC_KEY_WITH_WRONG_PARITY),
                key(OTHER_PUBLIC_KEY),
                key(UNCOMPRESSED_PUBLIC_KEY),
            ],
            6,
        );
        assert!(script.is_multisig());

        assert_eq!(
            output_addresses(&script, Network::Bitcoin),
            Some(addresses(
                &[PUBLIC_KEY_ADDRESSES, OTHER_PUBLIC_KEY_ADDRESSES].concat()
            ))
        );
    }

    #[test]
    fn should_support_bare_multisig_with_up_to_20_keys() {
        for n in [16, 17, 20] {
            let mut keys = vec![key(OTHER_PUBLIC_KEY); n - 1];
            keys.push(key(COMPRESSED_PUBLIC_KEY));
            let script = multisig(n as i64, &keys, n as i64);

            assert_eq!(
                output_addresses(&script, Network::Bitcoin),
                Some(addresses(
                    &[OTHER_PUBLIC_KEY_ADDRESSES, PUBLIC_KEY_ADDRESSES].concat()
                )),
                "{n}"
            );
        }
    }

    #[test]
    fn should_return_no_address_for_p2pk_output_with_invalid_public_key() {
        for public_key in [
            PushBytesBuf::from(INVALID_PUBLIC_KEY),
            PushBytesBuf::from(MALFORMED_PUBLIC_KEY),
            key(HYBRID_PUBLIC_KEY_WITH_WRONG_PARITY),
        ] {
            assert_eq!(
                output_addresses(&p2pk(public_key), Network::Bitcoin),
                Some(vec![])
            );
        }
    }

    #[test]
    fn should_not_support_other_scripts() {
        let blocked_p2pkh = addresses(&[blocklist::BTC_ADDRESS_BLOCKLIST[0]])[0].script_pubkey();
        assert!(blocked_p2pkh.is_p2pkh());
        let p2pkh_with_op_nop = Builder::from(blocked_p2pkh.to_bytes())
            .push_opcode(OP_NOP)
            .into_script();
        let p2pk_with_op_nop = Builder::from(p2pk(key(COMPRESSED_PUBLIC_KEY)).to_bytes())
            .push_opcode(OP_NOP)
            .into_script();
        let public_key_with_op_drop = Builder::new()
            .push_slice(key(COMPRESSED_PUBLIC_KEY))
            .push_opcode(OP_DROP)
            .push_opcode(OP_PUSHNUM_1)
            .into_script();
        let multisig_with_op_nop = Builder::new()
            .push_opcode(OP_PUSHNUM_1)
            .push_slice([0x02])
            .push_opcode(OP_NOP)
            .push_opcode(OP_CHECKMULTISIG)
            .into_script();
        let multisig_with_op_drop = Builder::new()
            .push_opcode(OP_PUSHNUM_1)
            .push_opcode(OP_PUSHBYTES_0)
            .push_opcode(OP_DROP)
            .push_opcode(OP_CHECKMULTISIG)
            .into_script();
        let multisig_with_opcode_as_key = Builder::new()
            .push_opcode(OP_PUSHNUM_1)
            .push_opcode(OP_PUSHNUM_2)
            .push_opcode(OP_PUSHNUM_1)
            .push_opcode(OP_CHECKMULTISIG)
            .into_script();
        let mut multisig_with_257_keys = Builder::new().push_opcode(OP_PUSHNUM_1);
        for _ in 0..257 {
            multisig_with_257_keys = multisig_with_257_keys.push_slice(key(COMPRESSED_PUBLIC_KEY));
        }
        let multisig_with_257_keys = multisig_with_257_keys
            .push_opcode(OP_PUSHNUM_1)
            .push_opcode(OP_CHECKMULTISIG)
            .into_script();
        let keys = vec![key(COMPRESSED_PUBLIC_KEY); 2];
        let op_return = ScriptBuf::new_op_return([0xaa; 32]);
        let anyone_can_spend = Builder::new().push_opcode(OP_PUSHNUM_1).into_script();

        for script in [
            p2pkh_with_op_nop,
            p2pk_with_op_nop,
            public_key_with_op_drop,
            multisig_with_op_nop,
            multisig_with_op_drop,
            multisig_with_opcode_as_key,
            multisig_with_257_keys,
            multisig(1, &keys, 3),
            multisig(3, &keys, 2),
            multisig(0, &keys, 2),
            multisig(1, &vec![key(COMPRESSED_PUBLIC_KEY); 21], 21),
            op_return,
            anyone_can_spend,
        ] {
            assert_eq!(
                output_addresses(&script, Network::Bitcoin),
                None,
                "{script}"
            );
        }
    }

    #[test]
    fn should_decode_script_numbers() {
        let push = |bytes: &[u8]| {
            script_num(&Instruction::PushBytes(
                PushBytesBuf::try_from(bytes.to_vec()).unwrap().as_ref(),
            ))
        };
        assert_eq!(push(&[]), Some(0));
        assert_eq!(push(&[0x11]), Some(17));
        assert_eq!(push(&[0x14, 0x00]), Some(20));
        assert_eq!(push(&[0x81]), Some(-1));
        assert_eq!(push(&[0x00, 0x01]), Some(256));
        assert_eq!(push(&[0x01, 0x00, 0x00, 0x00, 0x00]), None);
        assert_eq!(script_num(&Instruction::Op(OP_PUSHNUM_1)), Some(1));
        assert_eq!(script_num(&Instruction::Op(OP_PUSHNUM_16)), Some(16));
        assert_eq!(script_num(&Instruction::Op(OP_PUSHNUM_NEG1)), Some(-1));
        assert_eq!(script_num(&Instruction::Op(OP_NOP)), None);
    }
}

mod schema_upgrades {
    use crate::state::Config;
    use candid::Deserialize;
    use ic_btc_checker::{BtcNetwork, CheckMode};
    use proptest::arbitrary::any;
    use proptest::prelude::{Just, Strategy};
    use proptest::{prop_oneof, proptest};
    use serde::Serialize;

    #[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
    pub struct ConfigPreviousVersion {
        btc_network: BtcNetwork,
        check_mode: CheckMode,
    }

    impl From<Config> for ConfigPreviousVersion {
        fn from(
            Config {
                btc_network,
                check_mode,
                num_subnet_nodes: _,
            }: Config,
        ) -> Self {
            Self {
                btc_network,
                check_mode,
            }
        }
    }

    proptest! {
        #[test]
        fn should_be_able_to_upgrade_state(config in arb_config()) {
            let config_before_upgrade: ConfigPreviousVersion = config.into();

            let serialized_config_before_upgrade = encode(&config_before_upgrade);
            let config_after_upgrade: Config = decode(serialized_config_before_upgrade.as_slice());
            assert_eq!(config_before_upgrade, config_after_upgrade.clone().into());
        }
    }

    fn encode<S: ?Sized + serde::Serialize>(state: &S) -> Vec<u8> {
        let mut buf = vec![];
        ciborium::ser::into_writer(state, &mut buf).expect("failed to encode state");
        buf
    }

    fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> T {
        ciborium::de::from_reader(bytes)
            .unwrap_or_else(|e| panic!("failed to decode state bytes {}: {e}", hex::encode(bytes)))
    }

    pub fn arb_config() -> impl Strategy<Value = Config> {
        (arb_btc_network(), arb_check_mode(), any::<u16>()).prop_map(
            |(btc_network, check_mode, num_subnet_nodes)| Config {
                btc_network,
                check_mode,
                num_subnet_nodes,
            },
        )
    }

    pub fn arb_btc_network() -> impl Strategy<Value = BtcNetwork> {
        prop_oneof![
            Just(BtcNetwork::Mainnet),
            Just(BtcNetwork::Testnet),
            ".*".prop_map(|json_rpc_url| BtcNetwork::Regtest { json_rpc_url }),
        ]
    }

    pub fn arb_check_mode() -> impl Strategy<Value = CheckMode> {
        prop_oneof![
            Just(CheckMode::AcceptAll),
            Just(CheckMode::RejectAll),
            Just(CheckMode::Normal),
        ]
    }
}
