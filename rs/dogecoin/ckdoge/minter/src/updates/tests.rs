mod derivation {
    use crate::address::DogecoinAddress;
    use crate::lifecycle::init::Network;
    use crate::updates::get_doge_address::{derivation_path, derive_public_key};
    use candid::Principal;
    use icrc_ledger_types::icrc1::account::Account;

    #[test]
    fn should_be_stable() {
        let (canister_public_key, _) = crate::test_fixtures::canister_public_key_pair();
        let user_with_subaccount = Account {
            owner: Principal::from_text(
                "2oyh2-miczk-rzcqm-zbkes-q3kyi-lmen7-slvvl-byown-zz6v6-razzx-vae",
            )
            .unwrap(),
            subaccount: Some([42_u8; 32]),
        };
        let user_without_subaccount = Account::from(user_with_subaccount.owner);

        assert_eq!(
            derivation_path(&user_with_subaccount),
            vec![
                vec![1],
                b"doge".to_vec(),
                hex::decode("02caa39141990a89286d5842d846fe4bad561c3acdce7d5f4419cdea02").unwrap(),
                hex::decode("2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a")
                    .unwrap(),
            ]
        );
        let derived_public_key = derive_public_key(&canister_public_key, &user_with_subaccount);
        assert_eq!(
            derived_public_key.to_vec(),
            hex::decode("03e62317d6e4feb57c8d5face3f16d26abbc30609e9abd38fc8c7e3f04502f36cc")
                .unwrap()
        );
        let derived_address = DogecoinAddress::from_compressed_public_key(&derived_public_key);
        assert_eq!(
            derived_address.display(&Network::Mainnet),
            "DSdZym6ZBa4QNPnE7jpuryF6fRtVmvGgre"
        );
        assert_eq!(
            derived_address.display(&Network::Regtest),
            "n31RjZEthBbNcW5F6ioj98HpeHkuJsPBJm"
        );

        assert_eq!(
            derivation_path(&user_without_subaccount),
            vec![
                vec![1],
                b"doge".to_vec(),
                hex::decode("02caa39141990a89286d5842d846fe4bad561c3acdce7d5f4419cdea02").unwrap(),
                hex::decode("0000000000000000000000000000000000000000000000000000000000000000")
                    .unwrap(),
            ]
        );
        let derived_public_key = derive_public_key(&canister_public_key, &user_without_subaccount);
        assert_eq!(
            derived_public_key.to_vec(),
            hex::decode("02db987e631a12327a64695d96f7efaf355554633f8cdc37e1570a97b303cb8de8")
                .unwrap()
        );
        let derived_address = DogecoinAddress::from_compressed_public_key(&derived_public_key);
        assert_eq!(
            derived_address.display(&Network::Mainnet),
            "D7BZ4HNX9W1KSYv8gXi6yTSRg8Zwh6AFKw"
        );
        assert_eq!(
            derived_address.display(&Network::Regtest),
            "mhZQp5Wrf7YHgfD9fWgvFcV9ezSMJeHaNC"
        );
    }
}
