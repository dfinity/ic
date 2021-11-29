use canister_test::*;
use dfn_candid::{candid, candid_one, CandidOne};
use dfn_protobuf::protobuf;
use ic_canister_client::Sender;
use ic_types::{CanisterId, PrincipalId};
use ledger_canister::{
    AccountBalanceArgs, AccountIdentifier, ArchiveOptions, BinaryAccountBalanceArgs, Block,
    BlockArg, BlockHeight, BlockRes, EncodedBlock, GetBlocksArgs, GetBlocksRes, IterBlocksArgs,
    IterBlocksRes, LedgerCanisterInitPayload, Memo, NotifyCanisterArgs, Operation, SendArgs,
    Subaccount, TimeStamp, Tokens, TotalSupplyArgs, Transaction, TransferArgs, TransferError,
    MIN_BURN_AMOUNT, TRANSACTION_FEE,
};
use on_wire::IntoWire;
use std::collections::{HashMap, HashSet};
use std::convert::TryFrom;
use std::time::{Duration, SystemTime};

fn create_sender(i: u64) -> ic_canister_client::Sender {
    use rand_chacha::ChaChaRng;
    use rand_core::SeedableRng;
    let keypair = {
        let mut rng = ChaChaRng::seed_from_u64(i);
        ed25519_dalek::Keypair::generate(&mut rng)
    };
    ic_canister_client::Sender::from_keypair(&keypair)
}

// So we can get the size of EncodedBlock
fn example_block() -> Block {
    let transaction = Transaction::new(
        AccountIdentifier::new(CanisterId::from_u64(1).get(), None),
        AccountIdentifier::new(CanisterId::from_u64(2).get(), None),
        Tokens::new(10000, 50).unwrap(),
        TRANSACTION_FEE,
        Memo(456),
        TimeStamp::new(2_000_000_000, 123_456_789),
    );
    Block::new_from_transaction(None, transaction, TimeStamp::new(1, 1))
}

async fn simple_send(
    ledger: &Canister<'_>,
    to: &Sender,
    from: &Sender,
    amount_e8s: u64,
    fee_e8s: u64,
) -> Result<BlockHeight, String> {
    ledger
        .update_from_sender(
            "send_pb",
            protobuf,
            SendArgs {
                memo: Memo::default(),
                amount: Tokens::from_e8s(amount_e8s),
                fee: Tokens::from_e8s(fee_e8s),
                from_subaccount: None,
                to: to.get_principal_id().into(),
                created_at_time: None,
            },
            from,
        )
        .await
}

async fn query_balance(ledger: &Canister<'_>, acc: &Sender) -> Result<Tokens, String> {
    ledger
        .query_(
            "account_balance_pb",
            protobuf,
            AccountBalanceArgs {
                account: acc.get_principal_id().into(),
            },
        )
        .await
}

async fn account_balance_candid(ledger: &Canister<'_>, acc: &AccountIdentifier) -> Tokens {
    ledger
        .query_(
            "account_balance",
            candid_one,
            BinaryAccountBalanceArgs {
                account: acc.to_address(),
            },
        )
        .await
        .expect("failed to query balance")
}

async fn transfer_candid(
    ledger: &Canister<'_>,
    from: &Sender,
    args: TransferArgs,
) -> Result<BlockHeight, TransferError> {
    ledger
        .update_from_sender("transfer", candid_one, args, from)
        .await
        .expect("transfer call trapped")
}

fn make_accounts(num_accounts: u64, num_subaccounts: u8) -> HashMap<AccountIdentifier, Tokens> {
    (1..=num_accounts)
        .flat_map(|i| {
            let pid = CanisterId::from_u64(i).get();
            (1..=num_subaccounts).map(move |j| {
                let subaccount: [u8; 32] = [j; 32];
                (
                    AccountIdentifier::new(pid, Some(Subaccount(subaccount))),
                    Tokens::from_e8s(i * j as u64),
                )
            })
        })
        .collect()
}

#[test]
fn upgrade_test() {
    local_test_e(|r| async move {
        let proj = Project::new(env!("CARGO_MANIFEST_DIR"));

        let accounts = make_accounts(5, 4);

        let mut ledger = proj
            .cargo_bin("ledger-canister")
            .install_(
                &r,
                CandidOne(LedgerCanisterInitPayload::new(
                    CanisterId::from_u64(0).into(),
                    accounts,
                    None,
                    None,
                    None,
                    HashSet::new(),
                )),
            )
            .await?;

        let GetBlocksRes(blocks_before) = ledger
            .query_("get_blocks_pb", protobuf, GetBlocksArgs::new(0u64, 20usize))
            .await?;
        let blocks_before = blocks_before.unwrap();

        ledger.upgrade_to_self_binary(Vec::new()).await?;

        let GetBlocksRes(blocks_after) = ledger
            .query_("get_blocks_pb", protobuf, GetBlocksArgs::new(0u64, 20usize))
            .await?;
        let blocks_after = blocks_after.unwrap();

        assert_eq!(blocks_before, blocks_after);
        Ok(())
    })
}

#[test]
fn archive_blocks_small_test() {
    local_test_e(|r| async move {
        let proj = Project::new(env!("CARGO_MANIFEST_DIR"));

        // 12 blocks
        let accounts = make_accounts(4, 3);
        println!("[test] accounts: {:?}", accounts);

        // For this test we will use a tiny node size. This is because
        // we want multiple archive nodes to be created
        let blocks_per_archive_node = 2;
        println!(
            "[test] blocks per archive node: {}",
            blocks_per_archive_node
        );
        // The tiny maximum message size will force archiving one block at a
        // time
        let max_message_size_bytes = 192;
        let node_max_memory_size_bytes =
            example_block().encode().unwrap().size_bytes() * blocks_per_archive_node;
        let archive_options = Some(ArchiveOptions {
            trigger_threshold: 12,
            num_blocks_to_archive: 12,
            node_max_memory_size_bytes: Some(node_max_memory_size_bytes),
            max_message_size_bytes: Some(max_message_size_bytes),
            controller_id: CanisterId::from_u64(876),
        });

        println!("[test] installing ledger canister");
        let minting_account = create_sender(0);

        let ledger: canister_test::Canister = {
            let payload = LedgerCanisterInitPayload {
                minting_account: CanisterId::try_from(minting_account.get_principal_id())
                    .unwrap()
                    .into(),
                initial_values: accounts,
                max_message_size_bytes: Some(max_message_size_bytes),
                transaction_window: None,
                archive_options,
                send_whitelist: HashSet::new(),
            };
            let mut install = proj.cargo_bin("ledger-canister").install(&r);
            install.memory_allocation = Some(128 * 1024 * 1024);
            install.bytes(CandidOne(payload).into_bytes()?).await?
        };
        println!("[test] ledger canister id: {}", ledger.canister_id());

        // We will archive all Blocks from the ledger. Retrieving a copy to
        // compare with archive contents
        let IterBlocksRes(blocks) = ledger
            .query_(
                "iter_blocks_pb",
                protobuf,
                IterBlocksArgs::new(0usize, 128usize),
            )
            .await?;
        println!("[test] retrieved {} blocks", blocks.len());
        assert!(blocks.len() == 12);

        // To trigger archiving me need a send
        println!("[test] calling send() to trigger archiving");
        simple_send(&ledger, &create_sender(12345), &minting_account, 100, 0).await?;

        ledger_assert_num_blocks(&ledger, 1).await;
        let GetBlocksRes(ledger_blocks) = ledger
            .query_("get_blocks_pb", protobuf, GetBlocksArgs::new(12u64, 1usize))
            .await?;
        assert_eq!(ledger_blocks.unwrap().len(), 1);

        // First we get the CanisterId of each archive node that has been
        // created
        println!("[test] retrieving nodes");
        let nodes: Vec<CanisterId> = ledger.query_("get_nodes", dfn_candid::candid, ()).await?;
        // 12 blocks, 2 blocks per archive node = 6 archive nodes
        assert_eq!(nodes.len(), 6, "expected 6 archive nodes");
        println!("[test] retrieved {} nodes: {:?}", nodes.len(), nodes);

        // Then loop over these nodes and fetch all blocks
        let mut blocks_from_archive = vec![];
        for n in nodes {
            println!("[test] retrieving blocks from {}. calling iter_blocks()", n);
            let node = Canister::new(&r, n);
            let IterBlocksRes(mut blocks) = node
                .query_(
                    "iter_blocks_pb",
                    protobuf,
                    IterBlocksArgs::new(0usize, 128usize),
                )
                .await?;
            // Because blocks is emptied by append we need the length for the log message
            let blocks_len = blocks.len();
            blocks_from_archive.append(&mut blocks);
            println!(
                "[test] retrieved {} blocks from node {}. total blocks so far: {}",
                blocks_len,
                n,
                blocks_from_archive.len()
            );
        }

        // Finally check that we retrieved what we have expected
        assert_eq!(blocks_from_archive, blocks);

        Ok(())
    })
}

#[test]
fn archive_blocks_large_test() {
    local_test_e(|r| async move {
        let proj = Project::new(env!("CARGO_MANIFEST_DIR"));

        // 4096 blocks
        let accounts = make_accounts(64, 64);

        let blocks_per_archive_node: usize = 32768;

        // 1 MiB
        let max_message_size_bytes: usize = 1024 * 1024;
        let node_max_memory_size_bytes: usize =
            example_block().encode().unwrap().size_bytes() * blocks_per_archive_node;
        let archive_options = Some(ArchiveOptions {
            trigger_threshold: 64 * 64,
            num_blocks_to_archive: 64 * 64,
            node_max_memory_size_bytes: Some(node_max_memory_size_bytes),
            max_message_size_bytes: Some(max_message_size_bytes),
            controller_id: CanisterId::from_u64(876),
        });

        println!("[test] installing ledger canister");
        let minting_account = create_sender(0);

        let ledger: canister_test::Canister = {
            let payload = LedgerCanisterInitPayload {
                minting_account: CanisterId::try_from(minting_account.get_principal_id())
                    .unwrap()
                    .into(),
                initial_values: accounts,
                max_message_size_bytes: Some(max_message_size_bytes),
                transaction_window: None,
                archive_options,
                send_whitelist: HashSet::new(),
            };
            let mut install = proj.cargo_bin("ledger-canister").install(&r);
            install.memory_allocation = Some(128 * 1024 * 1024);
            install.bytes(CandidOne(payload).into_bytes()?).await?
        };
        println!("[test] ledger canister id: {}", ledger.canister_id());

        // We will archive all Blocks from the ledger. Retrieving a copy to
        // compare with archive contents
        let blocks = {
            let mut blocks = vec![];
            // Need to make multiple queries due to query message size limit
            let blocks_per_query: usize = 8192;
            for i in 0usize..(blocks_per_archive_node / blocks_per_query) - 1 {
                let offset = i * blocks_per_query;
                println!(
                    "[test] retrieving blocks[{}..{}] from the ledger",
                    offset,
                    offset + blocks_per_query
                );
                let IterBlocksRes(mut result) = ledger
                    .query_(
                        "iter_blocks_pb",
                        protobuf,
                        IterBlocksArgs::new(offset, blocks_per_query),
                    )
                    .await?;
                blocks.append(&mut result);
            }
            println!("[test] retrieved {} blocks", blocks.len());
            blocks
        };
        assert_eq!(blocks.len(), 4096, "Expected 4096 blocks.");

        // To trigger archiving me need a send
        println!("[test] calling send() to trigger archiving");
        simple_send(&ledger, &create_sender(12345), &minting_account, 100, 0).await?;

        // Only the last (simple_send) transaction should be on the ledger after
        // archiving blocks
        ledger_assert_num_blocks(&ledger, 1).await;

        // First we get the CanisterId of each archive node that has been
        // created
        println!("[test] retrieving nodes");
        let nodes: Vec<CanisterId> = ledger.query_("get_nodes", dfn_candid::candid, ()).await?;
        assert_eq!(nodes.len(), 1, "expected 1 archive node");
        println!("[test] retrieved {} nodes: {:?}", nodes.len(), nodes);

        // Then loop over these nodes and fetch all blocks
        let mut blocks_from_archive = vec![];
        for n in nodes {
            println!("[test] retrieving blocks from {}. calling iter_blocks()", n);
            let node = Canister::new(&r, n);

            let mut blocks = {
                let mut blocks = vec![];
                // Need to make multiple queries due to query message size limit
                let blocks_per_query: usize = 8192;
                for i in 0usize..blocks_per_archive_node / blocks_per_query {
                    let offset = i * blocks_per_query;
                    println!(
                        "[test] retrieving blocks[{}..{}]",
                        offset,
                        offset + blocks_per_query
                    );
                    let IterBlocksRes(mut result) = node
                        .query_(
                            "iter_blocks_pb",
                            protobuf,
                            IterBlocksArgs::new(offset, blocks_per_query),
                        )
                        .await?;
                    blocks.append(&mut result);
                }
                println!("[test] retrieved {} blocks", blocks.len());
                blocks
            };

            blocks_from_archive.append(&mut blocks);
            println!(
                "[test] blocks retrieved so far from all of the nodes: {}",
                blocks_from_archive.len()
            );
        }

        // Finally check that we retrieved what we have expected
        assert_eq!(blocks_from_archive, blocks);

        Ok(())
    })
}

#[test]
fn notify_timeout_test() {
    local_test_e(|r| async move {
        let proj = Project::new(env!("CARGO_MANIFEST_DIR"));
        let mut accounts = HashMap::new();
        let sender = create_sender(100);
        accounts.insert(
            sender.get_principal_id().into(),
            Tokens::from_tokens(100).unwrap(),
        );

        let test_canister = proj
            .cargo_bin("test-notified")
            .install_(&r, Vec::new())
            .await?;

        let minting_account = create_sender(0);

        let mut send_whitelist = HashSet::new();
        send_whitelist.insert(test_canister.canister_id());

        let ledger_canister = proj
            .cargo_bin("ledger-canister")
            .install_(
                &r,
                CandidOne(LedgerCanisterInitPayload {
                    minting_account: CanisterId::try_from(minting_account.get_principal_id())
                        .unwrap()
                        .into(),
                    initial_values: accounts,
                    max_message_size_bytes: None,
                    // A tiny notification window so notifications will fail
                    transaction_window: Some(Duration::from_millis(1)),
                    archive_options: None,
                    send_whitelist,
                }),
            )
            .await?;

        let block_height: BlockHeight = ledger_canister
            .update_from_sender(
                "send_pb",
                protobuf,
                SendArgs {
                    from_subaccount: None,
                    to: test_canister.canister_id().into(),
                    amount: Tokens::from_tokens(1).unwrap(),
                    fee: TRANSACTION_FEE,
                    memo: Memo(0),
                    created_at_time: None,
                },
                &sender,
            )
            .await?;

        let notify = NotifyCanisterArgs {
            block_height,
            max_fee: TRANSACTION_FEE,
            from_subaccount: None,
            to_canister: test_canister.canister_id(),
            to_subaccount: None,
        };

        let r1: Result<(), String> = ledger_canister
            .update_from_sender("notify_pb", protobuf, notify.clone(), &sender)
            .await;

        assert!(
            r1.unwrap_err().contains("that is more than"),
            "Cannot notify after duration"
        );

        Ok(())
    });
}

#[test]
fn notify_test() {
    local_test_e(|r| async move {
        let proj = Project::new(env!("CARGO_MANIFEST_DIR"));
        let mut accounts = HashMap::new();
        let sender = create_sender(100);
        accounts.insert(
            sender.get_principal_id().into(),
            Tokens::from_tokens(100).unwrap(),
        );

        let test_canister = proj
            .cargo_bin("test-notified")
            .install_(&r, Vec::new())
            .await?;

        let test_canister_2 = proj
            .cargo_bin("test-notified")
            .install_(&r, Vec::new())
            .await?;

        let minting_account = create_sender(0);

        let mut send_whitelist = HashSet::new();
        send_whitelist.insert(test_canister.canister_id());

        let (node_max_memory_size_bytes, max_message_size_bytes): (usize, usize) = {
            let blocks_per_archive_node = 8;

            let blocks_per_archive_call = 3;

            let e = example_block().encode().unwrap();
            println!("[test] encoded block size: {}", e.size_bytes());
            (
                e.size_bytes() * blocks_per_archive_node,
                e.size_bytes() * blocks_per_archive_call,
            )
        };

        let archive_options = Some(ArchiveOptions {
            node_max_memory_size_bytes: Some(node_max_memory_size_bytes),
            max_message_size_bytes: Some(max_message_size_bytes),
            controller_id: CanisterId::from_u64(876),
            trigger_threshold: 8,
            num_blocks_to_archive: 3,
        });

        let ledger_canister = proj
            .cargo_bin("ledger-canister")
            .install_(
                &r,
                CandidOne(LedgerCanisterInitPayload {
                    minting_account: CanisterId::try_from(minting_account.get_principal_id())
                        .unwrap()
                        .into(),
                    initial_values: accounts,
                    max_message_size_bytes: Some(max_message_size_bytes),
                    transaction_window: None,
                    archive_options,
                    send_whitelist,
                }),
            )
            .await?;

        let block_height: BlockHeight = ledger_canister
            .update_from_sender(
                "send_pb",
                protobuf,
                SendArgs {
                    from_subaccount: None,
                    to: test_canister.canister_id().into(),
                    amount: Tokens::from_tokens(1).unwrap(),
                    fee: TRANSACTION_FEE,
                    memo: Memo(0),
                    created_at_time: None,
                },
                &sender,
            )
            .await?;

        for i in 1..10 {
            let _: BlockHeight = ledger_canister
                .update_from_sender(
                    "send_pb",
                    protobuf,
                    SendArgs {
                        from_subaccount: None,
                        to: test_canister.canister_id().into(),
                        amount: Tokens::from_e8s(1),
                        fee: TRANSACTION_FEE,
                        memo: Memo(i),
                        created_at_time: None,
                    },
                    &sender,
                )
                .await?;
        }

        let notify = NotifyCanisterArgs {
            block_height,
            max_fee: TRANSACTION_FEE,
            from_subaccount: None,
            to_canister: test_canister.canister_id(),
            to_subaccount: None,
        };

        let r1: Result<(), String> = ledger_canister
            .update_from_sender("notify_pb", protobuf, notify.clone(), &sender)
            .await;

        let r2: Result<(), String> = ledger_canister
            .update_from_sender("notify_dfx", candid_one, notify.clone(), &sender)
            .await;

        let r3: Result<(), String> = ledger_canister
            .update_from_sender("notify_pb", protobuf, notify.clone(), &sender)
            .await;

        let count: u32 = test_canister.query_("check_counter", candid, ()).await?;

        assert_eq!(
            Err(
                "Canister rejected with message: Notification failed with message \'Rejected\'"
                    .to_string()
            ),
            r1
        );

        assert_eq!(r2, Ok(()));

        println!("{:?}", r3);
        // This is vague because it contains stuff like src spans as it's a panic
        assert!(r3
            .unwrap_err()
            .contains("notification state is already true"));

        assert_eq!(2, count);

        // Notification of non whitelisted target should fail
        let block_height: BlockHeight = ledger_canister
            .update_from_sender(
                "send_pb",
                protobuf,
                SendArgs {
                    from_subaccount: None,
                    to: test_canister_2.canister_id().into(),
                    amount: Tokens::from_tokens(1).unwrap(),
                    fee: TRANSACTION_FEE,
                    memo: Memo(0),
                    created_at_time: None,
                },
                &sender,
            )
            .await?;

        let notify_not_whitelisted = NotifyCanisterArgs {
            block_height,
            max_fee: TRANSACTION_FEE,
            from_subaccount: None,
            to_canister: test_canister_2.canister_id(),
            to_subaccount: None,
        };

        let r4: Result<(), String> = ledger_canister
            .update_from_sender("notify_pb", protobuf, notify_not_whitelisted, &sender)
            .await;

        assert!(r4
            .unwrap_err()
            .contains("Notifying non-whitelisted canister is not allowed"));

        Ok(())
    });
}

#[test]
fn sub_account_test() {
    local_test_e(|r| async move {
        let proj = Project::new(env!("CARGO_MANIFEST_DIR"));

        let mut initial_values = HashMap::new();

        let sub_account = |x| Some(Subaccount([x; 32]));

        let sender = create_sender(100);

        initial_values.insert(
            AccountIdentifier::new(sender.get_principal_id(), sub_account(1)),
            Tokens::from_tokens(10).unwrap(),
        );
        let from_subaccount = sub_account(1);
        let mut send_whitelist = HashSet::new();
        send_whitelist.insert(CanisterId::new(sender.get_principal_id()).unwrap());
        let ledger_canister = proj
            .cargo_bin("ledger-canister")
            .install_(
                &r,
                CandidOne(LedgerCanisterInitPayload::new(
                    CanisterId::from_u64(0).into(),
                    initial_values,
                    None,
                    None,
                    None,
                    send_whitelist,
                )),
            )
            .await?;

        // Send a payment to yourself on a different sub_account
        let _: BlockHeight = ledger_canister
            .update_from_sender(
                "send_pb",
                protobuf,
                SendArgs {
                    from_subaccount,
                    to: AccountIdentifier::new(sender.get_principal_id(), sub_account(2)),
                    amount: Tokens::from_tokens(1).unwrap(),
                    fee: TRANSACTION_FEE,
                    memo: Memo(0),
                    created_at_time: None,
                },
                &sender,
            )
            .await?;

        let balance_1 = ledger_canister
            .query_from_sender(
                "account_balance_pb",
                protobuf,
                AccountBalanceArgs {
                    account: AccountIdentifier::new(sender.get_principal_id(), sub_account(1)),
                },
                &sender,
            )
            .await?;

        let balance_2 = ledger_canister
            .query_from_sender(
                "account_balance_pb",
                protobuf,
                AccountBalanceArgs {
                    account: AccountIdentifier::new(sender.get_principal_id(), sub_account(2)),
                },
                &sender,
            )
            .await?;

        // Transaction fees are a pain so we're easy going with equality
        fn is_roughly(a: Tokens, b: Tokens) {
            let one_tenth = Tokens::from_e8s(10_000_000);
            assert!((a + one_tenth).unwrap() > b);
            assert!((a - one_tenth).unwrap() < b);
        }

        is_roughly(balance_1, Tokens::from_tokens(9).unwrap());

        is_roughly(balance_2, Tokens::from_tokens(1).unwrap());

        Ok(())
    })
}

#[test]
#[should_panic(expected = "Sending from 2vxsx-fae is not allowed")]
fn check_anonymous_cannot_send() {
    local_test_e(|r| async move {
        let proj = Project::new(env!("CARGO_MANIFEST_DIR"));
        let sub_account = |x| Some(Subaccount([x; 32]));
        // The principal ID of the test runner
        let us = PrincipalId::new_anonymous();
        let mut initial_values = HashMap::new();
        initial_values.insert(
            AccountIdentifier::new(us, sub_account(1)),
            Tokens::from_tokens(10).unwrap(),
        );

        let ledger_canister = proj
            .cargo_bin("ledger-canister")
            .install_(
                &r,
                CandidOne(LedgerCanisterInitPayload::new(
                    CanisterId::from_u64(0).into(),
                    initial_values,
                    None,
                    None,
                    None,
                    HashSet::new(),
                )),
            )
            .await?;

        // Send a payment from an anonymous user, should fail
        let _: BlockHeight = ledger_canister
            .update_(
                "send_pb",
                protobuf,
                SendArgs {
                    from_subaccount: sub_account(1),
                    to: AccountIdentifier::new(us, sub_account(2)),
                    amount: Tokens::from_tokens(1).unwrap(),
                    fee: TRANSACTION_FEE,
                    memo: Memo(0),
                    created_at_time: None,
                },
            )
            .await?;
        Ok(())
    })
}

#[test]
fn transaction_test() {
    local_test_e(|r| async move {
        let proj = Project::new(env!("CARGO_MANIFEST_DIR"));

        let minting_account = create_sender(0);
        let acc1 = create_sender(1);
        let acc2 = create_sender(2);

        // Amount is the send amount + the fee + the amount we burn
        let acc1_start_amount = 500 + TRANSACTION_FEE.get_e8s();
        let acc2_start_amount = MIN_BURN_AMOUNT.get_e8s();

        let mut accounts = HashMap::new();
        accounts.insert(
            acc1.get_principal_id().into(),
            Tokens::from_e8s(acc1_start_amount),
        );
        accounts.insert(
            acc2.get_principal_id().into(),
            Tokens::from_e8s(acc2_start_amount),
        );

        let ledger = proj
            .cargo_bin("ledger-canister")
            .install_(
                &r,
                CandidOne(LedgerCanisterInitPayload::new(
                    CanisterId::try_from(minting_account.get_principal_id())
                        .unwrap()
                        .into(),
                    accounts,
                    None,
                    None,
                    None,
                    HashSet::new(),
                )),
            )
            .await?;

        let acc1_balance = query_balance(&ledger, &acc1).await?;
        assert_eq!(acc1_balance.get_e8s(), acc1_start_amount);

        let acc2_balance = query_balance(&ledger, &acc2).await?;
        assert_eq!(acc2_balance.get_e8s(), acc2_start_amount);

        let supply: Tokens = ledger
            .query_("total_supply_pb", protobuf, TotalSupplyArgs {})
            .await?;
        assert_eq!(supply.get_e8s(), acc1_start_amount + acc2_start_amount);

        // perform a mint
        let mint_amount = 100;
        simple_send(&ledger, &acc1, &minting_account, mint_amount, 0).await?;

        let acc1_balance = query_balance(&ledger, &acc1).await?;
        assert_eq!(acc1_balance.get_e8s(), acc1_start_amount + mint_amount);

        let supply: Tokens = ledger
            .query_("total_supply_pb", protobuf, TotalSupplyArgs {})
            .await?;
        assert_eq!(
            supply.get_e8s(),
            acc1_start_amount + acc2_start_amount + mint_amount
        );

        // perform a send
        let send_amount = 500;
        let send_fee = TRANSACTION_FEE.get_e8s();
        simple_send(&ledger, &acc2, &acc1, send_amount, send_fee).await?;

        let acc1_balance = query_balance(&ledger, &acc1).await?;
        assert_eq!(
            acc1_balance.get_e8s(),
            acc1_start_amount + mint_amount - send_amount - send_fee
        );

        let acc2_balance = query_balance(&ledger, &acc2).await?;
        assert_eq!(acc2_balance.get_e8s(), acc2_start_amount + send_amount);

        // perform a burn
        let burn_amount = MIN_BURN_AMOUNT.get_e8s();
        simple_send(&ledger, &minting_account, &acc2, burn_amount, 0).await?;

        let acc2_balance = query_balance(&ledger, &acc2).await?;
        assert_eq!(
            acc2_balance.get_e8s(),
            acc2_start_amount + send_amount - burn_amount
        );

        // invalid transaction
        let invalid_transaction_res =
            simple_send(&ledger, &minting_account, &minting_account, burn_amount, 0).await;
        assert!(invalid_transaction_res.is_err());

        // invalid burn (too little)
        let invalid_burn_res = simple_send(&ledger, &minting_account, &acc2, 3, 0).await;
        assert!(invalid_burn_res.is_err());

        // invalid burn (too much)
        let invalid_burn_res = simple_send(&ledger, &minting_account, &acc2, 3000, 0).await;
        assert!(invalid_burn_res.is_err());

        // invalid send (too much)
        let invalid_send_res = simple_send(&ledger, &acc2, &acc1, 3000, send_fee).await;
        assert!(invalid_send_res.is_err());

        // invalid send (invalid fee)
        let invalid_send_res = simple_send(&ledger, &acc2, &acc1, 1, 0).await;
        assert!(invalid_send_res.is_err());

        let minting_canister_balance = query_balance(&ledger, &minting_account).await?;
        assert_eq!(minting_canister_balance.get_e8s(), 0);

        let blocks: Vec<Block> = {
            let IterBlocksRes(blocks) = ledger
                .query_(
                    "iter_blocks_pb",
                    protobuf,
                    IterBlocksArgs::new(0usize, 100usize),
                )
                .await?;
            blocks.iter().map(|rb| rb.decode().unwrap()).collect()
        };

        let mint_transaction = blocks
            .get(blocks.len() - 3)
            .unwrap()
            .transaction()
            .into_owned()
            .operation;
        let send_transaction = blocks
            .get(blocks.len() - 2)
            .unwrap()
            .transaction()
            .into_owned()
            .operation;
        let burn_transaction = blocks.last().unwrap().transaction().into_owned().operation;

        assert_eq!(
            mint_transaction,
            Operation::Mint {
                to: acc1.get_principal_id().into(),
                amount: Tokens::from_e8s(mint_amount)
            }
        );

        assert_eq!(
            send_transaction,
            Operation::Transfer {
                from: acc1.get_principal_id().into(),
                to: acc2.get_principal_id().into(),
                amount: Tokens::from_e8s(send_amount),
                fee: Tokens::from_e8s(send_fee)
            }
        );

        assert_eq!(
            burn_transaction,
            Operation::Burn {
                from: acc2.get_principal_id().into(),
                amount: Tokens::from_e8s(burn_amount)
            }
        );

        Ok(())
    })
}

// Verify that block() can fetch blocks regardless of whether they are stored
// in the ledger itself, or in the archive. To do this we create 32 blocks,
// fetch them all from the ledger using repeated calls to block(), then archive
// all of them, and then fetch the blocks again, this time from the archive,
// using the same repeated block() calls. The results before and after
// archiving should be identical. Furthermore, multiple archive nodes should be
// created during this test.
#[test]
fn get_block_test() {
    local_test_e(|r| async move {
        let proj = Project::new(env!("CARGO_MANIFEST_DIR"));

        // For printing and comparing blocks since they're now hidden behind a
        // trait
        let blk = |b: &ledger_canister::Block| (b.transaction().into_owned(), b.timestamp());

        let minting_account = create_sender(0);

        // This is how many blocks we want to generate for this test.
        // Generating blocks is done by proxy, that is, by creating multiple
        // accounts (since each account will generate a Mint transaction).
        let num_blocks = 32u64;

        // Generate initial blocks just below the archive threshold
        let accounts = make_accounts(num_blocks - 1, 1);

        // With a target of 32 accounts and 8 blocks per archive we should
        // generate multiple archive nodes
        let blocks_per_archive_node: usize = 8;

        let max_message_size_bytes: usize = 1024 * 1024;
        let node_max_memory_size_bytes: usize = {
            let e = example_block().encode().unwrap();
            println!("[test] encoded block size: {}", e.size_bytes());
            e.size_bytes() * blocks_per_archive_node
        };
        let archive_init_args = ArchiveOptions {
            trigger_threshold: 32,
            num_blocks_to_archive: 32,
            node_max_memory_size_bytes: Some(node_max_memory_size_bytes),
            max_message_size_bytes: Some(max_message_size_bytes),
            controller_id: CanisterId::from_u64(876),
        };

        println!(
            "[test] installing ledger canister with {} accounts",
            accounts.len()
        );
        let ledger: canister_test::Canister = {
            let payload = LedgerCanisterInitPayload::new(
                CanisterId::try_from(minting_account.get_principal_id())
                    .unwrap()
                    .into(),
                accounts,
                Some(archive_init_args),
                Some(max_message_size_bytes),
                None,
                HashSet::new(),
            );
            let mut install = proj.cargo_bin("ledger-canister").install(&r);
            install.memory_allocation = Some(128 * 1024 * 1024);
            install.bytes(CandidOne(payload).into_bytes()?).await?
        };
        println!("[test] ledger canister id: {}", ledger.canister_id());

        // Fetch some blocks using block() while they're still inside Ledger.
        // Later on we will archive them all and then block() has to
        // fetch them from Archive
        let mut blocks_from_ledger_before_archive = vec![];
        for i in 0..num_blocks - 1 {
            let BlockRes(block) = ledger.query_("block_pb", protobuf, i).await?;
            // Since blocks are still in the Ledger we should get Some(Ok(block))
            let block = block
                .unwrap()
                .unwrap()
                .decode()
                .expect("unable to decode block");
            blocks_from_ledger_before_archive.push(blk(&block))
        }

        // To trigger archiving me need a send. This will create the 32nd block
        println!("[test] calling send() to trigger archiving");
        simple_send(&ledger, &create_sender(12345), &minting_account, 100, 0).await?;

        // Make sure Ledger is empty after archiving blocks
        ledger_assert_num_blocks(&ledger, 0).await;

        // Assert that we have created multiple nodes. We want to make sure
        // ledger.block() seamlessly fetches Blocks from any node
        ledger_assert_num_nodes(&ledger, 4).await;

        let mut blocks_from_archive: Vec<(Transaction, TimeStamp)> = vec![];
        for i in 0..num_blocks {
            let block = {
                let BlockRes(result) = ledger.query_("block_pb", protobuf, BlockArg(i)).await?;
                // Since blocks are now in the archive we should get Some(Err(canister_id))
                let canister_id: CanisterId = result.unwrap().unwrap_err();
                let node: Canister = Canister::new(&r, canister_id);
                let BlockRes(block) = node.query_("get_block_pb", protobuf, BlockArg(i)).await?;
                // We should get Some(Ok(block))
                let block = block.expect("block not found in the archive node").unwrap();
                block.decode().unwrap()
            };
            println!("[test] retrieved block: {:?}", blk(&block));
            blocks_from_archive.push(blk(&block))
        }

        // We have copied the blocks before triggering archiving with a send.
        // Thus, our copy doesn't have that final block which triggered
        // archiving. We add it here so we can easily compare the results.
        blocks_from_ledger_before_archive.push(blocks_from_archive.last().unwrap().clone());
        assert_eq!(blocks_from_archive, blocks_from_ledger_before_archive);

        // Generate more blocks to almost trigger another archiving operation
        println!("[test] generating additional blocks");
        let acc1 = create_sender(1001);
        for _ in 0..num_blocks - 1 {
            simple_send(&ledger, &acc1, &minting_account, 9999, 0).await?;
        }

        // And fetch the first of the new blocks from from the ledger
        let block_index: u64 = num_blocks;
        let BlockRes(block_from_ledger) = ledger
            .query_("block_pb", protobuf, BlockArg(block_index))
            .await?;
        let block_from_ledger = block_from_ledger.unwrap().unwrap().decode().unwrap();
        println!(
            "[test] retrieved block [{}]: {:?}",
            block_index,
            blk(&block_from_ledger)
        );

        // Then, generate one final block to trigger archiving
        println!("[test] generating one more block to trigger archiving");
        simple_send(&ledger, &acc1, &minting_account, 9999, 0).await?;

        // Again, make sure Ledger is empty after archiving blocks
        ledger_assert_num_blocks(&ledger, 0).await;

        // And fetch the block again, at the same index, this time from the
        // archive
        let block_from_archive: EncodedBlock = {
            let BlockRes(result) = ledger
                .query_("block_pb", protobuf, BlockArg(block_index))
                .await?;
            // Since the block is now in the archive we should get Some(Err(canister_id))
            let canister_id: CanisterId = result.unwrap().unwrap_err();
            // So we need to fetch it from archive canister directly
            let node: Canister = Canister::new(&r, canister_id);
            let BlockRes(block) = node
                .query_("get_block_pb", protobuf, BlockArg(block_index))
                .await?;
            block.unwrap().unwrap()
        };
        let block_from_archive = block_from_archive.decode().unwrap();
        println!(
            "[test] retrieved block [{}]: {:?}",
            block_index,
            blk(&block_from_archive)
        );

        assert_eq!(blk(&block_from_ledger), blk(&block_from_archive));

        let ledger_canister::protobuf::ArchiveIndexResponse { entries } =
            ledger.query_("get_archive_index_pb", protobuf, ()).await?;
        println!("[test] archive_index: {:?}", entries);

        Ok(())
    })
}

#[test]
fn get_multiple_blocks_test() {
    local_test_e(|r| async move {
        let proj = Project::new(env!("CARGO_MANIFEST_DIR"));

        let minting_account = create_sender(0);

        // This is how many blocks we want to generate for this test.
        // Generating blocks is done by proxy, that is, by creating multiple
        // accounts (since each account will generate a Mint transaction).
        let num_blocks = 14u64;

        let accounts = make_accounts(num_blocks - 1, 1);

        // For this test we only need two archive nodes to check the range
        // queries. We will start with 14 blocks, so the first archive node
        // will be filled and then some space will be left in the second. Note
        // that the number here is **approximate**
        let blocks_per_archive_node: usize = 8;

        let max_message_size_bytes: usize = 1024 * 1024;
        let node_max_memory_size_bytes: usize = {
            let e = example_block().encode().unwrap();
            println!("[test] encoded block size: {}", e.size_bytes());
            e.size_bytes() * blocks_per_archive_node
        };
        let archive_options = Some(ArchiveOptions {
            trigger_threshold: num_blocks as usize,
            num_blocks_to_archive: num_blocks as usize,
            node_max_memory_size_bytes: Some(node_max_memory_size_bytes),
            max_message_size_bytes: Some(max_message_size_bytes),
            controller_id: CanisterId::from_u64(876),
        });

        println!(
            "[test] installing ledger canister with {} accounts",
            accounts.len()
        );
        let ledger: canister_test::Canister = {
            let payload = LedgerCanisterInitPayload::new(
                CanisterId::try_from(minting_account.get_principal_id())
                    .unwrap()
                    .into(),
                accounts,
                archive_options,
                Some(max_message_size_bytes),
                None,
                HashSet::new(),
            );
            let mut install = proj.cargo_bin("ledger-canister").install(&r);
            install.memory_allocation = Some(128 * 1024 * 1024);
            install.bytes(CandidOne(payload).into_bytes()?).await?
        };
        println!("[test] ledger canister id: {}", ledger.canister_id());

        let node: Canister = {
            // To trigger archiving me need a send
            println!("[test] calling send() to trigger archiving");
            simple_send(&ledger, &create_sender(12345), &minting_account, 100, 0).await?;

            // Make sure Ledger is empty after archiving blocks
            ledger_assert_num_blocks(&ledger, 0).await;

            // There should be two nodes
            let nodes: Vec<CanisterId> = ledger_assert_num_nodes(&ledger, 2).await;
            // We are interested in the second node which still has some empty
            // space
            Canister::new(&r, nodes[1])
        };

        // Blocks [0 .. 8] (inclusive) are stored in node [0]. Remaining five
        // blocks in node [1] are those with BlockHeights 9, 10, 11, 12 and 13

        // Query Blocks 10 and 11
        {
            println!("[test] querying blocks 10 and 11");
            let GetBlocksRes(blocks_from_node) = node
                .query_("get_blocks_pb", protobuf, GetBlocksArgs::new(10u64, 2usize))
                .await?;

            let blocks_from_node: Vec<EncodedBlock> = blocks_from_node.unwrap();
            assert!(blocks_from_node.len() == 2);
        }

        // Query Blocks 11 and 12
        {
            println!("[test] querying blocks 11 and 12");
            let GetBlocksRes(blocks_from_node) = node
                .query_("get_blocks_pb", protobuf, GetBlocksArgs::new(11u64, 2usize))
                .await?;

            let blocks_from_node: Vec<EncodedBlock> = blocks_from_node.unwrap();
            assert!(blocks_from_node.len() == 2);
        }

        // Query Blocks 12 and 13
        {
            println!("[test] querying blocks 12 and 13");
            let GetBlocksRes(blocks_from_node) = node
                .query_("get_blocks_pb", protobuf, GetBlocksArgs::new(11u64, 2usize))
                .await?;

            let blocks_from_node: Vec<EncodedBlock> = blocks_from_node.unwrap();
            assert!(blocks_from_node.len() == 2);
        }

        // Query all blocks
        {
            println!("[test] querying all blocks");
            let GetBlocksRes(blocks_from_node) = node
                .query_("get_blocks_pb", protobuf, GetBlocksArgs::new(9u64, 5usize))
                .await?;

            let blocks_from_node: Vec<EncodedBlock> = blocks_from_node.unwrap();
            assert!(blocks_from_node.len() == 5);
        }

        // And some invalid queries
        println!("[test] testing invalid queries to the archive node");
        {
            // outside range left
            let GetBlocksRes(blocks_from_node) = node
                .query_("get_blocks_pb", protobuf, GetBlocksArgs::new(8u64, 2usize))
                .await?;
            assert!(blocks_from_node.is_err());

            // outside range right
            let GetBlocksRes(blocks_from_node) = node
                .query_("get_blocks_pb", protobuf, GetBlocksArgs::new(10u64, 5usize))
                .await?;
            assert!(blocks_from_node.is_err());

            // outside range both sides
            let GetBlocksRes(blocks_from_node) = node
                .query_("get_blocks_pb", protobuf, GetBlocksArgs::new(8u64, 6usize))
                .await?;
            assert!(blocks_from_node.is_err());
        }

        println!("[test] generating additional blocks in the ledger");
        // Generate additional blocks. These should have heights 14 and 15
        let acc1 = create_sender(1001);
        simple_send(&ledger, &acc1, &minting_account, 9999, 0).await?;
        let acc2 = create_sender(1002);
        simple_send(&ledger, &acc2, &minting_account, 8888, 0).await?;

        {
            println!("[test] querying blocks from the ledger");
            // Fetch 2 blocks beginning at BlockHeight 14 from the ledger
            let GetBlocksRes(blocks_from_ledger) = ledger
                .query_("get_blocks_pb", protobuf, GetBlocksArgs::new(14u64, 2usize))
                .await?;
            let blocks_from_ledger = blocks_from_ledger.unwrap();
            assert!(
                blocks_from_ledger.len() == 2,
                "Expected Blocks 14 and 15 to be in the Ledger"
            );

            println!("[test] testing invalid queries to the ledger");
            // And some invalid queries
            let GetBlocksRes(blocks_from_ledger) = ledger
                .query_("get_blocks_pb", protobuf, GetBlocksArgs::new(10u64, 2usize))
                .await?;
            assert!(blocks_from_ledger.is_err());

            let GetBlocksRes(blocks_from_ledger) = ledger
                .query_("get_blocks_pb", protobuf, GetBlocksArgs::new(14u64, 3usize))
                .await?;
            assert!(blocks_from_ledger.is_err());

            let GetBlocksRes(blocks_from_ledger) = ledger
                .query_("get_blocks_pb", protobuf, GetBlocksArgs::new(13u64, 2usize))
                .await?;
            assert!(blocks_from_ledger.is_err());

            let GetBlocksRes(blocks_from_ledger) = ledger
                .query_("get_blocks_pb", protobuf, GetBlocksArgs::new(13u64, 7usize))
                .await?;
            assert!(blocks_from_ledger.is_err());
        }

        Ok(())
    })
}

#[test]
fn only_ledger_can_append_blocks_to_archive_nodes() {
    local_test_e(|r| async move {
        let proj = Project::new(env!("CARGO_MANIFEST_DIR"));

        let minting_account = create_sender(0);

        let num_blocks = 8u64;

        let accounts = make_accounts(num_blocks, 1);

        let blocks_per_archive_node: usize = 128;

        let node_max_memory_size_bytes: usize = {
            let e = example_block().encode().unwrap();
            println!("[test] encoded block size: {}", e.size_bytes());
            e.size_bytes() * blocks_per_archive_node
        };

        let max_message_size_bytes: usize = 1024 * 1024;

        let archive_options = Some(ArchiveOptions {
            trigger_threshold: num_blocks as usize,
            num_blocks_to_archive: num_blocks as usize,
            node_max_memory_size_bytes: Some(node_max_memory_size_bytes),
            max_message_size_bytes: Some(max_message_size_bytes),
            controller_id: CanisterId::from_u64(876),
        });

        println!(
            "[test] installing ledger canister with {} accounts",
            accounts.len()
        );
        let ledger: canister_test::Canister = {
            let payload = LedgerCanisterInitPayload::new(
                CanisterId::try_from(minting_account.get_principal_id())
                    .unwrap()
                    .into(),
                accounts,
                archive_options,
                Some(max_message_size_bytes),
                None,
                HashSet::new(),
            );
            let mut install = proj.cargo_bin("ledger-canister").install(&r);
            install.memory_allocation = Some(128 * 1024 * 1024);
            install.bytes(CandidOne(payload).into_bytes()?).await?
        };
        println!("[test] ledger canister id: {}", ledger.canister_id());

        // To trigger archiving me need a send
        println!("[test] calling send() to trigger archiving");
        simple_send(&ledger, &create_sender(12345), &minting_account, 100, 0).await?;

        // Check that only the Archive Canister can append blocks to a Node
        // canister
        {
            println!(
                "[test] checking that only ledger canister can append blocks to a node canister"
            );

            // Create a non-ledger sender
            let sender = create_sender(1234);

            let ledger_canister::protobuf::ArchiveIndexResponse { entries } =
                ledger.query_("get_archive_index_pb", protobuf, ()).await?;

            let node_canister_id = CanisterId::try_from(entries[0].canister_id.unwrap()).unwrap();
            let node: Canister = Canister::new(&r, node_canister_id);

            // Try appending blocks. We don't need any blocks (empty vector is
            // fine). Just need to send the message.
            let result: Result<(), String> = node
                .update_from_sender(
                    "append_blocks",
                    dfn_candid::candid_one,
                    Vec::<EncodedBlock>::new(),
                    &sender,
                )
                .await;

            // It should've failed
            assert!(
                result.is_err(),
                "Appending blocks from non-Ledger sender should not have succeeded"
            );
        }

        Ok(())
    })
}

#[test]
fn test_transfer_candid() {
    local_test_e(|r| async move {
        let proj = Project::new(env!("CARGO_MANIFEST_DIR"));

        let minting_account = create_sender(0);
        let acc1 = create_sender(1);
        let acc2 = create_sender(2);
        let acc3 = create_sender(3);

        let acc1_address: AccountIdentifier = acc1.get_principal_id().into();
        let acc2_address: AccountIdentifier = acc2.get_principal_id().into();
        let acc3_address: AccountIdentifier = acc3.get_principal_id().into();

        let mut accounts = HashMap::new();
        accounts.insert(acc1_address, Tokens::from_e8s(1_000_000_000));
        accounts.insert(acc2_address, Tokens::from_e8s(1_000_000_000));

        let ledger = proj
            .cargo_bin("ledger-canister")
            .install_(
                &r,
                CandidOne(LedgerCanisterInitPayload::new(
                    CanisterId::try_from(minting_account.get_principal_id())
                        .unwrap()
                        .into(),
                    accounts,
                    None,
                    None,
                    None,
                    HashSet::new(),
                )),
            )
            .await?;

        assert_eq!(
            account_balance_candid(&ledger, &acc1_address).await,
            Tokens::from_e8s(1_000_000_000)
        );
        assert_eq!(
            account_balance_candid(&ledger, &acc2_address).await,
            Tokens::from_e8s(1_000_000_000)
        );
        assert_eq!(
            account_balance_candid(&ledger, &acc3_address).await,
            Tokens::ZERO
        );

        let timestamp_nanos = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;

        const NANOS_PER_YEAR: u64 = 365 * 24 * 3600 * 1_000_000_000;

        let transfer_block = transfer_candid(
            &ledger,
            &acc1,
            TransferArgs {
                memo: Memo(0),
                amount: Tokens::from_e8s(10_000_000),
                fee: Tokens::from_e8s(10_000),
                from_subaccount: None,
                to: acc2_address.to_address(),
                created_at_time: Some(TimeStamp { timestamp_nanos }),
            },
        )
        .await
        .expect("failed to transfer funds");

        assert_eq!(
            account_balance_candid(&ledger, &acc1_address).await,
            Tokens::from_e8s(989_990_000)
        );
        assert_eq!(
            account_balance_candid(&ledger, &acc2_address).await,
            Tokens::from_e8s(1_010_000_000)
        );

        // Test error cases
        assert_eq!(
            transfer_candid(
                &ledger,
                &acc1,
                TransferArgs {
                    memo: Memo(0),
                    amount: Tokens::from_e8s(10_000_000),
                    fee: Tokens::from_e8s(10_000),
                    from_subaccount: None,
                    to: acc2_address.to_address(),
                    created_at_time: Some(TimeStamp { timestamp_nanos }),
                },
            )
            .await,
            Err(TransferError::TxDuplicate {
                duplicate_of: transfer_block
            })
        );

        assert_eq!(
            transfer_candid(
                &ledger,
                &acc3,
                TransferArgs {
                    memo: Memo(0),
                    amount: Tokens::from_e8s(10_000_000),
                    fee: Tokens::from_e8s(10_000),
                    from_subaccount: None,
                    to: acc2_address.to_address(),
                    created_at_time: None,
                },
            )
            .await,
            Err(TransferError::InsufficientFunds {
                balance: Tokens::ZERO
            })
        );

        assert_eq!(
            transfer_candid(
                &ledger,
                &acc3,
                TransferArgs {
                    memo: Memo(0),
                    amount: Tokens::from_e8s(10_000_000),
                    fee: Tokens::from_e8s(10),
                    from_subaccount: None,
                    to: acc1_address.to_address(),
                    created_at_time: None,
                },
            )
            .await,
            Err(TransferError::BadFee {
                expected_fee: Tokens::from_e8s(10_000),
            })
        );

        assert_eq!(
            transfer_candid(
                &ledger,
                &acc1,
                TransferArgs {
                    memo: Memo(0),
                    amount: Tokens::from_e8s(10_000_000),
                    fee: Tokens::from_e8s(10_000),
                    from_subaccount: None,
                    to: acc2_address.to_address(),
                    created_at_time: Some(TimeStamp {
                        timestamp_nanos: timestamp_nanos.saturating_sub(NANOS_PER_YEAR)
                    }),
                },
            )
            .await,
            Err(TransferError::TxTooOld {
                allowed_window_nanos: Duration::from_secs(24 * 3600).as_nanos() as u64,
            })
        );

        assert_eq!(
            transfer_candid(
                &ledger,
                &acc1,
                TransferArgs {
                    memo: Memo(0),
                    amount: Tokens::from_e8s(10_000_000),
                    fee: Tokens::from_e8s(10_000),
                    from_subaccount: None,
                    to: acc2_address.to_address(),
                    created_at_time: Some(TimeStamp {
                        timestamp_nanos: timestamp_nanos.saturating_add(NANOS_PER_YEAR)
                    }),
                },
            )
            .await,
            Err(TransferError::TxCreatedInFuture)
        );

        Ok(())
    });
}

async fn ledger_assert_num_blocks(ledger: &Canister<'_>, num_expected: usize) {
    let IterBlocksRes(blocks) = ledger
        .query_(
            "iter_blocks_pb",
            protobuf,
            IterBlocksArgs::new(0usize, 99999usize),
        )
        .await
        .unwrap();
    println!("[test] retrieved {} blocks from ledger", blocks.len());
    assert_eq!(blocks.len(), num_expected);
}

// Helper function to assert the number of Archive Nodes. Also, returns
// CanisterId's for convenience.
async fn ledger_assert_num_nodes(ledger: &Canister<'_>, num_expected: usize) -> Vec<CanisterId> {
    let nodes: Vec<CanisterId> = ledger
        .update_("get_nodes", dfn_candid::candid, ())
        .await
        .unwrap();
    println!("[test] retrieved {} archive nodes", nodes.len());
    assert_eq!(nodes.len(), num_expected);
    nodes
}

#[test]
fn call_with_cleanup() {
    local_test_e(|r| async move {
        let proj = Project::new(env!("CARGO_MANIFEST_DIR"));

        let test_canister = proj
            .cargo_bin("test-notified")
            .install_(&r, Vec::new())
            .await?;

        // Check the dirty call behaves badly
        let r: Result<(), String> = test_canister.update_("dirty_call", candid, ()).await;
        println!("{:?}", r);
        assert!(r.unwrap_err().contains("Failed successfully"),);

        let r: Result<(), String> = test_canister.update_("dirty_call", candid, ()).await;
        println!("{:?}", r);
        assert_eq!(r, Ok(()));

        let r: Result<(), String> = test_canister.update_("clean_call", candid, ()).await;
        println!("{:?}", r);

        assert!(r.unwrap_err().contains("Failed successfully"));

        let r: Result<(), String> = test_canister.update_("clean_call", candid, ()).await;
        println!("{:?}", r);
        assert!(
            r.unwrap_err().contains("Failed successfully"),
            "The lock was not released so it can't successfully fail"
        );
        Ok(())
    })
}
