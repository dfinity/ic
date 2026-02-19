use candid::encode_args;
use candid::Principal;
use ic_vetkeys_example_encrypted_chat_backend::types::*;
use rand::seq::SliceRandom;
use rand::Rng;

mod common;
use common::*;

/// This test ensures that the minimum value of the ChatId enum is the direct chat with the management canister as both participants.
#[test]
fn test_chat_id_min_value() {
    assert_eq!(
        ChatId::MIN_VALUE,
        ChatId::Direct(DirectChatId::new((
            Principal::management_canister(),
            Principal::management_canister(),
        )))
    );

    assert!(ChatId::MIN_VALUE < ChatId::Group(GroupChatId(0)));

    // modify this test if more enum variants are added
    match ChatId::MIN_VALUE {
        ChatId::Direct(_) => {}
        ChatId::Group(_) => {}
    };
}

#[test]
fn can_create_many_chats() {
    let rng = &mut reproducible_rng();
    let env = TestEnvironment::new(rng);

    let mut num_group_chats = 0;
    let mut num_direct_chats = 0;

    let participants = (0..10)
        .map(|_| random_self_authenticating_principal(rng))
        .collect::<Vec<_>>();

    let mut expected_chat_ids = std::collections::BTreeMap::new();

    while num_group_chats < 10 || num_direct_chats < 10 {
        let direct = rng.random_bool(0.5);

        if direct {
            let p_0 = participants[0];
            let p_1 = participants[rng.random_range(0..participants.len())];

            let chat_id = ChatId::Direct(DirectChatId::new((p_0, p_1)));
            if expected_chat_ids.insert((p_0, chat_id), ()).is_some() {
                continue;
            }
            expected_chat_ids.insert((p_1, chat_id), ());

            env.update::<Result<Time, String>>(
                p_0,
                "create_direct_chat",
                encode_args((p_1, Time(1_000), Time(10_000))).unwrap(),
            )
            .unwrap();

            num_direct_chats += 1;
        } else {
            let number_of_participants = rng.random_range(1..5);
            let mut invited_participants = participants.clone();
            invited_participants.shuffle(rng);
            invited_participants.truncate(number_of_participants);
            let group_creator = invited_participants.split_off(0);

            if group_creator[0] != participants[0]
                && !invited_participants.contains(&participants[0])
            {
                invited_participants.push(participants[0].clone());
            }

            let chat_id = ChatId::Group(GroupChatId(num_group_chats));

            assert!(expected_chat_ids
                .insert((group_creator[0], chat_id), ())
                .is_none());
            for p in invited_participants.clone() {
                assert!(expected_chat_ids.insert((p, chat_id), ()).is_none());
            }

            env.update::<Result<GroupChatMetadata, String>>(
                group_creator[0],
                "create_group_chat",
                encode_args((invited_participants, Time(1_000), Time(10_000))).unwrap(),
            )
            .unwrap();

            num_group_chats += 1;
        }

        for p in participants.clone() {
            let my_chat_ids = env.query::<Vec<(ChatId, ChatMessageId)>>(
                p,
                "get_my_chat_ids",
                encode_args(()).unwrap(),
            );

            let expected_chat_ids = expected_chat_ids
                .range((p, ChatId::MIN_VALUE)..)
                .take_while(|(key, _)| key.0 == p)
                .map(|(key, _value)| (key.1, ChatMessageId(0)))
                .collect::<Vec<_>>();

            assert_eq!(my_chat_ids, expected_chat_ids);
        }

        let p0_chat_ids = env.query::<Vec<(ChatId, ChatMessageId)>>(
            participants[0],
            "get_my_chat_ids",
            encode_args(()).unwrap(),
        );

        assert_eq!(p0_chat_ids.len() as u64, num_group_chats + num_direct_chats);
    }
}
