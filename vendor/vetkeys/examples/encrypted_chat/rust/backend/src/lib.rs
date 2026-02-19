use candid::Principal;
use ic_cdk::management_canister::{VetKDCurve, VetKDDeriveKeyArgs, VetKDKeyId, VetKDPublicKeyArgs};
use ic_stable_structures::memory_manager::{MemoryId, MemoryManager, VirtualMemory};
use ic_stable_structures::{
    BTreeMap as StableBTreeMap, Cell as StableCell, DefaultMemoryImpl, Storable,
};
use ic_vetkeys::encrypted_maps::EncryptedMaps;
use ic_vetkeys::types::AccessRights;
use sha2::Digest;
use std::borrow::Cow;
use std::cell::RefCell;

pub mod types;
use types::*;

type Memory = VirtualMemory<DefaultMemoryImpl>;

const NANOSECONDS_IN_MINUTE: u64 = 60_000_000_000;

pub static DOMAIN_SEPARATOR_VETKEY_ROTATION: &str = "vetkeys-example-encrypted-chat-rotation";
pub static DOMAIN_SEPARATOR_USER_CACHE: &str = "vetkeys-example-encrypted-chat-user-cache";
pub static DOMAIN_SEPARATOR_VETKEY_RESHARING: &str =
    "vetkeys-example-encrypted-chat-vetkey-resharing";

thread_local! {
    static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> =
        RefCell::new(MemoryManager::init(DefaultMemoryImpl::default()));

    static DIRECT_CHAT_MESSAGES: RefCell<StableBTreeMap<(DirectChatId, ChatMessageId), EncryptedMessage, Memory>> = RefCell::new(StableBTreeMap::init(
        MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(0))),
    ));

    static GROUP_CHAT_MESSAGES: RefCell<StableBTreeMap<(GroupChatId, ChatMessageId), EncryptedMessage, Memory>> = RefCell::new(StableBTreeMap::init(
        MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(1))),
    ));

    static GROUP_CHATS: RefCell<StableBTreeMap<GroupChatId, GroupChatMetadata, Memory>> = RefCell::new(StableBTreeMap::init(
        MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(2))),
    ));

    static CHAT_TO_MESSAGE_COUNTERS: RefCell<StableBTreeMap<ChatId, ChatMessageId, Memory>> = RefCell::new(StableBTreeMap::init(
        MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(3))),
    ));

    static SET_CHAT_AND_SENDER_AND_USER_MESSAGE_ID: RefCell<StableBTreeMap<(ChatId, Sender, Nonce), (), Memory>> = RefCell::new(StableBTreeMap::init(
        MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(4))),
    ));

    static CHAT_TO_VETKEYS_METADATA: RefCell<StableBTreeMap<(ChatId, Time), VetKeyEpochMetadata, Memory>> = RefCell::new(StableBTreeMap::init(
        MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(5))),
    ));

    static CHAT_TO_MESSAGE_EXPIRY_SETTING: RefCell<StableBTreeMap<ChatId, Time, Memory>> = RefCell::new(StableBTreeMap::init(
        MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(6))),
    ));

    static EXPIRING_MESSAGES: RefCell<StableBTreeMap<(Time, ChatId, ChatMessageId), (), Memory>> = RefCell::new(StableBTreeMap::init(
        MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(7))),
    ));

    static EXPIRING_VETKEY_EPOCHS_CACHES: RefCell<StableBTreeMap<(Time, ChatId, Principal),  VetKeyEpochId, Memory>> = RefCell::new(StableBTreeMap::init(
        MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(8))),
    ));

    static USER_TO_CHAT_MAP: RefCell<StableBTreeMap<(Principal, ChatId, VetKeyEpochId), (), Memory>> = RefCell::new(StableBTreeMap::init(
        MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(9))),
    ));

    static RESHARED_VETKEYS: RefCell<StableBTreeMap<(ChatId, VetKeyEpochId, Principal), IbeEncryptedVetKey, Memory>> = RefCell::new(StableBTreeMap::init(
        MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(11))),
    ));

    // Store symmetric key cache in encrypted maps. On a high level, store the cache in:
    //
    // map = ENCRYPTED_MAPS[(caller, "encrypted_chat_cache")]
    // map[SHA256(chat_id || vetkey_epoch_id)] = cache
    //
    // The reason for not storing that data directly is that in encrypted maps, the key is limited to 32 bytes, which is a conservative constant due to the fact that stable structures cannot currently store unbounded data in tuples.
    static ENCRYPTED_MAPS: RefCell<Option<EncryptedMaps<AccessRights>>> = const { RefCell::new(None) };

    static VETKD_KEY_NAME: RefCell<StableCell<String, Memory>> =
        RefCell::new(StableCell::init(MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(12))), String::new()));
}

#[ic_cdk::init]
fn init(key_name: String) {
    VETKD_KEY_NAME.with(|name| {
        name.borrow_mut().set(key_name);
    });

    ENCRYPTED_MAPS.with_borrow_mut(|maps| {
        let x = EncryptedMaps::init(
            DOMAIN_SEPARATOR_USER_CACHE,
            key_id(),
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(13))),
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(14))),
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(15))),
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(16))),
        );
        *maps = Some(x);
    });

    start_expired_cleanup_timer_job_with_interval(24 * 3600);
}

#[ic_cdk::post_upgrade]
fn post_upgrade(key_name: String) {
    init(key_name);
}

#[ic_cdk::update]
fn create_direct_chat(
    receiver: Principal,
    symmetric_key_rotation_duration_minutes: Time,
    message_expiry_time_minutes: Time,
) -> Result<Time, String> {
    let caller = ic_cdk::api::msg_caller();
    let chat_id = ChatId::Direct(DirectChatId::new((caller, receiver)));

    if latest_vetkey_epoch_id(chat_id).is_some() {
        return Err(format!("Chat {chat_id:?} already exists"));
    }

    let now = Time(ic_cdk::api::time());
    const NANOSECONDS_IN_MINUTE: u64 = 60_000_000_000;

    let symmetric_key_rotation_duration = Time(
        symmetric_key_rotation_duration_minutes
            .0
            .checked_mul(NANOSECONDS_IN_MINUTE)
            .ok_or("Overflow: too symmetric key rotation time".to_string())?,
    );

    let todo_remove_1 = CHAT_TO_VETKEYS_METADATA.with_borrow_mut(|metadata| {
        let vetkey_epoch_metadata = VetKeyEpochMetadata {
            epoch_id: VetKeyEpochId(0),
            participants: vec![caller, receiver],
            creation_timestamp: now,
            symmetric_key_rotation_duration,
            messages_start_with_id: ChatMessageId(0),
        };
        metadata.insert((chat_id, now), vetkey_epoch_metadata.clone())
    });
    assert!(todo_remove_1.is_none());

    let todo_remove_2 = CHAT_TO_MESSAGE_COUNTERS
        .with_borrow_mut(|counters| counters.insert(chat_id, ChatMessageId(0)));
    assert!(todo_remove_2.is_none());

    USER_TO_CHAT_MAP.with_borrow_mut(|map| {
        let todo_remove_3 = map.insert((caller, chat_id, VetKeyEpochId(0)), ());
        assert!(todo_remove_3.is_none());
        let todo_remove_4 = map.insert((receiver, chat_id, VetKeyEpochId(0)), ());
        if caller != receiver {
            assert!(todo_remove_4.is_none());
        }
    });

    let expiry_time_nanos = Time(
        message_expiry_time_minutes
            .0
            .checked_mul(NANOSECONDS_IN_MINUTE)
            .ok_or("Overflow: too large expiry time".to_string())?,
    );

    let todo_remove = CHAT_TO_MESSAGE_EXPIRY_SETTING
        .with_borrow_mut(|expiry_settings| expiry_settings.insert(chat_id, expiry_time_nanos));

    assert!(todo_remove.is_none());

    Ok(now)
}

#[ic_cdk::update]
fn create_group_chat(
    other_participants: Vec<Principal>,
    symmetric_key_rotation_duration_minutes: Time,
    message_expiry_time_minutes: Time,
) -> Result<GroupChatMetadata, String> {
    let caller = ic_cdk::api::msg_caller();
    let now = Time(ic_cdk::api::time());

    let chat_id_u64 =
        GROUP_CHATS.with_borrow(|chats| chats.last_key_value().map(|kv| kv.0 .0 + 1).unwrap_or(0));
    let group_chat_id = GroupChatId(chat_id_u64);

    let group_chat_metadata = GroupChatMetadata {
        chat_id: group_chat_id,
        creation_timestamp: now,
    };

    GROUP_CHATS.with_borrow_mut(|chats| {
        let todo_remove = chats.insert(group_chat_id, group_chat_metadata);
        assert!(todo_remove.is_none());
    });

    let chat_id = ChatId::Group(group_chat_id);

    let mut participants: Vec<_> = [caller].into_iter().chain(other_participants).collect();

    participants.sort();

    // ignore duplicates
    participants.dedup();

    let symmetric_key_rotation_duration = Time(
        symmetric_key_rotation_duration_minutes
            .0
            .checked_mul(NANOSECONDS_IN_MINUTE)
            .ok_or("Overflow: too symmetric key rotation time".to_string())?,
    );

    let todo_remove_1 = CHAT_TO_VETKEYS_METADATA.with_borrow_mut(|metadata| {
        let vetkey_epoch_metadata = VetKeyEpochMetadata {
            epoch_id: VetKeyEpochId(0),
            participants: participants.clone(),
            creation_timestamp: now,
            symmetric_key_rotation_duration,
            messages_start_with_id: ChatMessageId(0),
        };
        metadata.insert((chat_id, now), vetkey_epoch_metadata.clone())
    });
    assert!(todo_remove_1.is_none());

    let todo_remove_2 = CHAT_TO_MESSAGE_COUNTERS
        .with_borrow_mut(|counters| counters.insert(chat_id, ChatMessageId(0)));
    assert!(todo_remove_2.is_none());

    USER_TO_CHAT_MAP.with_borrow_mut(|map| {
        for participant in participants.iter().copied() {
            let todo_remove_3 = map.insert((participant, chat_id, VetKeyEpochId(0)), ());
            assert!(todo_remove_3.is_none());
        }
    });

    let expiry_time_nanos = Time(
        message_expiry_time_minutes
            .0
            .checked_mul(NANOSECONDS_IN_MINUTE)
            .ok_or("Overflow: too large expiry time".to_string())?,
    );

    let todo_remove = CHAT_TO_MESSAGE_EXPIRY_SETTING
        .with_borrow_mut(|expiry_settings| expiry_settings.insert(chat_id, expiry_time_nanos));

    assert!(todo_remove.is_none());

    Ok(group_chat_metadata)
}

#[ic_cdk::update]
async fn chat_public_key(chat_id: ChatId, vetkey_epoch_id: VetKeyEpochId) -> serde_bytes::ByteBuf {
    let request = VetKDPublicKeyArgs {
        canister_id: None,
        context: ratchet_context(chat_id, vetkey_epoch_id),
        key_id: key_id(),
    };

    let result = ic_cdk::management_canister::vetkd_public_key(&request)
        .await
        .expect("call to vetkd_derive_key failed");

    result.public_key.into()
}

/// Derives a vetKey for an existing chat or creates a new one if the chat does not exist.
///
/// # Arguments
/// * `chat_id`: The chat to derive a vetKey for.
/// * `opt_vetkey_epoch`: The vetKey epoch to derive a vetKey for. If `None`, a new epoch is created.
/// * `transport_key`: The transport key to derive a vetKey for.
///
/// # Errors
/// * If the vetKey epoch has expired.
/// * If the user does not have access to the chat or vetKey epoch.
/// * If the user has already cached the key.
#[ic_cdk::update]
async fn derive_chat_vetkey(
    chat_id: ChatId,
    opt_vetkey_epoch_id: Option<VetKeyEpochId>,
    transport_key: serde_bytes::ByteBuf,
) -> Result<serde_bytes::ByteBuf, String> {
    let caller = ic_cdk::api::msg_caller();

    let vetkey_epoch_id = opt_vetkey_epoch_id
        .or_else(|| latest_vetkey_epoch_id(chat_id))
        .ok_or_else(|| format!("No chat {chat_id:?} found"))?;

    ensure_chat_and_vetkey_epoch_exist(chat_id, vetkey_epoch_id)?;
    ensure_user_has_access_to_chat_at_epoch(caller, chat_id, vetkey_epoch_id)?;
    ensure_user_has_no_cached_key_for_chat_and_vetkey_epoch(caller, chat_id, vetkey_epoch_id)?;

    let request = VetKDDeriveKeyArgs {
        input: vec![],
        context: ratchet_context(chat_id, vetkey_epoch_id),
        key_id: key_id(),
        transport_public_key: transport_key.into_vec(),
    };

    let result = ic_cdk::management_canister::vetkd_derive_key(&request)
        .await
        .expect("call to vetkd_derive_key failed");

    Ok(result.encrypted_key.into())
}

#[ic_cdk::query]
fn get_latest_chat_vetkey_epoch_metadata(chat_id: ChatId) -> Result<VetKeyEpochMetadata, String> {
    let caller = ic_cdk::api::msg_caller();

    let latest_epoch_metadata =
        latest_vetkey_epoch_metadata(chat_id).ok_or(format!("No chat {chat_id:?} found"))?;
    ensure_chat_and_vetkey_epoch_exist(chat_id, latest_epoch_metadata.epoch_id)?;
    ensure_user_has_access_to_chat_at_epoch(caller, chat_id, latest_epoch_metadata.epoch_id)?;

    Ok(latest_epoch_metadata)
}

#[ic_cdk::query]
fn get_vetkey_epoch_metadata(
    chat_id: ChatId,
    vetkey_epoch_id: VetKeyEpochId,
) -> Result<VetKeyEpochMetadata, String> {
    let caller = ic_cdk::api::msg_caller();

    ensure_user_has_access_to_chat_at_epoch(caller, chat_id, vetkey_epoch_id)?;

    let epoch_metadata = CHAT_TO_VETKEYS_METADATA
        .with_borrow(|metadata| {
            metadata
                .range(&(chat_id, Time(0))..)
                .take_while(|metadata| metadata.key().0 == chat_id)
                .filter(|metadata| metadata.value().epoch_id == vetkey_epoch_id)
                .last()
                .map(|metadata| metadata.value())
        })
        .ok_or(format!(
            "No vetkey epoch {vetkey_epoch_id:?} found for chat {chat_id:?}"
        ))?;

    Ok(epoch_metadata)
}

#[ic_cdk::update]
fn rotate_chat_vetkey(chat_id: ChatId) -> Result<VetKeyEpochId, String> {
    let caller: Principal = ic_cdk::api::msg_caller();
    let now = Time(ic_cdk::api::time());

    let latest_epoch_metadata =
        latest_vetkey_epoch_metadata(chat_id).ok_or(format!("No chat {chat_id:?} found"))?;
    ensure_user_has_access_to_chat_at_epoch(caller, chat_id, latest_epoch_metadata.epoch_id)?;

    let messages_start_with_id = CHAT_TO_MESSAGE_COUNTERS.with_borrow(|counters| {
        counters
            .get(&chat_id)
            .expect("bug: uninitialized chat message counter")
    });

    let new_vetkey_epoch_id = CHAT_TO_VETKEYS_METADATA.with_borrow_mut(|metadata| {
        let new_vetkey_epoch_id = VetKeyEpochId(latest_epoch_metadata.epoch_id.0 + 1);
        let new_vetkey_epoch_metadata = VetKeyEpochMetadata {
            epoch_id: new_vetkey_epoch_id,
            creation_timestamp: now,
            messages_start_with_id,
            ..latest_epoch_metadata
        };

        for participant in new_vetkey_epoch_metadata.participants.iter().copied() {
            USER_TO_CHAT_MAP.with_borrow_mut(|map| {
                let todo_remove = map.insert((participant, chat_id, new_vetkey_epoch_id), ());
                assert!(todo_remove.is_none());
            });
        }

        let todo_remove = metadata.insert((chat_id, now), new_vetkey_epoch_metadata);
        assert!(todo_remove.is_none());

        clean_up_expired_vetkey_epochs(metadata, chat_id);

        new_vetkey_epoch_id
    });

    Ok(new_vetkey_epoch_id)
}

#[ic_cdk::update]
fn send_direct_message(user_message: UserMessage, receiver: Principal) -> Result<Time, String> {
    let caller = ic_cdk::api::msg_caller();
    let direct_chat_id = DirectChatId::new((caller, receiver));
    let chat_id = ChatId::Direct(direct_chat_id);

    ensure_chat_and_vetkey_epoch_exist(chat_id, user_message.vetkey_epoch)?;
    ensure_user_has_access_to_chat_at_epoch(caller, chat_id, user_message.vetkey_epoch)?;
    ensure_latest_and_correct_vetkey_and_symmetric_key_epoch(
        chat_id,
        user_message.vetkey_epoch,
        user_message.symmetric_key_epoch,
    )?;
    ensure_nonce_is_unique(chat_id, user_message.nonce)?;

    let now = Time(ic_cdk::api::time());

    let chat_message_id = CHAT_TO_MESSAGE_COUNTERS.with_borrow_mut(|counters| {
        let chat_message_id = counters
            .get(&chat_id)
            .expect("bug: uninitialized chat message counter");
        counters.insert(chat_id, ChatMessageId(chat_message_id.0 + 1));
        chat_message_id
    });

    let stored_message = EncryptedMessage {
        content: user_message.content,
        metadata: EncryptedMessageMetadata {
            sender: caller,
            timestamp: now,
            vetkey_epoch: user_message.vetkey_epoch,
            symmetric_key_epoch: user_message.symmetric_key_epoch,
            chat_message_id,
            nonce: user_message.nonce,
        },
    };

    SET_CHAT_AND_SENDER_AND_USER_MESSAGE_ID.with_borrow_mut(|message_times| {
        message_times.insert((chat_id, Sender(caller), user_message.nonce), ());
    });

    DIRECT_CHAT_MESSAGES.with_borrow_mut(|messages| {
        messages.insert((direct_chat_id, chat_message_id), stored_message.clone());
    });

    let expiry_time = CHAT_TO_MESSAGE_EXPIRY_SETTING.with_borrow(|expiry_settings| {
        expiry_settings
            .get(&chat_id)
            .expect("bug: uninitialized expiry setting")
    });

    EXPIRING_MESSAGES.with_borrow_mut(|expiring_messages| {
        let todo_insert =
            expiring_messages.insert((Time(now.0 + expiry_time.0), chat_id, chat_message_id), ());
        assert!(todo_insert.is_none());
    });

    Ok(now)
}

#[ic_cdk::update]
fn send_group_message(
    user_message: UserMessage,
    group_chat_id: GroupChatId,
) -> Result<Time, String> {
    let caller = ic_cdk::api::msg_caller();
    let chat_id = ChatId::Group(group_chat_id);

    ensure_chat_and_vetkey_epoch_exist(chat_id, user_message.vetkey_epoch)?;
    ensure_user_has_access_to_chat_at_epoch(caller, chat_id, user_message.vetkey_epoch)?;
    ensure_latest_and_correct_vetkey_and_symmetric_key_epoch(
        chat_id,
        user_message.vetkey_epoch,
        user_message.symmetric_key_epoch,
    )?;
    ensure_nonce_is_unique(chat_id, user_message.nonce)?;

    let now = Time(ic_cdk::api::time());

    let chat_message_id = CHAT_TO_MESSAGE_COUNTERS.with_borrow_mut(|counters| {
        let chat_message_id = counters
            .get(&chat_id)
            .expect("bug: uninitialized chat message counter");
        counters.insert(chat_id, ChatMessageId(chat_message_id.0 + 1));
        chat_message_id
    });

    let stored_message = EncryptedMessage {
        content: user_message.content,
        metadata: EncryptedMessageMetadata {
            sender: caller,
            timestamp: now,
            vetkey_epoch: user_message.vetkey_epoch,
            symmetric_key_epoch: user_message.symmetric_key_epoch,
            chat_message_id,
            nonce: user_message.nonce,
        },
    };

    SET_CHAT_AND_SENDER_AND_USER_MESSAGE_ID.with_borrow_mut(|message_times| {
        message_times.insert((chat_id, Sender(caller), user_message.nonce), ());
    });

    GROUP_CHAT_MESSAGES.with_borrow_mut(|messages| {
        messages.insert((group_chat_id, chat_message_id), stored_message);
    });

    let expiry_time = CHAT_TO_MESSAGE_EXPIRY_SETTING.with_borrow(|expiry_settings| {
        expiry_settings
            .get(&chat_id)
            .expect("bug: uninitialized expiry setting")
    });

    EXPIRING_MESSAGES.with_borrow_mut(|expiring_messages| {
        let todo_insert =
            expiring_messages.insert((Time(now.0 + expiry_time.0), chat_id, chat_message_id), ());
        assert!(todo_insert.is_none());
    });

    Ok(now)
}

#[ic_cdk::query]
fn get_my_chat_ids() -> Vec<(ChatId, ChatMessageId)> {
    let caller = ic_cdk::api::msg_caller();
    USER_TO_CHAT_MAP.with_borrow(|map| {
        CHAT_TO_MESSAGE_COUNTERS.with_borrow(|counters| {
            map.keys_range((caller, ChatId::MIN_VALUE, VetKeyEpochId(0))..)
                .take_while(|(user, _, _)| user == &caller)
                .map(|(_, chat_id, _)| {
                    (
                        chat_id,
                        ChatMessageId(
                            counters
                                .get(&chat_id)
                                .expect("bug: uninitialized chat message counter")
                                .0,
                        ),
                    )
                })
                .collect::<std::collections::BTreeSet<_>>()
                .into_iter()
                .collect()
        })
    })
}

/// Returns messages for a chat starting from a given message id.
///
/// # Arguments
/// * `chat_id`: The chat to get messages for.
/// * `message_id`: The message id to start from.
/// * `limit`: The maximum number of messages to return.
///
/// # Notes
/// * Does not fail if the chat does not exist or the user has no access -- returns empty vector instead.
#[ic_cdk::query]
fn get_messages(
    chat_id: ChatId,
    message_id: ChatMessageId,
    limit: Option<u32>,
) -> Vec<EncryptedMessage> {
    let caller = ic_cdk::api::msg_caller();

    match chat_id {
        ChatId::Direct(direct_chat) => DIRECT_CHAT_MESSAGES.with_borrow(|messages| {
            if direct_chat.0 == caller || direct_chat.1 == caller {
                messages
                    .range(&(direct_chat, message_id)..)
                    .take_while(|kv| kv.key().0 == direct_chat)
                    .map(|kv| kv.value())
                    .filter(|message| {
                        ensure_user_has_access_to_chat_at_epoch(
                            caller,
                            chat_id,
                            message.metadata.vetkey_epoch,
                        )
                        .is_ok()
                    })
                    .take(limit.unwrap_or(u32::MAX) as usize)
                    .collect()
            } else {
                vec![]
            }
        }),
        ChatId::Group(group_chat) => GROUP_CHAT_MESSAGES.with_borrow(|messages| {
            messages
                .range(&(group_chat, message_id)..)
                .take_while(|kv| kv.key().0 == group_chat)
                .map(|kv| kv.value())
                .filter(|message| {
                    ensure_user_has_access_to_chat_at_epoch(
                        caller,
                        chat_id,
                        message.metadata.vetkey_epoch,
                    )
                    .is_ok()
                })
                .take(limit.unwrap_or(u32::MAX) as usize)
                .collect()
        }),
    }
}

fn ensure_latest_and_correct_vetkey_and_symmetric_key_epoch(
    chat_id: ChatId,
    vetkey_epoch_id: VetKeyEpochId,
    symmetric_key_epoch_id: SymmetricKeyEpochId,
) -> Result<(), String> {
    let latest_vetkey_epoch_metadata = latest_vetkey_epoch_metadata(chat_id)
        .ok_or(format!("No vetkey epoch found for chat {chat_id:?}"))?;

    if vetkey_epoch_id != latest_vetkey_epoch_metadata.epoch_id {
        return Err(format!(
            "Wrong vetKey epoch: expected {:?} but got {:?}",
            latest_vetkey_epoch_metadata.epoch_id, vetkey_epoch_id
        ));
    }

    let now = ic_cdk::api::time();
    let creation = latest_vetkey_epoch_metadata.creation_timestamp.0;
    let rotation: u64 = latest_vetkey_epoch_metadata
        .symmetric_key_rotation_duration
        .0;
    let epoch_offset = rotation
        .checked_mul(symmetric_key_epoch_id.0)
        .ok_or(format!(
            "Overflow: too large epoch id ({}) or rotation duration ({rotation})",
            symmetric_key_epoch_id.0
        ))?;
    let epoch_start = creation.checked_add(epoch_offset).ok_or(format!(
        "Overflow: too large creation date ({creation}) or epoch offset ({epoch_offset})"
    ))?;
    let epoch_end = epoch_start.checked_add(rotation).ok_or(format!(
        "Overflow: too large epoch start ({epoch_start}) or rotation duration ({rotation})"
    ))?;

    if now < epoch_start {
        return Err(format!(
            "Wrong symmetric key epoch {:?} is not yet active, current time is {now} and epoch start is {epoch_start}",
            symmetric_key_epoch_id.0
        ));
    }

    if epoch_end <= now {
        return Err(format!(
            "Wrong symmetric key epoch: epoch {:?} is expired, current time is {now} and epoch end is {epoch_end}",
            symmetric_key_epoch_id.0
        ));
    }
    Ok(())
}

#[ic_cdk::update]
fn update_my_symmetric_key_cache(
    chat_id: ChatId,
    vetkey_epoch_id: VetKeyEpochId,
    user_cache: EncryptedSymmetricKeyEpochCache,
) -> Result<(), String> {
    let caller = ic_cdk::api::msg_caller();
    ensure_chat_and_vetkey_epoch_exist(chat_id, vetkey_epoch_id)?;
    ensure_user_has_access_to_chat_at_epoch(caller, chat_id, vetkey_epoch_id)?;
    ensure_payload_has_reasonable_size_for_key(&user_cache.0)?;

    ENCRYPTED_MAPS.with_borrow_mut(|opt_maps| {
        let maps = opt_maps
            .as_mut()
            .expect("bug: encrypted maps should be initialized after canister initialization");
        let _ = maps
            .insert_encrypted_value(
                caller,
                map_id(caller),
                map_key_id(chat_id, vetkey_epoch_id),
                ic_vetkeys::types::ByteBuf::from(user_cache.0),
            )
            .expect("bug: failed to insert encrypted value");
    });

    let now = Time(ic_cdk::api::time());
    EXPIRING_VETKEY_EPOCHS_CACHES.with_borrow_mut(|caches| {
        caches.insert((now, chat_id, caller), vetkey_epoch_id);
    });

    RESHARED_VETKEYS.with_borrow_mut(|reshared_vetkeys| {
        let _ = reshared_vetkeys.remove(&(chat_id, vetkey_epoch_id, caller));
    });

    Ok(())
}

#[ic_cdk::update]
fn get_my_symmetric_key_cache(
    chat_id: ChatId,
    vetkey_epoch_id: VetKeyEpochId,
) -> Result<Option<EncryptedSymmetricKeyEpochCache>, String> {
    let caller = ic_cdk::api::msg_caller();
    ensure_chat_and_vetkey_epoch_exist(chat_id, vetkey_epoch_id)?;
    ensure_user_has_access_to_chat_at_epoch(caller, chat_id, vetkey_epoch_id)?;

    ENCRYPTED_MAPS.with_borrow(|opt_maps| {
        let maps = opt_maps
            .as_ref()
            .expect("bug: encrypted maps should be initialized after canister initialization");

        maps.get_encrypted_value(caller, map_id(caller), map_key_id(chat_id, vetkey_epoch_id))
            .map(|opt_cache| opt_cache.map(|cache| EncryptedSymmetricKeyEpochCache(cache.into())))
    })
}

#[ic_cdk::update]
async fn get_encrypted_vetkey_for_my_cache_storage(
    transport_key: serde_bytes::ByteBuf,
) -> serde_bytes::ByteBuf {
    let caller: Principal = ic_cdk::api::msg_caller();
    let transport_key = ic_vetkeys::types::ByteBuf::from(transport_key.into_vec());

    let encrypted_vetkey = ENCRYPTED_MAPS
        .with_borrow(|opt_maps| {
            opt_maps
                .as_ref()
                .expect("bug: encrypted maps should be initialized after canister initialization")
                .get_encrypted_vetkey(caller, map_id(caller), transport_key)
                .expect("bug: failed to get user's vetkey")
        })
        .await;

    serde_bytes::ByteBuf::from(encrypted_vetkey.as_ref().to_vec())
}

#[ic_cdk::update]
async fn get_vetkey_verification_key_for_my_cache_storage() -> serde_bytes::ByteBuf {
    let verification_key = ENCRYPTED_MAPS
        .with_borrow(|opt_maps| {
            opt_maps
                .as_ref()
                .expect("bug: encrypted maps should be initialized after canister initialization")
                .get_vetkey_verification_key()
        })
        .await;

    serde_bytes::ByteBuf::from(verification_key.as_ref().to_vec())
}

#[ic_cdk::update]
fn reshare_ibe_encrypted_vetkeys(
    chat_id: ChatId,
    vetkey_epoch_id: VetKeyEpochId,
    users_and_encrypted_vetkeys: Vec<(Principal, IbeEncryptedVetKey)>,
) -> Result<(), String> {
    let caller = ic_cdk::api::msg_caller();
    ensure_chat_and_vetkey_epoch_exist(chat_id, vetkey_epoch_id)?;
    ensure_user_has_access_to_chat_at_epoch(caller, chat_id, vetkey_epoch_id)?;

    users_and_encrypted_vetkeys.iter().map(|(user, _encrypted_vetkey)| {
        ensure_user_has_access_to_chat_at_epoch(*user, chat_id, vetkey_epoch_id)?;
        ensure_user_has_no_cached_key_for_chat_and_vetkey_epoch(*user, chat_id, vetkey_epoch_id)?;

        if *user == caller {
            return Err(format!("User {user} cannot reshare a vetkey with themselves"));
        }

        RESHARED_VETKEYS.with_borrow_mut(|reshared_vetkeys| {
        let resharing_exists =  reshared_vetkeys.get(&(chat_id, vetkey_epoch_id, *user)).is_some();
        if resharing_exists {
            Err(format!("User {user} already has a reshared key for chat {chat_id:?} at vetkey epoch {vetkey_epoch_id:?}"))
        }
        else {
            Ok(())
        }
    })
    }).collect::<Result<Vec<_>, String>>()?;

    for (user, encrypted_vetkey) in users_and_encrypted_vetkeys.into_iter() {
        RESHARED_VETKEYS.with_borrow_mut(|reshared_vetkeys| {
            let todo_remove_ =
                reshared_vetkeys.insert((chat_id, vetkey_epoch_id, user), encrypted_vetkey);
            assert!(todo_remove_.is_none());
        });
    }
    Ok(())
}

#[ic_cdk::update]
fn get_my_reshared_ibe_encrypted_vetkey(
    chat_id: ChatId,
    vetkey_epoch_id: VetKeyEpochId,
) -> Result<Option<IbeEncryptedVetKey>, String> {
    let caller = ic_cdk::api::msg_caller();

    ensure_chat_and_vetkey_epoch_exist(chat_id, vetkey_epoch_id)?;

    Ok(RESHARED_VETKEYS
        .with_borrow(|reshared_vetkeys| reshared_vetkeys.get(&(chat_id, vetkey_epoch_id, caller))))
}

#[ic_cdk::update]
async fn get_vetkey_resharing_ibe_decryption_key(
    transport_key: serde_bytes::ByteBuf,
) -> serde_bytes::ByteBuf {
    let caller = ic_cdk::api::msg_caller();
    let args = ic_cdk::management_canister::VetKDDeriveKeyArgs {
        input: vec![],
        context: resharing_context(caller),
        transport_public_key: transport_key.into_vec(),
        key_id: key_id(),
    };
    let result = ic_cdk::management_canister::vetkd_derive_key(&args)
        .await
        .unwrap();
    serde_bytes::ByteBuf::from(result.encrypted_key)
}

#[ic_cdk::update]
async fn get_vetkey_resharing_ibe_encryption_key(user: Principal) -> serde_bytes::ByteBuf {
    let args = ic_cdk::management_canister::VetKDPublicKeyArgs {
        canister_id: None,
        context: resharing_context(user),
        key_id: key_id(),
    };
    let result = ic_cdk::management_canister::vetkd_public_key(&args)
        .await
        .unwrap();

    serde_bytes::ByteBuf::from(result.public_key)
}

#[ic_cdk::update]
fn modify_group_chat_participants(
    group_chat_id: GroupChatId,
    group_modification: GroupModification,
) -> Result<VetKeyEpochId, String> {
    let caller = ic_cdk::api::msg_caller();
    let now = Time(ic_cdk::api::time());
    let chat_id = ChatId::Group(group_chat_id);

    if group_modification.add_participants.is_empty()
        && group_modification.remove_participants.is_empty()
    {
        return Err("No modifications provided".to_string());
    }

    let latest_epoch_metadata =
        latest_vetkey_epoch_metadata(chat_id).ok_or(format!("No chat {chat_id:?} found"))?;
    ensure_user_has_access_to_chat_at_epoch(caller, chat_id, latest_epoch_metadata.epoch_id)?;

    for participant in group_modification.add_participants.iter() {
        if latest_epoch_metadata.participants.contains(participant) {
            return Err(format!(
                "Participant {participant} is already a member of the group chat and cannot be added"
            ));
        }
    }

    for participant in group_modification.remove_participants.iter() {
        if !latest_epoch_metadata.participants.contains(participant) {
            return Err(format!(
                "Participant {participant} is not a member of the group chat and cannot be removed"
            ));
        }
    }

    let mut new_participants = latest_epoch_metadata.participants.clone();
    new_participants.extend(group_modification.add_participants);
    new_participants
        .retain(|participant| !group_modification.remove_participants.contains(participant));
    new_participants.sort();

    let messages_start_with_id = CHAT_TO_MESSAGE_COUNTERS.with_borrow(|counters| {
        counters
            .get(&chat_id)
            .expect("bug: uninitialized chat message counter")
    });

    let new_vetkey_epoch_id = CHAT_TO_VETKEYS_METADATA.with_borrow_mut(|metadata| {
        let new_vetkey_epoch_id = VetKeyEpochId(latest_epoch_metadata.epoch_id.0 + 1);
        let new_vetkey_epoch_metadata = VetKeyEpochMetadata {
            epoch_id: new_vetkey_epoch_id,
            creation_timestamp: now,
            participants: new_participants,
            symmetric_key_rotation_duration: latest_epoch_metadata.symmetric_key_rotation_duration,
            messages_start_with_id,
        };

        for participant in new_vetkey_epoch_metadata.participants.iter().copied() {
            USER_TO_CHAT_MAP.with_borrow_mut(|map| {
                let todo_remove = map.insert((participant, chat_id, new_vetkey_epoch_id), ());
                assert!(todo_remove.is_none());
            });
        }

        for participant in group_modification.remove_participants.iter() {
            USER_TO_CHAT_MAP.with_borrow_mut(|map| {
                let keys_to_remove = map
                    .keys_range((caller, chat_id, VetKeyEpochId(0))..)
                    .take_while(|(user, this_chat_id, _)| {
                        user == participant && *this_chat_id == chat_id
                    })
                    .collect::<Vec<_>>();
                for key_to_remove in keys_to_remove {
                    let todo_remove = map.remove(&key_to_remove);
                    assert!(todo_remove.is_some());
                }
            });
        }

        let todo_remove = metadata.insert((chat_id, now), new_vetkey_epoch_metadata);
        assert!(todo_remove.is_none());

        clean_up_expired_vetkey_epochs(metadata, chat_id);

        new_vetkey_epoch_id
    });

    Ok(new_vetkey_epoch_id)
}

fn start_expired_cleanup_timer_job_with_interval(secs: u64) {
    let secs = std::time::Duration::from_secs(secs);
    let _timer_id = ic_cdk_timers::set_timer_interval(secs, periodic_cleanup_of_expired_items);
}

fn periodic_cleanup_of_expired_items() {
    let now = Time(ic_cdk::api::time());

    let mut num_expired_direct_messages: usize = 0;
    let mut num_expired_group_messages: usize = 0;
    let mut num_expired_vetkey_epochs_caches: usize = 0;
    let mut num_expired_reshared_vetkeys: usize = 0;

    EXPIRING_MESSAGES.with_borrow_mut(|expiring_messages| {
        let now = Time(ic_cdk::api::time());
        let expired_messages: Vec<_> = expiring_messages
            .iter()
            .filter(|entry| entry.key().0 <= now)
            .map(|entry| *entry.key())
            .collect();
        for key in expired_messages {
            let todo_remove = expiring_messages.remove(&key);
            assert!(todo_remove.is_some());

            match key.1 {
                ChatId::Direct(chat_id) => {
                    num_expired_direct_messages += 1;
                    DIRECT_CHAT_MESSAGES.with_borrow_mut(|messages| {
                        let todo_remove = messages.remove(&(chat_id, key.2));
                        assert!(todo_remove.is_some());
                    });
                }
                ChatId::Group(group_chat_id) => {
                    num_expired_group_messages += 1;
                    GROUP_CHAT_MESSAGES.with_borrow_mut(|messages| {
                        let todo_remove = messages.remove(&(group_chat_id, key.2));
                        assert!(todo_remove.is_some());
                    });
                }
            }
        }
    });

    EXPIRING_VETKEY_EPOCHS_CACHES.with_borrow_mut(|expiring_vetkey_epochs_caches| {
        let mut expired_vetkey_epochs = std::collections::BTreeSet::new();
        let expired_vetkey_epochs_caches: Vec<_> = expiring_vetkey_epochs_caches
            .iter()
            .filter(|entry| entry.key().0 <= now)
            .map(|entry| (*entry.key(), entry.value()))
            .collect();
        for ((time, chat_id, principal), vetkey_epoch_id) in expired_vetkey_epochs_caches {
            expired_vetkey_epochs.insert((chat_id, vetkey_epoch_id));
            let todo_remove_1 = expiring_vetkey_epochs_caches.remove(&(time, chat_id, principal));
            assert!(todo_remove_1.is_some());

            ENCRYPTED_MAPS.with_borrow_mut(|opt_maps| {
                let maps = opt_maps.as_mut().expect(
                    "bug: encrypted maps should be initialized after canister initialization",
                );
                if maps
                    .remove_encrypted_value(
                        principal,
                        map_id(principal),
                        map_key_id(chat_id, vetkey_epoch_id),
                    )
                    .unwrap()
                    .is_some()
                {
                    num_expired_vetkey_epochs_caches += 1
                }
            });
        }

        for (chat_id, vetkey_epoch_id) in expired_vetkey_epochs {
            RESHARED_VETKEYS.with_borrow_mut(|reshared_vetkeys| {
                let reshared_vetkeys_to_remove: Vec<_> = reshared_vetkeys
                    .range(&(chat_id, vetkey_epoch_id, Principal::management_canister())..)
                    .filter(|entry| entry.key().0 == chat_id && entry.key().1 == vetkey_epoch_id)
                    .map(|entry| *entry.key())
                    .collect();
                for key in reshared_vetkeys_to_remove {
                    let todo_remove = reshared_vetkeys.remove(&key);
                    assert!(todo_remove.is_some());
                    num_expired_reshared_vetkeys += 1;
                }
            });
        }
    });

    ic_cdk::println!(
        "Timer job: cleaned up {} expired direct messages, {} expired group messages, {} expired vetkey epochs caches, {} expired reshared vetkeys",
        num_expired_direct_messages,
        num_expired_group_messages,
        num_expired_vetkey_epochs_caches,
        num_expired_reshared_vetkeys
    );
}

fn clean_up_expired_vetkey_epochs(
    metadata: &mut StableBTreeMap<(ChatId, Time), VetKeyEpochMetadata, Memory>,
    chat_id: ChatId,
) {
    let now = Time(ic_cdk::api::time());
    let message_expiry_setting = CHAT_TO_MESSAGE_EXPIRY_SETTING
        .with_borrow(|expiry_settings| expiry_settings.get(&chat_id))
        .expect("bug: expiry should always exist for existing chats");

    let expired_epochs: Vec<_> = metadata
        .range((chat_id, Time(0))..)
        .take_while(|metadata| {
            (metadata.key().1 .0 + message_expiry_setting.0) < now.0 && metadata.key().0 == chat_id
        })
        .map(|metadata| metadata.value())
        .collect();

    for epoch in expired_epochs {
        let todo_remove = metadata.remove(&(chat_id, epoch.creation_timestamp));
        assert!(todo_remove.is_some());
    }
}

fn ensure_user_has_access_to_chat_at_epoch(
    user: Principal,
    chat_id: ChatId,
    vetkey_epoch_id: VetKeyEpochId,
) -> Result<(), String> {
    let result = USER_TO_CHAT_MAP.with_borrow(|chats| chats.get(&(user, chat_id, vetkey_epoch_id)));

    result.ok_or(format!(
        "User {} does not have access to chat {:?} at epoch {:?}",
        user, chat_id, vetkey_epoch_id
    ))
}

fn ensure_user_has_no_cached_key_for_chat_and_vetkey_epoch(
    user: Principal,
    chat_id: ChatId,
    vetkey_epoch_id: VetKeyEpochId,
) -> Result<(), String> {
    let cache_exists = ENCRYPTED_MAPS.with_borrow(|opt_maps| {
        let maps = opt_maps
            .as_ref()
            .expect("bug: encrypted maps should be initialized after canister initialization");
        let map_id = (
            user,
            ic_stable_structures::storable::Blob::<32>::from_bytes(Cow::Borrowed(
                b"encrypted_chat_cache",
            )),
        );
        let map_key_id = map_key_id(chat_id, vetkey_epoch_id);
        maps.get_encrypted_value(user, map_id, map_key_id)
            .expect("bug: failed to get encrypted value")
            .is_some()
    });
    if cache_exists {
        Err(format!(
            "User {} already has a cached key for chat {:?} at vetkey epoch {:?}",
            user, chat_id, vetkey_epoch_id
        ))
    } else {
        Ok(())
    }
}

fn ensure_chat_and_vetkey_epoch_exist(
    chat_id: ChatId,
    vetkey_epoch_id: VetKeyEpochId,
) -> Result<(), String> {
    let _ = latest_vetkey_epoch_id(chat_id).ok_or(format!("No chat {chat_id:?} found"))?;

    CHAT_TO_VETKEYS_METADATA.with_borrow(|metadata| {
        metadata
            .range(&(chat_id, Time(0))..)
            .take_while(|metadata| metadata.key().0 == chat_id)
            .find(|metadata| metadata.value().epoch_id == vetkey_epoch_id)
            .map(|_| ())
            .ok_or(format!(
                "vetKey epoch {vetkey_epoch_id:?} not found for chat {chat_id:?}"
            ))
    })
}

fn ensure_nonce_is_unique(chat_id: ChatId, nonce: Nonce) -> Result<(), String> {
    let caller = ic_cdk::api::msg_caller();
    let maybe_existing_id = SET_CHAT_AND_SENDER_AND_USER_MESSAGE_ID
        .with_borrow(|message_ids| message_ids.get(&(chat_id, Sender(caller), nonce)));

    match maybe_existing_id {
        Some(_) => Err(format!(
            "Message {nonce:?} already exists for sender {caller} chat {chat_id:?}"
        )),
        None => Ok(()),
    }
}

fn ensure_payload_has_reasonable_size_for_key(payload: &[u8]) -> Result<(), String> {
    if payload.len() > 200 {
        Err(format!(
            "Payload is way too large: expected <= 200 B, got {} B",
            payload.len()
        ))
    } else {
        Ok(())
    }
}

fn map_id(caller: Principal) -> (Principal, ic_stable_structures::storable::Blob<32>) {
    (
        caller,
        ic_stable_structures::storable::Blob::<32>::from_bytes(Cow::Borrowed(
            b"encrypted_chat_cache",
        )),
    )
}

fn map_key_id(
    chat_id: ChatId,
    vetkey_epoch_id: VetKeyEpochId,
) -> ic_stable_structures::storable::Blob<32> {
    ic_stable_structures::storable::Blob::<32>::from_bytes(Cow::Owned(
        sha2::Sha256::digest(
            chat_id
                .to_bytes()
                .iter()
                .cloned()
                .chain(vetkey_epoch_id.to_bytes().iter().cloned())
                .collect::<Vec<u8>>(),
        )
        .to_vec(),
    ))
}

fn latest_vetkey_epoch_id(chat_id: ChatId) -> Option<VetKeyEpochId> {
    CHAT_TO_VETKEYS_METADATA.with_borrow(|metadata| {
        metadata
            .range(&(chat_id, Time(0))..)
            .take_while(|metadata| metadata.key().0 == chat_id)
            .last()
            .map(|metadata| metadata.value().epoch_id)
    })
}

fn latest_vetkey_epoch_metadata(chat_id: ChatId) -> Option<VetKeyEpochMetadata> {
    CHAT_TO_VETKEYS_METADATA.with_borrow(|metadata| {
        metadata
            .range(&(chat_id, Time(0))..)
            .take_while(|metadata| metadata.key().0 == chat_id)
            .last()
            .map(|metadata| metadata.value())
    })
}

fn key_id() -> VetKDKeyId {
    let name = VETKD_KEY_NAME.with(|name| name.borrow().get().clone());
    VetKDKeyId {
        curve: VetKDCurve::Bls12_381_G2,
        name,
    }
}

pub fn ratchet_context(chat_id: ChatId, vetkey_epoch_id: VetKeyEpochId) -> Vec<u8> {
    let chat_id_bytes = chat_id.to_bytes();
    let mut context = vec![];

    context.extend_from_slice(&[DOMAIN_SEPARATOR_VETKEY_ROTATION.len() as u8]);
    context.extend_from_slice(DOMAIN_SEPARATOR_VETKEY_ROTATION.as_bytes());

    context.extend_from_slice(&[chat_id_bytes.len() as u8]);
    context.extend_from_slice(&chat_id_bytes);

    context.extend_from_slice(&vetkey_epoch_id.0.to_le_bytes());

    context
}

pub fn resharing_context(caller: Principal) -> Vec<u8> {
    let mut context = vec![];

    context.extend_from_slice(&[DOMAIN_SEPARATOR_VETKEY_RESHARING.len() as u8]);
    context.extend_from_slice(DOMAIN_SEPARATOR_VETKEY_ROTATION.as_bytes());

    context.extend_from_slice(caller.as_slice());

    context
}

ic_cdk::export_candid!();
