# vetKey Encrypted Chat

vetKey Encrypted Chat has two main components: the canister backend and user frontend. It provides the following features:

* End-to-end encrypted messaging.

* High security through symmetric ratchet and key rotation via [vetKeys](https://internetcomputer.org/docs/building-apps/network-features/vetkeys/introduction).

* Disappearing messages, enforced by the canister (ICP smart contract) logic. Messages are automatically removed from the frontend and encrypted messages are purged from the backend once they expire.

* Encrypted state recovery, enabling users to securely restore their message-decryption capability across different devices.

## Encryption Keys and State Recovery

### Key Hierarchy

vetKey encrypted chat uses three layers of cryptographic keys:
* **vetKeys**: shared keys established thorough the [vetKD protocol](https://internetcomputer.org/docs/references/vetkeys-overview). 
They rotate periodically, e.g. upon group configuration changes, to ensure both forward security and post-compromise security. 
This means that an adversary who obtains the key material for one vetKey epoch gains no information about past or future epochs. 
Deriving new vetKeys incurs some cost, as it requires interaction with the backend canister, which triggers a vetKey-derivation protocol on the ICP.
* **Symmetric key ratchet**: a continuously evolving chain of symmetric keys derived from the current vetKey. 
It provides forward security but not post-compromise security: an adversary who obtains the ratchet key for step i can derive all future ratchet states for that same vetKey epoch. 
Ratchet advancement is efficient and can be performed locally by each participant without interacting with the backend canister.
* **Message encryption keys**: per-message keys derived from the current symmetric ratchet state.

### Key Rotation

While vetKey rotations can occur at arbitrary times, the symmetric ratchet progresses strictly at fixed time-frame boundaries. 
The length of this time frame determines how long a user must retain ratchet key material to decrypt messages. 

Retaining some ratchet states is necessary to support out-of-order decryption. 
For example, a client may only want to decrypt recent messages shown in the UI—not the entire history, which may include large media requiring unnecessary downloads. 
To decrypt the oldest non-expired message, the client must keep the appropriate ratchet state.

The duration of the symmetric ratchet time frame directly affects how long clients must retain decryption capability beyond what is strictly necessary. 
For example, if each symmetric ratchet epoch has length `r` and the encrypted chat maintains a message history of length `h ≤ k·r`, then the frontend may need to keep the ratchet state for up to `k + 1` epochs in order to decrypt any message within that history window.


### Encrypted State Recovery

Encrypted state recovery allows a user to restore their ability to decrypt messages on a new device by securely caching encrypted symmetric ratchet states in the backend. 
Each ratchet state is encrypted client-side using an individual key, ensuring that the backend never learns any cryptographic material that would enable message decryption.

Since the symmetric ratchet is instantiated from a vetKey, the ability to obtain the vetKey allows to decrypt all messages encrypted using any derived ratchet states.
To provide a _limited_ state recovery it is crucial to:
* Prevent the frontend to obtain the initial vetKey once the user has uploaded the encrypted cache for its epoch.
* Encrypt and upload the necessary symmetric ratchet states using user-specific encryption keys.
* Retrieve and decrypt the stored ratchet states during recovery, restoring the user's ability to decrypt messages without exposing the initial vetKey.

Users who do not wish to enable state recovery may still want to signal to the backend that they have retrieved the vetKey, thereby preventing any future retrievals. This can be achieved, for example, by uploading a deliberately invalid encrypted cache once, which marks the vetKey as unrecoverable for that epoch.

Practical symmetric-ratchet epoch durations range from a few minutes to several hours or even days. 
When state recovery is enabled, shorter epochs increase the frequency of encrypted-cache updates, which in turn raises cycle consumption on the backend. 
As a result, very short time frames may be impractical in large or busy chats.

## Components

vetKey Encrypted Chat consists of a backend canister on the ICP and a user frontend.

The backend's responsibilities are:

* Providing APIs for chat interactions and key retrieval from vetKeys.

* Storing chat metadata and users' encrypted messages.

* Ordering of incoming messages.

* Validation of encryption key metadata correctness for incoming messages.

* Access control for user requests to both encryption keys and chat data.

* Cleanup of expired messages if message expiration is turned on in a chat.

* Storing user's encrypted key cache that allows the user to restore a former symmetric ratchet state in case of a state loss, e.g., upon browser change.

The frontend's responsibilities are:

* Providing a chat UI similar to Signal, WhatsApp, etc.

* Synchronizing metadata for accessible chats.

* Obtaining keys required for message encryption/decryption.

* Encrypting and sending outgoing messages.

* Fetching and decrypting incoming messages.

* Upload user's encrypted key cache in the backend. 

## Backend Canister Component

### Backend State

* Chat data

  * Chat IDs - each chat has a chat ID

  * vetKey epochs - each chat has one or more vetKey epochs

    * vetKey epoch ID for each vetKey epoch in the chat

    * Participants who have access to the chat at the vetKey epoch

    * Creation time of the vetKey epoch

    * Symmetric key ratchet rotation duration at the vetKey epoch

    * Message ID that the vetKey epoch starts with in the chat

  * Messages

    * Chat Message ID that is assigned by the canister

    * Nonce use for message encryption that is assigned by the user

    * Consensus time at message receival

    * vetKey epoch ID when the message was received

    * Encrypted bytes of the message content.

  * Message expiry

    * Number of expired messages in the chat

    * Message expiry setting - how long does it take for a message to expire

* User data per chat and vetKey epoch

  * [User-uploaded optional encrypted symmetric ratchet state cache](#state-cache)

  * Optional optimization: [IBE-encrypted vetKey reshared by another user](#ibe-encrypted-vetkey-resharing)

### Chat Creation

Upon receiving a call from the frontend to create a chat via one of the following APIs

```
type OtherParticipant = principal;
type TimeNanos = nat64;
type SymmetricKeyRotationMins = nat64;
type GroupChatId = nat64;
type GroupChatMetadata = record { creation_timestamp : TimeNanos; chat_id : GroupChatId };

create_direct_chat : (OtherParticipant, SymmetricKeyRotationMins) -> variant { Ok : TimeNanos; Err : text };
create_group_chat : (vec OtherParticipant, SymmetricKeyRotationMins) -> (variant { Ok : GroupChatMetadata; Err : text });
```

the backend does the following:

* Checks that a direct chat does not exist yet if `create_direct_chat` was called and returns an error if the check fails.

* Checks that `SymmetricKeyRotationMins` do not cause overflows in `nat64` types if converted to nanoseconds and returns an error if the check fails.

* Deduplicates group chat participants if `create_group_chat` was called.

* If all checks pass, adds the chat ID and users who have access to it to the state. The return value of `create_direct_chat` is the current consensus time indicating the chat creation time (which is required to correctly compute the symmetric key epoch that the frontend needs to encrypt messages with). The return value of `create_group_chat` is `GroupChatMetadata`, which contains the chat creation time as well as the group chat ID. The group chat ID does not depend on the caller's inputs (in contrast to direct chat IDs), and thus must be returned explicitly.

### Group Changes

Group changes in a group chat such as addition or removal of users can be triggered using the following backend canister API:
```
type GroupChatId = nat64;
type VetKeyEpochId = nat64;
type KeyRotationResult = variant { Ok : VetKeyEpochId; Err : text };
type GroupModification = record {
  remove_participants : vec principal;
  add_participants : vec principal;
};

modify_group_chat_participants : (GroupChatId, GroupModification) -> (KeyRotationResult);
```

The API takes in a group chat ID and a set of group changes.
When this API is triggered, the canister checks that:

* The group chat exists.

* The user has access to the group chat at the latest vetKey epoch.

* The user is authorized to make group changes. This is an implementation detail and is out of scope of this document. Authorizing users to make group changes can be performed via a separate API and can be implemented with different rules, e.g., admins can make changes, or more fine-grained access can be implemented such as admins, moderators, etc., or even every user can perform group changes.

* The passed `GroupModification` is valid:

  * `remove_participants` or `add_participants` is non-empty.

  * Every `principal` in `remove_participants` has access to the chat.

  * No `principal` in `add_participants` has access to the chat.

Note that the latter two points guarantee that there is no intersection between `remove_participants` and `add_participants`.

A group change triggers a vetKey epoch rotation that updates the set of group participants according to the passed `GroupModification` and stores it in the next vetKey epoch for the chat. The effects of vetKey epoch rotation are further discussed in the [vetKet Epoch Rotation](#vetkey-epoch-rotation) section.

The user removed from a group chat loses access to the messages and vetKeys (as well as key cache) in that chat and does not regain access if added to that group chat later.
Instead, if two users are added to the chat in the same call, while one of the users has previously had access to the chat but was removed and the other user never had access to that chat, they would be able to access only the same messages and vetKeys.

> [!NOTE]
> One call to `modify_group_chat_participants` triggers one vetKey epoch rotation even if multiple `principals` are added or removed. Further potential optimizations for reducing the number of vetKey epoch rotations or the number of vetKey retrievals are discussed in [Optimizations](#optimizations).

### Incoming Message Validation

Upon receival of a user message via the following API

```
type GroupChatId = nat64;
type ChatId = variant {
  Group : GroupChatId;
  Direct : record { principal; principal };
};
type VetKeyEpochId = nat64;
type EncryptedBytes = blob;
type SymmetricKeyEpochId = nat64;
type Nonce = blob;
type UserMessage = record {
  vetkey_epoch_id : VetKeyEpochId;
  content : EncryptedBytes;
  symmetric_key_epoch_id : SymmetricKeyEpochId;
  nonce : Nonce;
};
type MessagingError = variant { WrongVetKeyEpoch; WrongSymmetricKeyEpoch; Custom: text };

send_message : (ChatId, UserMessage) -> (variant { Ok; Err : MessageSendingError });
```

the canister validates the message metadata and ensures that the caller has access.

More specifically, the canister checks that:
* The caller has access to the chat at the passed `vetkey_epoch_id` or returns a `Custom` variant of `MessageSendingError` if the check fails.
* `vetkey_epoch_id` attached to the message is the latest for the chat ID or returns the `WrongVetKeyEpoch` variant of `MessageSendingError` if the check fails.
* `symmetric_key_epoch_id` attached to the message is equal to the [current symmetric key epoch ID](#calculating-current-symmetric-ratchet-epoch-id) corresponding the current consensus time. To check that, the canister calculates the current symmetric ratchet epoch ID for the chat and `vetkey_epoch_id`. If the check fails, the canister returns the `WrongSymmetricKeyEpoch` variant of `MessageSendingError` if the check fails.

> [!NOTE]
> This API assumes that the frontend's clock is reasonably synchronized with the ICP to encrypt the messages with the key from the right symmetric ratchet state. This does not pose a significant limitation, since 1) it must already be the case for facilitating reliable communication with the ICP in general and 2) re-encrypting and re-sending in case of failures can be done automatically by the frontend.

If the checks pass, the canister accepts the message, assigns to it:

* The current consensus time as its timestamp, which is needed for computing the message expiry but also to display the message arrival time in the chat UI.

* A chat message ID, which is unique and assigned from an incrementing counter starting from zero. Note that the current number of messages in the chat is different than the value of the counter if some messages have expired.

Finally, the canister adds the message to the state and returns an `Ok`.

### Exposing Metadata about Chats and New Messages

The backend canister exposes the following APIs for fetching metadata:

```
type GroupChatId = nat64;
type ChatId = variant {
  Group : GroupChatId;
  Direct : record { principal; principal };
};
type NumberOfMessages = nat64;
type ChatMetadata = record {
  chat_id : ChatId;
  number_of_messages : NumberOfMessages;
  vetkey_epoch_id : VetKeyEpochId;
};

type SymmetricKeyRotationMins = nat64;
type ChatMessageId = nat64;
type TimeNanos = nat64;
type VetKeyEpochId = nat64;
type VetKeyEpochMetadata = record {
  symmetric_key_rotation_duration : SymmetricKeyRotationMins;
  participants : vec principal;
  messages_start_with_id : ChatMessageId;
  creation_timestamp : TimeNanos;
  epoch_id : VetKeyEpochId;
};

get_my_chats_and_time : () -> (record { chats : vec ChatMetadata; consensus_time_now : TimeNanos }) query;
get_vetkey_epoch_metadata : (ChatId, VetKeyEpochId) -> (variant { Ok : VetKeyEpochMetadata; Err : text }) query;
```

* The `get_my_chats_and_time` API returns a vector of all chat IDs accessible to the user as well as their their current total number of messages and vetKey epoch ID. The frontend can detect new chats and new messages in existing chats by periodically querying `get_my_chats_and_time`. Also, this API returns the current consensus time, which is e.g. useful to compute the message expiry and to determine if symmetric ratchet states need to be evolved. The current total number of messages (`NumberOfMessages`) includes the messages in the accessible chat ID that are not accessible to the user. This can happen if some messages have expired or in group chats, where the user joined at a later point. If a user is [removed from a chat](#group-changes), the result of `get_my_chats_and_time` called by the user will not include that chat anymore. Note that the latter only leaks to the user how many messages were in the chat before the user joined.

* The `get_vetkey_epoch_metadata` API checks that the user has access to `ChatId` at `VetKeyEpochId` and if the test passes, the API returns the corresponding `VetKeyEpochMetadata` or an error otherwise.

> [!NOTE]
> This API is exposed as `query` and, therefore, requires handling of cases where a replica would return incorrect data. This is further discussed [Ensuring Correctness of Query Calls](#ensuring-correctness-of-query-calls).

### Encrypted Message Retrieval

To allow the frontend to retrieve encrypted messages, the backend canister exposes the following backend canister API:

```
type GroupChatId = nat64;
type ChatId = variant {
  Group : GroupChatId;
  Direct : record { principal; principal };
};
type ChatMessageId = nat64;
type Limit = nat32;
type EncryptedBytes = blob;
type EncryptedMessage = record {
  content : EncryptedBytes;
  metadata : EncryptedMessageMetadata;
};
type VetKeyEpochId = nat64;
type SymmetricKeyEpochId = nat64;
type TimeNanos = nat64;
type Nonce = blob;
type EncryptedMessageMetadata = record {
  vetkey_epoch : VetKeyEpochId;
  sender : principal;
  symmetric_key_epoch_id : SymmetricKeyEpochId;
  chat_message_id : ChatMessageId;
  timestamp : TimeNanos;
  nonce : Nonce;
};

get_messages : (ChatId, ChatMessageId, opt Limit) -> (
    vec EncryptedMessage,
  ) query;
```

The `get_messages` API takes in a chat ID, the first message ID to retrieve, and an optional limit value for the maximum number of messages to retrieve in this call.
The API returns a vector of `EncryptedMessage`s.
If the user does not have access to the chat or the chat does not exist, an empty vector is returned.
If the user does not have access to particular messages, e.g., if the user was [added to a group chat](#group-changes) after some activity, or if some of the messages [expired](#disappearing-messages), then those messages are skipped.

If a user is removed from a chat and afterwards the user is added to the chat again (with or without some messages being added in-between), the user will not have access to the messages that were visible before the user was removed from the chat.
This applies to any number of repetitions of this process.
That is, only the last range of messages without gaps is accessible to the user.
This also applies to other backend canister APIs that require the user to have access to a particular vetKey epoch such as vetKey epoch and encrypted user cache retrieval, and vetKey derivation.

> [!NOTE]
> This API is exposed as `query` and, therefore, requires handling of cases where a replica would return incorrect data. This is further discussed [Ensuring Correctness of Query Calls](#ensuring-correctness-of-query-calls).

### Providing vetKeys for Symmetric Ratchet Initialization

Symmetric ratchet state is initialized from a vetKey that is the same for all chat participants.
To fetch a vetKey, the user calls the following backend canister API:
```
type PublicTransportKey = blob;
type GroupChatId = nat64;
type VetKeyEpochId = nat64;
type ChatId = variant {
  Group : GroupChatId;
  Direct : record { principal; principal };
};
type EncryptedVetKey = blob;

derive_chat_vetkey : (ChatId, VetKeyEpochId, PublicTransportKey) -> (variant { Ok : EncryptedVetKey; Err : text });
```

Then, the canister checks that:

* The chat corresponding to the passed `ChatId` exists.

* The user has access to the chat at the passed `VetKeyEpochId`.

* The user did not upload an encrypted cache for his symmetric ratchet state for the vetKey epoch in question (see [State Recovery](#state-recovery)).

If the checks pass, the canister calls the [`vetkd_derive_key`](https://internetcomputer.org/docs/building-apps/network-features/vetkeys/api) API of the management canister with:

* `context` being computed by invoking the `ratchet_context` function defined below.

* `input` being the big-endian encoding of `VetKeyEpochId`.

* `transport_public_key` being the `PublicTransportKey` input argument.

* `key_id` being an implementation detail.

```rust
pub fn ratchet_context(chat_id_bytes: &[u8]) -> Vec<u8> {
  pub static DOMAIN_SEPARATOR_VETKEY_ROTATION: &str = "vetkeys-example-encrypted-chat-rotation";

  let mut context = vec![];
  context.extend_from_slice(&[DOMAIN_SEPARATOR_VETKEY_ROTATION.len() as u8]);
  context.extend_from_slice(DOMAIN_SEPARATOR_VETKEY_ROTATION.as_bytes());
  context.extend_from_slice(chat_id_bytes);
  context
}
```

> [!NOTE]
> `chat_id_bytes` is a serialization of the chat ID and is an implementation detail.

The actual initialization of the symmetric ratchet state is performed in the frontend and is, therefore, specified in [Ratchet Initialization](#ratchet-initialization) in the frontend.

### Encrypted Symmetric Ratchet State Cache

The encrypted ratchet state cache is intended to allow the user to upload encrypted symmetric ratchet epoch keys to the canister and then [recover](#state-recovery) the local state in the frontend whenever needed, e.g., for disaster recovery or after a browser change.

There is a relation between state recovery and the [disappearing messages](#disappearing-messages) duration.
The state recovery duration is always smaller or equal to the disappearing messages duration because keys for messages that don't exist anymore are not useful.

While disappearing messages duration is a chat-level setting, the state recovery duration is a user-level setting in a chat.
In general, the state recovery limit can be both chat-level and user-level setting, but it makes more sense to make state recovery a user setting because the user frontend is in full control of state recovery for a non-expired vetKey epoch. [Note that the current MVP of encrypted-chat does not support this setting.]

In the canister backend, the state recovery limit is used in three cases - all related to expired vetKey epochs:
* Removal of expired caches.
* Acceptance/rejection of cache uploads.
* Acceptance/rejection of cache downloads (because removal may not happen instantly).

The canister backend provides the following APIs for storing and obtaining users' encrypted symmetric ratchet states in the canister:
```
type PublicTransportKey = blob;
type EncryptedVetKey = blob;
type GroupChatId = nat64;
type ChatId = variant {
  Group : GroupChatId;
  Direct : record { principal; principal };
};
type VetKeyEpochId = nat64;
type EncryptedSymmetricRatchetCache = blob;
type DerivedVetKeyPublicKey = blob;

get_vetkey_for_my_cache_encryption : (PublicTransportKey) -> (EncryptedVetKey);
get_my_symmetric_key_cache : (ChatId, VetKeyEpochId) -> (variant { Ok : opt EncryptedSymmetricRatchetCache; Err : text });
update_my_symmetric_key_cache : (ChatId, VetKeyEpochId, EncryptedSymmetricRatchetCache) -> (variant { Ok; Err : text });
```

To facilitate those APIs, we make use of [Encrypted Maps](https://docs.rs/ic-vetkeys/latest/ic_vetkeys/encrypted_maps/struct.EncryptedMaps.html), which, as the name says, allow users to upload encrypted data into a map structure inside the canister.
The advantage in using Encrypted Maps is that 1) we do not need to design and implement such a scheme ourselves, and 2) Encrypted Maps allow to encrypt data efficiently in terms of both the number of fetched vetKeys and the efficiency of the used cryptography.

On a high level, the canister creates exactly one encrypted map for the user that stores _all_ their key caches.
The cache is stored in the map as a `(key, value)`, where `key` is a serialization of tuple `(ChatId, VetKeyEpochId)` and `value` is `EncryptedSymmetricRatchetCache`.

The user calls `get_vetkey_for_my_cache_encryption` to obtain the vetKey used for data encryption for their storage, which is called once upon initialization of the state in the frontend.
It can be called multiple times in general if the client loses their local state in the browser, e.g., when the client wants to use it on another device or in a different browser.

The user calls `update_my_symmetric_key_cache` and `get_my_symmetric_key_cache` to update or fetch their cache.
In `update_my_symmetric_key_cache`, the canister checks that:

* The user has access to the passed `ChatId` and `VetKeyEpochId`.

* The passed `EncryptedSymmetricRatchetCache` has a reasonable size. The purpose of this check is to prevent misuse e.g. for cycles draining attacks where an attacker would store huge amounts of data as `EncryptedSymmetricRatchetCache`. What a reasonable size is depends on how the symmetric ratchet state is serialized in the frontend, which is an implementation detail, but generally the limit can be quite generous, e.g., 100 bytes. In most cases the size will be fixed though, since `EncryptedSymmetricRatchetCache` contains an encryption of 1) a symmetric epoch key and 2) a `VetKeyEpochId`, which both have a fixed size. For example, if using AES-GCM with a 16-byte authentication tag and a 12-byte nonce, then `EncryptedSymmetricRatchetCache` will have the ciphertext overhead of 16 + 12 = 28 bytes in terms of size and the total ciphertext size will be 28 + 32 (symmetric epoch key) + 8 (`VetKeyEpochId`) = 68 bytes.

If the checks pass, the canister accepts the call and stores the cache, or overwrites if it exists, in the state.

The `get_my_symmetric_key_cache` call retrieves the response of Encrypted Maps for getting their cache corresponding to the input arguments, which is the encrypted bytes if the entry exists or `null` if it does not.

The expired caches are removed transparently to the frontend by the canister, i.e., the removal does not require explicit calls for doing that.
Expired cache is a cache, where both of the following is true:
* The cache neither has any messages associated with its vetKey epoch (see [Disappearing Messages](#disappearing-messages)) nor does it correspond to the _latest_ vetKey epoch for the chat ID.
* The vetKey epoch has not expired with regards to the state recovery limit (see below).

Let's denote the state recovery limit as `limit`, current consensus time as `consensus_time` and next vetKey epoch creation time as `next_epoch_creation`, which equals `None` it current epoch is the latest and there is no next epoch.
To determine if a vetKey epoch has expired with regards to the state recovery limit, the following function is used.

```rust
fn has_expired(limit: u64, consensus_time: u64, next_epoch_creation: Option<u64>) : bool {
  if next_epoch.is_none() {
    return false;
  } else {
    next_epoch.map(|next_epoch| consensus_time.saturating_sub(next_epoch) > limit)
  }
}
```

The canister backend API for setting the state recovery limit is defined as follows:
```candid
set_state_recovery_limit : (ChatId, MessageExpiryMins) -> (variant { Ok; Err : text });
```
and must remove expired caches before setting a _higher_ limit. In general, it could make sense to remove expired caches on each update, since the latency of this operation is usually not critical.

The canister backend API `get_state_recovery_limit` can be used by a frontend that has lost its state to recover the information about user's state recovery limit for a chat with ID `ChatId`.
```candid
get_state_recovery_limit : (ChatId) -> (variant { Ok : ?MessageExpiryMins; Err : text }) query;
```

Since cache update is usually a relatively rare operation compared to e.g. potential message updates, adding the cache metadata to the `get_my_chats_and_time` API of the backend canister seems like overkill. Instead, we could add a separate API that would return this metadata s.t. the frontend can find out which caches should be updated.
```candid
type StateRecoveryCacheMetadata = record {
  vetkey_epoch_id: VetKeyEpochId;
  symmetric_epoch_id : SymmetricEpochId;
};

get_metadata_for_my_state_recovery_caches : () -> (vec StateRecoveryCacheMetadata) query;
```

The garbage collection of expired caches happens when there can be no messages that need a particular ratchet state cache for decryption.
That ratchet state cache is then removed by the canister.
This can either happen during user's calls e.g. to add a new message to a chat, or by a timer job, or, actually, both in parallel to reduce the latency of cache deletion.

As a potential further optimization, it is possible to fetch the available cached ratchet states for all chats at once to reduce the number of calls.

In the best case, user's ratchet state cache should be synchronized with the frontend's state, i.e., whenever a ratchet state is evolved in the frontend, it should also be updated in the backend.
However, this only works if the user is online and active.
If the user is offline, the canister will delete the ratchet states that don't have any messages in canister storage that can be decrypted using those states, except for the very last state in order to be able to evolve it to a later when the user is online.

As an idea for further improvement in cases if keeping an older ratchet state is not desirable by some users even if the users may potentially go offline for longer time frames, this can be mitigated by setting up a periodic key rotation (not defined in this spec), where a frontend will not encrypt new messages with a ratchet state from an old vetKey epoch and will instead request a vetKey rotation before the next encryption.
In that case, the users' encrypted caches associated with the older vetKey epoch will be garbage-collected automatically by the canister once they are not required for state recovery anymore.
In that case, the caches for the latest vetKey epoch that should have been rotated could also be garbage-collected.
Note though that this is normally performed by a timer job, so despite that the canister APIs will return correct results for the state recovery, the actual cache deletion from a canister might happen at a later point, e.g., during an hour or a day, depending on the configuration.

Also, if the symmetric ratchet evolution duration is too short or the number of users in a chat is very high, updating the cache may be costly because that would involve many canister calls (one per user per chat).
To allow for mass adoption of a chat app, one could think of the following strategies to reduce costs:

* Allow only larger time frames for the symmetric ratchet evolution, e.g., in the order of hours or days.

* Instead of updating the caches separately, introduce a batch API for batch updates, which is performed only once per time frame for all chats.

* Let the privacy-focused users pay for the cost of the more frequent updates in the chats where they want to have the maximally fined-grained privacy guarantees.

### vetKey Epoch Rotation

The vetKey epoch rotation can happen because of two different reasons:

* Group change: this prevents a newly added user to be able to decrypt old messages or a deleted user to be able to decrypt new encrypted messages in the chat.

* User request: this prevents an attacker that obtained a symmetric ratchet state to be able do decrypt messages that will be encrypted after the vetKey epoch rotation takes place.

To facilitate this functionality, the canister provides two APIs:

```
type GroupChatId = nat64;
type ChatId = variant {
  Group : GroupChatId;
  Direct : record { principal; principal };
};
type VetKeyEpochId = nat64;
type GroupModification = record {
  remove_participants : vec principal;
  add_participants : vec principal;
};
type KeyRotationResult = variant { Ok : VetKeyEpochId; Err : text };

// Group change in a group chat such as user addition (without access to the past chat history) or user removal.
// Takes in a batch of such changes to potentially reduce the number of required rotations.
modify_group_chat_participants : (GroupChatId, GroupModification) -> (KeyRotationResult);

// User-initiated key rotation, e.g., periodic key rotation.
rotate_chat_vetkey : (ChatId) -> (KeyRotationResult);
```

Both have the same effect of rotation the vetKey epoch, but they follow different input validation rules. The rules for `modify_group_chat_participants` are discussed in [Group Changes](#group-changes).

To validate the inputs in a `rotate_chat_vetkey` call, the canister checks that the user has access to the passed chat ID and eventually if the user is authorized to perform a key rotation (see [Group Changes](#group-changes)).

Further validation rules can be added here and are an implementation detail. For example, the canister can rate-limit calls to `rotate_chat_vetkey` or make such calls dependent on further conditions such as user's subscription type.

### Disappearing Messages

The prefix of messages to be removed from a chat is defined by a non-negative integer, which identifies the size of the prefix of expired messages in the chat history, i.e., `e` expired messages means that any message ID in the chat smaller than `e` has expired.
The value of `e` is calculated from the consensus time and the messages in the chat and does not necessarily need to be stored in memory.
Expired messages cannot be [retrieved](#encrypted-message-retrieval) from the canister backend anymore and the canister backend will delete them eventually.

The deletion algorithm is an implementation detail of the canister backend, but in general we see two options:

* Delete expired messages in a timer job. This allows to delete messages periodically but running a timer job too often may be too expensive, so messages will be deleted with a delay.

* Delete expired messages while sending new messages, i.e., whenever the API for sending messages is invoked, it internally calls the message deletion routine. This works well if there is a lot of activity in the chat but will leave messages undeleted or deleted after a long delay if there is no or very little activity.

The chat allows to assign or update a disappearing messages duration for messages in a chat via the following backend canister API:

```
type GroupChatId = nat64;
type ChatId = variant {
  Group : GroupChatId;
  Direct : record { principal; principal };
};
type MessageExpiryMins = nat64;

set_message_expiry : (ChatId, MessageExpiryMins) ->  (variant { Ok; Err : text });
```

Upon receival of a `set_message_expiry` call, the backend canister checks that the user has access to `ChatId` and eventually that the user is authorized to call `set_message_expiry` for `ChatId` and sets `MessageExpiryMins` in the state for `ChatId`.

The semantics of `MessageExpiryMins` is as follows:

* If `MessageExpiryMins` is equal to zero, then this means no expiry is set and all messages are always returned.

* Otherwise the value of `MessageExpiryMins` is used as the message expiry.

Every chat is [created](#chat-creation) with the expiry of 0, which holds a special meaning that messages do not expire.
Once the state is updated, it affects the behavior of [the APIs returning the metadata about message IDs](#exposing-metadata-about-chats-and-new-messages) and [the APIs returning the actual messages](#encrypted-message-retrieval).

* `get_messages : (ChatId, ChatMessageId, opt Limit) -> (vec EncryptedMessage) query;` does not add expired messages to the output.

## User Frontend Component

### Frontend State

* Chat metadata for each chat.

  * Chat ID.

  * Number of received and decrypted messages so far.

  * Latest vetKey epoch ID.
  
  * VetKey epoch metadata for all vetKey epochs that were required for encryption or decryption. Note that the metadata of the vetKey epochs that are not the last vetKey epoch and whose messages have expired are removed from the state.

  * Message expiry for each decrypted message.

* Symmetric ratchet states for all vetKey epochs that were required for encryption or decryption. Similarly to vetKey epoch metadata, expired symmetric ratchet states are deleted from the state.

* Decrypted non-expired messages for each chat.

* Latest consensus time.

* Optional optimization: All messages and chats stored in browser storage.

### Chat UI

The chat UI is a UI that displays chats and their decrypted messages, and allows the user to send their own messages and change settings such as group membership and message expiration via UI elements.
It may also display the metadata about the encrypted chat such as the current epoch information if that fits the application.

The chat UI calls a few canister backend APIs directly, normally via dedicated UI buttons: [chat creation](#chat-creation), [vetKey rotation](#vetkey-epoch-rotation), [group changes](#group-changes), [updating the message expiry](#disappearing-messages).

Since the chat UI is mostly an implementation detail, only its interaction with [Encrypted Messaging Service (EMS)](#encrypted-messaging-service) is described here, whose purpose is it to take care of encryption and decryption of messages.

The chat UI uses the EMS in a black-box way to:

* Dispatch user messages to be encrypted and sent via the `enqueueSendMessage` API of the EMS.

* Fetch received and decrypted messages via periodically querying the `takeReceivedMessages` API of the EMS.

* Find out which chats are accessible at the moment via the `getCurrentChatIds` API of the EMS. New chats need to be added to the UI and chats that the user has lost access to need to be removed from the UI. 

### Encrypted Messaging Service

Encrypted Messaging Service (EMS) is a component that gives the developer a transparent way to interact with the encrypted chat by reading from a stream of received and decrypted messages and putting user messages to be encrypted and sent into a stream that the EMS will take care of encrypting and sending.

Types:

* `type ChatId = { 'Group' : bigint } | { 'Direct' : [Principal, Principal] };`

* `type ChatIdAsString = string`

* `interface Message {
      nonce: bigint;
      chatId: ChatId;
      senderId: Principal;
      content: string;
      timestamp: Date;
      vetkeyEpoch: bigint;
      symmetricRatchetEpoch: bigint;
    }
  `

The EMS exposes the following APIs:

* `enqueueSendMessage(chatId: ChatId, content: Uint8Array)`: adds the message `content` to be encrypted for and sent to the chat with ID `chatId`. This API does not give any guarantees that the message will actually be added to the chat but it makes attempts to recover from recoverable errors (see [Encrypting and Sending Messages in the EMS](#encrypting-and-sending-messages)).

* `takeReceivedMessages(): Map<ChatIdAsString, Message[]>`: returns latest chat messages that were received and decrypted by the EMS and were not yet taken by the user from the EMS (see [Fetching and Decrypting Messages in the EMS](#fetching-and-decrypting-messages)).

* `start()`: starts the EMS service. Before the service is started, calling any other APIs should throw an error. Once it is started, the APIs start to return their intended values, and the EMS starts background tasks to continuously update the relevant chat information from the canister.

* `skipMessagesAvailableLocally(chatId: ChatId, lastKnownChatMessageId: bigint)`: tells the EMS what chat message ID should be the first one to be fetched. This is relevant if some of the messages are available from another source such as [browser storage](#local-cache-in-indexeddb).

* `getCurrentChatIds(): ChatId[]`: returns the chat IDs that are currently accessible to the user. This particular API is mostly an efficiency optimization, since the message retrieval in the EMS anyways requires fetching the information about the currently accessible chats.

* `getCurrentUsersInChat(chatId: ChatId): Principal[]`: takes in a chat ID and returns the current users in the chat. If the EMS does not have data about the chat with `chatId` because either the user does not have access to the chat, or if `chatId` does not exist, or the frontend did not yet manage to synchronize with the backend, this function throws an error.

#### Encrypting and Sending Messages

For message [encryption](#ratchet-message-encryption) and [sending](#incoming-message-validation), the EMS makes use of the [`send_message`](#incoming-message-validation) backend canister API.

The EMS periodically takes a message from the sending stream that was added via the `enqueueSendMessage` API. If the stream is empty, the EMS retries with a timeout. If the stream is non-empty, the EMS takes the oldest message from the stream and performs the following steps:

1. If there is no symmetric ratchet state for the latest vetKey epoch of the chat, the EMS [initializes](#ratchet-initialization) it and calls `get_vetkey_epoch_metadata` to obtain its metadata, which the frontend stores in its state.

2. The EMS encrypts the message using the symmetric ratchet state that corresponds to the latest known vetKey epoch ID (see [Symmetric Ratchet](#symmetric-ratchet)) for the chat at the current time. It may happen that the symmetric ratchet epoch of the symmetric ratchet state is smaller than needed for the encryption at the current time. In that case, the state is copied to a temporary state and the temporary state is evolved to encrypt the message. After encryption, the temporary state may be deleted. Note that neither encryption nor decryption evolves the symmetric ratchet state and instead the ratchet evolution is performed in a background task (see [Ratchet Evolution](#ratchet-evolution)).

3. The EMS [sends](#incoming-message-validation) the encrypted message via the `send_message` canister backend API (see [Incoming Message Validation](#incoming-message-validation)).

4. If the canister returns the `WrongSymmetricKeyEpoch` variant of `MessageSendingError`, then the EMS was unlucky and the sent message arrived at a wrong (normally the next) symmetric key epoch. In this case the EMS goes to step 2.

5. If the canister returns the `WrongVetKeyEpoch` variant of `MessageSendingError`, then either the [manual vetKey epoch rotation](#vetkey-epoch-rotation) or a [group change](#group-changes) took place. In this case, the EMS makes a query call to `get_latest_vetkey_epoch` and updates the latest vetKey epoch ID of the chat in the state, and then goes to step 1.

To avoid infinite loops in case of too strict parameters, bad network connectivity, etc., the maximum number of retries should be capped.

> [!TIP]
> A useful feature of chat applications is displaying when a user joined or left the chat directly in the chat history. The current spec only makes use of such information in the vetKey epoch metadata, which returns the full list of participants for each vetKey epoch, which is a bit redundant for the purpose. More succinct data can be exposed by providing an additional backend API that returns a vector of `GroupModification`s (see [Group Changes](#group-changes)).

#### Fetching and Decrypting Messages

For message [retrieval](#encrypted-message-retrieval) and [decryption](#ratchet-message-decryption), the EMS makes use of the following backend canister APIs:

* [`get_my_chats_and_time`](#exposing-metadata-about-chats-and-new-messages) to retrieve the chat IDs and the number of messages to retrieve.

* [`get_messages`](#encrypted-message-retrieval) to retrieve the encrypted messages for the chats accessible to the user.

* Further canister APIs required for [Ratchet Initialization](#ratchet-initialization).

The frontend stores the following related data related in its state:

* The chat IDs accessible to the user.

* The first accessible message ID for the user for each chat

* The last fetched message for the chat.

* The total number of messages in the chat.

Let's call this information frontend chat metadata.

Periodically, the EMS queries the `get_my_chats_and_time` backend canister API.
Its result is compared to the frontend chat metadata in the state.
The existing chat metadata is updated if required.
If there is a new chat in the result that is not yet in the state, the EMS adds it to the state along with the information that no messages were obtained for this chat yet.
If one of the chats in the state does not appear in the result of `get_my_chats_and_time` anymore, then this chat is deleted from the state including from the queues containing received and decrypted messages.

Also periodically, two separate routines run.

1. Check if there are new messages to be fetched from the canister: if the largest received message ID for the chat plus one is smaller than the total number of messages in the chat. If it is, then `get_messages` is invoked with the first message ID to be fetched that is equal to the largest received message ID for the chat plus one, or if no messages were received so far for a chat, message ID 0 is used. If an error occurs due to too large messages that don't fit into the canister's response due to the query response limits on the ICP, the query to `get_messages` is retried with a limit of e.g. one. A successful result appended to the received messages queue.

2. Try to take a message from the received messages queue and decrypt it.

    a. The EMS checks if it already has the symmetric ratchet state in its state that is required to decrypt the message, whose metadata specifies the required vetKey epoch and symmetric ratchet epoch. If the symmetric ratchet state is not yet initialized, the EMS [initializes](#ratchet-initialization) it. An error to do so is unrecoverable.
    
    b. The EMS [decrypts](#ratchet-message-decryption) the message using the symmetric ratchet state and the vetKey epoch ID stored in the message metadata. A successfully decrypted message is put into the decrypted message queue that is exposed to the chat UI component via the [`takeReceivedMessages` API](#encrypted-messaging-service) of the EMS. If the decryption returns an error, such an error is unrecoverable and instead of a decrypted message, a message of special form is put into the decrypted message queue that indicated that this message could not be decrypted. Note that user-side errors cannot be avoided, since the canister cannot check if the encryption is valid.

#### Symmetric Ratchet

The backend canister APIs required for ratchet initialization are described in the [Providing vetKeys for Symmetric Ratchet Initialization](#providing-vetkeys-for-symmetric-ratchet-initialization) section.

A symmetric ratchet state consists of:

* Epoch key that is used to:

    1. Derive the next ratchet state.

    2. Derive chat participants' message encryption keys.

* Symmetric ratchet epoch ID that the key corresponds to, which is a non-negative number.

##### Ratchet Initialization

The ratchet state is initialized from a vetKey as follows:

1. Obtain the vetKey for the vetKey epoch of the chat

    a. [Generate](https://dfinity.github.io/vetkeys/classes/_dfinity_vetkeys.TransportSecretKey.html#random) a transport key pair.

    b. [Fetch](#providing-vetkeys-for-symmetric-ratchet-initialization) the encrypted vetKey for the chat and vetKey epoch from the backend canister.

    c. Compute the verification public key either [locally](https://dfinity.github.io/vetkeys/classes/_dfinity_vetkeys.MasterPublicKey.html) or via querying the `chat_public_key` backend canister API.

    d. [Decrypt and verify](https://dfinity.github.io/vetkeys/classes/_dfinity_vetkeys.EncryptedVetKey.html#decryptandverify) the vetKey.

2. Compute and save the ratchet state

    a. Compute [`let rootKey = deriveSymmetricKey(vetKeyBytes, DOMAIN_RATCHET_INIT, 32)`](https://github.com/dfinity/vetkeys/blob/83b887f220a2c1c40713a3512ce5a9994d5ec4c6/frontend/ic_vetkeys/src/utils/utils.ts#L352), where `DOMAIN_RATCHET_INIT` is a unique domain separator for ratchet initialization (TODO: this function is currently internal - we should make it public).

    b. Initialize the symmetric ratchet state as `rootKey` and symmetric ratchet epoch that is equal to zero.

More details about the retrieval and decryption of vetKeys can be found in the [developer docs](https://internetcomputer.org/docs/building-apps/network-features/vetkeys/api) of the ICP.

After initializing the ratchet state, the user uploads encrypted cache of the state to the backend canister which is further described in [Encrypted Ratchet State Cache](#encrypted-symmetric-ratchet-state-cache).

##### Ratchet Evolution

```ts
import { deriveSymmetricKey } from '@dfinity/vetkeys';

type RawSymmetricRatchetState = { epochKey: Uint8Array, epochId: bigint };

function ratchetStepDomainSeparator(epoch: bigInt) {
  return new Uint8Array([
		...DOMAIN_RATCHET_STEP,
		...uBigIntTo8ByteUint8ArrayBigEndian(symmetricRatchetState.epochId)
	]);
}

function evolve(symmetricRatchetState: RawSymmetricRatchetState) : RawSymmetricRatchetState {
	const nextEpoch = symmetricRatchetState.epochId + 1n;
	const domainSeparator = ratchetStepDomainSeparator(nextEpoch);
	const newEpochkey = deriveSymmetricKey(symmetricRatchetState.epochKey, domainSeparator, 32);

	return { epochKey: newEpochkey, epochId: nextEpoch };
}
```
where `DOMAIN_RATCHET_STEP` is a unique domain separator.

Alternatively, this can be implemented using Web Crypto API to make the current key non-extractable. Note though that Web Crypto API's `deriveKey` cannot derive an HKDF key and, therefore, derivation of the next epoch key is a two-step process:
1. Derive the next epoch key in form of a byte vector via `deriveBits`.
2. Import the derived byte vector as `CryptoKey`.

```ts
type SymmetricRatchetState = { epochKey: CryptoKey, epochId: bigint };

async function deriveNextSymmetricRatchetEpochCryptoKey(symmetricRatchetState: RawSymmetricRatchetState) : Promise<CryptoKey> {
	const exportable = false;
	const domainSeparator = ratchetStepDomainSeparator(symmetricRatchetState.epochKey)
	const algorithm = {
		name: 'HKDF',
		hash: 'SHA-256',
		length: 32 * 8,
		info: domainSeparator,
		salt: new Uint8Array()
	};

	const rawKey = await globalThis.crypto.subtle.deriveBits(algorithm, epochKey, 8 * 32);

	return await globalThis.crypto.subtle.importKey('raw', rawKey, algorithm, exportable, [
		'deriveKey',
		'deriveBits'
	]);
}
```

It would be quite natural and similar to [Signal's symmetric ratchet](https://signal.org/docs/specifications/doubleratchet/) if the decryption would trigger the ratchet evolution. However, that would force the frontend to decrypt all messages belonging to one vetKey epoch in cases where a chat has many messages and we only want to display the latest ones. This incurs a big and unnecessary overhead in terms of both communication and computation.

Therefore, neither encryption nor decryption directly evolve `SymmetricRatchetState` but instead, the state is evolved whenever the current consensus time obtained via `get_my_chats_and_time` minus the message expiry is larger than the timestamp of the current symmetric key epoch id + 1, i.e., whenever there can be no non-expired message that we would need the current symmetric ratchet epoch to decrypt. The state evolution can be triggered by a background job that periodically checks if state evolution should be performed. 

After evolving the ratchet state, the user uploads encrypted updated state cache to the canister backend which is further described in [Encrypted Ratchet State Cache](#encrypted-symmetric-ratchet-state-cache). 

##### Ratchet Message Encryption
```ts
import { DerivedKeyMaterial } from '@dfinity/vetkeys';

async encrypt(
    epochKey: CryptoKey,
	sender: Principal,
	nonce: Uint8Array,
	message: Uint8Array
): Promise<Uint8Array> {
	const domainSeparator = messageEncryptionDomainSeparator(sender, nonce);
	const derivedKeyMaterial = DerivedKeyMaterial.fromCryptoKey(epochKey);
	return await derivedKeyMaterial.encryptMessage(message, domainSeparator);
}
```
where [`messageEncryptionDomainSeparator`](#typescript-domain-separators) is a unique [size-prefixed](#typescript-size-prefix) domain separator and the `nonce` argument is a user-assigned nonce associated with the message that must be unique for `epochKey` (i.e., the symmetric ratchet epoch) und MUST NOT be reused.

##### Ratchet Message Decryption

```ts

import { DerivedKeyMaterial } from '@dfinity/vetkeys';

async decrypt(
    epochKey: CryptoKey,
	sender: Principal,
	nonce: Uint8Array,
	encryptedMessage: Uint8Array
): Promise<Uint8Array> {
	const domainSeparator = messageEncryptionDomainSeparator(sender, nonce);
	const derivedKeyMaterial = DerivedKeyMaterial.fromCryptoKey(epochKey);
	return await derivedKeyMaterial.decryptMessage(encryptedMessage, domainSeparator);
}
```
where [`messageEncryptionDomainSeparator`](#typescript-domain-separators) is a unique [size-prefixed](#typescript-size-prefix) domain separator.

## Ensuring Correctness of Query Calls

TODO

Idea 1: use query calls and start work, while in the background an update call is invoked to compare the result.

Idea 2: use certified variables.

Comment by Andrea regarding Idea 2:
In a multi-user canister scenario then it may be difficult to add certificates for this endpoint. However, for individual user/chat canisters, then it should be easy to provide certificates, e.g. of chat ID, time and latest message ID.

Is something like mixed hash tree possible in a single canister scenario to reduce hashing times if hashing a huge state? Probably not extremely important, but may be useful to discuss.

## Optimizations

Here, we discuss potential further optimizations that are not an essential part of the spec.

### Local Cache in indexedDB

The local cache in indexedDB is essentially a copy of the frontend state stored in a persistent storage.

* Keys - whenever a new ratchet state is created or evolved, it is stored in indexedDB at an index containing its chat ID and the vetKey epoch ID. Whenever a ratchet state is deleted locally, it is also deleted from indexedDB.

* Messages - in a similar fashion to keys, the decrypted messages are also added to and removed from indexedDB to keep it in sync with the frontend.

An important difference between keys and messages in indexedDB is the component that is responsible for caching.
For keys, the [EMS](#encrypted-messaging-service) is responsible.
Namely, whenever a ratchet state is required, the EMS first checks if it is available from IndexedDB.
For messages, the UI is responsible.
More specifically, upon initialization of the app, it first loads all messages available in indexedDB into the local state and updates the count of the messages available locally via the EMS API s.t. they are not loaded and decrypted again from the canister.

### IBE-Encrypted vetKey Resharing

To reduce the number of vetKeys required for group changes and periodic key rotations, IBE with long-term keys can be used:

1. Each user fetches a long-term IBE key for their principal.

2. Whenever a user fetches a vetKey for a chat, the user decrypts it and reshares with all other users by encrypting the vetKey with their public IBE keys, resulting in a vector containing a separate encryption for each user. Then, the user sends this vector to a special canister API (not described further in this spec).

3. Upon receival of a call to that API, the canister checks which users already have either an existing reshared vetKey or have a cached ratchet state. Such reshared vetKeys are filtered out and the rest is added to the canister state.

Then, the user frontend would check if there is a reshared vetKey stored for them in the canister state before trying to obtain the vetKey in the normal way.
If that is the case, the user would fetch and IBE-decrypt it, and then verify that the vetKey is valid (recall that the vetKey is a BLS signature that can efficiently be verified).
If the check fails, the reshared vetKey is ignored and the frontend proceeds as if there was no resharing, i.e., it obtains the vetKey via the normal API.

Note that this adds the overhead of resharing keys with potentially many users in the chat which incurs additional runtime overhead.
However, this can be done in the background and doesn't have to block the app.
For that, most of the more costly vetKey derivation calls by the canister can be replaced by cheaper calls to store small encrypted vetKeys.
Also, this optimization works well only if most of the users provide valid reshared vetKeys, but, on the other hand, the penalty to the honest users (some additional latency due to the higher number of steps in the vetKey retrieval logic) is rather small.

An additional step useful to save a small amount of storage in the resharing routine is to remove the reshared vetKey after an encrypted cache has been added for a user to the canister state. 

### Allowing New Users to See Old Message History

It is not necessarily always the case that a user added to a chat should not see the previous history, which is the default setting in this spec.
This not only allows specific users to see the chat history but also reduces the number of calls to derive vetKeys.

In the chat UI, this functionality can be realized e.g. via a flag set in the chat UI while adding a new user.

The current spec does not allow to integrate this optimization in a completely non-invasive way, since the chat participants of a vetKey epoch cannot be changed.
To facilitate this, the list of chat participants could have versioning, where for each version the list change would be stored in the canister and `get_my_chats_and_time` would return no only the last message in the chat but also all vetKey epoch IDs for each chat and their participant list versions, or only for those where actual changes happened.

### State Recovery

The frontend's role in enabling state recovery (see also [Encrypted Ratchet State Cache](#encrypted-symmetric-ratchet-state-cache) in the backend) is twofold:
* Initialization of caches.
* Updates of caches.

Independent of how the local ratchet state was initialized, once initialized the frontend checks if the ratchet state cache in the canister needs to be updated. If no cache state exists in the canister or it is outdated, the frontend encrypts and uploads the state via the `update_my_symmetric_key_cache` backend canister API.

In addition to cache updates upon initialization, the frontend should periodically check that the cache is up-to-date. How often this is done depends on the symmetric ratchet duration window.
However, note that only the client that is online can update their cache, which normally doesn't work perfectly practice, e.g., if we rotate the symmetric ratchet state every hour, there will be very few clients that will be online for actually performing cache updates every hour.
Also, cache updates cost cycles in the ICP, and hence excessive use undesirably costs additional money.
Therefore, cache updates every (half a) day, and therefore the symmetric ratchet duration of a similar length, seem to be most practical in the general use case.
If another use case requires more strict parameters, they can be set appropriately to enable that use case.

Encrypted maps handles the encryption of the map values transparently to the developer, i.e., the developer does not need to know how encryption exactly works in encrypted maps and can use encrypted maps as a black box.
For the purpose of using encrypted maps for the encryption of user's cached keys, the encrypted maps object is instantiated with the domain separator `"vetkeys-example-encrypted-chat-user-cache"` in the backend.
Then, to handle the cache, the frontend relies on the following:

* Store to encrypted maps - when the frontend obtained a new ratchet state or wants to update a ratchet state cache, the frontend calls.

* Load from encrypted maps - when the frontend requires to recover its previous ratchet states, it retrieves the encrypted cache and decrypts it locally.

```ts
    import { EncryptedMaps } from '@dfinity/vetkeys/encrypted_maps';

    function store(encryptedMaps: EncryptedMaps, myPrincipal: Principal, chatId: ChatId, vetKeyEpochId: bigint, cache: Uint8Array) {
      const epochBytes = uBigIntTo8ByteUint8ArrayBigEndian(vetKeyEpochId);
      const chatIdBytes = chatIdToBytes(chatId);
      const mapKey = new Uint8Array([...chatIdBytes, ...epochBytes]);
      encryptedMaps.setValue(myPrincipal, mapName(), mapKey, cache);
    }

    function load(encryptedMaps: EncryptedMaps, myPrincipal: Principal, chatId: ChatId, vetKeyEpochId: bigint) : Uint8Array {
      const epochBytes = uBigIntTo8ByteUint8ArrayBigEndian(vetKeyEpochId);
      const chatIdBytes = chatIdToBytes(chatId);
      const mapKey = new Uint8Array([...chatIdBytes, ...epochBytes]);
      return encryptedMaps.getValue(myPrincipal, mapName(), mapKey);
    }

    function chatIdToBytes(chatId: ChatId) : Uint8Array {
      if ('Direct' in chatId) {
        return new Uint8Array([
          0,
          ...chatId.Direct[0].toUint8Array(),
          ...chatId.Direct[1].toUint8Array()
        ]);
	    } else {
		    return new Uint8Array([1, ...uBigIntTo8ByteUint8ArrayBigEndian(chatId.Group)]);
	    }
    }

    function uBigIntTo8ByteUint8ArrayBigEndian(value: bigint): Uint8Array {
	    if (value < 0n) throw new RangeError('Accepts only bigint n >= 0');

	    const bytes = new Uint8Array(8);
	    for (let i = 0; i < 8; i++) {
	    	bytes[i] = Number((value >> BigInt(i * 8)) & 0xffn);
    	}
	    return bytes;
    }

    function mapName(): Uint8Array {
	    return new TextEncoder().encode('encrypted_chat_cache');
    }
```

## Appendix

### Constructing `ChatId`

```
type GroupChatId = nat64;

type ChatId = variant {
  Group : GroupChatId;
  Direct : record { principal; principal };
};
```

**Direct**: The `ChatId` type is constructed from a pair of _sorted_ principals. It is valid if the principals are equal and corresponds to a user's private chat (similar to e.g. Signal's "Note to Self" chat).

**Group**: The `ChatId` type is constructed from a _unique_ group chat ID, which is defined by an unsigned 64-bit number. The backend is responsible of issuing those and ensuring their uniqueness.

### Calculating Current Symmetric Ratchet Epoch ID

```rust
fn current_symmetric_ratchet_epoch(
  vetkey_epoch_creation_time_nanos: u64,
  symmetric_ratchet_rotation_duration_nanos: u64
) {
  let now = ic_cdk::api::time();
  let elapsed = vetkey_epoch_creation_time_nanos - now;
  return elapsed / symmetric_ratchet_rotation_duration_nanos;
}
```

### TypeScript Conversion of Unsigned BigInt to Uint8Array

```ts
function uBigIntTo8ByteUint8ArrayBigEndian(value: bigint): Uint8Array {
	if (value < 0n) throw new RangeError('Accepts only bigint n >= 0');
    if ((value >> 128) > 0n) throw new RangeError('Accepts only bigint fitting into an 8-byte array');

	const bytes = new Uint8Array(8);
	for (let i = 0; i < 8; i++) {
		bytes[i] = Number((value >> BigInt(i * 8)) & 0xffn);
	}
	return bytes;
}
```

### TypeScript CryptoKey Import
```ts
let keyBytes = /*  */;
let exportable = false;
await globalThis.crypto.subtle.importKey(
		'raw',
		keyBytes,
		'HKDF',
		exportable,
		['deriveKey', 'deriveBits']
	);
```

### TypeScript Size Prefix

```ts
export function sizePrefixedBytesFromString(text: string): Uint8Array {
	const bytes = new TextEncoder().encode(text);
	if (bytes.length > 255) {
		throw new Error('Text is too long');
	}
	const size = new Uint8Array(1);
	size[0] = bytes.length & 0xff;
	return new Uint8Array([...size, ...bytes]);
}
```

### TypeScript Domain Separators

```ts

// Example definition of the domain separators
const DOMAIN_RATCHET_INIT = sizePrefixedBytesFromString('ic-vetkeys-chat-ratchet-init');
const DOMAIN_RATCHET_STEP = sizePrefixedBytesFromString('ic-vetkeys-chat-ratchet-step');
const DOMAIN_MESSAGE_ENCRYPTION = sizePrefixedBytesFromString(
	'ic-vetkeys-chat-message-encryption'
);

export function messageEncryptionDomainSeparator(
	sender: Principal,
	nonce: Uint8Array
): Uint8Array {
  if (nonce.length !== 16) { throw RangeError("Expected nonce of size 16 but got " + nonce.length); }
	return new Uint8Array([
		...DOMAIN_MESSAGE_ENCRYPTION,
		...sender.toUint8Array(),
		...uBigIntTo8ByteUint8ArrayBigEndian(nonce)
	]);
}

export function ratchetStepDomainSeparator(currentSymmetricKeyEpoch: bigint){
  new Uint8Array([
	  	...DOMAIN_RATCHET_STEP,
  		...uBigIntTo8ByteUint8ArrayBigEndian(currentSymmetricKeyEpoch)
  	]);
}
```

### Candid Interface of the Backend

```candid
type GroupChatId = nat64;
type ChatId = variant {
  Group : GroupChatId;
  Direct : record { principal; principal };
};
type VetKeyEpochId = nat64;
type SymmetricKeyEpochId = nat64;
type ChatMessageId = nat64;
type Nonce = blob;
type Limit = nat32;
type TimeNanos = nat64;
type NumberOfMessages = nat64;
type SymmetricKeyRotationMins = nat64;
type MessageExpiryMins = nat64;

type KeyRotationResult = variant { Ok : VetKeyEpochId; Err : text };
type EncryptedMessage = record {
  content : EncryptedBytes;
  metadata : EncryptedMessageMetadata;
};

// vetKeys
type PublicTransportKey = blob;
type DerivedVetKeyPublicKey = blob;
type EncryptedVetKey = blob;
type IbeEncryptedVetKey = blob;
type EncryptedSymmetricRatchetCache = blob;

type EncryptedMessageMetadata = record {
  vetkey_epoch : VetKeyEpochId;
  sender : principal;
  symmetric_key_epoch_id : SymmetricKeyEpochId;
  chat_message_id : ChatMessageId;
  timestamp : TimeNanos;
  nonce : Nonce;
};
type GroupChatMetadata = record { creation_timestamp : TimeNanos; chat_id : GroupChatId };
type GroupModification = record {
  remove_participants : vec principal;
  add_participants : vec principal;
};
type EncryptedBytes = blob;
type UserMessage = record {
  vetkey_epoch_id : VetKeyEpochId;
  content : EncryptedBytes;
  symmetric_key_epoch_id : SymmetricKeyEpochId;
  nonce : Nonce;
};
type NumberOfMessages = nat64;
type Receiver = principal;
type OtherParticipant = principal;
type VetKeyEpochMetadata = record {
  symmetric_key_rotation_duration : SymmetricKeyRotationMins;
  participants : vec principal;
  messages_start_with_id : ChatMessageId;
  creation_timestamp : TimeNanos;
  epoch_id : VetKeyEpochId;
};
type KeyRotationResult = variant { Ok : VetKeyEpochId; Err : text };
type MessageSendingError = variant { WrongVetKeyEpoch; WrongSymmetricKeyEpoch; Custom: text };
type ChatMetadata = record {
  chat_id : ChatId;
  number_of_messages : NumberOfMessages;
  vetkey_epoch_id : VetKeyEpochId;
  symmetric_epoch_id : SymmetricEpochId;
};
type StateRecoveryCacheMetadata = record {
  vetkey_epoch_id: VetKeyEpochId;
  symmetric_epoch_id : SymmetricEpochId;
};

service : (text) -> {
  chat_public_key : (ChatId, VetKeyEpochId) -> (DerivedVetKeyPublicKey);
  create_direct_chat : (OtherParticipant, SymmetricKeyRotationMins) -> variant { Ok : TimeNanos; Err : text };
  create_group_chat : (vec OtherParticipant, SymmetricKeyRotationMins) -> (variant { Ok : GroupChatMetadata; Err : text });
  derive_chat_vetkey : (ChatId, VetKeyEpochId, PublicTransportKey) -> (variant { Ok : EncryptedVetKey; Err : text });
  get_vetkey_for_my_cache_encryption : (PublicTransportKey) -> (EncryptedVetKey);
  get_latest_chat_vetkey_epoch_metadata : (ChatId) -> (variant { Ok : VetKeyEpochMetadata; Err : text }) query;
  get_my_chats_and_time : () -> (vec ChatMetadata) query;
  get_my_reshared_ibe_encrypted_vetkey : (ChatId, VetKeyEpochId) -> (variant { Ok : opt IbeEncryptedVetKey; Err : text });
  get_my_symmetric_key_cache : (ChatId, VetKeyEpochId) -> (variant { Ok : opt EncryptedSymmetricRatchetCache; Err : text });
  // Returns messages for a chat starting from a given message id.
  get_messages : (ChatId, ChatMessageId, opt Limit) -> (
      vec EncryptedMessage,
    ) query;
  get_metadata_for_my_state_recovery_caches : () -> (vec StateRecoveryCacheMetadata) query;
  get_vetkey_epoch_metadata : (ChatId, VetKeyEpochId) -> (variant { Ok : VetKeyEpochMetadata; Err : text }) query;
  get_vetkey_resharing_ibe_decryption_key : (PublicTransportKey) -> (EncryptedVetKey);
  get_vetkey_resharing_ibe_encryption_key : (Receiver) -> (DerivedVetKeyPublicKey);
  modify_group_chat_participants : (ChatGroupId, GroupModification) -> (KeyRotationResult);
  reshare_ibe_encrypted_vetkeys : (
      ChatId,
      VetKeyEpochId,
      vec record { Receiver; IbeEncryptedVetKey },
    ) -> (variant { Ok; Err : text });
  rotate_chat_vetkey : (ChatId) -> (KeyRotationResult);
  send_message : (ChatId, UserMessage) -> (variant { Ok; Err : MessageSendingError });
  set_message_expiry : (ChatId, MessageExpiryMins) ->  (variant { Ok; Err : text });
  set_state_recovery_limit : (ChatId, MessageExpiryMins)  ->  (variant { Ok; Err : text });
  get_state_recovery_limit : (ChatId) -> (variant { Ok : ?MessageExpiryMins; Err : text }) query;
  update_my_symmetric_key_cache : (ChatId, VetKeyEpochId, EncryptedSymmetricRatchetCache) -> (variant { Ok; Err : text });
}
```
