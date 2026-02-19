use candid::{CandidType, Decode, Deserialize, Encode, Principal};
use ic_cdk::api::msg_caller;
use ic_cdk::init;
use ic_cdk::update;
use ic_stable_structures::memory_manager::{MemoryId, MemoryManager, VirtualMemory};
use ic_stable_structures::{
    storable::Bound, DefaultMemoryImpl, StableBTreeMap, StableCell, Storable,
};
use std::borrow::Cow;
use std::cell::RefCell;

type PrincipalName = String;
type Memory = VirtualMemory<DefaultMemoryImpl>;
type NoteId = u128;

#[derive(Clone, Debug, CandidType, Deserialize, Eq, PartialEq)]
pub struct EncryptedNote {
    id: NoteId,
    encrypted_text: String,
    owner: PrincipalName,
    /// Principals with whom this note is shared. Does not include the owner.
    /// Needed to be able to efficiently show in the UI with whom this note is shared.
    users: Vec<PrincipalName>,
}

impl EncryptedNote {
    pub fn is_authorized(&self, user: &PrincipalName) -> bool {
        user == &self.owner || self.users.contains(user)
    }
}

impl Storable for EncryptedNote {
    fn to_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(Encode!(self).unwrap())
    }
    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        Decode!(bytes.as_ref(), Self).unwrap()
    }
    const BOUND: Bound = Bound::Unbounded;
}

#[derive(CandidType, Deserialize, Default)]
pub struct NoteIds {
    ids: Vec<NoteId>,
}

impl NoteIds {
    pub fn iter(&self) -> impl std::iter::Iterator<Item = &NoteId> {
        self.ids.iter()
    }
}

impl Storable for NoteIds {
    fn to_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(Encode!(self).unwrap())
    }
    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        Decode!(bytes.as_ref(), Self).unwrap()
    }
    const BOUND: Bound = Bound::Unbounded;
}

// We use a canister's stable memory as storage. This simplifies the code and makes the appliation
// more robust because no (potentially failing) pre_upgrade/post_upgrade hooks are needed.
// Note that stable memory is less performant than heap memory, however.
// Currently, a single canister smart contract is limited to 96 GB of stable memory.
// For the current limits see https://internetcomputer.org/docs/current/developer-docs/production/resource-limits.
// To ensure that our canister does not exceed the limit, we put various restrictions (e.g., number of users) in place.
static MAX_USERS: u64 = 1_000;
static MAX_NOTES_PER_USER: usize = 500;
static MAX_NOTE_CHARS: usize = 1000;
static MAX_SHARES_PER_NOTE: usize = 50;

thread_local! {
    static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> =
        RefCell::new(MemoryManager::init(DefaultMemoryImpl::default()));

    static NEXT_NOTE_ID: RefCell<StableCell<NoteId, Memory>> = RefCell::new(
        StableCell::init(
            MEMORY_MANAGER.with_borrow(|m| m.get(MemoryId::new(0))),
            1
        ).expect("failed to init NEXT_NOTE_ID")
    );

    static NOTES: RefCell<StableBTreeMap<NoteId, EncryptedNote, Memory>> = RefCell::new(
        StableBTreeMap::init(
            MEMORY_MANAGER.with_borrow(|m| m.get(MemoryId::new(1))),
        )
    );

    static NOTE_OWNERS: RefCell<StableBTreeMap<PrincipalName, NoteIds, Memory>> = RefCell::new(
        StableBTreeMap::init(
            MEMORY_MANAGER.with_borrow(|m| m.get(MemoryId::new(2))),
        )
    );

    static NOTE_SHARES: RefCell<StableBTreeMap<PrincipalName, NoteIds, Memory>> = RefCell::new(
        StableBTreeMap::init(
            MEMORY_MANAGER.with_borrow(|m| m.get(MemoryId::new(3))),
        )
    );
    static KEY_NAME: RefCell<StableCell<String, Memory>> =
        RefCell::new(StableCell::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(1))),
            String::new(),
        )
        .expect("failed to initialize key name"));
}

#[init]
fn init(key_name_string: String) {
    KEY_NAME.with_borrow_mut(|key_name| {
        key_name
            .set(key_name_string)
            .expect("failed to set key name");
    });
}

/// Unlike Motoko, the caller identity is not built into Rust.
/// Thus, we use the ic_cdk::caller() method inside this wrapper function.
/// The wrapper prevents the use of the anonymous identity. Forbidding anonymous
/// interactions is the recommended default behavior for IC canisters.
fn caller() -> Principal {
    let caller = msg_caller();
    // The anonymous principal is not allowed to interact with the
    // encrypted notes canister.
    if caller == Principal::anonymous() {
        panic!("Anonymous principal not allowed to make calls.")
    }
    caller
}

// --- Queries vs. Updates ---
//
// Note that our public methods are declared as an *updates* rather than *queries*, e.g.:
// #[update(name = "notesCnt")] ...
// rather than
// #[query(name = "notesCnt")] ...
//
// While queries are significantly faster than updates, they are not certified by the IC.
// Thus, we avoid using queries throughout this dapp, ensuring that the result of our
// methods gets through consensus. Otherwise, this method could e.g. omit some notes
// if it got executed by a malicious node. (To make the dapp more efficient, one could
// use an approach in which both queries and updates are combined.)
//
// See https://internetcomputer.org/docs/current/concepts/canisters-code#query-and-update-methods

/// Reflects the [caller]'s identity by returning (a future of) its principal.
/// Useful for debugging.
#[update]
fn whoami() -> String {
    msg_caller().to_string()
}

// General assumptions
// -------------------
// All the functions of this canister's public API should be available only to
// registered users, with the exception of [whoami].

/// Returns (a future of) this [caller]'s notes.
/// Panics:
///     [caller] is the anonymous identity
#[update]
fn get_notes() -> Vec<EncryptedNote> {
    let user_str = caller().to_string();
    NOTES.with_borrow(|notes| {
        let owned = NOTE_OWNERS.with_borrow(|ids| {
            ids.get(&user_str)
                .unwrap_or_default()
                .iter()
                .map(|id| notes.get(id).ok_or(format!("missing note with ID {id}")))
                .collect::<Result<Vec<_>, _>>()
                .unwrap_or_else(|err| ic_cdk::trap(&err))
        });
        let shared = NOTE_SHARES.with_borrow(|ids| {
            ids.get(&user_str)
                .unwrap_or_default()
                .iter()
                .map(|id| notes.get(id).ok_or(format!("missing note with ID {id}")))
                .collect::<Result<Vec<_>, _>>()
                .unwrap_or_else(|err| ic_cdk::trap(&err))
        });
        let mut result = Vec::with_capacity(owned.len() + shared.len());
        result.extend(owned);
        result.extend(shared);
        result
    })
}

/// Delete this [caller]'s note with given id. If none of the
/// existing notes have this id, do nothing.
/// [id]: the id of the note to be deleted
///
/// Returns:
///      Future of unit
/// Panics:
///      [caller] is the anonymous identity
///      [caller] is not the owner of note with id `note_id`
#[update]
fn delete_note(note_id: u128) {
    let user_str = caller().to_string();
    NOTES.with_borrow_mut(|notes| {
        if let Some(note_to_delete) = notes.get(&note_id) {
            let owner = &note_to_delete.owner;
            if owner != &user_str {
                ic_cdk::trap("only the owner can delete notes");
            }
            NOTE_OWNERS.with_borrow_mut(|owner_to_nids| {
                if let Some(mut owner_ids) = owner_to_nids.get(owner) {
                    owner_ids.ids.retain(|&id| id != note_id);
                    if !owner_ids.ids.is_empty() {
                        owner_to_nids.insert(owner.clone(), owner_ids);
                    } else {
                        owner_to_nids.remove(owner);
                    }
                }
            });
            NOTE_SHARES.with_borrow_mut(|share_to_nids| {
                for share in note_to_delete.users {
                    if let Some(mut share_ids) = share_to_nids.get(&share) {
                        share_ids.ids.retain(|&id| id != note_id);
                        if !share_ids.ids.is_empty() {
                            share_to_nids.insert(share, share_ids);
                        } else {
                            share_to_nids.remove(&share);
                        }
                    }
                }
            });
            notes.remove(&note_id);
        }
    });
}

/// Replaces the encrypted text of note with ID [id] with [encrypted_text].
///
/// Panics:
///     [caller] is the anonymous identity
///     [caller] is not the note's owner and not a user with whom the note is shared
///     [encrypted_text] exceeds [MAX_NOTE_CHARS]
#[update]
fn update_note(id: NoteId, encrypted_text: String) {
    let user_str = caller().to_string();

    NOTES.with_borrow_mut(|notes| {
        if let Some(mut note_to_update) = notes.get(&id) {
            if !note_to_update.is_authorized(&user_str) {
                ic_cdk::trap("unauthorized update");
            }
            assert!(encrypted_text.chars().count() <= MAX_NOTE_CHARS);
            note_to_update.encrypted_text = encrypted_text;
            notes.insert(id, note_to_update);
        }
    })
}

/// Add new empty note for this [caller].
///
/// Returns:
///      Future of ID of new empty note
/// Panics:
///      [caller] is the anonymous identity
///      User already has [MAX_NOTES_PER_USER] notes
///      This is the first note for [caller] and [MAX_USERS] is exceeded
#[update]
fn create_note() -> NoteId {
    let owner = caller().to_string();

    NOTES.with_borrow_mut(|id_to_note| {
        NOTE_OWNERS.with_borrow_mut(|owner_to_nids| {
            let next_note_id = NEXT_NOTE_ID.with_borrow(|id| *id.get());
            let new_note = EncryptedNote {
                id: next_note_id,
                owner: owner.clone(),
                users: vec![],
                encrypted_text: String::new(),
            };

            if let Some(mut owner_nids) = owner_to_nids.get(&owner) {
                assert!(owner_nids.ids.len() < MAX_NOTES_PER_USER);
                owner_nids.ids.push(new_note.id);
                owner_to_nids.insert(owner, owner_nids);
            } else {
                assert!(owner_to_nids.len() < MAX_USERS);
                owner_to_nids.insert(
                    owner,
                    NoteIds {
                        ids: vec![new_note.id],
                    },
                );
            }
            assert_eq!(id_to_note.insert(new_note.id, new_note), None);

            NEXT_NOTE_ID.with_borrow_mut(|next_note_id| {
                let id_plus_one = next_note_id
                    .get()
                    .checked_add(1)
                    .expect("failed to increase NEXT_NOTE_ID: reached the maximum");
                next_note_id
                    .set(id_plus_one)
                    .unwrap_or_else(|_e| ic_cdk::trap("failed to set NEXT_NOTE_ID"))
            });
            next_note_id
        })
    })
}

/// Shares the note with ID `note_id`` with the `user`.
/// Has no effect if the note is already shared with that user.
///
/// Panics:
///      [caller] is the anonymous identity
///      [caller] is not the owner of note with id `note_id`
#[update]
fn add_user(note_id: NoteId, user: PrincipalName) {
    let caller_str = caller().to_string();
    NOTES.with_borrow_mut(|notes| {
        NOTE_SHARES.with_borrow_mut(|user_to_nids| {
            if let Some(mut note) = notes.get(&note_id) {
                let owner = &note.owner;
                if owner != &caller_str {
                    ic_cdk::trap("only the owner can share the note");
                }
                assert!(note.users.len() < MAX_SHARES_PER_NOTE);
                if !note.users.contains(&user) {
                    note.users.push(user.clone());
                    notes.insert(note_id, note);
                }
                if let Some(mut user_ids) = user_to_nids.get(&user) {
                    if !user_ids.ids.contains(&note_id) {
                        user_ids.ids.push(note_id);
                        user_to_nids.insert(user, user_ids);
                    }
                } else {
                    user_to_nids.insert(user, NoteIds { ids: vec![note_id] });
                }
            }
        })
    });
}

/// Unshares the note with ID `note_id`` with the `user`.
/// Has no effect if the note is not shared with that user.
///
/// Panics:
///      [caller] is the anonymous identity
///      [caller] is not the owner of note with id `note_id`
#[update]
fn remove_user(note_id: NoteId, user: PrincipalName) {
    let caller_str = caller().to_string();
    NOTES.with_borrow_mut(|notes| {
        NOTE_SHARES.with_borrow_mut(|user_to_nids| {
            if let Some(mut note) = notes.get(&note_id) {
                let owner = &note.owner;
                if owner != &caller_str {
                    ic_cdk::trap("only the owner can share the note");
                }
                note.users.retain(|u| u != &user);
                notes.insert(note_id, note);

                if let Some(mut user_ids) = user_to_nids.get(&user) {
                    user_ids.ids.retain(|&id| id != note_id);
                    if !user_ids.ids.is_empty() {
                        user_to_nids.insert(user, user_ids);
                    } else {
                        user_to_nids.remove(&user);
                    }
                }
            }
        })
    });
}

use ic_cdk::management_canister::{
    VetKDCurve, VetKDDeriveKeyArgs, VetKDDeriveKeyResult, VetKDKeyId, VetKDPublicKeyArgs,
    VetKDPublicKeyResult,
};

#[update]
async fn symmetric_key_verification_key_for_note() -> String {
    let request = VetKDPublicKeyArgs {
        canister_id: None,
        context: b"note_symmetric_key".to_vec(),
        key_id: key_id(),
    };

    let response: VetKDPublicKeyResult = ic_cdk::management_canister::vetkd_public_key(&request)
        .await
        .expect("call to vetkd_public_key failed");

    hex::encode(response.public_key)
}

#[update]
async fn encrypted_symmetric_key_for_note(
    note_id: NoteId,
    transport_public_key: Vec<u8>,
) -> String {
    let user_str = caller().to_string();
    let request = NOTES.with_borrow(|notes| {
        if let Some(note) = notes.get(&note_id) {
            if !note.is_authorized(&user_str) {
                ic_cdk::trap(format!("unauthorized key request by user {user_str}"));
            }
            VetKDDeriveKeyArgs {
                input: {
                    let mut buf = vec![];
                    buf.extend_from_slice(&note_id.to_be_bytes()); // fixed-size encoding
                    buf.extend_from_slice(note.owner.as_bytes());
                    buf // prefix-free
                },
                context: b"note_symmetric_key".to_vec(),
                key_id: key_id(),
                transport_public_key,
            }
        } else {
            ic_cdk::trap(format!("note with ID {note_id} does not exist"));
        }
    });

    let response: VetKDDeriveKeyResult = ic_cdk::management_canister::vetkd_derive_key(&request)
        .await
        .expect("call to vetkd_derive_key failed");

    hex::encode(response.encrypted_key)
}

fn key_id() -> VetKDKeyId {
    VetKDKeyId {
        curve: VetKDCurve::Bls12_381_G2,
        name: KEY_NAME.with_borrow(|key_name| key_name.get().clone()),
    }
}
