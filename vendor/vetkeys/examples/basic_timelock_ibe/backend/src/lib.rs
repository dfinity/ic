use crate::types::{
    BidCounter, DecryptedBid, EncryptedBid, LotId, LotInformation, VetKeyPublicKey,
};
use candid::Principal;
use ic_cdk::management_canister::{VetKDCurve, VetKDDeriveKeyArgs, VetKDKeyId, VetKDPublicKeyArgs};
use ic_cdk::{init, post_upgrade, query, update};
use ic_stable_structures::memory_manager::{MemoryId, MemoryManager, VirtualMemory};
use ic_stable_structures::{BTreeMap as StableBTreeMap, Cell as StableCell, DefaultMemoryImpl};
use ic_vetkeys::{DerivedPublicKey, EncryptedVetKey};
use std::cell::RefCell;

mod types;
use types::*;

type Memory = VirtualMemory<DefaultMemoryImpl>;

thread_local! {
    static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> =
        RefCell::new(MemoryManager::init(DefaultMemoryImpl::default()));

    static LOTS: RefCell<StableBTreeMap<LotId, LotInformation, Memory>> = RefCell::new(StableBTreeMap::init(
        MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(0))),
    ));
    /// The bids include a bid counter to ensure that if multiple users provide the same highest bid, the bid that was placed first wins.
    /// The counter is not unique for a lot, it is monotonically increasing for all bids.
    static BIDS_ON_LOTS: RefCell<StableBTreeMap<(LotId, BidCounter, Principal), Bid, Memory>> = RefCell::new(StableBTreeMap::init(
        MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(1))),
    ));
    static OPEN_LOTS_DEADLINES: RefCell<StableBTreeMap<(u64, LotId), (), Memory>> = RefCell::new(StableBTreeMap::init(
        MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(2))),
    ));

    static IBE_PUBLIC_KEY: RefCell<Option<VetKeyPublicKey>> =  const { RefCell::new(None) };

    static BID_COUNTER: RefCell<BidCounter> = const { RefCell::new(0) };

    static KEY_NAME: RefCell<StableCell<String, Memory>> =
        RefCell::new(StableCell::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(1))),
            String::new(),
        )
        .expect("failed to initialize key name"));
}

const DOMAIN_SEPARATOR: &str = "basic_timelock_ibe_example_dapp";
const TIMER_INTERVAL_SECS: u64 = 5;

#[init]
fn init(key_name_string: String) {
    KEY_NAME.with_borrow_mut(|key_name| {
        key_name
            .set(key_name_string)
            .expect("failed to set key name");
    });

    start_lot_closing_timer_job_with_interval_secs(TIMER_INTERVAL_SECS);
}

#[post_upgrade]
fn post_upgrade() {
    start_lot_closing_timer_job_with_interval_secs(TIMER_INTERVAL_SECS);
}

#[update(guard = "is_authenticated")]
fn create_lot(name: String, description: String, duration_seconds: u16) -> Result<LotId, String> {
    let caller = ic_cdk::api::msg_caller();

    if duration_seconds == 0 {
        return Err("Duration must be greater than 0".to_string());
    }

    let lot_id = LOTS.with_borrow_mut(|lots| {
        let lot_id = lots.len() as u128;

        const NANOS_IN_SEC: u64 = 1_000_000_000;
        let start_time = ic_cdk::api::time();

        let lot = LotInformation {
            id: lot_id,
            name,
            description,
            start_time,
            end_time: start_time + duration_seconds as u64 * NANOS_IN_SEC,
            creator: caller,
            status: LotStatus::Open,
        };

        OPEN_LOTS_DEADLINES.with_borrow_mut(|open_lots_deadlines| {
            open_lots_deadlines.insert((lot.end_time, lot_id), ());
        });

        lots.insert(lot_id, lot);

        lot_id
    });

    Ok(lot_id)
}

#[update(guard = "is_authenticated")]
async fn get_ibe_public_key() -> VetKeyPublicKey {
    if let Some(key) = IBE_PUBLIC_KEY.with_borrow(|key| key.clone()) {
        return key;
    }

    let request = VetKDPublicKeyArgs {
        canister_id: None,
        context: DOMAIN_SEPARATOR.as_bytes().to_vec(),
        key_id: key_id(),
    };

    let result = ic_cdk::management_canister::vetkd_public_key(&request)
        .await
        .expect("call to vetkd_public_key failed");

    IBE_PUBLIC_KEY.with_borrow_mut(|key| {
        key.replace(VetKeyPublicKey::from(result.public_key.clone()));
    });

    VetKeyPublicKey::from(result.public_key)
}

#[query(guard = "is_authenticated")]
fn get_lots() -> (OpenLotsResponse, ClosedLotsResponse) {
    let mut open_lots = OpenLotsResponse::default();
    let mut closed_lots = ClosedLotsResponse::default();

    LOTS.with_borrow(|lots| {
        for (lot_id, lot) in lots.iter() {
            match lot.status {
                LotStatus::Open => {
                    open_lots.lots.push(lot);
                    let bidders: Vec<Principal> = BIDS_ON_LOTS.with_borrow(|bids| {
                        bids.range((lot_id, 0, Principal::management_canister())..)
                            .take_while(|((this_lot_id, _, _), _)| *this_lot_id == lot_id)
                            .map(|((_, _, bidder), _)| bidder)
                            .collect()
                    });
                    open_lots.bidders.push(bidders);
                }
                _ => {
                    closed_lots.lots.push(lot);

                    let bids: Vec<(Principal, u128)> = BIDS_ON_LOTS.with_borrow(|bids| {
                        bids.range((lot_id, 0, Principal::management_canister())..)
                            .take_while(|((this_lot_id, _, _), _)| *this_lot_id == lot_id)
                            .map(|((_, _, bidder), bid)| match bid {
                                Bid::Encrypted(_) => {
                                    panic!("bug: encrypted bid in a closed lot")
                                }
                                Bid::Decrypted(decrypted_bid) => (bidder, decrypted_bid.amount),
                            })
                            .collect()
                    });
                    closed_lots.bids.push(bids);
                }
            }
        }
    });
    (open_lots, closed_lots)
}

#[update(guard = "is_authenticated")]
fn place_bid(lot_id: u128, encrypted_amount: Vec<u8>) -> Result<(), String> {
    let bidder = ic_cdk::api::msg_caller();
    let now = ic_cdk::api::time();

    LOTS.with_borrow(|lots| match lots.get(&lot_id) {
        Some(LotInformation {
            status: LotStatus::Open,
            creator,
            end_time,
            ..
        }) if creator != bidder && now < end_time => Ok(()),
        Some(LotInformation { creator, .. }) if creator == bidder => {
            Err("lot creator cannot bid".to_string())
        }
        Some(_) => Err("lot is closed".to_string()),
        None => Err("lot not found".to_string()),
    })?;

    if encrypted_amount.len() > 1000 {
        return Err("encrypted amount is too large to be valid".to_string());
    }

    BIDS_ON_LOTS.with_borrow_mut(|bids| {
        if let Some((existing_bid_key, _existing_bid)) = bids
            .range((lot_id, 0, Principal::management_canister())..)
            .take_while(|((this_lot_id, _, _), _)| *this_lot_id == lot_id)
            .find(|((_, _, this_bidder), _)| *this_bidder == bidder)
        {
            bids.remove(&existing_bid_key);
        }

        let bid_counter = BID_COUNTER.with_borrow_mut(|bid_counter| {
            let old_bid_counter = *bid_counter;
            *bid_counter += 1;
            old_bid_counter
        });

        bids.insert(
            (lot_id, bid_counter, bidder),
            Bid::Encrypted(EncryptedBid {
                encrypted_amount,
                bidder,
            }),
        );
    });

    Ok(())
}

#[update(guard = "is_self_call")]
fn start_lot_closing_timer_job_with_interval_secs(secs: u64) {
    let secs = std::time::Duration::from_secs(secs);
    ic_cdk_timers::set_timer_interval(secs, || {
        ic_cdk::futures::spawn(close_one_lot_if_any_is_open_and_expired())
    });
}

async fn close_one_lot_if_any_is_open_and_expired() {
    // get the lot with the earliest deadline (if any)
    let maybe_deadline_and_lot_id =
        OPEN_LOTS_DEADLINES.with_borrow(|open_lots_deadlines| open_lots_deadlines.iter().next());

    let lot_id = match maybe_deadline_and_lot_id {
        // if there was a lot and its deadline has passed, remove it from the open lots deadlines to prevent double processing
        Some(((deadline, lot_id), ())) if deadline <= ic_cdk::api::time() => {
            OPEN_LOTS_DEADLINES.with_borrow_mut(|open_lots_deadlines| {
                open_lots_deadlines
                    .remove(&(deadline, lot_id))
                    .expect("failed to remove deadline from open lots deadlines")
            });
            lot_id
        }
        // if there was no lot or the deadline has not passed, return without doing anything
        _ => return,
    };

    let (bid_counters, encrypted_bids) = get_encrypted_bids_on_lot(lot_id);
    let decrypted_bids = decrypt_bids(lot_id, encrypted_bids).await;
    close_lot(lot_id, bid_counters, decrypted_bids);
}

async fn decrypt_bids(lot_id: LotId, encrypted_bids: Vec<EncryptedBid>) -> Vec<DecryptedBid> {
    let decrypted_values = decrypt_ciphertexts(
        lot_id.to_le_bytes().to_vec(),
        encrypted_bids
            .iter()
            .map(|bid| bid.encrypted_amount.as_slice())
            .collect::<Vec<_>>(),
    )
    .await;

    convert_decrypted_values_to_decrypted_bids(lot_id, encrypted_bids, decrypted_values)
}

/// In the canister, using the IBE key derived from the identity decrypt a vector of ciphertexts, which makes them public.
/// Returns a vector, where each value is either a decrypted plaintext or an error message.
async fn decrypt_ciphertexts(
    identity: Vec<u8>,
    encrypted_values: Vec<&[u8]>,
) -> Vec<Result<Vec<u8>, String>> {
    let dummy_seed = vec![0; 32];
    let transport_secret_key = ic_vetkeys::TransportSecretKey::from_seed(dummy_seed.clone())
        .expect("failed to create transport secret key");

    let request = VetKDDeriveKeyArgs {
        context: DOMAIN_SEPARATOR.as_bytes().to_vec(),
        input: identity.clone(),
        key_id: key_id(),
        transport_public_key: transport_secret_key.public_key().to_vec(),
    };

    let result = ic_cdk::management_canister::vetkd_derive_key(&request)
        .await
        .expect("call to vetkd_derive_key failed");

    let ibe_public_key =
        DerivedPublicKey::deserialize(&get_ibe_public_key().await.into_vec()).unwrap();
    let encrypted_vetkey = EncryptedVetKey::deserialize(&result.encrypted_key).unwrap();

    let ibe_decryption_key = encrypted_vetkey
        .decrypt_and_verify(&transport_secret_key, &ibe_public_key, identity.as_ref())
        .expect("failed to decrypt ibe key");

    let mut decrypted_values = Vec::new();

    for encrypted_value in encrypted_values.into_iter() {
        let decrypted_value = ic_vetkeys::IbeCiphertext::deserialize(encrypted_value)
            .map_err(|e| format!("failed to deserialize ibe ciphertext: {e}"))
            .and_then(|c| {
                c.decrypt(&ibe_decryption_key)
                    .map_err(|_| "failed to decrypt ibe ciphertext".to_string())
            });
        decrypted_values.push(decrypted_value);
    }
    decrypted_values
}

fn convert_decrypted_values_to_decrypted_bids(
    lot_id: LotId,
    encrypted_bids: Vec<EncryptedBid>,
    decrypted_values: Vec<Result<Vec<u8>, String>>,
) -> Vec<DecryptedBid> {
    let mut decrypted_bids = Vec::with_capacity(encrypted_bids.len());
    for decrypted_value in decrypted_values {
        let decrypted_bid: Result<u128, String> = decrypted_value
            .and_then(|v| {
                v.as_slice()
                    .try_into()
                    .map_err(|_| "failed to convert amount to u128".to_string())
            })
            .map(u128::from_le_bytes);
        decrypted_bids.push(decrypted_bid);
    }

    encrypted_bids
        .into_iter()
        .zip(decrypted_bids)
        .inspect(|(encrypted_bid, decrypted_bid)| {
            if let Err(e) = decrypted_bid {
                ic_cdk::println!(
                    "Failed to decrypt bid for lot id {lot_id} by {}: {e}",
                    encrypted_bid.bidder
                );
            }
        })
        .filter_map(|(encrypted_bid, decrypted_bid)| {
            decrypted_bid.ok().map(|amount| DecryptedBid {
                amount,
                bidder: encrypted_bid.bidder,
            })
        })
        .collect()
}

fn get_encrypted_bids_on_lot(lot_id: LotId) -> (Vec<BidCounter>, Vec<EncryptedBid>) {
    BIDS_ON_LOTS.with_borrow(|bids| {
        bids.range((lot_id, 0, Principal::management_canister())..)
            .take_while(|((this_lot_id, _, _), _)| *this_lot_id == lot_id)
            .map(|((_, bid_counter, _), bid)| {
                let encrypted_bid = match bid {
                    Bid::Encrypted(encrypted_bid) => encrypted_bid,
                    Bid::Decrypted(_) => panic!("bug: decrypted bid in a closed lot"),
                };
                (bid_counter, encrypted_bid)
            })
            .collect()
    })
}

fn close_lot(lot_id: LotId, bid_counters: Vec<BidCounter>, decrypted_bids: Vec<DecryptedBid>) {
    let status = match decrypted_bids
        .iter()
        .rev() // reverse the bids to get the *oldest* maximum bid
        .max_by(|x, y| x.amount.cmp(&y.amount))
    {
        Some(winner_bid) => LotStatus::ClosedWithWinner(winner_bid.bidder),
        None => LotStatus::ClosedNoBids,
    };

    BIDS_ON_LOTS.with_borrow_mut(|bids| {
        for (bid_counter, decrypted_bid) in bid_counters.into_iter().zip(decrypted_bids.into_iter())
        {
            // replace the encrypted bid with the decrypted bid
            bids.insert(
                (lot_id, bid_counter, decrypted_bid.bidder),
                Bid::Decrypted(decrypted_bid),
            );
        }
    });

    LOTS.with_borrow_mut(|lots| {
        let lot_information = lots.get(&lot_id).unwrap();
        lots.insert(
            lot_id,
            LotInformation {
                id: lot_id,
                status,
                ..lot_information
            },
        );
    });
}

fn is_authenticated() -> Result<(), String> {
    let caller = ic_cdk::api::msg_caller();
    if caller != Principal::anonymous() {
        Ok(())
    } else {
        Err("the caller must be authenticated".to_string())
    }
}

fn is_self_call() -> Result<(), String> {
    if ic_cdk::api::msg_caller() == ic_cdk::api::canister_self() {
        Ok(())
    } else {
        Err("the caller must be the canister itself".to_string())
    }
}

fn key_id() -> VetKDKeyId {
    VetKDKeyId {
        curve: VetKDCurve::Bls12_381_G2,
        name: KEY_NAME.with_borrow(|key_name| key_name.get().clone()),
    }
}

// In the following, we register a custom getrandom implementation because
// otherwise getrandom (which is a dependency of some other dependencies) fails to compile.
// This is necessary because getrandom by default fails to compile for the
// wasm32-unknown-unknown target (which is required for deploying a canister).
// Our custom implementation always fails, which is sufficient here because
// the used RNGs are _manually_ seeded rather than by the system.
#[cfg(all(
    target_arch = "wasm32",
    target_vendor = "unknown",
    target_os = "unknown"
))]
getrandom::register_custom_getrandom!(always_fail);
#[cfg(all(
    target_arch = "wasm32",
    target_vendor = "unknown",
    target_os = "unknown"
))]
fn always_fail(_buf: &mut [u8]) -> Result<(), getrandom::Error> {
    Err(getrandom::Error::UNSUPPORTED)
}

ic_cdk::export_candid!();
