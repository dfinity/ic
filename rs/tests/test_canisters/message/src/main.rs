use futures::{stream::FuturesUnordered, StreamExt};
use ic_cdk::api::call::ManualReply;
use ic_message::ForwardParams;
use rand::{seq::IteratorRandom, SeedableRng};
use std::cell::RefCell;

thread_local! {
    static MSG: RefCell<Option<String>> = const { RefCell::new(None) };
}

#[ic_cdk::update]
fn store(text: String) {
    MSG.with(|msg| *msg.borrow_mut() = Some(text));
}

#[ic_cdk::query]
fn read() -> Option<String> {
    MSG.with(|msg| (*msg.borrow()).clone())
}

#[ic_cdk::update(manual_reply = true)]
pub async fn forward(
    ForwardParams {
        receiver,
        method,
        cycles,
        payload,
    }: ForwardParams,
) -> ManualReply<Vec<u8>> {
    match ic_cdk::api::call::call_raw128(receiver, &method, &payload, cycles).await {
        Ok(res) => ManualReply::one(res),
        Err((_, err)) => ManualReply::reject(err),
    }
}

mod sys {
    #[link(wasm_import_module = "ic0")]
    extern "C" {
        pub fn subnet_num_nodes() -> usize;
        pub fn subnet_node_id_copy(node_index: usize, dst: usize, offset: usize, size: usize);
        pub fn subnet_node_id_size(node_index: usize) -> usize;
    }
}

fn subnet_node_ids() -> Vec<candid::Principal> {
    fn subnet_num_nodes() -> usize {
        // SAFETY: ic0.subnet_self_size is always safe to call.
        unsafe { sys::subnet_num_nodes() }
    }
    fn subnet_node_id_size(node_index: usize) -> usize {
        // SAFETY: ic0.subnet_node_id_size is always safe to call.
        unsafe { sys::subnet_node_id_size(node_index) }
    }
    fn subnet_node_id_copy(node_index: usize, dst: &mut [u8]) {
        // SAFETY: ic0.subnet_node_id_copy is always safe to call.
        unsafe {
            sys::subnet_node_id_copy(node_index, dst.as_mut_ptr() as usize, 0, dst.len());
        }
    }

    fn get_node_id(node_index: usize) -> candid::Principal {
        let size = subnet_node_id_size(node_index);
        let mut id = vec![0u8; size];
        subnet_node_id_copy(node_index, &mut id);
        candid::Principal::from_slice(&id)
    }
    (0..subnet_num_nodes()).map(get_node_id).collect()
}

thread_local! {
    static PRNG: RefCell<rand_chacha::ChaCha8Rng> = RefCell::new(rand_chacha::ChaCha8Rng::seed_from_u64(ic_cdk::api::time() as u64));
}

type ResponseTypePlaceholder = String;
type CallErrorTypePlaceholder = String;
type ParametersError = String;

#[ic_cdk::update]
pub async fn k_of_n_http_requests(
    url: String,
    k: usize,
    n: usize,
) -> Result<Vec<Result<ResponseTypePlaceholder, CallErrorTypePlaceholder>>, ParametersError> {
    if k > n {
        return Err("k must be less than or equal to n".to_string());
    }
    let node_ids = subnet_node_ids();
    if n > node_ids.len() {
        return Err(
            "n must be less than or equal to the number of nodes in the subnet".to_string(),
        );
    }
    let chosen = PRNG.with_borrow_mut(|prng| node_ids.into_iter().choose_multiple(prng, n));
    let mut futures = chosen
        .into_iter()
        .map(|node_id| {
            ic_cdk::api::call::call_with_payment::<
                _,
                (ic_management_canister_types_private::CanisterHttpResponsePayload,),
            >(
                candid::Principal::management_canister(),
                "http_request",
                (
                    ic_management_canister_types_private::CanisterHttpRequestArgs {
                        url: url.clone(),
                        method: ic_management_canister_types_private::HttpMethod::GET,
                        body: None,
                        headers: ic_management_canister_types_private::BoundedVec::new(vec![]),
                        is_replicated: Some(node_id.into()),
                        max_response_bytes: Some(1000),
                        transform: None,
                    },
                ),
                50_000_000,
            )
        })
        .collect::<FuturesUnordered<_>>();

    let mut res = vec![];
    while (res.len() < k) {
        match futures.next().await {
            Some(Ok((response,))) => {
                res.push(Ok(String::from_utf8(response.body)
                    .map_err(|e| format!("Invalid UTF-8: {:?}", e))?));
            }
            Some(Err(e)) => {
                res.push(Err(format!("{:?}", e)));
            }
            None => break,
        }
    }

    Ok(res)
}

#[ic_cdk::update]
pub async fn nonreplicated_http_request() -> Vec<Result<ResponseTypePlaceholder, CallErrorTypePlaceholder>> {}

#[ic_cdk::update]
pub async fn multi_http_request(
    url: String,
) -> Vec<Result<ResponseTypePlaceholder, CallErrorTypePlaceholder>> {
    let node_ids = subnet_node_ids();
    let futures = node_ids.into_iter().map(|node_id| {
        ic_cdk::api::call::call_with_payment::<
            _,
            (ic_management_canister_types_private::CanisterHttpResponsePayload,),
        >(
            candid::Principal::management_canister(),
            "http_request",
            (
                ic_management_canister_types_private::CanisterHttpRequestArgs {
                    url: url.clone(),
                    method: ic_management_canister_types_private::HttpMethod::GET,
                    body: None,
                    headers: ic_management_canister_types_private::BoundedVec::new(vec![]),
                    is_replicated: Some(node_id.into()),
                    max_response_bytes: Some(1000),
                    transform: None,
                },
            ),
            50_000_000,
        )
    });
    futures::future::join_all(futures)
        .await
        .into_iter()
        .map(|res| {
            res.map_err(|e| format!("{:?}", e)).and_then(|(response,)| {
                String::from_utf8(response.body).map_err(|e| format!("Invalid UTF-8: {:?}", e))
            })
        })
        .collect()
}

#[ic_cdk::pre_upgrade]
fn pre_upgrade() {
    let msg = MSG.with(|msg| (*msg.borrow()).clone());
    ic_cdk::storage::stable_save((msg,)).expect("Saving message to stable memory must succeed.");
}

#[ic_cdk::post_upgrade]
fn post_upgrade() {
    let m = ic_cdk::storage::stable_restore::<(Option<String>,)>()
        .expect("Failed to read message from stable memory.")
        .0;

    MSG.with(|msg| *msg.borrow_mut() = m);
}

fn main() {}
