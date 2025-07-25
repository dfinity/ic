use ic_cdk::api::call::ManualReply;
use ic_message::ForwardParams;
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

#[ic_cdk::update]
pub async fn multi_http_request(url: String) -> Vec<Result<String, String>> {
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
