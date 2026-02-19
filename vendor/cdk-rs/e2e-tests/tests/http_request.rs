use candid::{Encode, Principal};
use pocket_ic::common::rest::{
    CanisterHttpHeader, CanisterHttpReply, CanisterHttpRequest, CanisterHttpResponse,
    MockCanisterHttpResponse,
};
use pocket_ic::PocketIc;

mod test_utilities;
use test_utilities::{cargo_build_canister, pic_base};

#[test]
fn test_http_request() {
    let wasm = cargo_build_canister("http_request");
    let pic = pic_base().build();

    let canister_id = pic.create_canister();
    pic.add_cycles(canister_id, 3_000_000_000_000u128);
    pic.install_canister(canister_id, wasm, vec![], None);

    test_one_http_request(&pic, canister_id, "get_without_transform");
    test_one_http_request(&pic, canister_id, "post");
    test_one_http_request(&pic, canister_id, "head");
    test_one_http_request(&pic, canister_id, "get_with_transform");
    test_one_http_request(&pic, canister_id, "get_with_transform_closure");
    test_one_http_request(&pic, canister_id, "non_replicated");
}

fn test_one_http_request(pic: &PocketIc, canister_id: Principal, method: &str) {
    let call_id = pic
        .submit_call(
            canister_id,
            Principal::anonymous(),
            method,
            Encode!(&()).unwrap(),
        )
        .unwrap();
    let canister_http_requests = tick_until_next_request(pic);
    assert_eq!(canister_http_requests.len(), 1);
    let request = &canister_http_requests[0];
    pic.mock_canister_http_response(MockCanisterHttpResponse {
        subnet_id: request.subnet_id,
        request_id: request.request_id,
        response: CanisterHttpResponse::CanisterHttpReply(CanisterHttpReply {
            status: 200,
            headers: vec![CanisterHttpHeader {
                name: "response_header_name".to_string(),
                value: "response_header_value".to_string(),
            }],
            body: vec![42],
        }),
        additional_responses: vec![],
    });
    pic.await_call(call_id).unwrap();
}

fn tick_until_next_request(pic: &PocketIc) -> Vec<CanisterHttpRequest> {
    for _ in 0..10 {
        let requests = pic.get_canister_http();
        if !requests.is_empty() {
            return requests;
        }
        pic.tick();
    }
    vec![]
}
