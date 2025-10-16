use candid::Principal;

use crate::{
    Request, RequestState,
    canister_state::requests::{find_request, insert_request},
};

#[test]
fn test() {
    let source = Principal::self_authenticating(vec![1]);
    let target = Principal::self_authenticating(vec![2]);
    let source_subnet = Principal::self_authenticating(vec![3]);
    let target_subnet = Principal::self_authenticating(vec![4]);
    let caller = Principal::self_authenticating(vec![5]);

    let request = Request::new(
        source,
        source_subnet,
        vec![],
        target,
        target_subnet,
        vec![],
        caller,
    );
    insert_request(RequestState::Accepted { request });
    assert!(find_request(source, target).len() == 1);
}
