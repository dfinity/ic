//! Canister HTTP request.

use crate::api::call::{call_with_payment128, CallResult};
use candid::Principal;
#[cfg(feature = "transform-closure")]
use slotmap::{DefaultKey, Key, KeyData, SlotMap};
#[cfg(feature = "transform-closure")]
use std::cell::RefCell;

mod types;
pub use types::*;

/// Make an HTTP request to a given URL and return the HTTP response, possibly after a transformation.
///
/// See [IC method `http_request`](https://internetcomputer.org/docs/current/references/ic-interface-spec/#ic-http_request).
///
/// This call requires cycles payment. The required cycles is a function of the request size and max_response_bytes.
/// Check [Gas and cycles cost](https://internetcomputer.org/docs/current/developer-docs/gas-cost) for more details.
pub async fn http_request(
    arg: CanisterHttpRequestArgument,
    cycles: u128,
) -> CallResult<(HttpResponse,)> {
    call_with_payment128(
        Principal::management_canister(),
        "http_request",
        (arg,),
        cycles,
    )
    .await
}

#[cfg(feature = "transform-closure")]
thread_local! {
    #[allow(clippy::type_complexity)]
    static TRANSFORMS: RefCell<SlotMap<DefaultKey, Box<dyn FnOnce(HttpResponse) -> HttpResponse>>> = RefCell::default();
}

#[cfg(feature = "transform-closure")]
#[export_name = "canister_query <ic-cdk internal> http_transform"]
extern "C" fn http_transform() {
    use crate::api::{
        call::{arg_data, reply, ArgDecoderConfig},
        caller,
    };
    if caller() != Principal::management_canister() {
        crate::trap("This function is internal to ic-cdk and should not be called externally.");
    }
    crate::setup();
    let (args,): (TransformArgs,) = arg_data(ArgDecoderConfig::default());
    let int = u64::from_be_bytes(args.context[..].try_into().unwrap());
    let key = DefaultKey::from(KeyData::from_ffi(int));
    let func = TRANSFORMS.with(|transforms| transforms.borrow_mut().remove(key));
    let Some(func) = func else {
        crate::trap(&format!("Missing transform function for request {int}"));
    };
    let transformed = func(args.response);
    reply((transformed,))
}

/// Make an HTTP request to a given URL and return the HTTP response, after a transformation.
///
/// Do not set the `transform` field of `arg`. To use a Candid function, call [`http_request`] instead.
///
/// See [IC method `http_request`](https://internetcomputer.org/docs/current/references/ic-interface-spec/#ic-http_request).
///
/// This call requires cycles payment. The required cycles is a function of the request size and max_response_bytes.
/// Check [Gas and cycles cost](https://internetcomputer.org/docs/current/developer-docs/gas-cost) for more details.
#[cfg(feature = "transform-closure")]
#[cfg_attr(docsrs, doc(cfg(feature = "transform-closure")))]
pub async fn http_request_with_closure(
    arg: CanisterHttpRequestArgument,
    cycles: u128,
    transform_func: impl FnOnce(HttpResponse) -> HttpResponse + 'static,
) -> CallResult<(HttpResponse,)> {
    assert!(
        arg.transform.is_none(),
        "`CanisterHttpRequestArgument`'s `transform` field must be `None` when using a closure"
    );
    let transform_func = Box::new(transform_func) as _;
    let key = TRANSFORMS.with(|transforms| transforms.borrow_mut().insert(transform_func));
    struct DropGuard(DefaultKey);
    impl Drop for DropGuard {
        fn drop(&mut self) {
            TRANSFORMS.with(|transforms| transforms.borrow_mut().remove(self.0));
        }
    }
    let key = DropGuard(key);
    let context = key.0.data().as_ffi().to_be_bytes().to_vec();
    let arg = CanisterHttpRequestArgument {
        transform: Some(TransformContext {
            function: TransformFunc(candid::Func {
                method: "<ic-cdk internal> http_transform".into(),
                principal: crate::id(),
            }),
            context,
        }),
        ..arg
    };
    http_request(arg, cycles).await
}
