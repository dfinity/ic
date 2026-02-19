use candid::{Encode, Principal};
use ic_cdk::api::canister_self;
use ic_cdk::call::Call;
use ic_cdk::update;

/// A simple entry point that takes empty arguments.
#[update]
fn foo() -> u32 {
    0
}

#[update]
async fn call_foo() {
    let n = 0u32;
    let bytes = Encode!(&n).unwrap();

    // unbounded_wait
    let res = Call::unbounded_wait(canister_self(), "foo").await.unwrap();
    assert_eq!(res, bytes);
    let res: u32 = Call::unbounded_wait(canister_self(), "foo")
        .await
        .unwrap()
        .candid()
        .unwrap();
    assert_eq!(res, n);
    let res: (u32,) = Call::unbounded_wait(canister_self(), "foo")
        .await
        .unwrap()
        .candid_tuple()
        .unwrap();
    assert_eq!(res.0, n);
    Call::unbounded_wait(canister_self(), "foo")
        .oneway()
        .unwrap();
    let res = Call::unbounded_wait(canister_self(), "foo")
        .with_cycles(1000)
        .await
        .unwrap();
    assert_eq!(res, bytes);

    // bounded_wait
    let res = Call::bounded_wait(canister_self(), "foo").await.unwrap();
    assert_eq!(res, bytes);
    let res: u32 = Call::bounded_wait(canister_self(), "foo")
        .await
        .unwrap()
        .candid()
        .unwrap();
    assert_eq!(res, n);
    let res: (u32,) = Call::bounded_wait(canister_self(), "foo")
        .await
        .unwrap()
        .candid_tuple()
        .unwrap();
    assert_eq!(res.0, n);
    Call::bounded_wait(canister_self(), "foo").oneway().unwrap();
    let res = Call::bounded_wait(canister_self(), "foo")
        .with_cycles(1000)
        .await
        .unwrap();
    assert_eq!(res, bytes);
    let res = Call::bounded_wait(canister_self(), "foo")
        .change_timeout(5)
        .await
        .unwrap();
    assert_eq!(res, bytes);
}

/// A simple entry point that takes a single `u32` argument and returns it.
#[update]
fn echo(arg: u32) -> u32 {
    arg
}

#[update]
async fn call_echo() {
    let n = 1u32;
    let bytes = Encode!(&n).unwrap();

    // unbounded_wait
    let res = Call::unbounded_wait(canister_self(), "echo")
        .with_arg(n)
        .await
        .unwrap();
    assert_eq!(res, bytes);
    let res = Call::unbounded_wait(canister_self(), "echo")
        .with_args(&(n,))
        .await
        .unwrap();
    assert_eq!(res, bytes);
    let res = Call::unbounded_wait(canister_self(), "echo")
        .with_raw_args(&bytes)
        .await
        .unwrap();
    assert_eq!(res, bytes);
    let res = Call::unbounded_wait(canister_self(), "echo")
        .take_raw_args(bytes.clone())
        .await
        .unwrap();
    assert_eq!(res, bytes);
    let res: u32 = Call::unbounded_wait(canister_self(), "echo")
        .with_arg(n)
        .await
        .unwrap()
        .candid()
        .unwrap();
    assert_eq!(res, n);
    let res: (u32,) = Call::unbounded_wait(canister_self(), "echo")
        .with_arg(n)
        .await
        .unwrap()
        .candid_tuple()
        .unwrap();
    assert_eq!(res.0, n);
    Call::unbounded_wait(canister_self(), "echo")
        .with_arg(n)
        .oneway()
        .unwrap();
    let res = Call::unbounded_wait(canister_self(), "echo")
        .with_arg(n)
        .with_cycles(1000)
        .await
        .unwrap();
    assert_eq!(res, bytes);

    // bounded_wait
    let res = Call::bounded_wait(canister_self(), "echo")
        .with_arg(n)
        .await
        .unwrap();
    assert_eq!(res, bytes);
    let res = Call::bounded_wait(canister_self(), "echo")
        .with_args(&(n,))
        .await
        .unwrap();
    assert_eq!(res, bytes);
    let res = Call::bounded_wait(canister_self(), "echo")
        .with_raw_args(&bytes)
        .await
        .unwrap();
    assert_eq!(res, bytes);
    let res = Call::bounded_wait(canister_self(), "echo")
        .take_raw_args(bytes.clone())
        .await
        .unwrap();
    assert_eq!(res, bytes);
    let res: u32 = Call::bounded_wait(canister_self(), "echo")
        .with_arg(n)
        .await
        .unwrap()
        .candid()
        .unwrap();
    assert_eq!(res, n);
    let res: (u32,) = Call::bounded_wait(canister_self(), "echo")
        .with_arg(n)
        .await
        .unwrap()
        .candid_tuple()
        .unwrap();
    assert_eq!(res.0, n);
    Call::bounded_wait(canister_self(), "echo")
        .with_arg(n)
        .oneway()
        .unwrap();
    let res = Call::bounded_wait(canister_self(), "echo")
        .with_arg(n)
        .with_cycles(1000)
        .await
        .unwrap();
    assert_eq!(res, bytes);
    let res = Call::bounded_wait(canister_self(), "echo")
        .with_arg(n)
        .change_timeout(5)
        .await
        .unwrap();
    assert_eq!(res, bytes);
}

/// Retries the call until it succeeds.
///
/// Returns the number of retries.
async fn retry(call_to_retry: Call<'_, '_>) -> u32 {
    let mut retry = 0;
    loop {
        match call_to_retry.clone().await {
            Ok(_) => break,
            Err(_) => {
                retry += 1;
                continue;
            }
        }
    }
    retry
}

#[update]
async fn retry_calls() {
    let n: u32 = 1u32;
    let call = Call::bounded_wait(canister_self(), "foo");
    assert_eq!(retry(call).await, 0);
    let call_with_arg = Call::bounded_wait(canister_self(), "echo").with_arg(n);
    assert_eq!(retry(call_with_arg).await, 0);
    let args = (n,);
    let call_with_args = Call::bounded_wait(canister_self(), "echo").with_args(&args);
    assert_eq!(retry(call_with_args).await, 0);
    let raw_args = Encode!(&n).unwrap();
    let call_with_raw_args = Call::bounded_wait(canister_self(), "echo").with_raw_args(&raw_args);
    assert_eq!(retry(call_with_raw_args).await, 0);
}

#[update]
async fn join_calls() {
    use futures::future::{join_all, Future};
    use std::pin::Pin;
    let future1 = async {
        Call::bounded_wait(canister_self(), "foo")
            .await
            .unwrap()
            .candid::<u32>()
            .unwrap()
    };
    let future2 = async {
        Call::bounded_wait(canister_self(), "echo")
            .with_arg(1u32)
            .await
            .unwrap()
            .candid::<u32>()
            .unwrap()
    };
    let futures: Vec<Pin<Box<dyn Future<Output = u32>>>> =
        vec![Box::pin(future1), Box::pin(future2)];
    let results = join_all(futures).await;
    assert_eq!(results, vec![0, 1]);
}

#[update]
async fn insufficient_liquid_cycle_balance_error() {
    // Attach the current liquid cycle balance to the call
    // to ensure that the call will fail with an InsufficientLiquidCycleBalance error.
    let liquid_cycle_balance = ic_cdk::api::canister_cycle_balance();
    let err = Call::unbounded_wait(canister_self(), "foo")
        .with_cycles(liquid_cycle_balance)
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        ic_cdk::call::CallFailed::InsufficientLiquidCycleBalance(_)
    ));
}

#[update]
async fn call_error_ext() {
    // The trait need to be in scope so that the provided methods can be called.
    use ic_cdk::call::CallErrorExt;
    // Trigger a DestinationInvalid rejection
    let err = Call::bounded_wait(Principal::anonymous(), "foobar")
        .await
        .unwrap_err();
    assert!(err.is_clean_reject());
    assert!(!err.is_immediately_retryable());
}

fn main() {}
