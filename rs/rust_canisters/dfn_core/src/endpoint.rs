use crate::api::{arg_data, reject, reply, spawn};
use crate::{printer, setup};
use core::fmt::Debug;
use core::future::Future;
use on_wire::{FromWire, IntoWire, NewType};

pub use on_wire::{bytes, from};

/// Over allows you to create canister endpoints easily
/// ```no_run
/// # use dfn_core::over;
/// #[export_name = "canister_query happy_birthday"]
/// fn hb() {
///     fn happy_birthday((name, age): (String, u16)) -> String {
///         format!("Happy Birthday {}", name)
///     }
///     over(dfn_json::json, happy_birthday)
/// }
/// ```
///
/// This function always call `reply` unless it traps. If you need a function
/// that may `reject` the call, use one of the _may_reject variant.
pub fn over<In, Out, F, Witness>(_: Witness, f: F)
where
    In: FromWire + NewType,
    Out: IntoWire + NewType,
    F: FnOnce(In::Inner) -> Out::Inner,
    Witness: FnOnce(Out, In::Inner) -> (Out::Inner, In),
{
    over_bytes(|inp| {
        // TODO(RPL-266) Rejecting instead of trapping seems more
        // natural for deserialization errors. Debate in Jira.
        let outer = In::from_bytes(inp).expect("Deserialization Failed");
        let input = outer.into_inner();
        let res = f(input);
        let output = Out::from_inner(res);
        Out::into_bytes(output).expect("Serialization Failed")
    })
}

/// Useful for writing the canister_init function because it doesn't return
/// anything
pub fn over_init<In, F>(f: F)
where
    In: FromWire + NewType,
    F: FnOnce(In),
{
    over_bytes_init(|inp| {
        let input = In::from_bytes(inp).expect("Deserialization Failed");
        f(input)
    })
}

/// Like over, but `reject`s the call when the function `f` given as argument
/// returns an `Err`. If `f` returns an `Ok`, it calls `reply`.
pub fn over_may_reject<In, Out, F, Witness>(_: Witness, f: F)
where
    In: FromWire + NewType,
    Out: IntoWire + NewType,
    F: FnOnce(In::Inner) -> Result<Out::Inner, String>,
    Witness: FnOnce(Out, In::Inner) -> (Out::Inner, In),
{
    over_bytes_may_reject(|inp| {
        let outer = In::from_bytes(inp).expect("Deserialization Failed");
        let input = outer.into_inner();
        f(input)
            .map(|output| Out::into_bytes(Out::from_inner(output)).expect("Serialization Failed"))
    })
}

/// Create endpoints with the incoming and outgoing encoding schemes explicitly
/// stated
/// ```no_run
/// # use dfn_core::over_explicit;
/// use dfn_json::Json;
///
/// #[export_name = "canister_query happy_birthday"]
/// fn hb() {
///     fn happy_birthday(Json((name, age)) :Json<(String, u16)>) -> Json<String> {
///         Json(format!("Happy Birthday {} {}", name, age))
///     }
///     over_explicit(happy_birthday)
/// }
/// ```
pub fn over_explicit<In, Out, F>(f: F)
where
    In: FromWire + NewType,
    Out: IntoWire + NewType,
    F: FnOnce(In) -> Out,
{
    over_bytes(|inp| {
        let input = In::from_bytes(inp).expect("Deserialization Failed");
        let output = f(input);
        Out::into_bytes(output).expect("Serialization Failed")
    })
}

/// Allows you to create asynchronous canister endpoints
/// ```no_run
/// # use dfn_core::over_async;
/// # async fn get_age(_: &str) -> Result<u16, String> {
/// #     Ok(28)
/// # }
/// #[export_name = "canister_query happy_birthday"]
/// fn hb() {
///     async fn happy_birthday(name :String) -> Result<String, String> {
///         let age = get_age(&name).await?;
///         Ok(format!("Happy Birthday {} {}", name, age))
///     }
///     over_async(dfn_json::json, happy_birthday)
/// }
/// ```
pub fn over_async<In, Out, F, Witness, Fut>(_: Witness, f: F)
where
    In: FromWire + NewType,
    Out: IntoWire + NewType,
    F: FnOnce(In::Inner) -> Fut + 'static,
    Fut: Future<Output = Out::Inner> + 'static,
    Witness: FnOnce(Out, In::Inner) -> (Out::Inner, In),
{
    over_async_bytes(|inp| async move {
        let outer = In::from_bytes(inp).expect("Deserialization Failed");
        let input = outer.into_inner();
        let res = f(input).await;
        let output = Out::from_inner(res);
        Out::into_bytes(output).expect("Serialization Failed")
    })
}

/// Like over_async, but `reject`s the call when the function `f` given as
/// argument returns an `Err`. If `f` returns an `Ok`, it calls `reply`.
pub fn over_async_may_reject<In, Out, F, Witness, Fut>(_: Witness, f: F)
where
    In: FromWire + NewType,
    Out: IntoWire + NewType,
    F: FnOnce(In::Inner) -> Fut + 'static,
    Fut: Future<Output = Result<Out::Inner, String>> + 'static,
    Witness: FnOnce(Out, In::Inner) -> (Out::Inner, In),
{
    over_async_bytes_may_reject(|inp| async move {
        let outer = In::from_bytes(inp).expect("Deserialization Failed");
        let input = outer.into_inner();
        f(input)
            .await
            .map(|output| Out::into_bytes(Out::from_inner(output)).expect("Serialization Failed"))
    })
}

pub fn over_async_explicit<In, Out, F, Fut>(f: F)
where
    In: FromWire + NewType,
    Out: IntoWire + NewType,
    F: FnOnce(In) -> Fut + 'static,
    Fut: Future<Output = Out> + 'static,
{
    over_async_bytes(|inp| async move {
        let input = In::from_bytes(inp).expect("Deserialization Failed");
        let output = f(input).await;
        Out::into_bytes(output).expect("Serialization Failed")
    })
}

pub fn over_async_may_reject_explicit<In, Out, F, Fut>(f: F)
where
    In: FromWire + NewType,
    Out: IntoWire + NewType,
    F: FnOnce(In) -> Fut + 'static,
    Fut: Future<Output = Result<Out, String>> + 'static,
{
    over_async_bytes_may_reject(|inp| async move {
        let input = In::from_bytes(inp).expect("Deserialization Failed");
        f(input)
            .await
            .map(|output| Out::into_bytes(output).expect("Serialization Failed"))
    })
}

pub fn over_bytes<F>(f: F)
where
    F: FnOnce(Vec<u8>) -> Vec<u8>,
{
    over_bytes_may_reject(|inp| Ok(f(inp)));
}

pub fn over_bytes_may_reject<F>(f: F)
where
    F: FnOnce(Vec<u8>) -> Result<Vec<u8>, String>,
{
    setup::START.call_once(|| {
        printer::hook();
    });
    let bs = arg_data();
    let res = f(bs);
    match res {
        Ok(output) => reply(&output),
        Err(msg) => reject(msg.as_str()),
    }
}

pub fn over_bytes_init<F>(f: F)
where
    F: FnOnce(Vec<u8>),
{
    setup::START.call_once(|| {
        printer::hook();
    });
    f(arg_data());
}

pub fn over_async_bytes<F, Fut>(f: F)
where
    F: FnOnce(Vec<u8>) -> Fut,
    Fut: Future<Output = Vec<u8>> + 'static,
{
    setup::START.call_once(|| {
        printer::hook();
    });
    let fut = f(arg_data());
    spawn(async move {
        let bytes = fut.await;
        reply(&bytes);
    })
}

pub fn over_async_bytes_may_reject<F, Fut>(f: F)
where
    F: FnOnce(Vec<u8>) -> Fut,
    Fut: Future<Output = Result<Vec<u8>, String>> + 'static,
{
    setup::START.call_once(|| {
        printer::hook();
    });

    let fut = f(arg_data());
    spawn(async move {
        match fut.await {
            Ok(output) => reply(&output),
            Err(msg) => reject(msg.as_str()),
        }
    })
}

pub fn over_bytes_result<F, Err>(f: F)
where
    F: FnOnce(Vec<u8>) -> Result<Vec<u8>, Err>,
    Err: Debug,
{
    over_bytes(|bs| f(bs).expect("Function threw an error in 'over_bytes_error'"))
}

pub fn over_from<F, In, Out>(f: F)
where
    F: FnOnce(In) -> Out,
    In: From<Vec<u8>>,
    Out: Into<Vec<u8>>,
{
    over(from, f)
}
