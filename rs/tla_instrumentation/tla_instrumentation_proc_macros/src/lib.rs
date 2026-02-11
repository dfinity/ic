use proc_macro::TokenStream;
use quote::quote;
use syn::{ItemFn, Lit, LitBool, parse_macro_input};

use syn::parse::{Parse, ParseStream};
use syn::{Expr, Ident, Token};

struct TlaUpdateArgs {
    update_expr: Expr,      // The positional argument
    snapshotter_expr: Expr, // Name of the function arg to use for snapshotter
    force_async_fn: bool,
}

/// Marks the method as the starting point of a TLA transition (or more concretely, a PlusCal process).
/// Assumes that the following are in scope:
/// 1. TLA_INSTRUMENTATION_STATE LocalKey storing a InstrumentationState
/// 2. TLA_TRACES_MUTEX Option<RwLock<Vec<UpdateTrace>>>
/// 3. TLA_TRACES_LKEY LocalKey storing a Mutex<Vec<UpdateTrace>>
/// 4. The tla_instrumentation crate
///
/// The macro REQUIRES two arguments:
/// 1. An expression of type `tla_instrumentation::Update` which describes the update method.
/// 2. A snapshotter function which takes a pointer to the canister and returns a `GlobalState`
///
/// It also supports the following keyword argument(s):
/// 1. force_async_fn, a boolean indicating whether the function is async even if it doesn't use
///    the async keyword. This is useful for async_trait functions, which are desugared into
///    functions that return a Pin<Box<dyn Future<...>>>, but are not async themselves.
///
///
/// It records the trace (sequence of states) resulting from `tla_log_request!` and `tla_log_response!`
/// macro calls in either:
/// 1. the TLA_TRACES_LKEY when available, or, failing that
/// 2. in TLA_TRACES_MUTEX, if it is not None. If it's None, then no trace is recorded.
#[proc_macro_attribute]
pub fn tla_update_method(attr: TokenStream, item: TokenStream) -> TokenStream {
    // Parse the input tokens of the attribute and the function
    let input_fn = parse_macro_input!(item as ItemFn);
    // let arg = parse_macro_input!(attr as Expr);
    // Convert proc_macro::TokenStream to proc_macro2::TokenStream
    // let attr2: TokenStream2 = attr.into();
    let attr_clone = attr.clone();
    let macro_args = parse_macro_input!(attr_clone as TlaUpdateArgs);

    // Deconstruct the function elements
    let ItemFn {
        attrs,
        vis,
        sig,
        block: body,
    } = input_fn;

    let original_name = sig.ident.to_string();

    // Creating the modified original function which calls f_impl
    let args: Vec<_> = sig
        .inputs
        .iter()
        .map(|arg| match arg {
            syn::FnArg::Receiver(_) => {
                quote! {
                    self
                }
            }
            syn::FnArg::Typed(pat_type) => {
                let pat = &pat_type.pat;
                quote! { #pat }
            }
        })
        .collect();

    let asyncness = sig.asyncness;

    let noninstrumented_invocation = if macro_args.force_async_fn {
        quote! {
            #body.await
        }
    } else if asyncness.is_some() {
        quote! {
            (|| async move {
                #body
            })().await
        }
    } else {
        quote! {
            (move || {
                #body
            })()
        }
    };

    let snapshotter = match &macro_args.snapshotter_expr {
        Expr::Path(expr_path) => {
            // User provided path: call it to get the snapshotter *value*
            quote! { #expr_path(#(#args),*) }
        }
        Expr::Macro(expr_macro) => {
            // User provided macro: invoke it to get the snapshotter *value*
            let mac_path = &expr_macro.mac.path;
            quote! { #mac_path!(#(#args),*) }
        }
        expr => {
            return syn::Error::new_spanned(
                    expr,
                    "Expected the snapshotter (second argument) to be a function path (e.g., `my_func`) or a macro invocation ending in `!()` (e.g., `my_macro! A()`)",
                )
                    .to_compile_error()
                    .into();
        }
    };

    let instrumented_invocation = if asyncness.is_some() || macro_args.force_async_fn {
        quote! {
            {
                let mut pinned = Box::pin(TLA_INSTRUMENTATION_STATE.scope(
                    tla_instrumentation::InstrumentationState::new(update.clone(), globals, snapshotter.clone(), start_location),
                    async move {
                        let res = #noninstrumented_invocation;
                        let globals = (*snapshotter.lock().expect("Couldn't lock snapshotter in tla_update_method after invocation"))();
                        let state: InstrumentationState = TLA_INSTRUMENTATION_STATE.get();
                        let mut handler_state = state.handler_state.lock().expect("Couldn't obtain the lock on the handler state in tla_update_method");
                        let state_pair = tla_instrumentation::log_method_return(&mut handler_state, globals, end_location);
                        let mut state_pairs = state.state_pairs.lock().expect("Couldn't obtain the lock on the state pairs in tla_update_method");
                        state_pairs.push(state_pair);
                        res
                    }
                ));
                let res = pinned.as_mut().await;
                let trace = pinned.as_mut().take_value().expect("No TLA trace in the future!");
                let pairs = trace.state_pairs.lock().expect("Couldn't obtain the lock on the trace state pairs in tla_update_method").clone();
                (pairs, res)
            }
        }
    } else {
        quote! {
            TLA_INSTRUMENTATION_STATE.sync_scope(
                tla_instrumentation::InstrumentationState::new(update.clone(), globals, snapshotter.clone(), start_location),
                || {
                    let res = #noninstrumented_invocation;
                    let globals = (*snapshotter.lock().expect("Couldn't lock snapshotter in tla_update_method after invocation"))();
                    let state: InstrumentationState = TLA_INSTRUMENTATION_STATE.get();
                    let mut handler_state = state.handler_state.lock().expect("Couldn't obtain the lock on the handler state in tla_update_method");
                    let state_pair = tla_instrumentation::log_method_return(&mut handler_state, globals, end_location);
                    let mut state_pairs = state.state_pairs.lock().expect("Couldn't obtain the lock on the state pairs in tla_update_method");
                    state_pairs.push(state_pair);
                    (state_pairs.clone(), res)
                }
            )
        }
    };

    let update = macro_args.update_expr;

    let with_instrumentation = quote! {
         let (update, snapshotter) = (#update, #snapshotter);
         let globals = (*snapshotter.lock().expect("Couldn't lock the snaphshotter in tla_update_method before instrumented invocation"))();
         let start_location = tla_instrumentation::SourceLocation { file: "Unknown file".to_string(), line: format!("Start of {}", #original_name) };
         let end_location = tla_instrumentation::SourceLocation { file: "Unknown file".to_string(), line: format!("End of {}", #original_name) };
         let (mut pairs, res) = #instrumented_invocation;

         let constants = (update.post_process)(&mut pairs);

         let trace = tla_instrumentation::UpdateTrace {
             model_name: update.process_id.clone(),
             state_pairs: pairs,
             constants,
         };
         match TLA_TRACES_LKEY.try_with(|t| {
             let mut traces = t.lock().expect("Couldn't obtain the lock on the TLA traces in tla_update_method");
             traces.push(trace.clone());
         }) {
             Ok(_) => (),
             Err(_) => {
                 // We can unwrap here, because we checked earlier that either
                 // we're in a TLA_TRACES_LKEY scope, or that TLA_TRACES_MUTEX isn't None
                 let mut traces = TLA_TRACES_MUTEX.as_ref().unwrap().write().unwrap();
                 traces.push(trace);
             },
         }
         res
    };

    let output = if macro_args.force_async_fn {
        quote! {
            #(#attrs)* #vis #sig {
                Box::pin(async move {
                    if !(TLA_TRACES_LKEY.try_with(|_| ()).is_ok() || TLA_TRACES_MUTEX.is_some()) {
                        #noninstrumented_invocation
                    } else {
                        #with_instrumentation
                    }
                })
            }
        }
    } else {
        quote! {
            #(#attrs)* #vis #sig {
                let enabled = TLA_TRACES_LKEY.try_with(|_| ()).is_ok() || TLA_TRACES_MUTEX.is_some();
                if !enabled {
                    #noninstrumented_invocation
                } else {
                    #with_instrumentation
                }
            }
        }
    };

    output.into()
}

/// Instructs the TLA instrumentation to "stack" PlusCal labels when entering a function.
/// This is useful when a Rust function makes inter-canister calls and is called from multiple
/// locations in the same update method. In this case, we want the labels in the TLA trace to
/// reflect the different call sites. We do this by "stacking" the labels; for example, if an
/// update method `upd` calls a function `foo` from two different locations, where the first location
/// has the label `A` and the second location has the label `B`, and `foo` adds a label `Call` when
/// it performs the call, then the labels in the TLA trace will be `A_Call` and `B_Call`.
#[proc_macro_attribute]
pub fn tla_function(attr: TokenStream, item: TokenStream) -> TokenStream {
    // Parse the input tokens of the attribute and the function
    let input_fn = parse_macro_input!(item as ItemFn);
    let mut modified_fn = input_fn.clone();

    // Deconstruct the function elements
    let ItemFn {
        attrs,
        vis,
        sig,
        block: body,
    } = input_fn;

    let mangled_name = syn::Ident::new(&format!("_tla_impl_{}", sig.ident), sig.ident.span());
    modified_fn.sig.ident = mangled_name.clone();

    let asyncness = sig.asyncness;
    let mut force_async_fn = false;

    let tla_function_parser = syn::meta::parser(|meta| {
        if meta.path.is_ident("force_async_fn") {
            force_async_fn = meta.value()?.parse::<LitBool>()?.value;
            Ok(())
        } else {
            Err(meta.error("unsupported tla_function property"))
        }
    });

    parse_macro_input!(attr with tla_function_parser);

    // We need three different ways to invoke the wrapped function.
    // One is when the function is in an async_trait, as this will get desugared
    // into a Pin<Box<...>>. There, we will want to await the result even though
    // the function itself is not async. The other is when the function is async,
    // in which case we want to await the result. The last is when the function is
    // synchronous, in which case we just want to call it.
    let call = if force_async_fn {
        quote! {
            #body.await
        }
    } else if asyncness.is_some() {
        quote! {
            (|| async move {
                #body
            })().await
        }
    } else {
        quote! {
            (move || {
                #body
            })()
        }
    };

    let with_instrumentation = quote! {
       TLA_INSTRUMENTATION_STATE.try_with(|state| {
            {
                let mut handler_state = state.handler_state.lock().expect("Couldn't obtain the lock on the handler state in tla_function");
                handler_state.context.call_function();
            }
       }).unwrap_or_else(|e| {
           // TODO(RES-152): fail if there's an error and if we're in some kind of strict mode?
            println!("Couldn't find TLA_INSTRUMENTATION_STATE when calling a tla_function; ignoring for the moment");
       });
       let res = #call;
       TLA_INSTRUMENTATION_STATE.try_with(|state| {
            {
                let mut handler_state = state.handler_state.lock().expect("Couldn't obtain the lock on the handler state in tla_function");
                handler_state.context.return_from_function();
            }
       }).unwrap_or_else(|e|
           // TODO(RES-152): fail if there's an error and if we're in some kind of strict mode?
           ()
       );
       res
    };

    let output = if force_async_fn {
        quote! {
            #(#attrs)* #vis #sig {
                Box::pin(async move {
                    #with_instrumentation
                })
            }
        }
    } else {
        quote! {
            #(#attrs)* #vis #sig {
                #with_instrumentation
            }
        }
    };

    output.into()
}

/// An annotation for tests whose TLA traces should be checked.
/// Assumes that the following are in scope:
/// 1. a LocalKey variable `TLA_TRACES_LKEY` of type Vec<UpdateTrace>,and
/// 2. a function tla_check_traces() (presumably fetching the contents at the `TLA_TRACES_LKEY`)
#[proc_macro_attribute]
pub fn with_tla_trace_check(_attr: TokenStream, item: TokenStream) -> TokenStream {
    // Parse the input tokens of the attribute and the function
    let input_fn = parse_macro_input!(item as ItemFn);

    let mut modified_fn = input_fn.clone();

    // Deconstruct the function elements
    let ItemFn {
        attrs,
        vis,
        sig,
        block: _,
    } = input_fn;

    let mangled_name = syn::Ident::new(&format!("_tla_check_impl_{}", sig.ident), sig.ident.span());
    modified_fn.sig.ident = mangled_name.clone();
    let args: Vec<_> = sig.inputs.iter().collect();

    let output = quote! {
        #modified_fn

        #(#attrs)* #vis #sig {
            TLA_TRACES_LKEY.sync_scope(::std::sync::Arc::new(::std::sync::Mutex::new(Vec::new())), || {
                let res = #mangled_name(#(#args),*);
                tla_check_traces();
                res
            })
        }
    };
    output.into()
}

impl Parse for TlaUpdateArgs {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let update_expr: Expr = input.parse()?;
        input.parse::<Token![,]>()?;
        let snapshotter_expr: Expr = input.parse()?;

        let mut force_async_fn = false;

        while !input.is_empty() {
            input.parse::<Token![,]>()?;
            if input.is_empty() {
                // Allow trailing comma
                break;
            }
            let key: Ident = input.parse()?;
            input.parse::<Token![=]>()?;
            let value: Expr = input.parse()?; // Expecting an identifier for the function argument name

            if key == "force_async_fn" {
                if let Expr::Lit(lit) = value {
                    if let Lit::Bool(lit_bool) = lit.lit {
                        force_async_fn = lit_bool.value();
                    } else {
                        return Err(syn::Error::new(
                            key.span(),
                            "Expected a boolean literal for 'force_async_fn'",
                        ));
                    }
                } else {
                    return Err(syn::Error::new(
                        key.span(),
                        "Expected a boolean literal for 'force_async_fn'",
                    ));
                }
            } else {
                return Err(syn::Error::new(key.span(), "Unknown keyword argument"));
            }
        }
        Ok(TlaUpdateArgs {
            update_expr,
            snapshotter_expr,
            force_async_fn,
        })
    }
}
