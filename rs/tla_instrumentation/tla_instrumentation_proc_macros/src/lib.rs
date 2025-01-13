use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::{parse_macro_input, AttributeArgs, ItemFn, Lit, Meta, NestedMeta};

/// Used to annotate top-level methods (which de-facto start an update call)
#[proc_macro_attribute]
pub fn tla_update(attr: TokenStream, item: TokenStream) -> TokenStream {
    // Parse the input tokens of the attribute and the function
    let input_fn = parse_macro_input!(item as ItemFn);
    // let arg = parse_macro_input!(attr as Expr);
    // Convert proc_macro::TokenStream to proc_macro2::TokenStream
    let attr2: TokenStream2 = attr.into();

    let mut modified_fn = input_fn.clone();

    // Deconstruct the function elements
    let ItemFn {
        attrs,
        vis,
        sig,
        block: _,
    } = input_fn;

    let mangled_name = syn::Ident::new(&format!("_tla_impl_{}", sig.ident), sig.ident.span());
    modified_fn.sig.ident = mangled_name.clone();

    // Creating the modified original function which calls f_impl
    let args: Vec<_> = sig
        .inputs
        .iter()
        .map(|arg| match arg {
            syn::FnArg::Typed(pat_type) => &*pat_type.pat,
            _ => panic!("Expected typed arguments in function signature."),
        })
        .collect();

    let asyncness = sig.asyncness;

    let output = if asyncness.is_some() {
        quote! {
            #modified_fn

            #(#attrs)* #vis #sig {
                // Fail the compilation if we're not in debug mode
                #[cfg(not(debug_assertions))]
                let i:u32 = "abc";

                let globals = tla_get_globals!();
                tla_instrumentation::tla_log_method_call!(#attr2, globals);
                let res = #mangled_name(#(#args),*).await;
                let globals = tla_get_globals!();
                tla_instrumentation::tla_log_method_return!(globals);
                res
            }
        }
    } else {
        quote! {
            #modified_fn

            #(#attrs)* #vis #sig {
                // Fail the compilation if we're not in debug mode
                #[cfg(not(debug_assertions))]
                let i:u32 = "abc";

                let globals = tla_get_globals!();
                tla_instrumentation::tla_log_method_call!(#attr2, globals);
                let res = #mangled_name(#(#args),*);
                let globals = tla_get_globals!();
                tla_instrumentation::tla_log_method_return!(globals);
                res
            }
        }
    };

    output.into()
}

/// Marks the method as the starting point of a TLA transition (or more concretely, a PlusCal process).
/// Assumes that the following are in scope:
/// 1. TLA_INSTRUMENTATION_STATE LocalKey storing a Rc<RefCell<InstrumentationState>>
/// 2. TLA_TRACES_MUTEX RwLock storing a Vec<UpdateTrace>
/// 3. TLA_TRACES_LKEY LocalKey storing a RefCell<Vec<UpdateTrace>>
/// 4. tla_get_globals! a macro which takes a self parameter iff this is a method
/// 5. tla_instrumentation crate
///
/// It records the trace (sequence of states) resulting from `tla_log_request!` and `tla_log_response!`
/// macro calls in either the
#[proc_macro_attribute]
pub fn tla_update_method(attr: TokenStream, item: TokenStream) -> TokenStream {
    // Parse the input tokens of the attribute and the function
    let input_fn = parse_macro_input!(item as ItemFn);
    // let arg = parse_macro_input!(attr as Expr);
    // Convert proc_macro::TokenStream to proc_macro2::TokenStream
    let attr2: TokenStream2 = attr.into();

    let mut modified_fn = input_fn.clone();

    // Deconstruct the function elements
    let ItemFn {
        attrs,
        vis,
        sig,
        block: _,
    } = input_fn;

    let original_name = sig.ident.to_string();
    let mangled_name = syn::Ident::new(&format!("_tla_impl_{}", sig.ident), sig.ident.span());
    modified_fn.sig.ident = mangled_name.clone();

    // Creating the modified original function which calls f_impl
    let args: Vec<_> = sig
        .inputs
        .iter()
        .filter_map(|arg| match arg {
            syn::FnArg::Receiver(_) => None,
            syn::FnArg::Typed(pat_type) => Some(&*pat_type.pat),
        })
        .collect();

    let asyncness = sig.asyncness;

    let invocation = if asyncness.is_some() {
        quote! { {
            let mut pinned = Box::pin(TLA_INSTRUMENTATION_STATE.scope(
                tla_instrumentation::InstrumentationState::new(update.clone(), globals, snapshotter, start_location),
                async move {
                    let res = self.#mangled_name(#(#args),*).await;
                    let globals = tla_get_globals!(self);
                    let state: InstrumentationState = TLA_INSTRUMENTATION_STATE.get();
                    let mut handler_state = state.handler_state.borrow_mut();
                    let state_pair = tla_instrumentation::log_method_return(&mut handler_state, globals, end_location);
                    let mut state_pairs = state.state_pairs.borrow_mut();
                    state_pairs.push(state_pair);
                    res
                }
            ));
            let res = pinned.as_mut().await;
            let trace = pinned.as_mut().take_value().expect("No TLA trace in the future!");
            let pairs = trace.state_pairs.borrow_mut().clone();
            (pairs, res)
        } }
    } else {
        quote! {
            TLA_INSTRUMENTATION_STATE.sync_scope(
                tla_instrumentation::InstrumentationState::new(update.clone(), globals, snapshotter, start_location),
                || {
                    let res = self.#mangled_name(#(#args),*);
                    let globals = tla_get_globals!(self);
                    let state: InstrumentationState = TLA_INSTRUMENTATION_STATE.get();
                    let mut handler_state = state.handler_state.borrow_mut();
                    let state_pair = tla_instrumentation::log_method_return(&mut handler_state, globals, end_location);
                    let mut state_pairs = state.state_pairs.borrow_mut();
                    state_pairs.push(state_pair);
                    (state_pairs.clone(), res)
                }
            )
        }
    };

    let output = {
        quote! {
            #modified_fn

            #(#attrs)* #vis #sig {
                use std::cell::RefCell;
                use std::rc::Rc;

                let globals = tla_get_globals!(self);
                let raw_ptr = self as *const _;
                let snapshotter = Rc::new(move || { unsafe { tla_get_globals!(&*raw_ptr) } });
                let update = #attr2;
                let start_location = tla_instrumentation::SourceLocation { file: "Unknown file".to_string(), line: format!("Start of {}", #original_name) };
                let end_location = tla_instrumentation::SourceLocation { file: "Unknown file".to_string(), line: format!("End of {}", #original_name) };
                let (mut pairs, res) = #invocation;

                let constants = (update.post_process)(&mut pairs);

                let trace = tla_instrumentation::UpdateTrace {
                    update,
                    state_pairs: pairs,
                    constants,
                };
                match TLA_TRACES_LKEY.try_with(|t| {
                    let mut traces = t.borrow_mut();
                    traces.push(trace.clone());
                }) {
                    Ok(_) => (),
                    Err(_) => {
                        let mut traces = TLA_TRACES_MUTEX.write().unwrap();
                        traces.push(trace);
                    },
                }
                res
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
    let args = parse_macro_input!(attr as AttributeArgs);
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
    let mut async_trait_fn = false;

    // Examine each attribute argument
    for arg in args {
        if let NestedMeta::Meta(Meta::NameValue(name_value)) = arg {
            if name_value.path.is_ident("async_trait_fn") {
                if let Lit::Bool(lit_bool) = name_value.lit {
                    async_trait_fn = lit_bool.value();
                }
            }
        }
    }

    // We need three different ways to invoke the wrapped function.
    // One is when the function is in an async_trait, as this will get desugared
    // into a Pin<Box<...>>. There, we will want to await the result even though
    // the function itself is not async. The other is when the function is async,
    // in which case we want to await the result. The last is when the function is
    // synchronous, in which case we just want to call it.
    let call = if async_trait_fn {
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
                let mut handler_state = state.handler_state.borrow_mut();
                handler_state.context.call_function();
            }
       }).unwrap_or_else(|e| {
           // TODO(RES-152): fail if there's an error and if we're in some kind of strict mode?
            println!("Couldn't find TLA_INSTRUMENTATION_STATE when calling a tla_function; ignoring for the moment");
       });
       let res = #call;
       TLA_INSTRUMENTATION_STATE.try_with(|state| {
            {
                let mut handler_state = state.handler_state.borrow_mut();
                handler_state.context.return_from_function();
            }
       }).unwrap_or_else(|e|
           // TODO(RES-152): fail if there's an error and if we're in some kind of strict mode?
           ()
       );
       res
    };

    let output = if async_trait_fn {
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
/// 2. a function tla_check_traces() (presumably looking at the `TLA_TRACES_LKEY`
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
            TLA_TRACES_LKEY.sync_scope(std::cell::RefCell::new(Vec::new()), || {
                let res = #mangled_name(#(#args),*);
                tla_check_traces();
                res
            })
        }
    };
    output.into()
}
