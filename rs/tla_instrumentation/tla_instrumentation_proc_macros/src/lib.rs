use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::{parse_macro_input, ItemFn};

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

    let output = if asyncness.is_some() {
        quote! {
            #modified_fn

            #(#attrs)* #vis #sig {
                // Fail the compilation if we're not in debug mode
                // #[cfg(not(debug_assertions))]
                // let i:u32 = "abc";

                use std::cell::RefCell;
                use std::rc::Rc;

                let globals = tla_get_globals!(self);
                let raw_ptr = self as *const _;
                let snapshotter = Rc::new(move || { unsafe { tla_get_globals!(&*raw_ptr) } });
                let update = #attr2;
                let start_location = tla_instrumentation::SourceLocation { file: "Unknown file".to_string(), line: format!("Start of {}", #original_name) };
                let end_location = tla_instrumentation::SourceLocation { file: "Unknown file".to_string(), line: format!("End of {}", #original_name) };
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
                let mut pairs = trace.state_pairs.borrow_mut().clone();
                let constants = (update.post_process)(&mut pairs);
                // println!("State pairs in the expanded macro: {:?}", pairs);
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

#[proc_macro_attribute]
pub fn tla_function(_attr: TokenStream, item: TokenStream) -> TokenStream {
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

    let mangled_name = syn::Ident::new(&format!("_tla_impl_{}", sig.ident), sig.ident.span());
    modified_fn.sig.ident = mangled_name.clone();

    let has_receiver = sig.inputs.iter().any(|arg| match arg {
        syn::FnArg::Receiver(_) => true,
        syn::FnArg::Typed(_) => false,
    });
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

    let call = match (asyncness.is_some(), has_receiver) {
        (true, true) => quote! { self.#mangled_name(#(#args),*).await },
        (true, false) => quote! { #mangled_name(#(#args),*).await },
        (false, true) => quote! { self.#mangled_name(#(#args),*) },
        (false, false) => quote! { #mangled_name(#(#args),*) },
    };

    let output = quote! {
        #modified_fn

        #(#attrs)* #vis #sig {
           TLA_INSTRUMENTATION_STATE.try_with(|state| {
                {
                    let mut handler_state = state.handler_state.borrow_mut();
                    handler_state.context.call_function();
                }
           }).unwrap_or_else(|e|
               // TODO(RES-152): fail if there's an error and if we're in some kind of strict mode?
               ()
           );


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
