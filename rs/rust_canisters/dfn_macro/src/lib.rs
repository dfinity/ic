#![cfg_attr(nightly_compiler, feature(proc_macro_diagnostic))]
/*
This is very gradually getting depreciated.
You'll get much better error messages if you use 'dfn_core::{over, over_async}' instead

This dfn_macro code turns this
```no_run
#[update]
async fn compute(a: A, b: B) -> C {
    a

```
into this
```no_run
#[export_name = "canister_query compute_query"]
fn compute_query___() {
use dfn_core::over_async;
use dfn_json::json;
over_async(json, |(canister_id, words)| async move {
compute_query(canister_id, words).await
    });
}
async fn compute_query(canister_id: Vec<u8>, words: Vec<String>) -> Vec<String> {
    compute(canister_id, words).await
}
```
If you run this on a nightly compiler you can get multiple compiler errors at
once and the errors will be of a higher quality.

When developing this you can run
```bash
cargo watch -x 'expand --bin inter_canister' -w ..
```
in the rust_canisters/rs folder to inspect how they expand.
*/

extern crate proc_macro;

use proc_macro2::{Ident, Span, TokenStream};
use quote::{quote, quote_spanned};
use std::collections::VecDeque;
use syn::{
    punctuated::Punctuated, spanned::Spanned, token::Comma, token::Paren, Expr, ExprCall, ExprPath,
    FnArg, ItemFn, Pat, PatIdent, PatTuple, Path, PathArguments, PathSegment,
};

#[derive(Clone)]
struct Errors {
    queue: VecDeque<(String, Span)>,
}

/// A list of errors which will be sent to the user
/// On a nightly compiler this will use Diagnostic, otherwise it will panic
/// If you call emit on an empty set of errors nothing will happen
impl Errors {
    fn new() -> Self {
        Errors {
            queue: VecDeque::new(),
        }
    }
    fn add<S: Spanned, M: Into<String>>(&mut self, msg: M, s: S) {
        self.queue.push_back((msg.into(), s.span()));
    }

    #[cfg(nightly_compiler)]
    fn emit(mut self) {
        match self.queue.pop_front() {
            Some((msg, span)) => {
                let mut diag = span.unwrap().error(msg);
                for (msg, span) in self.queue.iter() {
                    diag = diag.span_error(span.unwrap(), msg);
                }
                diag.emit()
            }
            None => (),
        }
    }

    #[cfg(not(nightly_compiler))]
    fn emit(self) {
        if !self.queue.is_empty() {
            let errors = self
                .queue
                .iter()
                .map(|(msg, span)| format!("{}\nAt: {:?}", msg, span));

            panic!("{}", errors.collect::<Vec<_>>().join("\n"))
        }
    }
}

fn get_ident(arg: &FnArg, default_id: &str, method: &str) -> Result<PatIdent, (String, Span)> {
    match arg {
        FnArg::Receiver(r) => {
            let msg = format!(
                "#[{}] cannot be above functions with `self` as a parameter",
                method
            );
            Err((msg, r.span()))
        }
        FnArg::Typed(t) => match &*t.pat {
            // If the user gives us a simple function Ident i.e. not patterns
            // then we will use that identifier throughout the dfn_macro, if they
            // give use something fancy they get worse errors
            Pat::Ident(i) => Ok(i.clone()),
            s => {
                let ident = Ident::new(default_id, s.span());
                let pat_id = PatIdent {
                    attrs: Vec::new(),
                    by_ref: None,
                    mutability: None,
                    ident,
                    subpat: None,
                };
                Ok(pat_id)
            }
        },
    }
}

struct FunctionInfo {
    pub function_call: ExprCall,
    pub tuple_pat: Pat,
    pub name: Ident,
    pub is_async: bool,
}

fn function_info(
    input: &TokenStream,
    method: &str,
    mut errors: Errors,
) -> WithErrors<FunctionInfo> {
    let fun: ItemFn = syn::parse2::<syn::ItemFn>(input.clone()).map_err(|e| {
        let msg = format!("#[{0}] must be above a function, \n{1}", method, e);
        errors.add(msg, input);
        errors.clone()
    })?;
    let signature = fun.sig;
    let generics = &signature.generics;

    if !generics.params.is_empty() {
        let msg = format!(
            "#[{}] must be above a function with no generic parameters",
            method
        );
        errors.add(msg, generics);
    }
    let function_args = signature.inputs;
    let is_async = signature.asyncness.is_some();

    let mut elems: VecDeque<PatIdent> = VecDeque::new();
    for (i, arg) in function_args.iter().enumerate() {
        let default = format!("arg_{}", i);
        match get_ident(arg, &default, method) {
            Ok(ident) => elems.push_back(ident),
            Err((msg, span)) => errors.add(msg, span),
        }
    }
    let tuple_elems: Punctuated<PatIdent, Comma> = elems.into_iter().collect();

    let tuple_pat: Pat = Pat::Tuple(PatTuple {
        attrs: Vec::new(),
        paren_token: Paren::default(),
        elems: tuple_elems
            .iter()
            .map(|pi| Pat::Ident(pi.clone()))
            .collect(),
    });

    let name = signature.ident;

    let args: Punctuated<ExprPath, Comma> = tuple_elems
        .iter()
        .map(|el| ExprPath {
            attrs: Vec::new(),
            qself: None,
            path: Path {
                leading_colon: None,
                segments: {
                    let mut seg = Punctuated::new();
                    seg.push(PathSegment {
                        arguments: PathArguments::None,
                        ident: el.ident.clone(),
                    });
                    seg
                },
            },
        })
        .collect();

    let callable_function = ExprPath {
        attrs: Vec::new(),
        qself: None,
        path: Path {
            leading_colon: None,
            segments: {
                let mut seg = Punctuated::new();
                seg.push(PathSegment {
                    arguments: PathArguments::None,
                    ident: name.clone(),
                });
                seg
            },
        },
    };

    let function_call = ExprCall {
        attrs: Vec::new(),
        func: Box::new(Expr::Path(callable_function)),
        paren_token: Paren::default(),
        args: args.iter().map(|e| Expr::Path(e.clone())).collect(),
    };

    Ok((
        errors,
        FunctionInfo {
            function_call,
            tuple_pat,
            name,
            is_async,
        },
    ))
}

/// TODO(EXC-278): allow witnesses to be passed in via attributes for different
/// types of serialization
fn check_attributes(attr: proc_macro::TokenStream, method: &str, mut errors: Errors) -> Errors {
    let tokens = TokenStream::from(attr).into_iter().collect::<Vec<_>>();
    if tokens.is_empty() {
        let msg = format!("expected #[{}] to have no attributes", method);
        for t in tokens.iter() {
            errors.add(&msg, t);
        }
    }
    errors
}

fn dfn_macro(
    method: &str,
    attr: proc_macro::TokenStream,
    item: proc_macro::TokenStream,
) -> WithErrors<proc_macro::TokenStream> {
    let errors = Errors::new();
    let errors = check_attributes(attr, method, errors);
    let item = TokenStream::from(item);

    let (
        errors,
        FunctionInfo {
            function_call,
            tuple_pat,
            name,
            is_async,
            ..
        },
    ) = function_info(&item, method, errors)?;

    let async_runner_fn = Ident::new(&format!("{}___", name), Span::call_site());

    let export_name = format!("canister_{0} {1}", method, name);

    let function_call = if is_async {
        quote! {#function_call.await}
    } else {
        quote! {#function_call}
    };
    let ret: TokenStream = quote_spanned! {
        proc_macro2::Span::call_site() =>
        #[export_name = #export_name]
        fn #async_runner_fn(){
            use dfn_json::json;
            use dfn_core::over_async;
            over_async(json, |#tuple_pat| async move { #function_call });
        }

        #item
    };
    Ok((errors, ret.into()))
}

/// Conceptually this is (Errors, Option Res), when there is no result there
/// has been a fatal error in the macro. This is a Result so the ? operator can
/// be used without the loss of Errors
type WithErrors<Res> = Result<(Errors, Res), Errors>;

fn handle_errors(res: WithErrors<proc_macro::TokenStream>) -> proc_macro::TokenStream {
    // We return an empty tokenstream on a fatal error as not to display the error
    // twice
    let (errors, res) = res.unwrap_or_else(|e| (e, proc_macro::TokenStream::new()));
    errors.emit();
    res
}

#[proc_macro_attribute]
pub fn query(
    attr: proc_macro::TokenStream,
    item: proc_macro::TokenStream,
) -> proc_macro::TokenStream {
    handle_errors(dfn_macro("query", attr, item))
}

#[proc_macro_attribute]
pub fn update(
    attr: proc_macro::TokenStream,
    item: proc_macro::TokenStream,
) -> proc_macro::TokenStream {
    handle_errors(dfn_macro("update", attr, item))
}
