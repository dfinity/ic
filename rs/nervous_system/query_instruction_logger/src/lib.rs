use proc_macro::TokenStream;
use quote::{ToTokens, quote};
use syn::{ItemFn, Meta, parse::Parser, parse_macro_input, punctuated::Punctuated, Token};

/// Wraps the `#[ic_cdk::query]` macro and adds a statement to log the instructions used.
#[proc_macro_attribute]
pub fn query(attr: TokenStream, item: TokenStream) -> TokenStream {
    let attr = Punctuated::<Meta, Token![,]>::parse_terminated
        .parse(attr)
        .expect("Failed to parse attribute arguments");
    
    let query_attr = if attr.is_empty() {
        quote! { #[ic_cdk::query] }
    } else {
        let attrs = attr.iter();
        quote! { #[ic_cdk::query(#(#attrs),*)] }
    };

    let item_fn = parse_macro_input!(item as ItemFn);
    let fn_name = item_fn.sig.ident.to_string();

    // Reconstruct the function so that we capture its execution and then log instructions
    // at the very end before returning the result. No drop needed.
    let attrs = &item_fn.attrs;
    let vis = &item_fn.vis;
    let sig = &item_fn.sig;
    let block = &item_fn.block;

    // Expand to the new function definition
    let new_fn = quote! {
        #(#attrs)*
        #query_attr
        #vis #sig {
            let __result = {
                #block
            };

            ic_cdk::println!(
                "{}Instructions used by method {}: {}",
                crate::LOG_PREFIX,
                #fn_name,
                ic_cdk::api::call_context_instruction_counter()
            );
            
            __result
        }
    };

    TokenStream::from(new_fn.into_token_stream())
}
