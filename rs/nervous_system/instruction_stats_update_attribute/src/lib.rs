use proc_macro::TokenStream;
use quote::{ToTokens, quote};
use syn::{ItemFn, Meta, Stmt, Token, parse::Parser, parse_macro_input, punctuated::Punctuated};

/// This does almost the same thing as ic_cdk::update. There is just one
/// difference: This adds a statement to the beginning of the function. It looks
/// something like this:
///
/// let _on_drop = foo(#function_name);
///
/// For this to work, you will need to depend on
/// ic-nervous-system-instruction-stats, because foo is defined there.
///
/// More precisely, foo tracks instructions used by the call context. To expose
/// this data, ic_nervous_system_instruction_stats::encode_instruction_metrics
/// needs to be called.
#[proc_macro_attribute]
pub fn update(attr: TokenStream, item: TokenStream) -> TokenStream {
    let attr = Punctuated::<Meta, Token![,]>::parse_terminated
        .parse(attr)
        .expect("Failed to parse attribute arguments");
    let update_attr = if attr.is_empty() {
        quote! { #[ic_cdk::update] }
    } else {
        let attrs = attr.iter();
        quote! { #[ic_cdk::update(#(#attrs),*)] }
    };

    let mut item_fn = parse_macro_input!(item as ItemFn);

    let function_name = format!("canister_method:{}", item_fn.sig.ident);

    // Create statement that we'll insert into the function.
    let new_stmt = quote! {
        let _on_drop = ic_nervous_system_instruction_stats::UpdateInstructionStatsOnDrop::new(
            #function_name, std::collections::BTreeMap::new(),
        );
    };
    let new_stmt = TokenStream::from(new_stmt);
    let new_stmt = parse_macro_input!(new_stmt as Stmt);

    item_fn.block.stmts.insert(0, new_stmt);

    let updated_item_fn = quote! {
        #update_attr
        #item_fn
    };

    TokenStream::from(updated_item_fn.into_token_stream())
}
