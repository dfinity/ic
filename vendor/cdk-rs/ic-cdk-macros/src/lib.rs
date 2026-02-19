#![doc = include_str!("../README.md")]
#![warn(
    elided_lifetimes_in_paths,
    missing_debug_implementations,
    unsafe_op_in_unsafe_fn,
    clippy::undocumented_unsafe_blocks,
    clippy::missing_safety_doc
)]

use proc_macro::TokenStream;
use syn::Error;

mod export;

fn handle_debug_and_errors<F>(
    cb: F,
    name: &str,
    attr: TokenStream,
    item: TokenStream,
) -> TokenStream
where
    F: FnOnce(
        proc_macro2::TokenStream,
        proc_macro2::TokenStream,
    ) -> Result<proc_macro2::TokenStream, Error>,
{
    if std::env::var_os("IC_CDK_DEBUG").is_some() {
        eprintln!("--- IC_CDK_MACROS DEBUG ---");
        eprintln!("{name}\n    attr: {attr}\n    item: {item}");
    }

    let result = cb(attr.into(), item.into());

    if std::env::var_os("IC_CDK_DEBUG").is_some() {
        eprintln!("--------- RESULT  ---------");
        if let Ok(ref stream) = result {
            eprintln!("{stream}");
        }
        eprintln!("---------------------------");
    }

    result.map_or_else(|e| e.to_compile_error().into(), Into::into)
}

#[proc_macro]
pub fn export_candid(input: TokenStream) -> TokenStream {
    let input: proc_macro2::TokenStream = input.into();
    quote::quote! {
        ::candid::export_service!(#input);

        #[unsafe(no_mangle)]
        pub fn get_candid_pointer() -> *mut std::os::raw::c_char {
            let c_string = std::ffi::CString::new(__export_service()).unwrap();
            c_string.into_raw()
        }
    }
    .into()
}

#[proc_macro_attribute]
pub fn query(attr: TokenStream, item: TokenStream) -> TokenStream {
    handle_debug_and_errors(export::ic_query, "ic_query", attr, item)
}

#[proc_macro_attribute]
pub fn update(attr: TokenStream, item: TokenStream) -> TokenStream {
    handle_debug_and_errors(export::ic_update, "ic_update", attr, item)
}

#[proc_macro_attribute]
pub fn init(attr: TokenStream, item: TokenStream) -> TokenStream {
    handle_debug_and_errors(export::ic_init, "ic_init", attr, item)
}

#[proc_macro_attribute]
pub fn pre_upgrade(attr: TokenStream, item: TokenStream) -> TokenStream {
    handle_debug_and_errors(export::ic_pre_upgrade, "ic_pre_upgrade", attr, item)
}

#[proc_macro_attribute]
pub fn post_upgrade(attr: TokenStream, item: TokenStream) -> TokenStream {
    handle_debug_and_errors(export::ic_post_upgrade, "ic_post_upgrade", attr, item)
}

#[proc_macro_attribute]
pub fn heartbeat(attr: TokenStream, item: TokenStream) -> TokenStream {
    handle_debug_and_errors(export::ic_heartbeat, "ic_heartbeat", attr, item)
}

#[proc_macro_attribute]
pub fn inspect_message(attr: TokenStream, item: TokenStream) -> TokenStream {
    handle_debug_and_errors(export::ic_inspect_message, "ic_inspect_message", attr, item)
}

#[proc_macro_attribute]
pub fn on_low_wasm_memory(attr: TokenStream, item: TokenStream) -> TokenStream {
    handle_debug_and_errors(
        export::ic_on_low_wasm_memory,
        "ic_on_low_wasm_memory",
        attr,
        item,
    )
}
