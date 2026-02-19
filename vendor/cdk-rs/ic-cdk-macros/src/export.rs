use darling::FromMeta;
use darling::ast::NestedMeta;
use proc_macro2::{Ident, Span, TokenStream};
use quote::{ToTokens, format_ident, quote};
use std::fmt::Formatter;
use syn::punctuated::Punctuated;
use syn::spanned::Spanned;
use syn::{
    Error, FnArg, ItemFn, Pat, PatIdent, PatType, Path, ReturnType, Signature, Type, parse_str,
};

#[derive(Default, FromMeta)]
struct ExportAttributes {
    pub name: Option<String>,
    #[darling(multiple)]
    pub guard: Vec<String>,
    /// The name of the function to use for decoding arguments.
    /// If not provided, the arguments are decoded as Candid.
    ///
    /// Even if the argument type is empty, the specified function will still be executed.
    pub decode_with: Option<String>,
    /// The name of the function to use for encoding the return value.
    /// If not provided, the return value is encoded as Candid.
    ///
    /// If the method returns a tuple, this custom encoder function should take the tuple as an argument.
    pub encode_with: Option<String>,
    #[darling(default)]
    pub manual_reply: bool,
    #[darling(default)]
    pub composite: bool,
    #[darling(default)]
    pub hidden: bool,
    #[darling(rename = "crate")]
    pub cratename: Option<String>,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum MethodType {
    Init,
    PreUpgrade,
    PostUpgrade,
    Update,
    Query,
    Heartbeat,
    InspectMessage,
    OnLowWasmMemory,
}

impl MethodType {
    /// A lifecycle method is a method that is called by the system and not by the user.
    /// So far, `update` and `query` are the only methods that are not lifecycle methods.
    ///
    /// We have a few assumptions for lifecycle methods:
    /// - They cannot have a return value.
    /// - The export name is prefixed with `canister_`, e.g. `init` => `canister_init`.
    pub fn is_lifecycle(&self) -> bool {
        match self {
            MethodType::Init
            | MethodType::PreUpgrade
            | MethodType::PostUpgrade
            | MethodType::Heartbeat
            | MethodType::InspectMessage
            | MethodType::OnLowWasmMemory => true,
            MethodType::Update | MethodType::Query => false,
        }
    }

    /// `init`, `post_upgrade`, `update`, `query` can have arguments.
    pub fn can_have_args(&self) -> bool {
        match self {
            MethodType::Init | MethodType::PostUpgrade | MethodType::Update | MethodType::Query => {
                true
            }
            MethodType::PreUpgrade
            | MethodType::Heartbeat
            | MethodType::InspectMessage
            | MethodType::OnLowWasmMemory => false,
        }
    }

    pub fn is_state_persistent(&self) -> bool {
        match self {
            Self::Query | Self::InspectMessage => false,
            Self::Update
            | Self::Heartbeat
            | Self::Init
            | Self::PreUpgrade
            | Self::PostUpgrade
            | Self::OnLowWasmMemory => true,
        }
    }
}

impl std::fmt::Display for MethodType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            MethodType::Init => f.write_str("init"),
            MethodType::PreUpgrade => f.write_str("pre_upgrade"),
            MethodType::PostUpgrade => f.write_str("post_upgrade"),
            MethodType::Query => f.write_str("query"),
            MethodType::Update => f.write_str("update"),
            MethodType::Heartbeat => f.write_str("heartbeat"),
            MethodType::InspectMessage => f.write_str("inspect_message"),
            MethodType::OnLowWasmMemory => f.write_str("on_low_wasm_memory"),
        }
    }
}

fn get_args(method: MethodType, signature: &Signature) -> Result<Vec<(Ident, Box<Type>)>, Error> {
    // We only need the tuple of arguments, not their types. Magic of type inference.
    let mut args = vec![];
    for (i, arg) in signature.inputs.iter().enumerate() {
        let (ident, ty) = match arg {
            FnArg::Receiver(r) => {
                return Err(Error::new(
                    r.span(),
                    format!("#[{method}] cannot be above functions with `self` as a parameter."),
                ));
            }
            FnArg::Typed(PatType { pat, ty, .. }) => {
                let ident = if let Pat::Ident(PatIdent { ident, .. }) = pat.as_ref() {
                    // If the argument is named the same as the function, we need to rename it.
                    if ident == &signature.ident {
                        format_ident!("__arg_{}", ident, span = pat.span())
                    } else {
                        ident.clone()
                    }
                } else {
                    format_ident!("__unnamed_arg_{i}", span = pat.span())
                };
                (ident, ty.clone())
            }
        };

        args.push((ident, ty));
    }

    Ok(args)
}

fn dfn_macro(
    method: MethodType,
    attr: TokenStream,
    item: TokenStream,
) -> Result<TokenStream, Error> {
    let attr_span = attr.span();
    let attr_args = NestedMeta::parse_meta_list(attr)?;
    let attrs = ExportAttributes::from_list(&attr_args)?;

    let fun: ItemFn = syn::parse2::<syn::ItemFn>(item.clone()).map_err(|e| {
        Error::new(
            item.span(),
            format!("#[{method}] must be above a function. \n{e}"),
        )
    })?;
    let signature = &fun.sig;
    let generics = &signature.generics;

    if !generics.params.is_empty() {
        return Err(Error::new(
            generics.span(),
            format!("#[{method}] must be above a function with no generic parameters."),
        ));
    }
    let cratename: Path = syn::parse_str(attrs.cratename.as_deref().unwrap_or("::ic_cdk"))?;

    // 1. function name(s)
    let name = &signature.ident;
    let outer_function_ident = format_ident!("__canister_method_{name}");
    let candid_method_name = format_ident!("__candid_method_{name}");
    let function_name = if let Some(custom_name) = attrs.name {
        if method.is_lifecycle() {
            return Err(Error::new(
                attr_span,
                format!("#[{method}] cannot have a custom name"),
            ));
        }
        if custom_name.starts_with("<ic-cdk internal>") {
            return Err(Error::new(
                attr_span,
                "Functions starting with `<ic-cdk internal>` are reserved for CDK internal use.",
            ));
        }
        custom_name
    } else {
        name.to_string()
    };
    let export_name = if method.is_lifecycle() {
        format!("canister_{method}")
    } else if method == MethodType::Query && attrs.composite {
        format!("canister_composite_query {function_name}",)
    } else {
        format!("canister_{method} {function_name}")
    };
    let host_compatible_name = export_name.replace(' ', ".").replace(['-', '<', '>'], "_");

    // 2. guard(s)
    if !attrs.guard.is_empty() && method.is_lifecycle() {
        return Err(Error::new(
            attr_span,
            format!("#[{method}] cannot have guard function(s)."),
        ));
    }
    let guards = attrs
        .guard
        .iter()
        .map(|guard_name| -> Result<_, Error> {
            let guard_path = parse_str::<Path>(guard_name)?;
            Ok(quote! {
                let r: Result<(), String> = #guard_path ();
                if let Err(e) = r {
                    #cratename::api::msg_reject(&e);
                    return;
                }
            })
        })
        .collect::<Result<Vec<_>, Error>>()?;
    let guard = quote! {
        #(#guards)*
    };

    // 3. decode arguments
    let (arg_tuple, _): (Vec<Ident>, Vec<Box<Type>>) =
        get_args(method, signature)?.iter().cloned().unzip();
    if !method.can_have_args() {
        if !arg_tuple.is_empty() {
            return Err(Error::new(
                Span::call_site(),
                format!("#[{method}] function cannot have arguments."),
            ));
        }
        if attrs.decode_with.is_some() {
            return Err(Error::new(
                attr_span,
                format!("#[{method}] function cannot have a decode_with attribute."),
            ));
        }
    }
    let arg_decode = if let Some(decode_with) = &attrs.decode_with {
        let decode_with_ident = parse_str::<Path>(decode_with)?;
        if arg_tuple.len() == 1 {
            let arg_one = &arg_tuple[0];
            quote! {
                let arg_bytes = #cratename::api::msg_arg_data();
                let #arg_one = #decode_with_ident(arg_bytes);
            }
        } else {
            quote! {
            let arg_bytes = #cratename::api::msg_arg_data();
            let ( #( #arg_tuple, )* ) = #decode_with_ident(arg_bytes); }
        }
    } else if arg_tuple.is_empty() {
        quote! {}
    } else {
        quote! {
            let arg_bytes = #cratename::api::msg_arg_data();
            let mut decoder_config = ::candid::DecoderConfig::new();
            decoder_config.set_skipping_quota(10000);
            let ( #( #arg_tuple, )* ) = ::candid::utils::decode_args_with_config(&arg_bytes, &decoder_config).unwrap();
        }
    };

    // 4. function call
    let function_call = if signature.asyncness.is_some() {
        quote! { #name ( #(#arg_tuple),* ) .await }
    } else {
        quote! { #name ( #(#arg_tuple),* ) }
    };

    // 5. return
    let return_length = match &signature.output {
        ReturnType::Default => 0,
        ReturnType::Type(_, ty) => match ty.as_ref() {
            Type::Tuple(tuple) => tuple.elems.len(),
            _ => 1,
        },
    };
    if method.is_lifecycle() {
        if return_length > 0 {
            return Err(Error::new(
                Span::call_site(),
                format!("#[{method}] function cannot have a return value."),
            ));
        }
        if attrs.encode_with.is_some() {
            return Err(Error::new(
                attr_span,
                format!("#[{method}] function cannot have an encode_with attribute."),
            ));
        }
    }
    let return_encode = if method.is_lifecycle() || attrs.manual_reply {
        quote! {}
    } else {
        let return_bytes = if let Some(encode_with) = &attrs.encode_with {
            let encode_with_ident = parse_str::<Path>(encode_with)?;
            match return_length {
                0 => quote! { #encode_with_ident()},
                _ => quote! { #encode_with_ident(result)},
            }
        } else {
            match return_length {
                0 => quote! { ::candid::utils::encode_one(()).unwrap() },
                1 => quote! { ::candid::utils::encode_one(result).unwrap() },
                _ => quote! { ::candid::utils::encode_args(result).unwrap() },
            }
        };
        quote! {
            let bytes: Vec<u8> = #return_bytes;
            #cratename::api::msg_reply(bytes);
        }
    };

    // 6. candid attributes for export_candid!()
    let candid_method_attr = if attrs.hidden {
        quote! {}
    } else {
        let annotation = match method {
            MethodType::Query if attrs.composite => {
                quote! { #[::candid::candid_method(composite_query, rename = #function_name)] }
            }
            MethodType::Query => {
                quote! { #[::candid::candid_method(query, rename = #function_name)] }
            }
            MethodType::Update => {
                quote! { #[::candid::candid_method(update, rename = #function_name)] }
            }
            MethodType::Init => quote! { #[::candid::candid_method(init)] },
            _ => quote! {},
        };
        let mut dummy_fun = fun.clone();
        dummy_fun.sig.ident = candid_method_name;
        dummy_fun.block = Box::new(syn::parse_quote!({
            panic!("candid dummy function called")
        }));
        if attrs.decode_with.is_some() {
            let mut inputs = Punctuated::new();
            inputs.push(syn::parse_quote!(arg_bytes: Vec<u8>));
            dummy_fun.sig.inputs = inputs;
        }
        if attrs.encode_with.is_some() {
            dummy_fun.sig.output = syn::parse_quote!(-> Vec<u8>);
        }
        let dummy_fun = dummy_fun.into_token_stream();
        quote! {
            #annotation
            #[allow(unused_variables)]
            #dummy_fun
        }
    };

    // 7. exported function body
    let async_context_name = if method.is_state_persistent() {
        format_ident!("in_executor_context")
    } else {
        format_ident!("in_query_executor_context")
    };
    let body = if signature.asyncness.is_some() {
        quote! {
            #cratename::futures::internals::#async_context_name(|| {
                #guard
                #[allow(clippy::disallowed_methods)]
                #cratename::futures::spawn(async {
                    #arg_decode
                    let result = #function_call;
                    #return_encode
                });
            });
        }
    } else {
        quote! {
            #guard
            #cratename::futures::internals::#async_context_name(|| {
                #arg_decode
                let result = #function_call;
                #return_encode
            });
        }
    };

    Ok(quote! {
        #[cfg_attr(target_family = "wasm", unsafe(export_name = #export_name))]
        #[cfg_attr(not(target_family = "wasm"), unsafe(export_name = #host_compatible_name))]
        fn #outer_function_ident() {
            #body
        }

        #candid_method_attr

        #item
    })
}

pub(crate) fn ic_query(attr: TokenStream, item: TokenStream) -> Result<TokenStream, Error> {
    dfn_macro(MethodType::Query, attr, item)
}

pub(crate) fn ic_update(attr: TokenStream, item: TokenStream) -> Result<TokenStream, Error> {
    dfn_macro(MethodType::Update, attr, item)
}

pub(crate) fn ic_init(attr: TokenStream, item: TokenStream) -> Result<TokenStream, Error> {
    dfn_macro(MethodType::Init, attr, item)
}

pub(crate) fn ic_pre_upgrade(attr: TokenStream, item: TokenStream) -> Result<TokenStream, Error> {
    dfn_macro(MethodType::PreUpgrade, attr, item)
}

pub(crate) fn ic_post_upgrade(attr: TokenStream, item: TokenStream) -> Result<TokenStream, Error> {
    dfn_macro(MethodType::PostUpgrade, attr, item)
}

pub(crate) fn ic_heartbeat(attr: TokenStream, item: TokenStream) -> Result<TokenStream, Error> {
    dfn_macro(MethodType::Heartbeat, attr, item)
}

pub(crate) fn ic_inspect_message(
    attr: TokenStream,
    item: TokenStream,
) -> Result<TokenStream, Error> {
    dfn_macro(MethodType::InspectMessage, attr, item)
}

pub(crate) fn ic_on_low_wasm_memory(
    attr: TokenStream,
    item: TokenStream,
) -> Result<TokenStream, Error> {
    dfn_macro(MethodType::OnLowWasmMemory, attr, item)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn ic_query_empty() {
        let generated = ic_query(
            quote!(),
            quote! {
                fn query() {}
            },
        )
        .unwrap();
        let parsed = syn::parse2::<syn::File>(generated).unwrap();
        assert!(parsed.items.len() == 3);
        // 0. The exported function
        let fn_name = match parsed.items[0] {
            syn::Item::Fn(ref f) => &f.sig.ident,
            _ => panic!("Incorrect parsed AST."),
        };

        let expected = quote! {
            #[cfg_attr(target_family = "wasm", unsafe(export_name = "canister_query query"))]
            #[cfg_attr(not(target_family = "wasm"), unsafe(export_name = "canister_query.query"))]
            fn #fn_name() {
                ::ic_cdk::futures::internals::in_query_executor_context(|| {
                    let result = query();
                    let bytes: Vec<u8> = ::candid::utils::encode_one(()).unwrap();
                    ::ic_cdk::api::msg_reply(bytes);
                });
            }
        };
        let expected = syn::parse2::<syn::ItemFn>(expected).unwrap();
        match &parsed.items[0] {
            syn::Item::Fn(f) => {
                assert_eq!(*f, expected);
            }
            _ => panic!("not a function"),
        };
        // 1. The #[candid_method] over a dummy function
        let expected = quote! {
            #[::candid::candid_method(query, rename = "query")]
            #[allow(unused_variables)]
            fn __candid_method_query() { panic!("candid dummy function called") }
        };
        let expected = syn::parse2::<syn::ItemFn>(expected).unwrap();
        match &parsed.items[1] {
            syn::Item::Fn(f) => {
                assert_eq!(*f, expected);
            }
            _ => panic!("not a function"),
        };
    }

    #[test]
    fn ic_query_return_one_value() {
        let generated = ic_query(
            quote!(),
            quote! {
                fn query() -> u32 {}
            },
        )
        .unwrap();
        let parsed = syn::parse2::<syn::File>(generated).unwrap();
        assert!(parsed.items.len() == 3);
        // 0. The exported function
        let fn_name = match parsed.items[0] {
            syn::Item::Fn(ref f) => &f.sig.ident,
            _ => panic!("Incorrect parsed AST."),
        };
        let expected = quote! {
            #[cfg_attr(target_family = "wasm", unsafe(export_name = "canister_query query"))]
            #[cfg_attr(not(target_family = "wasm"), unsafe(export_name = "canister_query.query"))]
            fn #fn_name() {
                ::ic_cdk::futures::internals::in_query_executor_context(|| {
                    let result = query();
                    let bytes: Vec<u8> = ::candid::utils::encode_one(result).unwrap();
                    ::ic_cdk::api::msg_reply(bytes);
                });
            }
        };
        let expected = syn::parse2::<syn::ItemFn>(expected).unwrap();
        match &parsed.items[0] {
            syn::Item::Fn(f) => {
                assert_eq!(*f, expected);
            }
            _ => panic!("not a function"),
        };
    }

    #[test]
    fn ic_query_return_tuple() {
        let generated = ic_query(
            quote!(),
            quote! {
                fn query() -> (u32, u32) {}
            },
        )
        .unwrap();
        let parsed = syn::parse2::<syn::File>(generated).unwrap();
        assert!(parsed.items.len() == 3);
        let fn_name = match parsed.items[0] {
            syn::Item::Fn(ref f) => &f.sig.ident,
            _ => panic!("Incorrect parsed AST."),
        };

        let expected = quote! {
            #[cfg_attr(target_family = "wasm", unsafe(export_name = "canister_query query"))]
            #[cfg_attr(not(target_family = "wasm"), unsafe(export_name = "canister_query.query"))]
            fn #fn_name() {
                ::ic_cdk::futures::internals::in_query_executor_context(|| {
                    let result = query();
                    let bytes: Vec<u8> = ::candid::utils::encode_args(result).unwrap();
                    ::ic_cdk::api::msg_reply(bytes);
                });
            }
        };
        let expected = syn::parse2::<syn::ItemFn>(expected).unwrap();
        match &parsed.items[0] {
            syn::Item::Fn(f) => {
                assert_eq!(*f, expected);
            }
            _ => panic!("not a function"),
        };
    }

    #[test]
    fn ic_query_one_arg() {
        let generated = ic_query(
            quote!(),
            quote! {
                fn query(a: u32) {}
            },
        )
        .unwrap();
        let parsed = syn::parse2::<syn::File>(generated).unwrap();
        assert!(parsed.items.len() == 3);
        let fn_name = match parsed.items[0] {
            syn::Item::Fn(ref f) => &f.sig.ident,
            _ => panic!("Incorrect parsed AST."),
        };
        let expected = quote! {
            #[cfg_attr(target_family = "wasm", unsafe(export_name = "canister_query query"))]
            #[cfg_attr(not(target_family = "wasm"), unsafe(export_name = "canister_query.query"))]
            fn #fn_name() {
                ::ic_cdk::futures::internals::in_query_executor_context(|| {
                    let arg_bytes = ::ic_cdk::api::msg_arg_data();
                    let mut decoder_config = ::candid::DecoderConfig::new();
                    decoder_config.set_skipping_quota(10000);
                    let (a,) = ::candid::utils::decode_args_with_config(&arg_bytes, &decoder_config).unwrap();
                    let result = query(a);
                    let bytes: Vec<u8> = ::candid::utils::encode_one(()).unwrap();
                    ::ic_cdk::api::msg_reply(bytes);
                });
            }
        };
        let expected = syn::parse2::<syn::ItemFn>(expected).unwrap();
        match &parsed.items[0] {
            syn::Item::Fn(f) => {
                assert_eq!(*f, expected);
            }
            _ => panic!("not a function"),
        };
    }

    #[test]
    fn ic_query_two_args() {
        let generated = ic_query(
            quote!(),
            quote! {
                fn query(a: u32, b: u32) {}
            },
        )
        .unwrap();
        let parsed = syn::parse2::<syn::File>(generated).unwrap();
        assert!(parsed.items.len() == 3);
        let fn_name = match parsed.items[0] {
            syn::Item::Fn(ref f) => &f.sig.ident,
            _ => panic!("Incorrect parsed AST."),
        };
        let expected = quote! {
            #[cfg_attr(target_family = "wasm", unsafe(export_name = "canister_query query"))]
            #[cfg_attr(not(target_family = "wasm"), unsafe(export_name = "canister_query.query"))]
            fn #fn_name() {
                ::ic_cdk::futures::internals::in_query_executor_context(|| {
                    let arg_bytes = ::ic_cdk::api::msg_arg_data();
                    let mut decoder_config = ::candid::DecoderConfig::new();
                    decoder_config.set_skipping_quota(10000);
                    let (a, b,) = ::candid::utils::decode_args_with_config(&arg_bytes, &decoder_config).unwrap();
                    let result = query(a, b);
                    let bytes: Vec<u8> = ::candid::utils::encode_one(()).unwrap();
                    ::ic_cdk::api::msg_reply(bytes);
                });
            }
        };
        let expected = syn::parse2::<syn::ItemFn>(expected).unwrap();
        match &parsed.items[0] {
            syn::Item::Fn(f) => {
                assert_eq!(*f, expected);
            }
            _ => panic!("not a function"),
        };
    }

    #[test]
    fn ic_query_two_args_return_value() {
        let generated = ic_query(
            quote!(),
            quote! {
                fn query(a: u32, b: u32) -> u64 {}
            },
        )
        .unwrap();
        let parsed = syn::parse2::<syn::File>(generated).unwrap();
        assert!(parsed.items.len() == 3);
        let fn_name = match parsed.items[0] {
            syn::Item::Fn(ref f) => &f.sig.ident,
            _ => panic!("Incorrect parsed AST."),
        };
        let expected = quote! {
            #[cfg_attr(target_family = "wasm", unsafe(export_name = "canister_query query"))]
            #[cfg_attr(not(target_family = "wasm"), unsafe(export_name = "canister_query.query"))]
            fn #fn_name() {
                ::ic_cdk::futures::internals::in_query_executor_context(|| {
                    let arg_bytes = ::ic_cdk::api::msg_arg_data();
                    let mut decoder_config = ::candid::DecoderConfig::new();
                    decoder_config.set_skipping_quota(10000);
                    let (a, b,) = ::candid::utils::decode_args_with_config(&arg_bytes, &decoder_config).unwrap();
                    let result = query(a, b);
                    let bytes: Vec<u8> = ::candid::utils::encode_one(result).unwrap();
                    ::ic_cdk::api::msg_reply(bytes);
                });
            }
        };
        let expected = syn::parse2::<syn::ItemFn>(expected).unwrap();
        match &parsed.items[0] {
            syn::Item::Fn(f) => {
                assert_eq!(*f, expected);
            }
            _ => panic!("not a function"),
        };
    }

    #[test]
    fn ic_query_export_name() {
        let generated = ic_query(
            quote!(name = "custom_query"),
            quote! {
                fn query() {}
            },
        )
        .unwrap();
        let parsed = syn::parse2::<syn::File>(generated).unwrap();
        assert!(parsed.items.len() == 3);
        let fn_name = match parsed.items[0] {
            syn::Item::Fn(ref f) => &f.sig.ident,
            _ => panic!("Incorrect parsed AST."),
        };
        let expected = quote! {
            #[cfg_attr(target_family = "wasm", unsafe(export_name = "canister_query custom_query"))]
            #[cfg_attr(not(target_family = "wasm"), unsafe(export_name = "canister_query.custom_query"))]
            fn #fn_name() {
                ::ic_cdk::futures::internals::in_query_executor_context(|| {
                    let result = query();
                    let bytes: Vec<u8> = ::candid::utils::encode_one(()).unwrap();
                    ::ic_cdk::api::msg_reply(bytes);
                });
            }
        };
        let expected = syn::parse2::<syn::ItemFn>(expected).unwrap();
        match &parsed.items[0] {
            syn::Item::Fn(f) => {
                assert_eq!(*f, expected);
            }
            _ => panic!("not a function"),
        };
    }

    #[test]
    fn ic_query_custom_decoder() {
        let generated = ic_query(
            quote!(decode_with = "custom_decoder"),
            quote! {
                fn query(a: u32) {}
            },
        )
        .unwrap();
        let parsed = syn::parse2::<syn::File>(generated).unwrap();
        assert!(parsed.items.len() == 3);
        // 0. The exported function
        let fn_name = match parsed.items[0] {
            syn::Item::Fn(ref f) => &f.sig.ident,
            _ => panic!("Incorrect parsed AST."),
        };
        let expected = quote! {
            #[cfg_attr(target_family = "wasm", unsafe(export_name = "canister_query query"))]
            #[cfg_attr(not(target_family = "wasm"), unsafe(export_name = "canister_query.query"))]
            fn #fn_name() {
                ::ic_cdk::futures::internals::in_query_executor_context(|| {
                    let arg_bytes = ::ic_cdk::api::msg_arg_data();
                    let a = custom_decoder(arg_bytes);
                    let result = query(a);
                    let bytes: Vec<u8> = ::candid::utils::encode_one(()).unwrap();
                    ::ic_cdk::api::msg_reply(bytes);
                });
            }
        };
        let expected = syn::parse2::<syn::ItemFn>(expected).unwrap();
        match &parsed.items[0] {
            syn::Item::Fn(f) => {
                assert_eq!(*f, expected);
            }
            _ => panic!("not a function"),
        };
        // 1. The #[candid_method] over a dummy function
        let expected = quote! {
            #[::candid::candid_method(query, rename = "query")]
            #[allow(unused_variables)]
            fn __candid_method_query(arg_bytes: Vec<u8>) { panic!("candid dummy function called") }
        };
        let expected = syn::parse2::<syn::ItemFn>(expected).unwrap();
        match &parsed.items[1] {
            syn::Item::Fn(f) => {
                assert_eq!(*f, expected);
            }
            _ => panic!("not a function"),
        };
    }

    #[test]
    fn ic_query_custom_encoder() {
        let generated = ic_query(
            quote!(encode_with = "custom_encoder"),
            quote! {
                fn query() -> u32 {}
            },
        )
        .unwrap();
        let parsed = syn::parse2::<syn::File>(generated).unwrap();
        assert!(parsed.items.len() == 3);
        // 0. The exported function
        let fn_name = match parsed.items[0] {
            syn::Item::Fn(ref f) => &f.sig.ident,
            _ => panic!("Incorrect parsed AST."),
        };
        let expected = quote! {
            #[cfg_attr(target_family = "wasm", unsafe(export_name = "canister_query query"))]
            #[cfg_attr(not(target_family = "wasm"), unsafe(export_name = "canister_query.query"))]
            fn #fn_name() {
                ::ic_cdk::futures::internals::in_query_executor_context(|| {
                    let result = query();
                    let bytes: Vec<u8> = custom_encoder(result);
                    ::ic_cdk::api::msg_reply(bytes);
                });
            }
        };
        let expected = syn::parse2::<syn::ItemFn>(expected).unwrap();
        match &parsed.items[0] {
            syn::Item::Fn(f) => {
                assert_eq!(*f, expected);
            }
            _ => panic!("not a function"),
        };
        // 1. The #[candid_method] over a dummy function
        let expected = quote! {
            #[::candid::candid_method(query, rename = "query")]
            #[allow(unused_variables)]
            fn __candid_method_query() -> Vec<u8> { panic!("candid dummy function called") }
        };
        let expected = syn::parse2::<syn::ItemFn>(expected).unwrap();
        match &parsed.items[1] {
            syn::Item::Fn(f) => {
                assert_eq!(*f, expected);
            }
            _ => panic!("not a function"),
        };
    }

    #[test]
    fn ic_guards() {
        let generated = ic_query(
            quote!(guard = "guard1", guard = "guard2"),
            quote! {
                fn query() {}
            },
        )
        .unwrap();
        let parsed = syn::parse2::<syn::File>(generated).unwrap();
        assert!(parsed.items.len() == 3);
        let fn_name = match parsed.items[0] {
            syn::Item::Fn(ref f) => &f.sig.ident,
            _ => panic!("Incorrect parsed AST."),
        };
        let expected = quote! {
            #[cfg_attr(target_family = "wasm", unsafe(export_name = "canister_query query"))]
            #[cfg_attr(not(target_family = "wasm"), unsafe(export_name = "canister_query.query"))]
            fn #fn_name() {
                let r: Result<(), String> = guard1 ();
                if let Err(e) = r {
                    ::ic_cdk::api::msg_reject(&e);
                    return;
                }
                let r: Result<(), String> = guard2 ();
                if let Err(e) = r {
                    ::ic_cdk::api::msg_reject(&e);
                    return;
                }
                ::ic_cdk::futures::internals::in_query_executor_context(|| {
                    let result = query();
                    let bytes: Vec<u8> = ::candid::utils::encode_one(()).unwrap();
                    ::ic_cdk::api::msg_reply(bytes);
                });
            }
        };
        let expected = syn::parse2::<syn::ItemFn>(expected).unwrap();
        match &parsed.items[0] {
            syn::Item::Fn(f) => {
                assert_eq!(*f, expected);
            }
            _ => panic!("not a function"),
        };
    }

    #[test]
    fn alternate_crate() {
        let generated = ic_query(
            quote!(crate = "ic_cdk_old"),
            quote! {
                fn query() -> u32 {}
            },
        )
        .unwrap();
        let parsed = syn::parse2::<syn::File>(generated).unwrap();
        assert!(parsed.items.len() == 3);
        // 0. The exported function
        let fn_name = match parsed.items[0] {
            syn::Item::Fn(ref f) => &f.sig.ident,
            _ => panic!("Incorrect parsed AST."),
        };
        let expected = quote! {
            #[cfg_attr(target_family = "wasm", unsafe(export_name = "canister_query query"))]
            #[cfg_attr(not(target_family = "wasm"), unsafe(export_name = "canister_query.query"))]
            fn #fn_name() {
                ic_cdk_old::futures::internals::in_query_executor_context(|| {
                    let result = query();
                    let bytes: Vec<u8> = ::candid::utils::encode_one(result).unwrap();
                    ic_cdk_old::api::msg_reply(bytes);
                });
            }
        };
        let expected = syn::parse2::<syn::ItemFn>(expected).unwrap();
        match &parsed.items[0] {
            syn::Item::Fn(f) => {
                assert_eq!(*f, expected);
            }
            _ => panic!("not a function"),
        };
    }
}
