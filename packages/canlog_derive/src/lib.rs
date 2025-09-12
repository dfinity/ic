//! Procedural macros for the canlog crate. Refer to the canlog crate documentation.

#![forbid(unsafe_code)]

use darling::FromVariant;
use proc_macro::TokenStream;
use proc_macro2::Ident;
use quote::quote;
use syn::{Data, DataEnum, DeriveInput, parse_macro_input};

#[proc_macro_derive(LogPriorityLevels, attributes(log_level))]
pub fn derive_log_priority(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let enum_ident = &input.ident;

    let Data::Enum(DataEnum { variants, .. }) = &input.data else {
        panic!("This trait can only be derived for enums");
    };

    // Declare a buffer and sink for each enum variant
    let buffer_declarations = variants.iter().map(|variant| {
        let variant_ident = &variant.ident;
        let info = LogLevelInfo::from_variant(variant)
            .unwrap_or_else(|_| panic!("Invalid attributes for log level: {variant_ident}"));

        let buffer_ident = get_buffer_ident(variant_ident);
        let sink_ident = get_sink_ident(variant_ident);
        let capacity = info.capacity;

        quote! {
            ::canlog::declare_log_buffer!(name = #buffer_ident, capacity = #capacity);
            pub const #sink_ident: ::canlog::PrintProxySink<#enum_ident> = ::canlog::PrintProxySink(&#enum_ident::#variant_ident, &#buffer_ident);
        }
    });

    // Match arms to get the corresponding buffer, sink and display name for each enum variant
    let buffer_match_arms = variants.iter().map(|variant| {
        let variant_ident = &variant.ident;
        let buffer_ident = get_buffer_ident(variant_ident);
        quote! {
            Self::#variant_ident => &#buffer_ident,
        }
    });
    let sink_match_arms = variants.iter().map(|variant| {
        let variant_ident = &variant.ident;
        let sink_ident = get_sink_ident(variant_ident);
        quote! {
            Self::#variant_ident => &#sink_ident,
        }
    });
    let display_name_match_arms = variants.iter().map(|variant| {
        let variant_ident = &variant.ident;
        let display_name = LogLevelInfo::from_variant(variant).unwrap().name;
        quote! {
            Self::#variant_ident => #display_name,
        }
    });
    let variants_array = variants.iter().map(|variant| {
        let variant_ident = &variant.ident;
        quote! { Self::#variant_ident, }
    });

    // Generate buffer declarations and trait implementation
    let trait_impl = quote! {
        #(#buffer_declarations)*

        impl ::canlog::LogPriorityLevels for #enum_ident {
            fn get_buffer(&self) -> &'static ::canlog::GlobalBuffer {
                match self {
                    #(#buffer_match_arms)*
                }
            }

            fn get_sink(&self) -> &impl ::canlog::Sink {
                match self {
                    #(#sink_match_arms)*
                }
            }

            fn display_name(&self) -> &'static str {
                match self {
                    #(#display_name_match_arms)*
                }
            }

            fn get_priorities() -> &'static [Self] {
                &[#(#variants_array)*]
            }
        }
    };

    trait_impl.into()
}

#[derive(FromVariant)]
#[darling(attributes(log_level))]
struct LogLevelInfo {
    capacity: usize,
    name: String,
}

fn get_sink_ident(variant_ident: &Ident) -> Ident {
    quote::format_ident!("{}", variant_ident.to_string().to_uppercase())
}

fn get_buffer_ident(variant_ident: &Ident) -> Ident {
    quote::format_ident!("{}_BUF", variant_ident.to_string().to_uppercase())
}
