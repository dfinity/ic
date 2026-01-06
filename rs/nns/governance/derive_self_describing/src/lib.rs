//! A derive macro for automatically implementing `From<T> for SelfDescribingValue`.
//!
//! This macro generates an implementation that converts a struct or enum into a `SelfDescribingValue`.
//!
//! For structs:
//! - Named fields: creates a map where each field name is a key
//! - Unit structs: NOT supported (compile error)
//! - Tuple structs: NOT supported (compile error)
//!
//! For enums:
//! - If all variants are unit types: uses `Text(VariantName)`
//! - Otherwise:
//!   - Single-field tuple variants: map `{ "VariantName": inner_value }`
//!   - Unit variants: map `{ "VariantName": [] }`
//!   - Multi-field tuple variants: NOT supported (compile error)
//!   - Named field variants: NOT supported (compile error)
//!
//! # Example
//!
//! ```ignore
//! use ic_nns_governance_derive_self_describing::SelfDescribing;
//!
//! #[derive(SelfDescribing)]
//! struct MyStruct {
//!     name: String,
//!     count: u64,
//! }
//!
//! #[derive(SelfDescribing)]
//! enum MyEnum {
//!     VariantA(InnerA),
//!     VariantB(InnerB),
//! }
//! ```

extern crate proc_macro;

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::{Data, DataEnum, DeriveInput, Fields, FieldsNamed, Ident, parse_macro_input};

/// Derives `From<T> for SelfDescribingValue` for a struct or enum.
///
/// For structs:
/// - Named fields: Creates a map with field names as keys
/// - Unit structs: Creates an empty array
/// - Tuple structs: NOT supported (compile error)
///
/// For enums:
/// - If all variants are unit types: uses `Text(VariantName)`
/// - Otherwise:
///   - Single-field tuple variants: Map with variant name as key and inner value as value
///   - Unit variants: Map with variant name as key and empty array as value
///   - Multi-field tuple variants: NOT supported (compile error)
///   - Named field variants: NOT supported (compile error)
#[proc_macro_derive(SelfDescribing)]
pub fn derive_self_describing(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = &input.ident;

    let expanded = match &input.data {
        Data::Struct(data_struct) => match &data_struct.fields {
            Fields::Named(fields_named) => derive_struct_with_named_fields(name, fields_named),
            Fields::Unnamed(_) => {
                // We could have supported this with an array, but we don't expect it to be useful.
                // It can be extended in the future if needed.
                return syn::Error::new_spanned(
                    &input,
                    "SelfDescribing does not support tuple structs. Use a struct with named fields instead.",
                )
                .to_compile_error()
                .into();
            }
            Fields::Unit => {
                // We could have supported this with an empty array or map, but we don't expect
                // it to be useful. It can be extended in the future if needed.
                return syn::Error::new_spanned(
                    &input,
                    "SelfDescribing does not support unit structs. Use a struct with named fields instead.",
                )
                .to_compile_error()
                .into();
            }
        },
        Data::Enum(data_enum) => {
            let all_unit = data_enum
                .variants
                .iter()
                .all(|v| matches!(v.fields, Fields::Unit));

            if all_unit {
                derive_all_unit_enum(name, data_enum)
            } else {
                derive_mixed_enum(name, data_enum).unwrap_or_else(|err| err)
            }
        }
        Data::Union(_) => {
            return syn::Error::new_spanned(&input, "SelfDescribing does not support unions")
                .to_compile_error()
                .into();
        }
    };

    TokenStream::from(expanded)
}

/// Generates `From` impl for a struct with named fields.
/// Creates a map where each field name is a key.
fn derive_struct_with_named_fields(name: &Ident, fields_named: &FieldsNamed) -> TokenStream2 {
    let field_additions = fields_named.named.iter().map(|field| {
        let field_name = field.ident.as_ref().unwrap();
        let field_name_str = field_name.to_string();
        quote! {
            .add_field(#field_name_str, value.#field_name)
        }
    });

    quote! {
        impl From<#name> for crate::pb::v1::SelfDescribingValue {
            fn from(value: #name) -> Self {
                crate::proposals::self_describing::ValueBuilder::new()
                    #(#field_additions)*
                    .build()
            }
        }
    }
}

/// Generates `From` impl for an enum where all variants are unit types.
/// Uses `Text(VariantName)` for each variant.
fn derive_all_unit_enum(name: &Ident, data_enum: &DataEnum) -> TokenStream2 {
    let match_arms = data_enum.variants.iter().map(|variant| {
        let variant_name = &variant.ident;
        let variant_name_str = variant_name.to_string();

        quote! {
            #name::#variant_name => {
                crate::pb::v1::SelfDescribingValue::from(#variant_name_str)
            }
        }
    });

    quote! {
        impl From<#name> for crate::pb::v1::SelfDescribingValue {
            fn from(value: #name) -> Self {
                match value {
                    #(#match_arms)*
                }
            }
        }
    }
}

/// Generates `From` impl for a mixed enum (not all unit variants).
/// - Single-field tuple variants: map with variant name as key, inner value as value
/// - Unit variants: map with variant name as key, empty array as value
///
/// Returns an error if the enum contains unsupported variants (multi-field tuples or named fields).
fn derive_mixed_enum(name: &Ident, data_enum: &DataEnum) -> Result<TokenStream2, TokenStream2> {
    let match_arms: Vec<_> = data_enum
        .variants
        .iter()
        .map(|variant| {
            let variant_name = &variant.ident;
            let variant_name_str = variant_name.to_string();

            match &variant.fields {
                Fields::Unnamed(fields) if fields.unnamed.len() > 1 => {
                    let field_count = fields.unnamed.len();
                    // We could have supported this with an array, but we don't expect it to
                    // be useful. It can be extended in the future if needed.
                    let error_msg = format!(
                        "SelfDescribing does not support enum variants with multiple tuple fields. \
                        Variant `{}` has {} fields.",
                        variant_name, field_count
                    );
                    Err(syn::Error::new_spanned(variant, error_msg).to_compile_error())
                }
                Fields::Unnamed(_) => {
                    // Single field: map with variant name as key, inner value as value
                    Ok(quote! {
                        #name::#variant_name(inner) => {
                            crate::proposals::self_describing::ValueBuilder::new()
                                .add_field(#variant_name_str, inner)
                                .build()
                        }
                    })
                }
                Fields::Unit => {
                    // Unit variant in mixed enum: map with variant name as key, null value as value
                    Ok(quote! {
                        #name::#variant_name => {
                            crate::proposals::self_describing::ValueBuilder::new()
                                .add_field(#variant_name_str, crate::proposals::self_describing::SelfDescribingValue::NULL)
                                .build()
                        }
                    })
                }
                Fields::Named(_) => {
                    // We could have supported this with a map, but we don't expect it to
                    // be useful. It can be extended in the future if needed.
                    let error_msg = format!(
                        "SelfDescribing does not support enum variants with named fields. \
                        Variant `{}` has named fields.",
                        variant_name
                    );
                    Err(syn::Error::new_spanned(variant, error_msg).to_compile_error())
                }
            }
        })
        .collect::<Result<_, _>>()?;

    Ok(quote! {
        impl From<#name> for crate::pb::v1::SelfDescribingValue {
            fn from(value: #name) -> Self {
                match value {
                    #(#match_arms)*
                }
            }
        }
    })
}
