//! Derive macro for `StableHash`.
//!
//! Generates implementations that produce the exact same byte stream as
//! `derive(Hash)` on Rust 1.93 / x86_64.
//!
//! # Enum discriminant rules
//!
//! These match the behavior of `derive(Hash)` + `mem::discriminant()`:
//!
//! - **1 variant**: no discriminant bytes are written (zero-sized discriminant).
//! - **2+ variants without `#[repr]`**: discriminant is written as `i64`
//!   (matching `isize` on x86_64). Values are 0, 1, 2, … in declaration order,
//!   offset by any explicit discriminant expressions.
//! - **`#[repr(u8)]`, `#[repr(i32)]`, etc.**: discriminant is written as the
//!   specified repr type, using the declared discriminant values.

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::{Data, DataEnum, DataStruct, DeriveInput, Fields, Ident, Index, parse_macro_input};

#[proc_macro_derive(StableHash)]
pub fn stable_hash(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = &input.ident;
    let generics = &input.generics;

    let body = match &input.data {
        Data::Struct(data) => gen_struct(data),
        Data::Enum(data) => gen_enum(name, data, &input.attrs),
        Data::Union(_) => panic!("StableHash cannot be derived for unions"),
    };

    // Add StableHash bounds to generic type parameters.
    let mut gen_clone = generics.clone();
    for param in gen_clone.type_params_mut() {
        param
            .bounds
            .push(syn::parse_quote!(ic_stable_hash::StableHash));
    }
    let (impl_generics, ty_generics, where_clause) = gen_clone.split_for_impl();

    let expanded = quote! {
        impl #impl_generics ic_stable_hash::StableHash for #name #ty_generics #where_clause {
            fn stable_hash<__H: ::std::hash::Hasher>(&self, __state: &mut __H) {
                #body
            }
        }
    };

    expanded.into()
}

fn gen_struct(data: &DataStruct) -> TokenStream2 {
    gen_hash_fields_via_self(&data.fields)
}

/// Generate hashing code for fields accessed via `self.field` / `self.0`.
fn gen_hash_fields_via_self(fields: &Fields) -> TokenStream2 {
    match fields {
        Fields::Named(named) => {
            let stmts: Vec<_> = named
                .named
                .iter()
                .map(|f| {
                    let name = f.ident.as_ref().unwrap();
                    quote! {
                        ic_stable_hash::StableHash::stable_hash(&self.#name, __state);
                    }
                })
                .collect();
            quote! { #(#stmts)* }
        }
        Fields::Unnamed(unnamed) => {
            let stmts: Vec<_> = (0..unnamed.unnamed.len())
                .map(|i| {
                    let idx = Index::from(i);
                    quote! {
                        ic_stable_hash::StableHash::stable_hash(&self.#idx, __state);
                    }
                })
                .collect();
            quote! { #(#stmts)* }
        }
        Fields::Unit => quote! {},
    }
}

fn gen_enum(name: &Ident, data: &DataEnum, attrs: &[syn::Attribute]) -> TokenStream2 {
    let variant_count = data.variants.len();

    // Single-variant enums: derive(Hash) writes no discriminant.
    if variant_count <= 1 {
        return gen_enum_single_variant(data);
    }

    // Determine repr type, if any.
    let repr_type = parse_repr(attrs);
    gen_enum_multi(name, data, repr_type.as_ref())
}

/// Single-variant enum: no discriminant, just hash the fields.
fn gen_enum_single_variant(data: &DataEnum) -> TokenStream2 {
    if data.variants.is_empty() {
        return quote! { unreachable!() };
    }
    let variant = &data.variants[0];
    let vident = &variant.ident;
    let (pattern, body) = destructure_variant(vident, &variant.fields);
    quote! {
        let Self::#pattern = self;
        #body
    }
}

/// Multi-variant enum: write discriminant + fields.
///
/// `repr_type` is `None` for enums without `#[repr]` (discriminant written as
/// i64, matching isize on x86_64), or `Some(type)` for repr enums.
fn gen_enum_multi(name: &Ident, data: &DataEnum, repr_type: Option<&Ident>) -> TokenStream2 {
    // Track discriminant values using the same auto-increment rules as Rust:
    // start at 0, each variant is previous + 1, unless an explicit value resets it.
    let mut disc_exprs: Vec<TokenStream2> = Vec::new();
    let mut next_disc: TokenStream2 = quote! { 0 };

    for variant in &data.variants {
        let disc = if let Some((_, expr)) = &variant.discriminant {
            quote! { #expr }
        } else {
            next_disc.clone()
        };
        next_disc = quote! { (#disc) + 1 };
        disc_exprs.push(disc);
    }

    let arms: Vec<_> = data
        .variants
        .iter()
        .zip(disc_exprs.iter())
        .map(|(variant, disc)| {
            let vident = &variant.ident;
            let (pattern, field_hash) = destructure_variant(vident, &variant.fields);

            // Cast discriminant to the appropriate type.
            let disc_hash = match repr_type {
                None => {
                    // No repr: hash as i64 (matching isize on x86_64).
                    quote! {
                        ic_stable_hash::StableHash::stable_hash(
                            &((#disc) as i64), __state,
                        );
                    }
                }
                Some(ty) => {
                    // Repr enum: hash as the repr type.
                    quote! {
                        ic_stable_hash::StableHash::stable_hash(
                            &((#disc) as #ty), __state,
                        );
                    }
                }
            };

            quote! {
                #name::#pattern => {
                    #disc_hash
                    #field_hash
                }
            }
        })
        .collect();

    quote! {
        match self {
            #(#arms)*
        }
    }
}

/// Destructure a variant into a pattern and the code to hash its fields.
///
/// Patterns use plain bindings (no `ref`) to be compatible with Rust 1.93+
/// match ergonomics, where `ref` is rejected inside implicitly-borrowing
/// patterns (matching on `&self`).
fn destructure_variant(vident: &Ident, fields: &Fields) -> (TokenStream2, TokenStream2) {
    match fields {
        Fields::Named(named) => {
            let field_names: Vec<_> = named
                .named
                .iter()
                .map(|f| f.ident.as_ref().unwrap())
                .collect();
            let hash_stmts: Vec<_> = field_names
                .iter()
                .map(|n| {
                    quote! { ic_stable_hash::StableHash::stable_hash(#n, __state); }
                })
                .collect();
            (
                quote! { #vident { #(#field_names),* } },
                quote! { #(#hash_stmts)* },
            )
        }
        Fields::Unnamed(unnamed) => {
            let binding_names: Vec<syn::Ident> = (0..unnamed.unnamed.len())
                .map(|i| syn::Ident::new(&format!("__field_{}", i), proc_macro2::Span::call_site()))
                .collect();
            let hash_stmts: Vec<_> = binding_names
                .iter()
                .map(|n| {
                    quote! { ic_stable_hash::StableHash::stable_hash(#n, __state); }
                })
                .collect();
            (
                quote! { #vident(#(#binding_names),*) },
                quote! { #(#hash_stmts)* },
            )
        }
        Fields::Unit => (quote! { #vident }, quote! {}),
    }
}

/// Parse `#[repr(...)]` attribute to find an integer repr type.
fn parse_repr(attrs: &[syn::Attribute]) -> Option<Ident> {
    for attr in attrs {
        if !attr.path().is_ident("repr") {
            continue;
        }
        let mut result = None;
        let _ = attr.parse_nested_meta(|meta| {
            if let Some(ident) = meta.path.get_ident() {
                let s = ident.to_string();
                match s.as_str() {
                    "u8" | "u16" | "u32" | "u64" | "u128" | "usize" | "i8" | "i16" | "i32"
                    | "i64" | "i128" | "isize" => {
                        result = Some(ident.clone());
                    }
                    _ => {}
                }
            }
            Ok(())
        });
        if result.is_some() {
            return result;
        }
    }
    None
}
