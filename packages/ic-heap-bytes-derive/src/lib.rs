use darling::{FromDeriveInput, FromField, FromVariant, ast::Data};
use quote::quote;
use syn::{DeriveInput, Expr, Ident, parse_macro_input, spanned::Spanned};

#[derive(FromDeriveInput)]
struct DeriveInputReceiver {
    ident: Ident,
    data: Data<VariantReceiver, FieldReceiver>,
}

#[derive(Debug, FromVariant)]
#[darling(attributes(heap_bytes, deterministic_heap_bytes))]
struct VariantReceiver {
    ident: Ident,
    fields: darling::ast::Fields<FieldReceiver>,
    #[darling(default)]
    with: Option<Expr>,
}

#[derive(Debug, FromField)]
#[darling(attributes(heap_bytes, deterministic_heap_bytes))]
struct FieldReceiver {
    ident: Option<Ident>,
    ty: syn::Type,
    #[darling(default)]
    with: Option<Expr>,
}

#[proc_macro_derive(HeapBytes, attributes(heap_bytes))]
pub fn derive_heap_bytes(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let trait_name = "HeapBytes";
    let method_name = "heap_bytes";

    sum(input, trait_name, method_name)
}

#[proc_macro_derive(DeterministicHeapBytes, attributes(deterministic_heap_bytes))]
pub fn derive_deterministic_heap_bytes(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let trait_name = "DeterministicHeapBytes";
    let method_name = "deterministic_heap_bytes";

    sum(input, trait_name, method_name)
}

fn sum(
    input: proc_macro::TokenStream,
    trait_name: &str,
    method_name: &str,
) -> proc_macro::TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let receiver = match DeriveInputReceiver::from_derive_input(&input) {
        Ok(r) => r,
        Err(e) => return e.write_errors().into(),
    };

    let struct_name = &receiver.ident;
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();

    let body = match receiver.data {
        Data::Enum(variants) => enum_sum(&variants, method_name),
        Data::Struct(fields) => struct_sum(&fields, method_name),
    };

    let trait_name = Ident::new(trait_name, receiver.ident.span());
    let method_name = Ident::new(method_name, receiver.ident.span());
    quote! {
        impl #impl_generics #trait_name for #struct_name #ty_generics #where_clause {
            fn #method_name(&self) -> usize {
                #body
            }
        }
    }
    .into()
}

fn struct_sum(
    fields: &darling::ast::Fields<FieldReceiver>,
    method_name: &str,
) -> proc_macro2::TokenStream {
    let fields = fields.fields.iter().enumerate().map(|(index, field)| {
        let index = syn::Index::from(index);
        let (accessor, span) = if let Some(ident) = &field.ident {
            (quote! { self.#ident }, ident.span())
        } else {
            // Tuple struct fields can only be accessed by index, e.g. `struct S(u8, u16)`
            (quote! { self.#index }, field.ty.span())
        };
        if let Some(closure) = &field.with {
            quote! { (#closure)(&#accessor) }
        } else {
            let method_name = Ident::new(method_name, span);
            quote! { #accessor.#method_name() }
        }
    });

    quote! { 0 #(+ #fields)* }
}

fn enum_sum(variants: &[VariantReceiver], method_name: &str) -> proc_macro2::TokenStream {
    let match_arms = variants.iter().map(|variant| {
        let variant_ident = &variant.ident;

        // Generate bindings for fields in the match pattern (e.g., `v0, v1` or `field1, field2`).
        let (field_pats, exprs): (Vec<_>, Vec<_>) = variant
            .fields
            .fields
            .iter()
            .enumerate()
            .map(|(index, field)| {
                let (field_pat, accessor, span) = if let Some(ident) = &field.ident {
                    (quote! { #ident }, quote! { #ident }, ident.span())
                } else {
                    let var_name = format!("v{index}");
                    let ident = Ident::new(&var_name, field.ty.span());
                    (quote! { #ident }, quote! { #ident }, field.ty.span())
                };

                let expr = if let Some(closure) = &field.with {
                    quote! { (#closure)(&#accessor) }
                } else if let Some(_closure) = &variant.with {
                    quote! { &#accessor }
                } else {
                    let method_name = Ident::new(method_name, span);
                    quote! { #accessor.#method_name() }
                };

                (field_pat, expr)
            })
            .unzip();

        let expr = if let Some(closure) = &variant.with {
            quote! { (#closure)(#(#exprs, )*) }
        } else {
            quote! { 0 #(+ #exprs)* }
        };

        // Create the full match arm for this variant.
        match variant.fields.style {
            darling::ast::Style::Struct => {
                quote! { Self::#variant_ident { #(#field_pats),* } => #expr }
            }
            darling::ast::Style::Tuple => {
                quote! { Self::#variant_ident(#(#field_pats),*) => #expr }
            }
            darling::ast::Style::Unit => {
                quote! { Self::#variant_ident => 0 }
            }
        }
    });

    // The final implementation is a `match` statement over `self`.
    quote! {
        match self {
            #(#match_arms),*
        }
    }
}
