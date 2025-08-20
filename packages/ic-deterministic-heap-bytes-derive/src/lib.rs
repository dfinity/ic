use darling::{ast::Data, FromDeriveInput, FromField, FromVariant};
use quote::quote;
use syn::{parse_macro_input, DeriveInput, Expr, Ident};

#[derive(FromDeriveInput)]
struct DeterministicHeapBytesReceiver {
    ident: Ident,
    data: Data<VariantReceiver, FieldReceiver>,
}

#[derive(Debug, FromVariant)]
#[darling(attributes(deterministic_heap_bytes))]
struct VariantReceiver {
    ident: Ident,
    fields: darling::ast::Fields<FieldReceiver>,
    #[darling(default)]
    with: Option<Expr>,
}

#[derive(Debug, FromField)]
#[darling(attributes(deterministic_heap_bytes))]
struct FieldReceiver {
    ident: Option<Ident>,
    #[darling(default)]
    with: Option<Expr>,
}

#[proc_macro_derive(DeterministicHeapBytes, attributes(deterministic_heap_bytes))]
pub fn derive_heap_bytes(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let receiver = match DeterministicHeapBytesReceiver::from_derive_input(&input) {
        Ok(r) => r,
        Err(e) => return e.write_errors().into(),
    };

    let struct_name = &receiver.ident;
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();

    let heap_bytes_body = match receiver.data {
        Data::Enum(variants) => enum_heap_bytes(&variants),
        Data::Struct(fields) => struct_heap_bytes(&fields),
    };

    quote! {
        impl #impl_generics DeterministicHeapBytes for #struct_name #ty_generics #where_clause {
            fn deterministic_heap_bytes(&self) -> usize {
                #heap_bytes_body
            }
        }
    }
    .into()
}

fn struct_heap_bytes(fields: &darling::ast::Fields<FieldReceiver>) -> proc_macro2::TokenStream {
    let fields = fields.fields.iter().enumerate().map(|(index, field)| {
        let index = syn::Index::from(index);
        let accessor = if let Some(ident) = &field.ident {
            quote! { self.#ident }
        } else {
            // Tuple struct fields can only be accessed by index, e.g. `struct S(u8, u16)`
            quote! { self.#index }
        };
        if let Some(closure) = &field.with {
            quote! { (#closure)(&#accessor) }
        } else {
            quote! { #accessor.deterministic_heap_bytes() }
        }
    });

    quote! { 0 #(+ #fields)* }
}

fn enum_heap_bytes(variants: &[VariantReceiver]) -> proc_macro2::TokenStream {
    let match_arms = variants.iter().map(|variant| {
        let variant_ident = &variant.ident;

        // Generate bindings for fields in the match pattern (e.g., `v0, v1` or `field1, field2`).
        let (field_pats, exprs): (Vec<_>, Vec<_>) = variant
            .fields
            .fields
            .iter()
            .enumerate()
            .map(|(index, field)| {
                let (field_pat, accessor) = if let Some(ident) = &field.ident {
                    (quote! { #ident }, quote! { #ident })
                } else {
                    let var_name = format!("v{}", index);
                    let ident = Ident::new(&var_name, proc_macro2::Span::call_site());
                    (quote! { #ident }, quote! { #ident })
                };

                let expr = if let Some(closure) = &field.with {
                    quote! { (#closure)(&#accessor) }
                } else if let Some(_closure) = &variant.with {
                    quote! { &#accessor }
                } else {
                    quote! { #accessor.deterministic_heap_bytes() }
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
