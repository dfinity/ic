use darling::{ast::Data, FromDeriveInput, FromField, FromVariant};
use quote::quote;
use syn::{parse_macro_input, DeriveInput, Ident, Index};

#[derive(FromDeriveInput)]
struct ByteCountReceiver {
    ident: Ident,
    data: Data<VariantReceiver, FieldReceiver>,
}

#[derive(Debug, FromVariant)]
#[darling(attributes(byte_count))]
struct VariantReceiver {
    ident: Ident,
    fields: darling::ast::Fields<FieldReceiver>,
    #[darling(default)]
    approx: bool,
}

#[derive(Debug, FromField)]
#[darling(attributes(byte_count))]
struct FieldReceiver {
    ident: Option<Ident>,
    #[darling(default)]
    approx: bool,
}

#[proc_macro_derive(ByteCount, attributes(byte_count))]
pub fn derive_byte_count(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let receiver = match ByteCountReceiver::from_derive_input(&input) {
        Ok(r) => r,
        Err(e) => return e.write_errors().into(),
    };

    let heap_bytes_body = match receiver.data {
        Data::Enum(variants) => enum_heap_bytes_body(&variants),
        Data::Struct(fields) => struct_heap_bytes_body(&fields),
    };

    let struct_name = &receiver.ident;
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();

    quote! {
        impl #impl_generics ByteCount for #struct_name #ty_generics #where_clause {
            fn heap_bytes(&self) -> usize {
                #heap_bytes_body
            }
        }
    }
    .into()
}

fn struct_heap_bytes_body(
    fields: &darling::ast::Fields<FieldReceiver>,
) -> proc_macro2::TokenStream {
    let field_sum_exprs = fields.fields.iter().enumerate().map(|(i, field)| {
        let field_accessor = if let Some(ident) = &field.ident {
            // Named field: `self.my_field`
            quote! { self.#ident }
        } else {
            // Tuple field: `self.0`
            let index = Index::from(i);
            quote! { self.#index }
        };

        if field.approx {
            quote! { #field_accessor.approx_heap_bytes() }
        } else {
            quote! { #field_accessor.heap_bytes() }
        }
    });

    // Sum the heap bytes of all fields. The initial `0` handles unit structs correctly.
    quote! {
        0 #(+ #field_sum_exprs)*
    }
}

fn enum_heap_bytes_body(variants: &[VariantReceiver]) -> proc_macro2::TokenStream {
    let match_arms = variants.iter().map(|variant| {
        let variant_ident = &variant.ident;

        // Generate bindings for fields in the match pattern (e.g., `v0, v1` or `field1, field2`).
        let (field_pats, sum_exprs): (Vec<_>, Vec<_>) = variant
            .fields
            .fields
            .iter()
            .enumerate()
            .map(|(i, field)| {
                let (field_pat, field_accessor) = if let Some(ident) = &field.ident {
                    (quote! { #ident }, quote! { #ident })
                } else {
                    let var_name = format!("v{}", i);
                    let ident = Ident::new(&var_name, proc_macro2::Span::call_site());
                    (quote! { #ident }, quote! { #ident })
                };

                let expr = if variant.approx || field.approx {
                    quote! { #field_accessor.approx_heap_bytes() }
                } else {
                    quote! { #field_accessor.heap_bytes() }
                };

                (field_pat, expr)
            })
            .unzip();

        // Generate the expression to sum the heap bytes of all fields in the variant.
        let sum_expr = quote! { 0 #(+ #sum_exprs)* };

        // Create the full match arm for this variant.
        match variant.fields.style {
            darling::ast::Style::Struct => {
                quote! { Self::#variant_ident { #(#field_pats),* } => #sum_expr }
            }
            darling::ast::Style::Tuple => {
                quote! { Self::#variant_ident(#(#field_pats),*) => #sum_expr }
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
