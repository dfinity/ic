extern crate proc_macro;
extern crate quote;
extern crate syn;

use proc_macro::TokenStream;
use quote::quote;
use syn::Data::Struct;

/// Derive of ValidateEq trait.
/// Derived implementation compares fields of lhs and rhs and returns the first divergence if any.
/// A field can have one #[validate_eq(CompareWithValidateEq|Ignore)] attribute.
///   - CompareWithValidateEq calls .validate_eq() and returns path + its error in case of divergence
///   - Ignore ignores the field.
///   - None (default) compares fields using PartialEq and reports their name in case of
///     divergence.

enum ValidateEqFieldAttr {
    /// Compare using .eq() and return field name if diverges.
    CompareWithPartialEq,
    /// Call .validate_eq(); in case of deivergence return the field name and the underlying
    /// divergence error string.
    CompareWithValidateEq,
    /// Ignore for ValidateEq
    Ignore,
}

/// Find #[validate_eq(...)] attribute if any.
fn find_validate_eq_attr(field: &syn::Field) -> syn::Result<Option<&syn::Attribute>> {
    let matching_attrs = field
        .attrs
        .iter()
        .filter(|attr| attr.path.is_ident("validate_eq"))
        .collect::<Vec<_>>();
    if matching_attrs.len() == 1 {
        Ok(Some(matching_attrs[0]))
    } else if matching_attrs.is_empty() {
        Ok(None)
    } else {
        Err(syn::Error::new_spanned(
            field,
            "More than one #[validate_eq] attr",
        ))
    }
}

/// Given the field of a named struct to derive ValidateEq for, return the attribute.
fn parse_validate_eq_attr(field: &syn::Field) -> syn::Result<ValidateEqFieldAttr> {
    let attr = find_validate_eq_attr(field)?;

    match attr {
        None => Ok(ValidateEqFieldAttr::CompareWithPartialEq),
        Some(attr) => {
            let ident: syn::Ident = attr.parse_args()?;
            match ident.to_string().as_str() {
                "CompareWithValidateEq" => Ok(ValidateEqFieldAttr::CompareWithValidateEq),
                "Ignore" => Ok(ValidateEqFieldAttr::Ignore),
                _ => Err(syn::Error::new_spanned(
                    ident,
                    "Expected value for validate_eq(...): CompareWithValidateEq | Ignore",
                )),
            }
        }
    }
}

#[proc_macro_derive(ValidateEq, attributes(validate_eq))]
pub fn derive_validate_eq_impl(item: TokenStream) -> TokenStream {
    let input = syn::parse_macro_input!(item as syn::DeriveInput);

    let struct_identifier = &input.ident;

    if let Struct(syn::DataStruct { fields, .. }) = &input.data {
        let mut impl_body = quote! {};
        for item in fields.iter() {
            let Some(ident) = item.ident.as_ref() else {
                return syn::Error::new_spanned(
                    item,
                    "Derive ValidateEq: field name must be an identifier",
                )
                .into_compile_error()
                .into();
            };
            let attr = parse_validate_eq_attr(item);
            let ty = &item.ty;
            match attr {
                Err(err) => {
                    return err.into_compile_error().into();
                }
                Ok(ValidateEqFieldAttr::CompareWithPartialEq) => {
                    impl_body.extend(quote! {
                        // This block of magic breaks if the type of the field implements
                        // ValidateEq, yet we requested ParitalEq. This is taken from static_assertions
                        // packages (assert_not_impl_any), it's not easy to call external crates in
                        // auto derived code.
                        // It cannot catch generics or subfield implementing ValidateEq.
                        const _: fn() = || {
                            // Generic trait with a blanket impl over `()` for all types.
                            trait AmbiguousIfImpl<A> {
                                // Required for actually being able to reference the trait.
                                fn some_item() {}
                            }

                            impl<T: ?Sized> AmbiguousIfImpl<()> for T {}

                            // Used for the specialized impl when ValdiateEq is implemented.
                            #[allow(dead_code)]
                            struct Invalid;

                            impl<T: ?Sized + ValidateEq> AmbiguousIfImpl<Invalid> for T {}

                            // If there is only one specialized trait impl, type inference with
                            // `_` can be resolved and this can compile. Fails to compile if
                            // `#ty` implements `AmbiguousIfImpl<Invalid>`.
                            let _ = <#ty as AmbiguousIfImpl<_>>::some_item;
                        };
                        if self.#ident != rhs.#ident {
                            return Err(stringify!(#ident).to_string());
                        }
                    });
                }
                Ok(ValidateEqFieldAttr::CompareWithValidateEq) => {
                    impl_body.extend(quote! {
                        if let Err(err) = self.#ident.validate_eq(&rhs.#ident) {
                            return Err(format!("{}.{}", stringify!(#ident), err));
                        }
                    });
                }
                Ok(ValidateEqFieldAttr::Ignore) => (),
            }
        }
        let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();
        quote! {
            #[automatically_derived]
            impl #impl_generics ValidateEq for #struct_identifier #ty_generics #where_clause {
                fn validate_eq(&self, rhs: &Self) -> Result<(), String> {
                    #impl_body
                    Ok(())
                }
            }
        }
        .into()
    } else {
        syn::Error::new_spanned(
            input,
            "ValidateEq can be auto-derived for named structures only.",
        )
        .into_compile_error()
        .into()
    }
}
