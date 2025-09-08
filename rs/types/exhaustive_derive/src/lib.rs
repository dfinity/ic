use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::ToTokens;
use quote::{format_ident, quote};
use syn::{
    Data, DataEnum, DataStruct, DeriveInput, Fields, FieldsNamed, FieldsUnnamed, Generics, Ident,
    Index, Type, parse_macro_input, parse_quote,
};

/// NOTE: Do not derive this implementation for types that have some special invariants
/// and require a constructor. For those fields, the trait must be implemented manually.
///
/// This proc macro automatically implements the ExhaustiveSet trait for algebraic
/// data types, as long as all its members implement ExhaustiveSet themselves. For more
/// context, please read the documentation of the `ExhaustiveSet` trait.
///
/// For bare enums, the exhaustive set just the vec of all variants.
///
/// ```
/// enum E {
///     V1,
///     V2,
/// }
/// // E::exhaustive_set(..) == [V1, V2]
/// ```
///
/// For structs and tuples, the implementation is a bit more complicated. To understand the
/// reason, let's consider a struct `Foo`, whose exhaustive set contains 3 elements. Now how
/// could we derive the following struct?
///
/// ```
/// struct Example {
///     f1: Foo,
///     f2: Foo,
/// }
/// ```
///
/// One way to derive an implementation is to just use two for-loops, and explore every
/// combination of exhaustive set members for f1 and f2. This would give us 9 different
/// values for `Example`'s exhaustive set.
///
/// The problem is that this approach doesn't compose or scale well. If we look at
///
/// ```
/// struct Nested {
///     e1: Example,
///     e2: Example,
/// }
/// ```
///
/// We now have 81 different values to explore. That doesn't seem reasonable, especially
/// because the purpose of `ExhaustiveSet` is to test *correct serialization*. Exploring the
/// entire state space is not necessary for our purposes.
///
/// Instead, we can can construct the exhaustive set by letting each struct field cycle
/// through its own set at the same time. For `Example` that would mean
///
/// ```
/// let foo = Foo::exhaustive_set(..);
///
/// let example_exhaustive_set = vec![
///     Example { f1: foo[0], f2: foo[0] }
///     Example { f1: foo[1], f2: foo[1] }
///     Example { f1: foo[2], f2: foo[2] }
/// ]
/// ```
///
/// Now let's consider a mixed case:
///
/// ```
/// struct Mixed {
///     e: E,
///     f: Foo
/// }
/// ```
///
/// Here, the exhaustive sets of `e` and `f` have different lengths. In this case, we let the
/// shorter ones wrap around (cyclic iteration).
///
/// ```
/// let foo = Foo::exhaustive_set(..);
///
/// let mixed_exhaust = vec![
///     Mixed { e: E::V1, f: foo[0] },
///     Mixed { e: E::V2, f: foo[1] },
///     Mixed { e: E::V1, f: foo[2] },
///                ^^^^^
///             we go back to V1
/// ]
/// ```
///
/// With this approach, we still make sure that every exhaustive set element of every type
/// was included at least once in the composite exhaustive set. Instead of a combinatorial
/// explosion of states, a struct's exhaustive set is as big as the largest exhaustive set of
/// its fields. Applying this strategy to `Example` would yield a set length of 3, and the
/// same for the `Nested` struct.
///
/// For enums with nested tuples, the implementation follows organically.
///
/// ```
/// enum NestedE {
///     V1(S1),
///     V2(S2),
/// }
///
/// // the exhaustive set is derived by concatenating the two following sets
/// S1::exhaustive_set().into_iter().map(NestedE::V1)
/// S2::exhaustive_set().into_iter().map(NestedE::V2)
/// ```
#[proc_macro_derive(ExhaustiveSet)]
pub fn exhaustive_set(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    match input.data {
        Data::Struct(inner) => parse_struct(input.ident, inner, input.generics),
        Data::Enum(inner) => parse_enum(input.ident, inner, input.generics),
        Data::Union(_) => {
            // NOTE: We can add support for unions if we actually need unions
            unimplemented!("ExhaustiveSet cannot be derived for unions.")
        }
    }
}

fn parse_struct(ident: Ident, input: DataStruct, generics: Generics) -> TokenStream {
    match input.fields {
        Fields::Unit => unimplemented!("no support for unit structs"),
        Fields::Named(named) => parse_named_struct(ident, named, generics),
        Fields::Unnamed(unnamed) => parse_unnamed_struct(ident, unnamed, generics),
    }
}

fn parse_named_struct(ident: Ident, input: FieldsNamed, generics: Generics) -> TokenStream {
    let (field_names, types): (Vec<_>, Vec<_>) = input
        .named
        .into_pairs()
        .map(|p| {
            let f = p.value().clone();
            (f.ident.expect("field should have a name"), f.ty)
        })
        .unzip();
    impl_product_type(ident, field_names, types, generics).into()
}

fn parse_unnamed_struct(ident: Ident, input: FieldsUnnamed, generics: Generics) -> TokenStream {
    let types: Vec<_> = input
        .unnamed
        .into_pairs()
        .map(|p| p.value().clone().ty)
        .collect();

    let field_names: Vec<_> = (0..types.len()).map(Index::from).collect();

    impl_product_type(ident, field_names, types, generics).into()
}

/// Creates a token stream of a derived implementation for product types
/// (i.e. records and tuples).
fn impl_product_type<T: ToTokens>(
    ident: Ident,
    field_names: Vec<T>,
    types: Vec<Type>,
    mut generics: Generics,
) -> TokenStream2 {
    let var_names: Vec<_> = (0..types.len())
        .map(|i| format_ident!("field_{}", i))
        .collect();

    // Add ExhaustiveSet bounds to generic type parameters
    for param in generics.type_params_mut() {
        param
            .bounds
            .push(parse_quote!(crate::exhaustive::ExhaustiveSet));
    }
    let (gen_impl, gen_ty, gen_where) = generics.split_for_impl();

    quote! {
        impl #gen_impl crate::exhaustive::ExhaustiveSet for #ident #gen_ty #gen_where {
            fn exhaustive_set<R: rand::RngCore + rand::CryptoRng>(rng: &mut R) -> Vec<Self> {
                #(let mut #var_names = <#types as crate::exhaustive::ExhaustiveSet>::exhaustive_set(rng));*;

                // compute maximum number of elements of all exhaustive sets
                let mut max = 0;
                #(if #var_names.len() > max { max = #var_names.len(); })*

                // create cyclic iterators
                #(let mut #var_names = #var_names.iter().cycle());*;

                let mut result = vec![];
                for i in 0..max {
                    let base = Self {
                        #(#field_names: #var_names.next().unwrap().clone()),*
                    };
                    result.push(base);
                }
                result
            }
        }
    }
}

fn parse_enum(ident: Ident, input: DataEnum, mut generics: Generics) -> TokenStream {
    let variants = input
        .variants
        .into_pairs()
        .map(|p| p.into_value())
        .collect::<Vec<_>>();

    let mut unit_variants = Vec::new();
    let mut variant_tokenstreams = Vec::new();

    for variant in variants {
        match variant.fields {
            Fields::Unit => unit_variants.push(variant.ident),
            Fields::Named(named) => {
                variant_tokenstreams.push(enumerate_named_enum_fields(variant.ident, named));
            }
            Fields::Unnamed(unnamed) => {
                variant_tokenstreams.push(enumerate_unnamed_enum_fields(variant.ident, unnamed));
            }
        };
    }

    // Add ExhaustiveSet bounds to generic type parameters
    for param in generics.type_params_mut() {
        param
            .bounds
            .push(parse_quote!(crate::exhaustive::ExhaustiveSet));
    }
    let (gen_impl, gen_ty, gen_where) = generics.split_for_impl();

    quote! {
        impl #gen_impl crate::exhaustive::ExhaustiveSet for #ident #gen_ty #gen_where {
            fn exhaustive_set<R: rand::RngCore + rand::CryptoRng>(rng: &mut R) -> Vec<Self> {
                let mut result = vec![#(Self::#unit_variants),*];
                #(
                result.append(&mut {
                    #variant_tokenstreams
                });
                )*
                result
            }
        }
    }
    .into()
}

macro_rules! enumerate_enum_fields {
    ($ident:ident, $names:ident, $types:ident) => {{
        let vars: Vec<_> = (0..$types.len())
            .map(|i| format_ident!("field_{}", i))
            .collect();
        let ident = $ident;
        let names = $names;
        let types = $types;
        quote! {
            #(let mut #vars = <#types as crate::exhaustive::ExhaustiveSet>::exhaustive_set(rng));*;

            // compute maximum number of elements of all exhaustive sets
            let mut max = 0;
            #(if #vars.len() > max { max = #vars.len(); })*

            // create cyclic iterators
            #(let mut #vars = #vars.iter().cycle());*;

            let mut inner_result = Vec::new();

            for i in 0..max {
                inner_result.push(Self::#ident {
                    #(#names: #vars
                        .next()
                        .expect(
                            format!("exhaustive set for type {} must be non-empty",
                                stringify!(#types)).as_str()
                        )
                        .clone()
                    ),*
                });
            }

            inner_result

        }
    }};
}

fn enumerate_named_enum_fields(ident: Ident, input: FieldsNamed) -> TokenStream2 {
    let (names, types): (Vec<_>, Vec<_>) = input
        .named
        .into_pairs()
        .map(|p| {
            let val = p.value().clone();
            (val.ident.unwrap(), val.ty)
        })
        .unzip();
    enumerate_enum_fields!(ident, names, types)
}

fn enumerate_unnamed_enum_fields(ident: Ident, input: FieldsUnnamed) -> TokenStream2 {
    let (names, types): (Vec<_>, Vec<_>) = input
        .unnamed
        .into_pairs()
        .enumerate()
        .map(|(i, p)| (Index::from(i), p.value().clone().ty))
        .unzip();
    enumerate_enum_fields!(ident, names, types)
}
