use proc_macro::TokenStream;
use quote::{quote, ToTokens};
use syn::{parse_macro_input, AttributeArgs, ItemFn, NestedMeta, ReturnType};

/// A macro for declaring a benchmark where only some part of the function is
/// benchmarked.
#[proc_macro_attribute]
pub fn bench(arg_tokens: TokenStream, item: TokenStream) -> TokenStream {
    // Parse the input as a function
    let input = parse_macro_input!(item as ItemFn);

    // Parse the attribute arguments
    let args = parse_macro_input!(arg_tokens as AttributeArgs);

    // Extract function name, inputs, and output
    let func_name = &input.sig.ident;
    let inputs = &input.sig.inputs;
    let output = &input.sig.output;

    // Check that there are no function arguments
    if !inputs.is_empty() {
        return syn::Error::new_spanned(inputs, "Benchmark should not take any arguments")
            .to_compile_error()
            .into();
    }

    // Prefix the benchmark name with "__canbench__".
    // This is to inform that the `canbench` binary that this query is a benchmark
    // that it should run.
    let renamed_func_name =
        syn::Ident::new(&format!("__canbench__{}", func_name), func_name.span());
    let tracing_func_name = syn::Ident::new(&format!("__tracing__{}", func_name), func_name.span());

    // Validate the argument and generate code accordingly
    let expanded = match args.as_slice() {
        [NestedMeta::Meta(meta)] if meta.path().is_ident("raw") => {
            // If the argument is "raw", validate that the function returns BenchResult
            if let ReturnType::Type(_, ty) = output {
                if ty.to_token_stream().to_string() != quote!(BenchResult).to_string()
                    && ty.to_token_stream().to_string()
                        != quote!(canbench_rs::BenchResult).to_string()
                {
                    // If the return type is not BenchResult, generate a compile-time error
                    return syn::Error::new_spanned(ty, "Raw benchmark should return BenchResult.")
                        .to_compile_error()
                        .into();
                }
            } else {
                // If there is no return type, generate a compile-time error
                return syn::Error::new_spanned(output, "Raw benchmark should return BenchResult.")
                    .to_compile_error()
                    .into();
            }

            quote! {
                #input

                #[ic_cdk::query]
                #[allow(non_snake_case)]
                fn #renamed_func_name() -> canbench_rs::BenchResult {
                    #func_name()
                }

                #[ic_cdk::query]
                #[allow(non_snake_case)]
                fn #tracing_func_name(bench_instructions: u64) -> Result<Vec<(i32, i64)>, String> {
                    #func_name();
                    canbench_rs::get_traces(bench_instructions)
                }
            }
        }
        [] => {
            // If there is no argument, validate that the function returns nothing
            if let ReturnType::Type(_, ty) = &input.sig.output {
                // If the return type is not empty, generate a compile-time error
                return syn::Error::new_spanned(ty, "Benchmark should not return any values.")
                    .to_compile_error()
                    .into();
            }

            quote! {
                #input

                #[ic_cdk::query]
                #[allow(non_snake_case)]
                fn #renamed_func_name() -> canbench_rs::BenchResult {
                    canbench_rs::bench_fn(|| {
                        #func_name();
                    })
                }

                #[ic_cdk::query]
                #[allow(non_snake_case)]
                fn #tracing_func_name(bench_instructions: u64) -> Result<Vec<(i32, i64)>, String> {
                    canbench_rs::bench_fn(|| {
                        #func_name();
                    });
                    canbench_rs::get_traces(bench_instructions)
                }
            }
        }
        _ => {
            // If there is any other argument, generate a compile-time error
            let args_tokens = args
                .iter()
                .map(|arg| quote!(#arg).to_token_stream())
                .collect::<proc_macro2::TokenStream>();

            return syn::Error::new_spanned(
                args_tokens,
                "Invalid argument. Use 'raw' or no argument.",
            )
            .to_compile_error()
            .into();
        }
    };

    TokenStream::from(expanded)
}
