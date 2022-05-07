extern crate proc_macro;
use proc_macro::TokenStream;

const BUILD_INFO_FORMAT: &str = r#"
        build_info::format!(
            "\
                profile: {}\n\
                optimization_level: {}\n\
                crate_name: {}\n\
                enabled_features: {}\n\
                compiler_version: {}\n\
            ",
            $.profile,
            $.optimization_level,
            $.crate_info.name,
            $.crate_info.enabled_features,
            $.compiler.version,
        )
    "#;

/// Generates a couple of function definitions such that the calling canister
/// has a Candid method named get_build_metadata that takes no arguments, and
/// returns a string.
///
/// No need to pass any arguments
///
/// There are some unusual requirements. Basically, calling crates must be ready
/// to use the build-info crate. More specifically, calling crates must do the
/// following:
///   1. List the following in the [dependencies] section of their Cargo.toml:
///     a. build-info
///     b. candid
///     c. dfn_candid
///     d. dfn_core
///   2. List build-info-build in the [build-dependencies] section of their Cargo.toml.
///   3. Have a ./build.rs where main calls build_info::build_script() (either directly or indirectly).
#[proc_macro]
pub fn define_get_build_metadata_candid_method(_: TokenStream) -> TokenStream {
    format!(
        r#"
            #[export_name = "canister_query get_build_metadata"]
            fn get_build_metadata() {{
                dfn_core::over(dfn_candid::candid_one, |()| get_build_metadata_())
            }}

            #[candid::candid_method(query, rename = "get_build_metadata")]
            fn get_build_metadata_() -> &'static str {{
                {}
            }}
        "#,
        BUILD_INFO_FORMAT,
    )
    .parse()
    .unwrap()
}

/// The caller does not need to pass anything.
#[proc_macro]
pub fn get_description(_: TokenStream) -> TokenStream {
    BUILD_INFO_FORMAT.parse().unwrap()
}
