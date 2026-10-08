//! Proc-macro companion of `ic-test-utilities-privileges`.
//!
//! Don't depend on this crate directly: use the [`enforce_file_permissions`]
//! attribute re-exported from `ic_test_utilities_privileges`.

use proc_macro::TokenStream;
use quote::quote;
use syn::{Error, ItemFn, parse_macro_input};

/// Runs the annotated test with the filesystem permission bits enforced against
/// it, even when the test process is privileged.
///
/// This is attribute sugar for wrapping the whole test body in
/// `ic_test_utilities_privileges::run_with_file_permissions_enforced`: root
/// bypasses file permission bits via `CAP_DAC_OVERRIDE`/`CAP_DAC_READ_SEARCH`,
/// so tests asserting `PermissionDenied` only observe the denial once those are
/// dropped (e.g. under Bazel remote execution, which runs test actions as root).
/// See the documentation of `run_with_file_permissions_enforced` for the exact
/// semantics and limitations.
///
/// Place it after `#[test]` (and `#[should_panic]`, which keeps working since
/// the body runs in-process and its panic propagates unchanged):
///
/// ```ignore
/// #[test]
/// #[ic_test_utilities_privileges::enforce_file_permissions]
/// fn should_deny_write() {
///     // ... assertions relying on file permission bits ...
/// }
/// ```
#[proc_macro_attribute]
pub fn enforce_file_permissions(attr: TokenStream, item: TokenStream) -> TokenStream {
    if !attr.is_empty() {
        return Error::new_spanned(
            proc_macro2::TokenStream::from(attr),
            "#[enforce_file_permissions] takes no arguments",
        )
        .to_compile_error()
        .into();
    }

    let item_fn = parse_macro_input!(item as ItemFn);

    if let Some(asyncness) = &item_fn.sig.asyncness {
        return Error::new_spanned(
            asyncness,
            "#[enforce_file_permissions] does not support async functions: capabilities \
             are a per-thread property, and there is no synchronous scope to drop them \
             for. Put this attribute *below* `#[tokio::test]` instead — attribute macros \
             expand top-down, so `#[tokio::test]` then expands first and this one wraps \
             the synchronous `block_on` wrapper it produces (which also builds the \
             runtime inside the guarded scope, so its worker threads inherit the drop). \
             Alternatively call \
             `ic_test_utilities_privileges::run_with_file_permissions_enforced` directly \
             around the blocking assertion",
        )
        .to_compile_error()
        .into();
    }

    let ItemFn {
        attrs,
        vis,
        sig,
        block,
    } = item_fn;

    quote! {
        #(#attrs)*
        #vis #sig {
            ::ic_test_utilities_privileges::run_with_file_permissions_enforced(|| #block)
        }
    }
    .into()
}
