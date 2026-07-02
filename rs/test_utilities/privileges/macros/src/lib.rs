//! Proc-macro companion of `ic-test-utilities-privileges`.
//!
//! Don't depend on this crate directly: use the [`as_nobody_when_root`]
//! attribute re-exported from `ic_test_utilities_privileges`.

use proc_macro::TokenStream;
use quote::quote;
use syn::{Error, ItemFn, ReturnType, parse_macro_input};

/// Runs the annotated test as the unprivileged `nobody` user when the process
/// is root, and unchanged otherwise.
///
/// This is attribute sugar for wrapping the whole test body in
/// `ic_test_utilities_privileges::run_as_nobody_if_root`: root bypasses file
/// permission bits (`CAP_DAC_OVERRIDE`), so tests asserting `PermissionDenied`
/// only observe the denial when dropping to `nobody` on root-run workers
/// (e.g. under Bazel remote execution). See the documentation of
/// `run_as_nobody_if_root` for the exact semantics.
///
/// Place it after `#[test]` (and `#[should_panic]`, which keeps working since
/// the wrapper re-raises the child's panic message):
///
/// ```ignore
/// #[test]
/// #[ic_test_utilities_privileges::as_nobody_when_root]
/// fn should_deny_write() {
///     // ... assertions relying on file permission bits ...
/// }
/// ```
#[proc_macro_attribute]
pub fn as_nobody_when_root(attr: TokenStream, item: TokenStream) -> TokenStream {
    if !attr.is_empty() {
        return Error::new_spanned(
            proc_macro2::TokenStream::from(attr),
            "#[as_nobody_when_root] takes no arguments",
        )
        .to_compile_error()
        .into();
    }

    let item_fn = parse_macro_input!(item as ItemFn);

    if let Some(asyncness) = &item_fn.sig.asyncness {
        return Error::new_spanned(
            asyncness,
            "#[as_nobody_when_root] does not support async functions: \
             forking around an async runtime does not compose",
        )
        .to_compile_error()
        .into();
    }
    if let ReturnType::Type(_, ty) = &item_fn.sig.output {
        return Error::new_spanned(
            ty,
            "#[as_nobody_when_root] only supports functions without a return type",
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
            ::ic_test_utilities_privileges::run_as_nobody_if_root(|| #block);
        }
    }
    .into()
}
