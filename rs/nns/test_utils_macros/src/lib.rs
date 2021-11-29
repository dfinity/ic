//! A helper to create paramaterized tests for various canister self-upgrades
//! test scenarios. Using this for integration tests increases test coverage of
//! the canister stable memory and of the upgrade cycle.

extern crate proc_macro;

use proc_macro::TokenStream;
use quote::{format_ident, quote};
use syn::parse_macro_input;

/// When attached to a function called <func>, this generates several tests at
/// compile time that invoke <func> with various value for the
/// UpgradeTestingScenario.
///
/// The function to which this attribute is attached MUST have the following
/// signature:
///
/// async fn test_name(
///     runtime: &Runtime,
///     upgrade_scenario: UpgradeTestingScenario,
/// ) -> ()
///
/// Only using this macro is not quite enough, though: it is only useful if
/// function `maybe_upgrade_to_self` or
/// `maybe_upgrade_root_controlled_canister_to_self` is used inside the body of
/// the function --- the more often, better the coverage of the upgrade process.
///
/// The generated test for the Never scenario is generated for debug and release
/// builds.
///
/// The generated test for the Always scenario is generated for the release
/// builds only. This way, it is easy to skip the Always tests, which tend to be
/// very slow.
#[proc_macro_attribute]
pub fn parameterized_upgrades(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let func = parse_macro_input!(item as syn::ItemFn);
    let clone = func.clone();
    let original_fn_ident = func.sig.ident;
    let always_testname =
        format_ident!("test_{}_always_upgrade_to_self_slowtest", original_fn_ident);
    let never_testname = format_ident!("test_{}_never_upgrade_to_self", original_fn_ident);

    let expanded = quote! {
      // Re-export the function that was marked with [#parameterized_upgrades], unchanged
      #clone

      // Export a #[test] with the `Always` upgrade scenario
      #[test]
      fn #always_testname() {
          ic_nns_test_utils::itest_helpers::local_test_on_nns_subnet(|runtime| async move {
            #original_fn_ident(
                &runtime,
                ic_nns_test_utils::itest_helpers::UpgradeTestingScenario::Always).await;
            Ok(())
          });
      }

      // Export a #[test] with the `Never` upgrade scenario
      #[test]
      fn #never_testname() {
          ic_nns_test_utils::itest_helpers::local_test_on_nns_subnet(|runtime| async move {
            #original_fn_ident(
                &runtime,
                ic_nns_test_utils::itest_helpers::UpgradeTestingScenario::Never).await;
            Ok(())
          });
      }
    };

    TokenStream::from(expanded)
}
