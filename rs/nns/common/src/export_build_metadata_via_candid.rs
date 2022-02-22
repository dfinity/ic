use dfn_candid::candid_one;
use dfn_core::over;

/// Creates a candid method named get_build_metadata, which returns a string
/// describing how the canister was built.
///
/// As usual, make this macro available by adding this incantation to your
/// canister code:
///
///   // Makes expose_build_metadata! available.
///   #[macro_use]
///   extern crate ic_nns_common;
///
/// Then, simply invoke this macro anywhere, like so:
///
///   expose_build_metadata! {}
///
/// Notice the lack of semicolon. This is allowed when (curly) braces are used
/// instead of paren.
#[macro_export]
macro_rules! expose_build_metadata {
    () => {
        use ic_nns_common::export_build_metadata_via_candid;

        #[export_name = "canister_query get_build_metadata"]
        fn get_build_metadata() {
            export_build_metadata_via_candid::get_build_metadata()
        }

        #[candid::candid_method(query, rename = "get_build_metadata")]
        fn get_build_metadata_() -> &'static str {
            export_build_metadata_via_candid::get_build_metadata_()
        }
    };
}

/// Returns a string that describes how the binary was built.
pub fn get_build_metadata() {
    over(candid_one, |()| get_build_metadata_())
}

pub fn get_build_metadata_() -> &'static str {
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
        $.compiler.version
    )
}

#[test]
fn test_get_build_metadata() {
    let build_metadata = get_build_metadata_();

    for chunk in [
        "profile: ",
        "optimization_level: ",
        "crate_name: ",
        "enabled_features: ",
        "compiler_version: ",
    ] {
        assert!(
            build_metadata.contains(chunk),
            "\
              chunk: {}\n\
              build_metadata: {}\
            ",
            chunk,
            build_metadata,
        );
    }
}
