use super::*;
use candid_parser::utils::{service_equal, CandidSource};
use std::{fmt::Debug, io::Write, process::Command};
use tempfile::NamedTempFile;

/// This is NOT affected by
///
///   1. comments (in ./registry.did)
///   2. whitespace
///   3. order of type definitions
///   4. names of types
///   5. etc.
///
/// Whereas, this test fails in the following cases
///
///   1. extra (or missing) fields
///   2. differences in field names
///   3. etc.
///
/// If this test passes, that does NOT mean that the API has evolved safely;
/// there is a different test for that (namely,
/// candid_changes_are_backwards_compatible). This test does not compare the
/// current working copy against master. Rather, it only compares ./canister.rs
/// to registry.did.
#[test]
fn test_implemented_interface_matches_declared_interface_exactly() {
    let declared_interface_path = format!(
        "{}/canister/registry.did",
        std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set")
    );
    let declared_interface = std::fs::read(&declared_interface_path).unwrap();
    let declared_interface = String::from_utf8(declared_interface).unwrap();
    let declared_interface = CandidSource::Text(&declared_interface);

    // The line below generates did types and service definition from the
    // methods annotated with `candid_method` above. The definition is then
    // obtained with `__export_service()`.
    candid::export_service!();
    let implemented_interface_str = __export_service();
    let implemented_interface = CandidSource::Text(&implemented_interface_str);

    let result = service_equal(implemented_interface, declared_interface);

    let err = match result {
        Err(err) => err,
        Ok(()) => return,
    };

    let diff_declared_to_implemented_interface = || -> Result<String, String> {
        fn to_debug(err: impl Debug) -> String {
            format!(
                "Unable to diff declared vs. implemented interfaces: {:?}",
                err
            )
        }

        // Write implemented interface to (temporary) file, so we can diff it.
        let mut implemented_interface_file = NamedTempFile::new().map_err(to_debug)?;
        write!(implemented_interface_file, "{}", implemented_interface_str).map_err(to_debug)?;
        implemented_interface_file.flush().map_err(to_debug)?;
        let implemented_interface_path = implemented_interface_file
            .path()
            .to_str()
            .ok_or_else(|| to_debug("Where implemented interface file?"))?;

        let result = Command::new("diff")
            .args([
                "--unified",
                "--ignore-matching-lines=^\\s*//",
                "--ignore-all-space",
                "--ignore-space-change",
                "--ignore-blank-lines",
                "--show-function-line=.*{$",
                &declared_interface_path,
                implemented_interface_path,
            ])
            .output();

        match result {
            Ok(ok) => Ok(String::from_utf8(ok.stdout).map_err(to_debug)?),
            Err(err) => Err(to_debug(err)),
        }
    };

    let diff = diff_declared_to_implemented_interface().unwrap_or_else(|err| err);
    panic!(
        "The interface implemented by the registry canister does NOT \
         match the its declared interface in registry.did:\n{}\n\n\
         diff:\n{}",
        err, diff,
    );
}
