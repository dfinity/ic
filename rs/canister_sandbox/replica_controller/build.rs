use escargot::CargoBuild;
use std::env;
use std::path::PathBuf;

// Context: Runtime provides a sandboxed mode of operation beyond the
// threaded in-process mode. Replica controller forks and `execs`()
// the sandbox binary, establishing a socket in the process. To test
// the IPC, robustness, correctness and process management properly we
// require access to the actual sandbox binary, as we depend on proper
// behaviour of COW memory, state coherence between the replica
// controller and the sandboxed binary and socket communication to
// test correctness.
//
// The suggested approach of building and linking dependencies is via
// build.rs for rust. This leaves a lot to be desired. However,
// currently other approaches do not work for us. Firstly, providing a
// setup build mechanism prior to each unit test, would imply
// inability to run and process tests in parallel and also allow races
// (tests running different binaries or overriding a binary used by
// another test): both cases are unacceptable for correctness and
// process management validation in an efficient manner.
//
// Secondly, we require the canister sandbox binary to be rebuilt
// every time we change the appropriate crate. All other options
// investigated right now do not provide any such means.
//
// Finally, note that Hydra can still not support any separate binary
// build, as we may define single semantics that have to work for
// Gitlab which works from a workspaces perspective and we can not
// differentiate between Hydra and local nix-shell environment, to our
// knowledge and requests for that ability. The only way for Hydra to
// provide support would be to provide a workspace self-reference to
// canister_sandbox crate, which would break Gitlab. Thus, we face a
// catch 22 and need a single CI.
//
// # Semantics
//
// Briefly, the sandboxed wasm runtime executes and connects with a
// sandbox process binary (under canister_sandbox crate). For security
// reasons, this binary needs to be co-located with any executable
// that utilizes the sandboxed runtime.
//
// Thus, we need to ensure the sandbox process binary has been built and is
// available when we run the execution environment tests.
fn main() {
    // Rebuild if any changes occur in canister_sandbox and related crates (uses
    // mtime).
    println!("cargo:rerun-if-changed=../../canister_sandbox/src");
    // Clippy (and other related workspace tooling) also invokes the
    // build script. Clippy works in a non-standard fashion and breaks
    // crate isolation and build flags -- see
    // https://github.com/rust-lang/cargo/pull/7533. In particular, it
    // communicates with cargo via the RUSTC_WORKSPACE_WRAPPER
    // (https://github.com/rust-lang/cargo/issues/8143) environment
    // flag. Furthermore, cargo internally requires unstable options
    // on when it detects this variable has been set.
    //
    // Then a (CI) script or tool like clippy or cargo fix or dfix
    // that sets RUSTC_WORKSPACE_WRAPPER would require us to correctly
    // build with unstable options and without proper crate isolation
    // or build flags. That is not necessary however and we can skip
    // the build of the sandbox.
    let should_not_run = env::var("RUSTC_WORKSPACE_WRAPPER").is_ok();
    if should_not_run {
        eprintln!(
            "Not running sandbox process build script due to RUSTC_WORKSPACE_WRAPPER being set."
        );
        return;
    }
    // The CI (Hydra included) modify RUSTC and the cargo flow. We can
    // not expect the same behaviour as normal local development right
    // now. The NIX_BUILD_TOP and similar environment variables are
    // also set in the local nix shell. Therefore, we check for the
    // CI_PIPELINE_ID which we expect to be set when building inside the
    // Gitlab environment. However, Hydra does not work as it restricts
    // dependencies.
    let in_gitlab = env::var("CI_PIPELINE_ID").is_ok();
    let sandbox_testing_on = env::var("SANDBOX_TESTING_ON").is_ok();
    if !in_gitlab || !sandbox_testing_on {
        eprintln!("Not running sandbox process build script due to CI_PIPELINE_ID being set.");
        return;
    }

    // OUT_DIR points to the path that the result of the build script
    // is going to be placed.
    let out_dir = env::var("OUT_DIR").unwrap();
    let canister_sandbox_crate = "../../canister_sandbox".to_owned();
    let mut canister_sandbox_crate_toml = PathBuf::from(&canister_sandbox_crate);
    canister_sandbox_crate_toml.push("Cargo.toml");
    let binary = CargoBuild::new()
        .bin("canister_sandbox")
        .current_release()
        .current_target()
        .manifest_path(canister_sandbox_crate_toml)
        .target_dir(out_dir.clone())
        .run()
        .expect("Cargo failed to compile canister sandbox binary.");
    let bin_path = binary.path();

    let mut dest_dir_path = PathBuf::from(&out_dir);
    // We want to make the canister_sandbox binary available to all
    // the generated test binaries. That implies (by security
    // requirement) we have to place it in the same directory with the
    // test binaries.
    //
    // Cargo has a default build cache file hierarchy under the target
    // directory. This is described at length in
    // https://doc.rust-lang.org/cargo/guide/build-cache.html. When we
    // build a dependency -- in this case the canister_sandbox -- this
    // should be placed under the deps/ subdirectory under the build profile
    // directory (e.g. debug/).
    //
    // Here we want to copy the resulting binary, to the respective
    // dependencies folder of the execution environment. Recall that
    // the OUT_DIR points to the new directory -- which in our case is
    // under build/<pkg>/output. Thus, we copy the output from
    // `build/<pkg>/output` to `deps/canister_sandbox`.
    dest_dir_path.pop();
    dest_dir_path.pop();
    dest_dir_path.pop();
    dest_dir_path.push("deps");
    dest_dir_path.push("canister_sandbox");
    std::fs::copy(bin_path, dest_dir_path.as_os_str()).unwrap_or_else(|_| {
        panic!(
            "Failed to copy the canister sandbox binary to: {:?}",
            &dest_dir_path
        )
    });
}
