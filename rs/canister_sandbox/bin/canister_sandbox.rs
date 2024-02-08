#[cfg(target_os = "linux")]
extern "C" {
    fn install_backtrace_handler();
}

fn main() {
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    unsafe {
        install_backtrace_handler();
    }
    // Do not edit this function. Make changes in `canister_sandbox_main` instead.
    ic_canister_sandbox_backend_lib::canister_sandbox_main();
}
