#[cfg(target_os = "linux")]
extern "C" {
    fn install_backtrace_handler();
}

fn main() {
    #[cfg(target_os = "linux")]
    unsafe {
        install_backtrace_handler();
    }
    // Do not edit this function. Make changes in `canister_sandbox_main` instead.
    ic_canister_sandbox_backend_lib::canister_sandbox_main();
}
