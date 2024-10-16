#[cfg(target_os = "linux")]
extern "C" {
    fn install_backtrace_handler();
}

#[global_allocator]
static ALLOCATOR: ic_canister_sandbox_backend_lib::alloc_metrics::MetricsAlloc =
    ic_canister_sandbox_backend_lib::alloc_metrics::MetricsAlloc {};

fn main() {
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    unsafe {
        install_backtrace_handler();
    }
    // Do not edit this function. Make changes in `canister_sandbox_main` instead.
    ic_canister_sandbox_backend_lib::canister_sandbox_main();
}
