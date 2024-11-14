#[global_allocator]
static GLOBAL: ic_canister_sandbox_backend_lib::allocator::Allocator =
    ic_canister_sandbox_backend_lib::allocator::Allocator;

#[cfg(target_os = "linux")]
extern "C" {
    fn install_backtrace_handler();
}

fn main() {
    std::thread::spawn(|| loop {
        let allocated = ic_canister_sandbox_backend_lib::allocator::ALLOCATED
            .load(std::sync::atomic::Ordering::Relaxed);
        let in_mbs = allocated as f32 / (1024.0 * 1024.0);
        println!("Allocated MiBs: {:.2}", in_mbs);
        std::thread::sleep(std::time::Duration::from_secs(10));
    });
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    unsafe {
        install_backtrace_handler();
    }
    // Do not edit this function. Make changes in `canister_sandbox_main` instead.
    ic_canister_sandbox_backend_lib::canister_sandbox_main();
}
