use ic_canister_sandbox_backend_lib::{
    canister_sandbox_main, compiler_sandbox::compiler_sandbox_main,
    launcher::sandbox_launcher_main, RUN_AS_CANISTER_SANDBOX_FLAG, RUN_AS_COMPILER_SANDBOX_FLAG,
    RUN_AS_SANDBOX_LAUNCHER_FLAG,
};
use libfuzzer_sys::test_input_wrap;
use std::ffi::CString;
use std::os::raw::c_char;
use std::process::{exit, Command};
use std::os::unix::process::CommandExt;
use nix::sys::ptrace;
use nix::sys::wait::wait;
use nix::unistd::{fork, ForkResult};

#[allow(improper_ctypes)]
extern "C" {
    fn LLVMFuzzerRunDriver(
        argc: *const isize,
        argv: *const *const *const u8,
        UserCb: fn(data: *const u8, size: usize) -> i32,
    ) -> i32;

}

// In general, fuzzers don't include `main()` and the initialisation logic is deferred to libfuzzer.
// However, to enable canister sandboxing, we override the initialisation by providing our own `main()`
// which acts as a dispatcher for different sandboxed under certain arguments.
//
// The default case invokes `LLVMFuzzerRunDriver` which invokes a callback with similar signature as
// `LLVMFuzzerTestOneInput`. For more details, see https://llvm.org/docs/LibFuzzer.html#using-libfuzzer-as-a-library
//
// We provide `libfuzzer_sys::test_input_wrap` as callback for `LLVMFuzzerRunDriver` since libfuzzer_sys
// already exports `LLVMFuzzerTestOneInput` and we can't override it. `test_input_wrap` internally calls
// `rust_fuzzer_test_input`, which is generated via the macro `fuzz_target!`.
// See https://github.com/rust-fuzz/libfuzzer/blob/c8275d1517933765b56a6de61a371bb1cc4268cb/src/lib.rs#L62

pub fn fuzzer_main() {
    if std::env::args().any(|arg| arg == RUN_AS_CANISTER_SANDBOX_FLAG) {
        #[cfg(not(fuzzing))]
        syscall_monitor(|| { 
            canister_sandbox_main();
            Command::new("ls").exec();
        });
        
    } else if std::env::args().any(|arg| arg == RUN_AS_SANDBOX_LAUNCHER_FLAG) {
        #[cfg(not(fuzzing))]
        sandbox_launcher_main();
    } else if std::env::args().any(|arg| arg == RUN_AS_COMPILER_SANDBOX_FLAG) {
        #[cfg(not(fuzzing))]
        compiler_sandbox_main();
    } else {
        // Collect command-line arguments
        let args: Vec<CString> = std::env::args()
            .map(|arg| CString::new(arg).unwrap())
            .collect();

        // Prepare argc as *const isize
        let argc = args.len() as isize;
        let argc: *const isize = &argc;

        // Prepare argv as *const *const *const u8
        let argv: Vec<*const c_char> = args.iter().map(|arg| arg.as_ptr()).collect();
        let argv_ptr: *const *const u8 = argv.as_ptr() as *const *const u8;
        let argv: *const *const *const u8 = &argv_ptr;

        unsafe {
            LLVMFuzzerRunDriver(argc, argv, test_input_wrap);
        }
    }
}


fn syscall_monitor<F>(f: F)
where
    F: FnOnce() -> (),
{
    match unsafe { fork() } {
        Ok(ForkResult::Child) => {
            ptrace::traceme().unwrap();
            f();
            exit(0)
        }

        Ok(ForkResult::Parent { child }) => loop {
            wait().unwrap();

            match ptrace::getregs(child) {
                Ok(x) => println!("Syscall name: {:?}", x.orig_rax),
                Err(_) => break,
            };

            match ptrace::syscall(child, None) {
                Ok(_) => continue,
                Err(_) => break,
            }
        },

        Err(err) => {
            panic!("[main] fork() failed: {}", err);
        }
    }
}