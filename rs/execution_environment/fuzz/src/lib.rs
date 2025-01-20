use ic_canister_sandbox_backend_lib::{
    canister_sandbox_main, compiler_sandbox::compiler_sandbox_main,
    launcher::sandbox_launcher_main, RUN_AS_CANISTER_SANDBOX_FLAG, RUN_AS_COMPILER_SANDBOX_FLAG,
    RUN_AS_SANDBOX_LAUNCHER_FLAG,
};
use libfuzzer_sys::test_input_wrap;
use std::ffi::CString;
use std::os::raw::c_char;

#[cfg(target_os = "linux")]
use {
    nix::{
        sys::ptrace, sys::ptrace::Options, sys::wait::waitpid, sys::wait::WaitStatus, unistd::fork,
        unistd::ForkResult, unistd::Pid,
    },
    procfs::process::Process,
    std::collections::BTreeSet,
    syscalls::Sysno,
};

#[allow(improper_ctypes)]
extern "C" {
    fn LLVMFuzzerRunDriver(
        argc: *const isize,
        argv: *const *const *const u8,
        UserCb: fn(data: *const u8, size: usize) -> i32,
    ) -> i32;

}

#[derive(Debug, Default)]
pub struct SandboxFeatures {
    pub syscall_tracing: bool,
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

pub fn fuzzer_main(features: SandboxFeatures) {
    if std::env::args().any(|arg| arg == RUN_AS_CANISTER_SANDBOX_FLAG) {
        #[cfg(not(fuzzing))]
        if features.syscall_tracing {
            syscall_monitor("canister_sandbox_main", canister_sandbox_main);
            return;
        }
        canister_sandbox_main();
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

#[cfg(target_os = "linux")]
fn syscall_monitor<F>(name: &str, sandbox: F)
where
    F: Fn(),
{
    match unsafe { fork() } {
        Ok(ForkResult::Child) => {
            sandbox();
        }
        Ok(ForkResult::Parent { child }) => {
            std::thread::sleep(std::time::Duration::from_secs(1));
            let allowed_syscalls: BTreeSet<Sysno> = BTreeSet::from([
                Sysno::mmap,
                Sysno::mprotect,
                Sysno::munmap,
                Sysno::madvise,
                Sysno::sendmsg,
                Sysno::sigaltstack,
                Sysno::futex,
                Sysno::close,
                Sysno::restart_syscall,
            ]);
            let children = get_children(child.into());
            let threads: Vec<_> = children
                .iter()
                .map(|child| {
                    std::thread::spawn({
                        let allowed_syscalls = allowed_syscalls.clone();
                        let child = *child;
                        let name = name.to_string();
                        move || {
                            trace(name, Pid::from_raw(child), allowed_syscalls);
                        }
                    })
                })
                .collect();

            for handle in threads {
                handle.join().unwrap();
            }
        }
        Err(err) => {
            panic!("{} fork() failed: {}", name, err);
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn syscall_monitor<F>(_name: &str, sandbox: F)
where
    F: Fn(),
{
    sandbox();
}

#[cfg(target_os = "linux")]
fn trace(name: String, child: Pid, allowed_syscalls: BTreeSet<Sysno>) {
    if let Err(err) = ptrace::attach(child) {
        println!(
            "ptrace: failed to attach process {}::{}: {}",
            name, child, err
        );
        return;
    }

    let mut is_syscall_entry = true;
    while let Ok(result) = waitpid(child, None) {
        match result {
            WaitStatus::Stopped(..) => {
                if let Err(err) = ptrace::setoptions(child, Options::all()) {
                    panic!(
                        "ptrace: failed to setoptions process {}::{}: {}",
                        name, child, err
                    );
                }

                if let Err(err) = ptrace::syscall(child, None) {
                    panic!(
                        "ptrace: failed to continue to next syscall {}::{}: {}",
                        name, child, err
                    );
                }
            }
            WaitStatus::PtraceSyscall(_) => {
                if is_syscall_entry {
                    if let Ok(regs) = ptrace::getregs(child) {
                        let sysno = Sysno::from(regs.orig_rax as u32);
                        if !allowed_syscalls.contains(&sysno) {
                            panic!("Syscall not present: {:?} {}::{}", sysno, name, child,);
                        }
                    }
                }

                is_syscall_entry = !is_syscall_entry;
                if let Err(err) = ptrace::syscall(child, None) {
                    panic!(
                        "ptrace: failed to continue to next syscall {}::{}: {}",
                        name, child, err
                    );
                }
            }
            WaitStatus::Exited(..) => {
                println!(
                    "ptrace: process exited {}::{} child pids: {:?}",
                    name,
                    child,
                    get_children(child.into())
                );
            }
            WaitStatus::PtraceEvent(..) => {
                if let Err(err) = ptrace::detach(child, None) {
                    panic!(
                        "ptrace: failed to detach process {}::{}: {}",
                        name, child, err
                    );
                }
                return;
            }
            _ => (),
        }
    }
}

#[cfg(target_os = "linux")]
fn get_children(parent_pid: i32) -> BTreeSet<i32> {
    let mut pids = BTreeSet::new();

    if let Ok(process) = Process::new(parent_pid) {
        if let Ok(tasks) = process.tasks() {
            for task in tasks.flatten() {
                let child_pid = task.tid;
                pids.insert(child_pid);
            }
        }
    }
    pids.remove(&parent_pid);
    pids
}
