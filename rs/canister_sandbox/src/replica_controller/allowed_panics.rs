pub(crate) fn panic_launcher_exited_due_to_signal(pid: u32) -> ! {
    panic!(
        "Error from launcher process, pid {pid} exited due to signal! In test environments (e.g., PocketIC), you can safely ignore this message."
    )
}
