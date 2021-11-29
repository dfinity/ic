// For context, see the comment at the top of lib.rs. Moving the entire main
// function into a separate file is much easier than annotating 15+ top level
// declarations with #[cfg] directives.
#[cfg(target_os = "linux")]
include!("agent.rs");

#[cfg(not(target_os = "linux"))]
fn main() {
    panic!("This tool is not available on this operating system.")
}
