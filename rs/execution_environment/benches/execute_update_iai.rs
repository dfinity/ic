///
/// Compare `execute_update()` performance for messages with and without exit.
///
/// The `iai` gives a very precise number of CPU instructions, cache accesses,
/// and cycles.
///
/// Example `iai` output:
/// ```
/// iai_baseline
///   Instructions:            24471794 (-7.448422%)
///   L1 Accesses:             36503846 (-7.462859%)
///   L2 Accesses:               216153 (+9.165425%)
///   RAM Accesses:               87311 (-14.29763%)
///   Estimated Cycles:        40640496 (-7.642579%)
/// ```
mod update;
mod wat;
use wat::*;

fn iai_baseline_empty_test() {
    update::run_benchmark(
        None,
        "baseline/empty test",
        render_test_func("", "(drop (i32.const 0))"),
        0,
    );
}

fn iai_baseline_empty_loop_1m() {
    update::run_benchmark(
        None,
        "baseline/empty loop/1M",
        render_test_func("", render_loop(LOOP_1M, "")),
        0,
    );
}

fn iai_baseline_add_loop_1m() {
    update::run_benchmark(
        None,
        "baseline/adds loop/1M",
        render_test_func(
            "",
            render_loop(
                LOOP_1M,
                "(set_local $s (i32.add (get_local $s) (i32.load (i32.const 0))))",
            ),
        ),
        0,
    );
}

fn iai_ic0_stable_size_loop_1m() {
    update::run_benchmark(
        None,
        "ic0.stable_size() loop/1M",
        render(LOOP_1M, "stable_size", NoParams(), Result1()),
        0,
    );
}

fn iai_ic0_stable_read_loop_1m_1b() {
    update::run_benchmark(
        None,
        "ic0.stable_read() loop/1M/1B",
        render(LOOP_1M, "stable_read", Params3(0, 0, 1), NoResults()),
        0,
    );
}

fn iai_ic0_stable_read_loop_1m_8kb() {
    update::run_benchmark(
        None,
        "ic0.stable_read() loop/1M/8KiB",
        render(LOOP_1M, "stable_read", Params3(0, 0, 8192), NoResults()),
        0,
    );
}

fn iai_ic0_stable_write_loop_1m_1b() {
    update::run_benchmark(
        None,
        "ic0.stable_write() loop/1M/1B",
        render(LOOP_1M, "stable_write", Params3(0, 0, 1), NoResults()),
        0,
    );
}

fn iai_ic0_stable_write_loop_1m_8kb() {
    update::run_benchmark(
        None,
        "ic0.stable_write() loop/1M/8KiB",
        render(LOOP_1M, "stable_write", Params3(0, 0, 8192), NoResults()),
        0,
    );
}

// That's the only way to use iai for now :(
iai::main!(
    iai_baseline_empty_test,
    iai_baseline_empty_loop_1m,
    iai_baseline_add_loop_1m,
    iai_ic0_stable_size_loop_1m,
    iai_ic0_stable_read_loop_1m_1b,
    iai_ic0_stable_read_loop_1m_8kb,
    iai_ic0_stable_write_loop_1m_1b,
    iai_ic0_stable_write_loop_1m_8kb,
);
