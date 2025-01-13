"""
This module defines functions to run benchmarks using canbench.
"""

load("@rules_rust//rust:defs.bzl", "rust_binary")
load("//bazel:canisters.bzl", "wasm_rust_binary_rule")

def rust_canbench(name, results_file, add_test = False, opt = "3", **kwargs):
    """ Run a Rust benchmark using canbench. 

    This creates 2 executable rules: :${name} for running the benchmark and :${name}_update for
    updating the results file and optionally a :${name}_test rule.

    Args:
        name: The name of the rule.
        results_file: The file used store the benchmark results for future comparison.
        add_test: If True add an additional :${name}_test rule that fails if canbench benchmark fails.
        opt: The optimization level to use for the rust_binary compilation.
        **kwargs: Additional arguments to pass to rust_binary.
    """

    rust_binary(
        name = name + "_bin",
        **kwargs
    )

    wasm_rust_binary_rule(
        name = name + "_wasm",
        binary = ":{name}_bin".format(name = name),
        opt = opt,
    )

    canbench_bin = "$(location @crate_index//:canbench__canbench)"
    wasm_path = "$(location :{name}_wasm)".format(name = name)
    pocket_ic_bin = "$(rootpath //:pocket-ic-mainnet)"
    data = [
        ":{name}_wasm".format(name = name),
        "@crate_index//:canbench__canbench",
        results_file,
        "//:WORKSPACE.bazel",
        "//:pocket-ic-mainnet",
    ]
    canbench_results_path = "$(rootpath {results_file})".format(results_file = results_file)
    env = {
        "CANBENCH_BIN": canbench_bin,
        "WASM_PATH": wasm_path,
        "CANBENCH_RESULTS_PATH": canbench_results_path,
        "POCKET_IC_BIN": pocket_ic_bin,
        # Hack to escape the sandbox and update the actual repository
        "WORKSPACE": "$(rootpath //:WORKSPACE.bazel)",
    }

    native.sh_binary(
        name = name,
        testonly = True,
        srcs = [
            "//bazel:canbench.sh",
        ],
        data = data,
        env = env,
    )

    native.sh_binary(
        name = name + "_update",
        testonly = True,
        srcs = [
            "//bazel:canbench.sh",
        ],
        data = data,
        env = env,
        args = ["--update"],
    )

    if add_test:
        native.sh_test(
            name = name + "_test",
            srcs = [
                "//bazel:canbench.sh",
            ],
            data = data,
            env = env,
            args = ["--test"],
        )
