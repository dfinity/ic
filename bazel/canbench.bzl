"""
This module defines functions to run benchmarks using canbench.
"""

load("@rules_rust//rust:defs.bzl", "rust_binary")
load("@rules_shell//shell:sh_binary.bzl", "sh_binary")
load("@rules_shell//shell:sh_test.bzl", "sh_test")
load("//bazel:canisters.bzl", "wasm_rust_binary_rule")

def rust_canbench(name, results_file, add_test = False, opt = "3", noise_threshold = None, data = [], env = {}, **kwargs):
    """ Run a Rust benchmark using canbench. 

    This creates 2 executable rules: :${name} for running the benchmark and :${name}_update for
    updating the results file and optionally a :${name}_test rule.

    Args:
        name: The name of the rule.
        results_file: The file used store the benchmark results for future comparison.
        add_test: If True add an additional :${name}_test rule that fails if canbench benchmark fails.
        opt: The optimization level to use for the rust_binary compilation.
        data: Additional data resources passthrough.
        env: Additional environment variables passthrough.
        **kwargs: Additional arguments to pass to rust_binary.
        noise_threshold: The noise threshold to use for the benchmark. If None, the default value from
            canbench is used.
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
    data = data + [
        ":{name}_wasm".format(name = name),
        "@crate_index//:canbench__canbench",
        results_file,
        "//:WORKSPACE.bazel",
        "//:pocket-ic-mainnet",
    ]
    canbench_results_path = "$(rootpath {results_file})".format(results_file = results_file)
    env = env | {
        "CANBENCH_BIN": canbench_bin,
        "WASM_PATH": wasm_path,
        "CANBENCH_RESULTS_PATH": canbench_results_path,
        "POCKET_IC_BIN": pocket_ic_bin,
        # Hack to escape the sandbox and update the actual repository
        "WORKSPACE": "$(rootpath //:WORKSPACE.bazel)",
    }

    if noise_threshold:
        env["NOISE_THRESHOLD"] = str(noise_threshold)
    sh_binary(
        name = name,
        testonly = True,
        srcs = [
            "//bazel:canbench.sh",
        ],
        data = data,
        env = env,
    )
    sh_binary(
        name = name + "_update",
        testonly = True,
        srcs = [
            "//bazel:canbench.sh",
        ],
        data = data,
        env = env,
        args = ["--update"],
    )
    sh_binary(
        name = name + "_debug",
        testonly = True,
        srcs = [
            "//bazel:canbench.sh",
        ],
        data = data,
        env = env,
        args = ["--debug"],
    )

    if add_test:
        sh_test(
            name = name + "_test",
            srcs = [
                "//bazel:canbench.sh",
            ],
            data = data,
            env = env,
            args = ["--test"],
        )
