"""
This module defines functions to run benchmarks using canbench.
"""

load("@rules_rust//rust:defs.bzl", "rust_binary")
load("@rules_shell//shell:sh_binary.bzl", "sh_binary")
load("@rules_shell//shell:sh_test.bzl", "sh_test")
load("//bazel:canisters.bzl", "wasm_rust_binary_rule")

def rust_canbench(name, results_file, opt = "3", noise_threshold = None, data = [], env = {}, timeout = None, **kwargs):
    """ Run a Rust benchmark using canbench.

    This creates 2 executable rules: :${name} for running the benchmark and :${name}_update for
    updating the results file and a :${name}_test rule.

    Args:
        name: The name of the rule.
        results_file: The file used store the benchmark results for future comparison.
        opt: The optimization level to use for the rust_binary compilation.
        data: Additional data resources passthrough.
        env: Additional environment variables passthrough.
        timeout: The timeout for the test rule. If None, the default Bazel timeout is used.
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

    data = data + [
        ":{name}_wasm".format(name = name),
        "@crate_index//:canbench__canbench",
        results_file,
        "//:pocket-ic-mainnet",
    ]
    env = env | {
        "CANBENCH_BIN": "$(location @crate_index//:canbench__canbench)",
        "WASM_PATH": "$(location :{name}_wasm)".format(name = name),
        "CANBENCH_RESULTS_PATH": "$(rootpath {results_file})".format(results_file = results_file),
        "POCKET_IC_BIN": "$(rootpath //:pocket-ic-mainnet)",
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

    test_kwargs = {}
    if timeout:
        test_kwargs["timeout"] = timeout

    sh_test(
        name = name + "_test",
        srcs = [
            "//bazel:canbench.sh",
        ],
        data = data,
        env = env,
        args = ["--test"],
        **test_kwargs
    )
