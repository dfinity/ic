# rust_integration_tests.bzl

def rust_integration_tests(name, test_srcs, deps):
    for src in test_srcs:
        test_name = name + "_" + src.basename.replace(".rs", "")
        rust_test(
            srcs = [src],
            data = [
                ":tla_models",
                "@bazel_tools//tools/jdk:current_java_runtime",
                "@tla_apalache//:contents",
            ],
            env = {
                "JAVABASE": "$(JAVABASE)",
            },
            proc_macro_deps = [":proc_macros"],
            toolchains = ["@bazel_tools//tools/jdk:current_java_runtime"],
            deps = [
                ":local_key",
                ":tla_instrumentation",
                "@crate_index//:candid",
                "@crate_index//:tokio-test",
            ],
        )
