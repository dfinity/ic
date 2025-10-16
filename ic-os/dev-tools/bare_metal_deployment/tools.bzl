"""
Bare metal utility functions. Use this macro to define a target to launch an OS on bare metal. For usage, see readme.md
"""

load("@python_deps//:requirements.bzl", "requirement")
load("@rules_python//python:defs.bzl", "py_binary")
load("@rules_shell//shell:sh_binary.bzl", "sh_binary")

def launch_bare_metal(name, image_zst_file):
    binary_name = name + "_main"
    py_binary(
        name = binary_name,
        srcs = ["//ic-os/dev-tools/bare_metal_deployment:deploy.py"],
        main = "//ic-os/dev-tools/bare_metal_deployment:deploy.py",
        deps = [
            requirement("fabric"),
            requirement("idracredfishsupport"),
            requirement("invoke"),
            requirement("loguru"),
            requirement("pyyaml"),
            requirement("requests"),
            requirement("simple-parsing"),
            requirement("tqdm"),
        ],
        tags = ["manual"],
    )
    sh_binary(
        name = name,
        srcs = ["//toolchains/sysimage:proc_wrapper.sh"],
        args = [
            "python3",
            "$(location :" + binary_name + ")",
            "--inject_configuration_tool",
            "$(location //rs/ic_os/dev_test_tools/setupos-image-config:setupos-inject-config)",
            "--upload_img",
            "$(location " + image_zst_file + ")",
            "--idrac_script",
            "$(location //ic-os/dev-tools/bare_metal_deployment:redfish_scripts)" + "/IdracRedfishSupport-0.0.8.data/scripts/VirtualDiskExpansionREDFISH.py",
            "--benchmark_driver_script",
            "$(location //ic-os/dev-tools/bare_metal_deployment:benchmark_driver.sh)",
            "--benchmark_runner_script",
            "$(location //ic-os/dev-tools/bare_metal_deployment:benchmark_runner.sh)",
            "--benchmark_tools",
            "$(location //ic-os/dev-tools/hw_validation:stress.sh)",
            "$(location //ic-os/dev-tools/hw_validation:benchmark.sh)",
        ],
        data = [
            ":" + binary_name,
            image_zst_file,
            "//rs/ic_os/dev_test_tools/setupos-image-config:setupos-inject-config",
            "//ic-os/dev-tools/bare_metal_deployment:redfish_scripts",
            "//ic-os/dev-tools/bare_metal_deployment:benchmark_runner.sh",
            "//ic-os/dev-tools/bare_metal_deployment:benchmark_driver.sh",
            "//ic-os/dev-tools/hw_validation:stress.sh",
            "//ic-os/dev-tools/hw_validation:benchmark.sh",
        ],
        tags = ["manual"],
    )
