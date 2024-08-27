"""
Bare metal utility functions. Use this macro to define a target to launch an OS on bare metal. For usage, see readme.md
"""

load("@python_deps//:requirements.bzl", "requirement")

def launch_bare_metal(name, image_zst_file):
    native.py_binary(
        name = name + "_main",
        srcs = ["//ic-os/dev-tools/bare_metal_deployment:deploy.py"],
        main = "//ic-os/dev-tools/bare_metal_deployment:deploy.py",
        deps = [
            requirement("fabric"),
            requirement("icmplib"),
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

    native.sh_binary(
        name = name,
        srcs = ["//toolchains/sysimage:proc_wrapper.sh"],
        args = [
            "python3",
            "$(location :" + name + "_main)",
            "--inject_configuration_tool",
            "$(location //rs/ic_os/setupos-inject-configuration)",
            "--upload_img",
            "$(location " + image_zst_file + ")",
            "--idrac_script_dir",
            "$(location //ic-os/dev-tools/bare_metal_deployment:find_idrac_package_path)",
        ],
        data = [":%s_main" % name, image_zst_file, "//rs/ic_os/setupos-inject-configuration", "//ic-os/dev-tools/bare_metal_deployment:find_idrac_package_path"],
        tags = ["manual"],
    )
