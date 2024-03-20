"""
Bare metal utility functions. Use this macro to define a target to launch an OS on bare metal. For usage, see readme.md
"""

load("@python_deps//:requirements.bzl", "requirement")

def launch_bare_metal(name, image_zst_file):
    native.py_binary(
        name = name,
        srcs = ["//ic-os/utils/bare_metal_deployment:deploy.py"],
        main = "//ic-os/utils/bare_metal_deployment:deploy.py",
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
        data = [image_zst_file, "//rs/ic_os/setupos-inject-configuration", "//ic-os/utils/bare_metal_deployment:find_idrac_package_path"],
        args = [
            "--inject_configuration_tool",
            "$(location //rs/ic_os/setupos-inject-configuration)",
            "--upload_img",
            "$(location " + image_zst_file + ")",
            "--idrac_script_dir",
            "$(location //ic-os/utils/bare_metal_deployment:find_idrac_package_path)",
        ],
        tags = ["manual"],
    )
