load("@rules_python//python:defs.bzl", "py_test")

# Adds a component conformance test rule that checks that component_files
# only refer to file paths that are available in the image.
def component_conformance_test(name, component_files, image):
    deps = [image]
    component_paths = []
    for component in component_files:
        deps.append(component)
        component_paths.append("$(location %s)" % component)

    native.sh_test(
        name = name + "_component_conformance_test",
        srcs = ["//ic-os/components/conformance:check_components.py"],
        data = deps,
        args = [
            "--files",
            ",".join(component_paths),
            "--image $(location %s)" % image,
        ],
    )
