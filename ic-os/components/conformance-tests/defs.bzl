"""Rules for component conformance checks."""

def component_file_references_test(name, component_files, image):
    """
    Verifies that the `component_files` only reference file
    paths that are accessible within the provided `image`.
    """

    deps = [image]
    component_paths = []
    for component in component_files:
        deps.append(component)
        component_paths.append("$(location %s)" % component)

    native.sh_test(
        name = name,
        srcs = ["//ic-os/components/conformance-tests:check_file_references.py"],
        data = deps,
        args = [
            "--files",
            ",".join(component_paths),
            "--image $(location %s)" % image,
        ],
    )
