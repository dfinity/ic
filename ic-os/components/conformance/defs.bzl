"""Rules for component conformance checks."""

def component_conformance_test(name, component_files, image):
    """
    Adds a new component conformance test rule.

    The conformance test verifies that the `component_files` only reference file
    paths that are accessible within the provided `image`.

    Args:
        name: The name of the test rule (must end in _test).
        component_files: A list of Labels that reference components.
        image: The compressed image where the referenced file paths can be found.
    """

    deps = [image]
    component_paths = []
    for component in component_files:
        deps.append(component)
        component_paths.append("$(location %s)" % component)

    native.sh_test(
        name = name,
        srcs = ["//ic-os/components/conformance:check_components.py"],
        data = deps,
        args = [
            "--files",
            ",".join(component_paths),
            "--image $(location %s)" % image,
        ],
    )
