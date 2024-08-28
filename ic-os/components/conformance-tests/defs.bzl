""" Rules for component conformance tests. """

def component_file_references_test(name, component_files, image):
    """
    Verifies that the `component_files` only reference file paths that are accessible within the provided `image`.

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
        srcs = ["//ic-os/components/conformance-tests:check_file_references.py"],
        data = deps,
        args = [
            "--files",
            ",".join(component_paths),
            "--image $(location %s)" % image,
        ],
    )

def _check_unused_components_test_impl(ctx):
    """
    Verifies that every file in components/ is actually being used in one of the images.
    """
    repo_components = [component.label.name for component in ctx.attr.repo_components]
    used_components = [component.label.name for component in ctx.attr.used_components]

    # ADDITIONAL_USED_COMPONENT_FILES are files used for testing and development
    ADDITIONAL_USED_COMPONENT_FILES = ["networking/dev-certs/canister_http_test_ca.key", "networking/dev-certs/root_cert_gen.sh"]
    used_components += ADDITIONAL_USED_COMPONENT_FILES

    unused_components = [file for file in repo_components if file not in used_components]

    unused_components_file = ctx.actions.declare_file(ctx.label.name + ".unused_components")
    ctx.actions.write(
        output = unused_components_file,
        content = "\n".join(unused_components),
    )

    if unused_components:
        content = "echo Unused components check failed; echo Unused components:; echo {}; exit 1".format(", ".join(unused_components))
    else:
        content = "echo Unused components check completed"

    script = ctx.actions.declare_file(ctx.label.name + ".sh")
    ctx.actions.write(
        output = script,
        content = content,
    )

    return [
        DefaultInfo(
            files = depset([unused_components_file]),
            executable = script,
        ),
    ]

check_unused_components_test = rule(
    test = True,
    implementation = _check_unused_components_test_impl,
    attrs = {
        "repo_components": attr.label_list(
            allow_files = True,
        ),
        "used_components": attr.label_list(
            allow_files = True,
        ),
    },
)
