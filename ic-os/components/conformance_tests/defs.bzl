""" Rules for component conformance tests. """

load("@rules_shell//shell:sh_test.bzl", "sh_test")

def component_file_references_test(name, component_files, image, tags = None):
    """
    Verifies that the `component_files` only reference file paths that are accessible within the provided `image`.

    Args:
        name: The name of the test rule (must end in _test).
        component_files: A list of Labels that reference components.
        image: The compressed image where the referenced file paths can be found.
        tags: Tags to apply to the generated test target.
    """

    deps = [image]
    component_paths = []
    for component in component_files:
        deps.append(component)
        component_paths.append("$(location %s)" % component)
    sh_test(
        name = name,
        srcs = ["//ic-os/components/conformance_tests:check_file_references.py"],
        data = deps,
        args = [
            "--files",
            ",".join(component_paths),
            "--image $(location %s)" % image,
        ],
        tags = tags,
    )

def _check_unused_components_test_impl(ctx):
    """
    Verifies that every file in components/ is actually being used in one of the images.
    """
    repo_components_labels = [component.label for component in ctx.attr.repo_components]
    used_components_labels = [component.label for component in ctx.attr.used_components]

    unused_component_files = [
        label.name
        for label in repo_components_labels
        if label not in used_components_labels and label.name not in ctx.attr.ignored_repo_components
    ]

    if unused_component_files:
        script_content = """
        echo "Unused components check failed"
        echo "Unused components:"
        echo "{unused_component_files}"
        exit 1
        """.format(unused_component_files = "\n".join(unused_component_files))
    else:
        script_content = "echo 'Unused components check completed'"

    script = ctx.actions.declare_file(ctx.label.name + ".sh")
    ctx.actions.write(
        output = script,
        content = script_content,
    )

    return [
        DefaultInfo(
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
        "ignored_repo_components": attr.string_list(),
        "used_components": attr.label_list(
            allow_files = True,
        ),
    },
)
