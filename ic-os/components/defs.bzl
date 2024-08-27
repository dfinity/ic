"""
Rules for check unused components checks.
"""

def _check_unused_components_test_impl(ctx):
    repo_components = [target.label.name for target in ctx.attr.repo_components]
    used_components = [target.label.name for target in ctx.attr.used_components]

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
        fail("Unused components found: {}".format(", ".join(unused_components)))

    script = ctx.actions.declare_file(ctx.label.name + ".sh")
    ctx.actions.write(
        output = script,
        content = "echo Unused components check completed",
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
