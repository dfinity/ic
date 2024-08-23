load("//ic-os/components:guestos.bzl", "component_files")

# todo: add comment
def _check_unused_components_test_impl(ctx):
    args = []
    inputs = []
    outputs = []

    repo_components = [target.label.name for target in ctx.attr.repo_components]
    used_components = [target.label.name for target in ctx.attr.used_components]

    # ADDITIONAL_USED_COMPONENT_FILES are files used for testing and development
    ADDITIONAL_USED_COMPONENT_FILES = ["networking/dev-certs/canister_http_test_ca.key", "networking/dev-certs/root_cert_gen.sh"]
    used_components += ADDITIONAL_USED_COMPONENT_FILES

    unused_components = [file for file in repo_components if file not in used_components]
    print(unused_components)

    if unused_components:
        fail("Unused components found: {}".format(", ".join(unused_components)))

    # todo: fix return type
    # return [DefaultInfo(
    #     files = depset(outputs),
    #     runfiles = ctx.runfiles(outputs),
    # )]
    # todo: need to return true/false

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
