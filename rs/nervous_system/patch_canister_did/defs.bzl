"""
This module defines a macro to generate a test DID given a main DID and a patch, as well as some
helper targets to generate the test DID and patch when the patch cannot be applied.
"""

load("@rules_shell//shell:sh_binary.bzl", "sh_binary")

def canister_test_did(name, canister_did, canister_test_did_patch, output_path = None):
    """ Generates a test DID file from a main DID file and a patch file.

    Args:
        name: The name of the rule that represents the generated test candid file.
        canister_did: The main candid file.
        canister_test_did_patch: The patch file representing the differences between the main and test candid files.
        output_path: The filepath to use for the output, patched did (defaults to 'name').
    """

    if output_path == None:
        output_path = canister_did

    if not output_path.endswith("_test.did"):
        fail("output path must end with '_test.did'")

    canister_test_did = output_path
    canister_did_path = "$(location {})".format(canister_did)
    canister_test_did_patch_path = "$(location {})".format(canister_test_did_patch)
    target_base_name = native.package_name() + ":" + canister_test_did

    native.genrule(
        name = name,
        srcs = [canister_did, canister_test_did_patch],
        outs = [canister_test_did],
        testonly = True,
        cmd = r"""
            # The --follow-symlinks option is needed for Linux, as it doesn't follow symlinks by default, and for `bazel build` the input files are symlinks to the original files.
            if [ "$$(uname)" == "Linux" ]; then
                PATCH_OPTS="--follow-symlinks"
            else
                PATCH_OPTS=""
            fi
            if ! patch $$PATCH_OPTS {canister_did_path} -i {canister_test_did_patch_path} -o $@; then
                echo "Error generating {canister_test_did}, please run the //{target_base_name}_generate_test_did to edit the generated file"
                exit 1
            fi
            """
            .format(
            canister_did_path = canister_did_path,
            canister_test_did_patch_path = canister_test_did_patch_path,
            canister_test_did = canister_test_did,
            target_base_name = target_base_name,
        ),
    )
    sh_binary(
        name = name + "_generate_test_did",
        srcs = [
            "//rs/nervous_system/patch_canister_did:helper.sh",
        ],
        data = [
            canister_did,
            canister_test_did_patch,
        ],
        env = {
            "TARGET_BASE_NAME": target_base_name,
        },
        args = [
            canister_did_path,
            canister_test_did_patch_path,
            "--generate-test-did",
        ],
    )
    sh_binary(
        name = name + "_update_patch",
        srcs = [
            "//rs/nervous_system/patch_canister_did:helper.sh",
        ],
        data = [
            canister_did,
            canister_test_did_patch,
        ],
        env = {
            "TARGET_BASE_NAME": target_base_name,
        },
        args = [
            canister_did_path,
            canister_test_did_patch_path,
            "--update-patch",
        ],
    )
