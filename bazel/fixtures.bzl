load("@rules_rust//rust:defs.bzl", "rust_binary")

def strip_extension(basename):
    return '.'.join(basename.split('.')[:-1])

def with_fixture_extension(basename):
    return basename + ".fixture"

def release_fixture_name(name):
    return "release_fixture_" + name


def rust_fixture_generator(name, **kwargs):
    """
    Define a Rust binary target that generates a fixture file

    This is a thin wrapper around rust_binary that also generates a fixture file.
    It's meant to be used as a an element of the `inputs` dependency the `upload_fixtures` rule.
    Whan added to upload_fixtures, the CI will, on release, generate an `http_file` target 
    that can be used to download the fixture file (and later used in tests).
    To compute the name of the http_target, given a rust_fixture_generator called `name`,
    use `release_fixture_name(name)`.
    """
    binary_name = name + "_binary"
    rust_binary(
        name = binary_name,
        **kwargs,
    )

    native.genrule(
        name = name,
        tools = [
            ":" + binary_name,
        ],
        outs = [name + ".fixture"],
        cmd = "$(location :{binary_name}) > $@".format(binary_name = binary_name),
    )

