load("@rules_rust//rust:defs.bzl", "rust_binary")

def strip_extension(basename):
    return '.'.join(basename.split('.')[:-1])

def with_fixture_extension(basename):
    return basename + ".fixture"

def release_fixture_name(name):
    return "release_fixture_" + name


def rust_fixture_generator(name, **kwargs):
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

