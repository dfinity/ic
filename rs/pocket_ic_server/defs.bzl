"""Wrap various rules with added pocket-ic support."""

load("@rules_rust//rust:defs.bzl", "rust_test", "rust_test_suite")
load("//bazel:defs.bzl", "rust_ic_test", "rust_ic_test_suite", "rust_ic_test_suite_with_extra_srcs", "rust_test_suite_with_extra_srcs")

def _wrapper(**kwargs):
    env = kwargs.pop("env", {})
    env.update({
        "POCKET_IC_BIN": "$(rootpath //rs/pocket_ic_server:pocket-ic-server)",
        # TODO: Update TMPDIR here
        # "TMPDIR": ""
    })
    kwargs.update({"env": env})

    data = kwargs.pop("data", [])
    data.append("//rs/pocket_ic_server:pocket-ic-server")
    kwargs.update({"data": data})

    return kwargs

def pocket_ic_rust_test(**kwargs):
    """
    Wrap rust_test with the proper data and env to use pocket-ic, added.

    Args:
      **kwargs: Pass through args to the inner rule.
    """

    rust_test(**_wrapper(**kwargs))

def pocket_ic_rust_test_suite(**kwargs):
    """
    Wrap rust_test_suite with the proper data and env to use pocket-ic, added.

    Args:
      **kwargs: Pass through args to the inner rule.
    """

    rust_test_suite(**_wrapper(**kwargs))

# -----------------------------------------------------------------------------

def pocket_ic_rust_ic_test_suite_with_extra_srcs(**kwargs):
    """
    Wrap rust_ic_test_suite_with_extra_srcs with the proper data and env to use pocket-ic, added.

    Args:
      **kwargs: Pass through args to the inner rule.
    """

    rust_ic_test_suite_with_extra_srcs(**_wrapper(**kwargs))

def pocket_ic_rust_ic_test_suite(**kwargs):
    """
    Wrap rust_ic_test_suite with the proper data and env to use pocket-ic, added.

    Args:
      **kwargs: Pass through args to the inner rule.
    """

    rust_ic_test_suite(**_wrapper(**kwargs))

def pocket_ic_rust_ic_test(**kwargs):
    """
    Wrap rust_ic_test with the proper data and env to use pocket-ic, added.

    Args:
      **kwargs: Pass through args to the inner rule.
    """

    rust_ic_test(**_wrapper(**kwargs))

def pocket_ic_rust_test_suite_with_extra_srcs(**kwargs):
    """
    Wrap rust_test_suite_with_extra_srcs with the proper data and env to use pocket-ic, added.

    Args:
      **kwargs: Pass through args to the inner rule.
    """

    rust_test_suite_with_extra_srcs(**_wrapper(**kwargs))
