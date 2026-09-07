"""Unit tests for //bazel:mainnet-artifact-refs.bzl and the download URL builders.

The values that mainnet-canister-revisions.json and mainnet-icos-revisions.json
contribute to a download URL are not reviewed by a human before they reach master, so
the repository rules validate them. These tests pin down what is accepted and
what is rejected, including the fields of poisoned copies of the real JSON records.

The rejecting path of the URL builders themselves cannot be asserted -- `fail()` is
uncatchable in Starlark -- which is exactly why the validators return an error message
instead of failing: the builders are the only path from JSON to URL and they call
these very functions.
"""

load("@bazel_skylib//lib:unittest.bzl", "asserts", "unittest")
load(
    "//bazel:mainnet-artifact-refs.bzl",
    "artifact_name_error",
    "commit_id_error",
    "github_repository_error",
    "icos_record_error",
    "sha256_error",
    "tag_error",
    "variant_error",
)
load("//bazel:mainnet-canisters.bzl", "canister_download_url")
load("//bazel:mainnet-icos-binaries.bzl", "binary_download_url")
load("//bazel:mainnet-icos-images.bzl", "icos_dev_image_download_url", "icos_image_download_url")

# Values taken from the committed JSON files: these must never start failing.
_REAL_COMMIT_IDS = [
    "3ae3649a2366aaca83404b692fc58e4c6e604a25",
    "512cf412f33d430b79f42330518166d14fc6884e",
    "59c42492cd6ee3ef5e60cd35d7b766e7bfd085da",
    "79c01052b5f7f49d3cf53d04d696cb2893294cd3",
    "d4ee25b0865e89d3eaac13a60f0016d5e3296b31",
]

_REAL_TAGS = [
    "0.7.0",
    "cycles-ledger-v1.0.6",
    "proposal-138924-agg",
    "proposal-143661",
    "release-2026-08-19",
    "release-2026-08-21",
    "release/2026-04-15",
    "release/2026-05-27",
]

_REAL_NAMES = [
    "canister_sandbox",
    "ic-icrc1-index-ng-u256.wasm.gz",
    "ic-replay",
    "internet_identity_production.wasm.gz",
    "ledger-canister_notify-method.wasm.gz",
    "sns_aggregator_dev.wasm.gz",
]

_REAL_SHA256S = [
    "5bf34cb029e437c4ccb990b1595876d4c869566d66b8b58059d0ee742891c219",
    "5e67e60caf8b71d79f6f2300ceb2461086d9d763cabc5656175307c13a4410e2",
]

# The escape described by F-051: with standard RFC 3986 dot-segment normalization by
# the HTTP client or server this leaves the hard-coded GitHub repository.
_EXPLOIT_TAG = "../../../evil-org/evil-repo/releases/download/x"

# A poisoned field can be of any JSON type, so every validator has to survive one.
_NON_STRINGS = [None, 0, 42, True, ["x"], {"x": 1}]

def _accepts(env, error_fn, values, what):
    for value in values:
        asserts.equals(env, None, error_fn(value), "%s should accept %r" % (what, value))

def _rejects(env, error_fn, values, what):
    for value in values:
        asserts.true(env, error_fn(value) != None, "%s should reject %r" % (what, value))

def _commit_id_test_impl(ctx):
    env = unittest.begin(ctx)

    _accepts(env, commit_id_error, _REAL_COMMIT_IDS, "commit_id_error")
    _rejects(env, commit_id_error, [
        "",
        "3ae3649a2366aaca83404b692fc58e4c6e604a2",  # 39 characters
        "3ae3649a2366aaca83404b692fc58e4c6e604a255",  # 41 characters
        "3AE3649A2366AACA83404B692FC58E4C6E604A25",  # uppercase
        ".." + "0" * 38,  # exactly 40 characters, but a traversal
        "../../../../evil/guest-os/update-img",
        "..",
        "release-2026-08-19",  # a tag is not a commit id
        _REAL_SHA256S[0],  # a sha256 is not a commit id
    ] + _NON_STRINGS, "commit_id_error")

    return unittest.end(env)

commit_id_test = unittest.make(_commit_id_test_impl)

def _tag_test_impl(ctx):
    env = unittest.begin(ctx)

    _accepts(env, tag_error, _REAL_TAGS, "tag_error")
    _rejects(env, tag_error, [
        _EXPLOIT_TAG,
        "..",
        "release/../../evil",
        "release/..",
        "../release",
        "/release-2026-08-19",
        "release-2026-08-19/",
        "release//2026-08-19",
        ".release",
        "-release",
        "release 2026-08-19",
        "release\n2026-08-19",
        "release\t2026",
        "%2e%2e/x",
        "https://evil.example/x",
        "release?ref=evil",
        "release#evil",
        "release@evil.example",
        "",
        "a" * 129,
    ] + _NON_STRINGS, "tag_error")

    return unittest.end(env)

tag_test = unittest.make(_tag_test_impl)

def _sha256_test_impl(ctx):
    env = unittest.begin(ctx)

    _accepts(env, sha256_error, _REAL_SHA256S, "sha256_error")
    _rejects(env, sha256_error, [
        # Not merely malformed: repository_ctx.download reads the empty string as
        # "do not verify this download".
        "",
        "0" * 63,
        "0" * 65,
        _REAL_SHA256S[0].upper(),
        ".." + "0" * 62,  # exactly 64 characters, but a traversal
        _REAL_COMMIT_IDS[0],  # a commit id is not a sha256
    ] + _NON_STRINGS, "sha256_error")

    return unittest.end(env)

sha256_test = unittest.make(_sha256_test_impl)

def _artifact_name_test_impl(ctx):
    env = unittest.begin(ctx)

    _accepts(env, artifact_name_error, _REAL_NAMES, "artifact_name_error")
    _rejects(env, artifact_name_error, [
        "",
        "..",
        "../../x",
        "a/b",
        "canister..sandbox",
        ".hidden",
        "-dash",
        # An ICOS binary name is interpolated verbatim into a generated BUILD file.
        'ic-replay"]) load("@evil//:evil.bzl", "evil")',
        "ic-replay\n)",
        "ic replay",
        "a" * 129,
    ] + _NON_STRINGS, "artifact_name_error")

    return unittest.end(env)

artifact_name_test = unittest.make(_artifact_name_test_impl)

def _github_repository_test_impl(ctx):
    env = unittest.begin(ctx)

    _accepts(env, github_repository_error, [
        "dfinity/ic",
        "dfinity/internet-identity",
        "dfinity/cycles-ledger",
        "dfinity/subnet-rental-canister",
    ], "github_repository_error")
    _rejects(env, github_repository_error, [
        "",
        "dfinity",
        "dfinity/ic/extra",
        "dfinity/..",
        "dfinity/../evil",
        "../dfinity/ic",
        "/ic",
        "dfinity/",
        "dfinity/i c",
        "evil.example/dfinity/ic",
    ] + _NON_STRINGS, "github_repository_error")

    return unittest.end(env)

github_repository_test = unittest.make(_github_repository_test_impl)

def _variant_test_impl(ctx):
    env = unittest.begin(ctx)

    _accepts(env, variant_error, ["guest-os", "host-os", "setup-os"], "variant_error")
    _rejects(env, variant_error, [
        "",
        "guestos",
        "GUEST-OS",
        "../guest-os",
        "guest-os/..",
    ] + _NON_STRINGS, "variant_error")

    return unittest.end(env)

variant_test = unittest.make(_variant_test_impl)

# A copy of real mainnet-canister-revisions.json entries with one poisoned field
# each: a tag that escapes the pinned GitHub repository, a rev that escapes the
# pinned CDN prefix, and a sha256 that disables verification.
_POISONED_CANISTERS_JSON = """{
  "internet_identity_backend": {
    "sha256": "5bf34cb029e437c4ccb990b1595876d4c869566d66b8b58059d0ee742891c219",
    "tag": "../../../evil-org/evil-repo/releases/download/x"
  },
  "registry": {
    "rev": "../../../../evil/release/canisters",
    "sha256": "5bf34cb029e437c4ccb990b1595876d4c869566d66b8b58059d0ee742891c219"
  },
  "governance": {
    "rev": "3ae3649a2366aaca83404b692fc58e4c6e604a25",
    "sha256": ""
  }
}"""

_CLEAN_CANISTERS_JSON = """{
  "internet_identity_backend": {
    "sha256": "5bf34cb029e437c4ccb990b1595876d4c869566d66b8b58059d0ee742891c219",
    "tag": "release-2026-08-21"
  },
  "registry": {
    "rev": "3ae3649a2366aaca83404b692fc58e4c6e604a25",
    "sha256": "5e67e60caf8b71d79f6f2300ceb2461086d9d763cabc5656175307c13a4410e2"
  }
}"""

def _poisoned_canisters_json_test_impl(ctx):
    env = unittest.begin(ctx)

    poisoned = json.decode(_POISONED_CANISTERS_JSON)
    asserts.true(
        env,
        tag_error(poisoned["internet_identity_backend"]["tag"]) != None,
        "the crafted tag must be rejected",
    )
    asserts.true(
        env,
        commit_id_error(poisoned["registry"]["rev"]) != None,
        "the crafted rev must be rejected",
    )
    asserts.true(
        env,
        sha256_error(poisoned["governance"]["sha256"]) != None,
        "the empty sha256 must be rejected",
    )

    clean = json.decode(_CLEAN_CANISTERS_JSON)
    asserts.equals(env, None, tag_error(clean["internet_identity_backend"]["tag"]))
    asserts.equals(env, None, sha256_error(clean["internet_identity_backend"]["sha256"]))
    asserts.equals(env, None, commit_id_error(clean["registry"]["rev"]))
    asserts.equals(env, None, sha256_error(clean["registry"]["sha256"]))

    return unittest.end(env)

poisoned_canisters_json_test = unittest.make(_poisoned_canisters_json_test_impl)

# Records shaped like mainnet-icos-revisions.json: "clean" is a (trimmed) copy of a
# real one, every other record poisons exactly one field.
_ICOS_JSON = """{
  "clean": {
    "version": "59c42492cd6ee3ef5e60cd35d7b766e7bfd085da",
    "update_img_hash": "5e67e60caf8b71d79f6f2300ceb2461086d9d763cabc5656175307c13a4410e2",
    "update_img_hash_dev": "3924d5e9c86822b367cbfdbaab48c667f2a32bee3ab65e5772d54c32e6a829ed",
    "setupos_disk_img_hash": "5c488a88730dd52c2cf3186d10517b8e86cfbc445f47e850a07479632d466390",
    "setupos_disk_img_hash_dev": "18330bb4c6fcf94977fb7e8576e0d781864777406a8b33b47153f15fbef4e454",
    "binaries": {
      "canister_sandbox": "2a2e8891dc8837b02b1bf00972b71e5e8393fc5334ac611638071bc151b37cfc",
      "ic-replay": "6fc9e9b24e74690964357ac1681d4dcfac1c7907af6fbdd4d24a45e986d56ee5"
    }
  },
  "no_version": {
    "update_img_hash": "5e67e60caf8b71d79f6f2300ceb2461086d9d763cabc5656175307c13a4410e2"
  },
  "poisoned_version": {
    "version": "../../../../evil/guest-os/update-img",
    "update_img_hash": "5e67e60caf8b71d79f6f2300ceb2461086d9d763cabc5656175307c13a4410e2"
  },
  "downgraded_version": {
    "version": 79,
    "update_img_hash": "5e67e60caf8b71d79f6f2300ceb2461086d9d763cabc5656175307c13a4410e2"
  },
  "poisoned_update_img_hash": {
    "version": "59c42492cd6ee3ef5e60cd35d7b766e7bfd085da",
    "update_img_hash": ""
  },
  "poisoned_setupos_hash": {
    "version": "59c42492cd6ee3ef5e60cd35d7b766e7bfd085da",
    "setupos_disk_img_hash_dev": "not-a-hash"
  },
  "poisoned_binary_name": {
    "version": "59c42492cd6ee3ef5e60cd35d7b766e7bfd085da",
    "binaries": {
      "../../../../evil/binaries/x86_64-linux/ic-replay": "6fc9e9b24e74690964357ac1681d4dcfac1c7907af6fbdd4d24a45e986d56ee5"
    }
  },
  "poisoned_binary_hash": {
    "version": "59c42492cd6ee3ef5e60cd35d7b766e7bfd085da",
    "binaries": {
      "ic-replay": ""
    }
  },
  "poisoned_binaries": {
    "version": "59c42492cd6ee3ef5e60cd35d7b766e7bfd085da",
    "binaries": ["ic-replay"]
  }
}"""

def _icos_record_test_impl(ctx):
    env = unittest.begin(ctx)

    records = json.decode(_ICOS_JSON)

    asserts.equals(env, None, icos_record_error(records["clean"]), "the real record must be accepted")

    # A record with no "binaries" is left to the rule that requires them, which
    # reports a more helpful error (how to regenerate the JSON).
    asserts.equals(
        env,
        None,
        icos_record_error({"version": "59c42492cd6ee3ef5e60cd35d7b766e7bfd085da"}),
        "a record without optional fields must be accepted",
    )

    for key in sorted(records.keys()):
        if key != "clean":
            asserts.true(env, icos_record_error(records[key]) != None, "%s must be rejected" % key)

    _rejects(env, icos_record_error, _NON_STRINGS, "icos_record_error")

    return unittest.end(env)

icos_record_test = unittest.make(_icos_record_test_impl)

def _download_url_test_impl(ctx):
    env = unittest.begin(ctx)

    # Adding the validation must not have changed any URL that is fetched today.
    asserts.equals(
        env,
        "https://download.dfinity.systems/ic/3ae3649a2366aaca83404b692fc58e4c6e604a25/canisters/ledger-archive-node-canister.wasm.gz",
        canister_download_url(
            "3ae3649a2366aaca83404b692fc58e4c6e604a25",
            None,
            None,
            "ledger-archive-node-canister.wasm.gz",
            "test",
        ),
    )
    asserts.equals(
        env,
        "https://github.com/dfinity/internet-identity/releases/download/release-2026-08-21/internet_identity_production.wasm.gz",
        canister_download_url(
            None,
            "dfinity/internet-identity",
            "release-2026-08-21",
            "internet_identity_production.wasm.gz",
            "test",
        ),
    )
    asserts.equals(
        env,
        "https://github.com/dfinity/bitcoin-canister/releases/download/release/2026-04-15/ic-btc-canister.wasm.gz",
        canister_download_url(
            None,
            "dfinity/bitcoin-canister",
            "release/2026-04-15",
            "ic-btc-canister.wasm.gz",
            "test",
        ),
    )
    asserts.equals(
        env,
        "https://download.dfinity.systems/ic/79c01052b5f7f49d3cf53d04d696cb2893294cd3/binaries/x86_64-linux/ic-replay.gz",
        binary_download_url("79c01052b5f7f49d3cf53d04d696cb2893294cd3", "ic-replay"),
    )
    asserts.equals(
        env,
        "https://download.dfinity.systems/ic/79c01052b5f7f49d3cf53d04d696cb2893294cd3/guest-os/update-img/update-img.tar.zst",
        icos_image_download_url("79c01052b5f7f49d3cf53d04d696cb2893294cd3", "guest-os", True),
    )
    asserts.equals(
        env,
        "https://download.dfinity.systems/ic/79c01052b5f7f49d3cf53d04d696cb2893294cd3/setup-os/disk-img/disk-img.tar.zst",
        icos_image_download_url("79c01052b5f7f49d3cf53d04d696cb2893294cd3", "setup-os", False),
    )
    asserts.equals(
        env,
        "https://download.dfinity.systems/ic/79c01052b5f7f49d3cf53d04d696cb2893294cd3/setup-os/disk-img-dev/disk-img.tar.zst",
        icos_dev_image_download_url("79c01052b5f7f49d3cf53d04d696cb2893294cd3", "setup-os", False),
    )
    asserts.equals(
        env,
        "https://download.dfinity.systems/ic/79c01052b5f7f49d3cf53d04d696cb2893294cd3/host-os/update-img-dev/update-img.tar.zst",
        icos_dev_image_download_url("79c01052b5f7f49d3cf53d04d696cb2893294cd3", "host-os", True),
    )

    return unittest.end(env)

download_url_test = unittest.make(_download_url_test_impl)

def mainnet_artifact_refs_test_suite(name):
    """Registers every test in this file under a test_suite called `name`.

    Args:
      name: the name of the generated test_suite.
    """
    unittest.suite(
        name,
        artifact_name_test,
        commit_id_test,
        download_url_test,
        github_repository_test,
        icos_record_test,
        poisoned_canisters_json_test,
        sha256_test,
        tag_test,
        variant_test,
    )
