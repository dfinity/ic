#!/usr/bin/env python3
"""
Strip the quinn-proto wasm-bindgen leak from the cargo-bazel lockfiles.

Background:
    quinn-proto 0.11.14 declares dependencies for the
    `wasm32-unknown-unknown` target that activate ring's
    `wasm32_unknown_unknown_js` feature via cargo's feature unification. That
    feature pulls `getrandom/js` on `getrandom 0.2.10`, which in turn requires
    `wasm-bindgen` and `js-sys`. IC's canister wasm build rejects any output
    that links `wasm-bindgen`'s placeholder imports, so the universal canister
    fails to compile.

    IC never builds quinn-proto for wasm (it is used only by the replica P2P
    stack on Linux), so removing these transitive entries from the lockfiles
    is a no-op for the real build graph.

    `crate.annotation(patches = ...)` is not enough: cargo-bazel applies
    patches to crate sources *after* cargo metadata has resolved the workspace,
    so the leak is already baked into Cargo.Bazel.{json,toml}.lock. This
    script removes the leak from the lockfiles and adjusts the cargo-bazel
    digest so rules_rust accepts them.

Invocation:
    Called from `bin/bazel-pin.sh` after cargo-bazel has run. The script is
    idempotent: if the leak is already absent and the digest is valid it
    exits without touching anything.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
import tomllib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
JSON_LOCK = REPO_ROOT / "Cargo.Bazel.json.lock"
TOML_LOCK = REPO_ROOT / "Cargo.Bazel.toml.lock"

LEAKED_FEATURES = ("js", "js-sys", "wasm-bindgen")
LEAKED_DEP_IDS = ("js-sys 0.3.77", "wasm-bindgen 0.2.100")

CRATE_INDEX_QUERY_TARGET = "@crate_index//:all"
DIGEST_PLACEHOLDER = "0" * 64
EXPECTED_DIGEST_RE = re.compile(r'Expected Digest\("([0-9a-f]{64})"\)')


def strip_json_lock(data: dict) -> bool:
    """Remove the wasm-bindgen leak from `getrandom 0.2.10` in the JSON lock."""
    crate = data.get("crates", {}).get("getrandom 0.2.10")
    if crate is None:
        return False
    attrs = crate["common_attrs"]
    changed = False

    feat_selects = attrs.get("crate_features", {}).get("selects", {})
    bucket = feat_selects.get("wasm32-unknown-unknown")
    if bucket is not None:
        cleaned = [f for f in bucket if f not in LEAKED_FEATURES]
        if cleaned != bucket:
            if cleaned:
                feat_selects["wasm32-unknown-unknown"] = cleaned
            else:
                del feat_selects["wasm32-unknown-unknown"]
            changed = True

    dep_selects = attrs.get("deps", {}).get("selects", {})
    bucket = dep_selects.get("wasm32-unknown-unknown")
    if bucket is not None:
        cleaned = [d for d in bucket if d.get("id") not in LEAKED_DEP_IDS]
        if cleaned != bucket:
            if cleaned:
                dep_selects["wasm32-unknown-unknown"] = cleaned
            else:
                del dep_selects["wasm32-unknown-unknown"]
            changed = True

    return changed


def strip_toml_lock(text: str) -> tuple[str, bool]:
    """Remove `js-sys` and `wasm-bindgen` from `getrandom 0.2.10`'s deps."""
    data = tomllib.loads(text)
    target = next(
        (
            pkg
            for pkg in data.get("package", [])
            if pkg.get("name") == "getrandom" and pkg.get("version") == "0.2.10"
        ),
        None,
    )
    if target is None:
        return text, False
    deps = target.get("dependencies", [])
    cleaned = [d for d in deps if d not in ("js-sys", "wasm-bindgen")]
    if cleaned == deps:
        return text, False

    # cargo's Cargo.lock format uses 1-space-indented array items. We need to
    # preserve that exactly so subsequent cargo-bazel runs don't see a spurious
    # diff. There's no TOML writer in the Python stdlib that produces this
    # format, so we splice the rewritten `dependencies = [...]` array back into
    # the original text at the location tomllib located for us.
    block_header = '[[package]]\nname = "getrandom"\nversion = "0.2.10"\n'
    block_start = text.find(block_header)
    if block_start == -1:
        sys.exit("Could not locate getrandom 0.2.10 [[package]] block.")
    deps_open = text.find("dependencies = [", block_start)
    deps_close = text.find("]", deps_open)
    if deps_open == -1 or deps_close == -1:
        sys.exit("Could not locate getrandom 0.2.10 dependencies array.")
    new_block = "dependencies = [\n" + "".join(f' "{d}",\n' for d in cleaned) + "]"
    return text[:deps_open] + new_block + text[deps_close + 1 :], True


def write_json_lock(data: dict) -> None:
    JSON_LOCK.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n")


def query_expected_digest() -> str:
    """
    Run `bazel query` to force cargo-bazel digest verification and parse
    the expected digest from the failure output.
    """
    result = subprocess.run(
        ["bazel", "query", CRATE_INDEX_QUERY_TARGET],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    if result.returncode == 0:
        sys.exit(
            "bazel query unexpectedly succeeded with placeholder digest; "
            "cargo-bazel digest verification may have changed."
        )
    combined = result.stdout + "\n" + result.stderr
    match = EXPECTED_DIGEST_RE.search(combined)
    if not match:
        sys.exit("Could not find expected digest in bazel output. " "Full output:\n" + combined)
    return match.group(1)


def verify_lockfile() -> None:
    """Re-run `bazel query` to confirm the digest now matches."""
    result = subprocess.run(
        ["bazel", "query", CRATE_INDEX_QUERY_TARGET],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        sys.exit("bazel query still fails after digest update. Output:\n" + result.stdout + "\n" + result.stderr)


def main() -> int:
    json_data = json.loads(JSON_LOCK.read_text())
    toml_text = TOML_LOCK.read_text()

    json_changed = strip_json_lock(json_data)
    toml_text, toml_changed = strip_toml_lock(toml_text)

    if not (json_changed or toml_changed):
        return 0

    print("Stripping quinn-proto wasm-bindgen leak from cargo-bazel lockfiles...")

    if toml_changed:
        TOML_LOCK.write_text(toml_text)

    # Write the JSON lock with a placeholder digest, then ask cargo-bazel
    # what the digest should be. We can't replicate cargo-bazel's digest
    # algorithm in Python reliably (it includes serialized config / splicing
    # manifest content from the bazel cache), so we let cargo-bazel tell us.
    json_data["checksum"] = DIGEST_PLACEHOLDER
    write_json_lock(json_data)

    expected = query_expected_digest()
    json_data["checksum"] = expected
    write_json_lock(json_data)

    verify_lockfile()
    print(f"Lockfile cleaned and re-digested ({expected[:12]}...).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
