# Each binary must also be present in the GuestOS rootfs install list; the
# overlay reuses its install path.
OVERLAY_BINARIES = [
    "//publish/binaries:replica",
    "//publish/binaries:orchestrator",
    "//publish/binaries:ic-crypto-csp",
    "//publish/binaries:ic-btc-adapter",
    "//publish/binaries:ic-https-outcalls-adapter-https-only",
    "//publish/binaries:canister_sandbox",
    "//publish/binaries:compiler_sandbox",
    "//publish/binaries:sandbox_launcher",
]
