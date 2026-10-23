# Proposal to upgrade the ckDOGE minter canister

Git hash: `78c8977a7a6c496435edfcce47ceecded9779b21`

New compressed Wasm hash: `9276c48eaffa7e8c9deef3cd4a43b67d7f548aa7611fe91a1ce67112bb8547fa`

Upgrade args hash: `2fe5c6f806dbe3b1d986577ea120c775b8b1fc5dfaafa1d6db889ecff6bc8a32`

Target canister: `eqltq-xqaaa-aaaar-qb3vq-cai`

Previous ckDOGE minter proposal: https://dashboard.internetcomputer.org/proposal/140292

---

## Security patch update

In accordance with the Security Patch Policy and Procedure that was adopted in proposal [48792](https://dashboard.internetcomputer.org/proposal/48792), the source code that was used to build this canister release will be exposed at the latest 10 days after the fix is rolled out.

The community will be able to retroactively verify the wasm binaries that were rolled out.

## Argument verification

```
git fetch
git checkout 78c8977a7a6c496435edfcce47ceecded9779b21
didc encode -d rs/dogecoin/ckdoge/minter/ckdoge_minter.did -t '(MinterArg)' '(variant { Upgrade = null })' | xxd -r -p | sha256sum
```
