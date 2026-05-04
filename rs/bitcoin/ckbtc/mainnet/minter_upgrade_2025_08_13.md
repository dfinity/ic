# Proposal to upgrade the ckBTC minter canister

Repository: `https://github.com/dfinity/ic.git`

Git hash: `1db8f933fdadc81a90e7db2389b081e21263a9b6`

New compressed Wasm hash: `b9688aed7377dc6ec4ec33cb303d73355ee47f2a1faea2bfc111abe2c7fa3186`

Upgrade args hash: `0fee102bd16b053022b69f2c65fd5e2f41d150ce9c214ac8731cfaf496ebda4e`

Target canister: `mqygn-kiaaa-aaaar-qaadq-cai`

Previous ckBTC minter proposal: https://dashboard.internetcomputer.org/proposal/137163

---

## Motivation

Upgrade the ckBTC minter to ensure that a transaction signed by the minter does not use too many inputs.
Otherwise, the resulting transaction may be *non-standard* as the resulting transaction size may be above 100k vbytes,
which implies that the transaction will not be relayed by Bitcoin nodes and this transaction will be effectively stuck.
This is currently the case for transaction `87ebf46e400a39e5ec22b28515056a3ce55187dba9669de8300160ac08f64c30`.

This is a stop-gap solution until a proper solution is implemented.

## Release Notes

```
git log --format='%C(auto) %h %s' 47c5931cdafd82167feee85faf1e1dffa30fc3d8..1db8f933fdadc81a90e7db2389b081e21263a9b6 -- rs/bitcoin/ckbtc/minter
1db8f933fd fix(ckbtc): prevent signing transaction with too many inputs (#6260)
55ec0283bb build: update ic0 to v1.0.0. (#6216)
 ```

## Upgrade args

```
git fetch
git checkout 1db8f933fdadc81a90e7db2389b081e21263a9b6
didc encode '()' | xxd -r -p | sha256sum
```

## Wasm Verification

Verify that the hash of the gzipped WASM matches the proposed hash.

```
git fetch
git checkout 1db8f933fdadc81a90e7db2389b081e21263a9b6
"./ci/container/build-ic.sh" "--canisters"
sha256sum ./artifacts/canisters/ic-ckbtc-minter.wasm.gz
```
