# ckDOGE Mainnet Deployment

* Subnet: [`pzp6e-ekpqk-3c5x7-2h6so-njoeq-mt45d-h3h6c-q3mxf-vpeq5-fk5o7-yae`](https://dashboard.internetcomputer.org/network/subnets/pzp6e-ekpqk-3c5x7-2h6so-njoeq-mt45d-h3h6c-q3mxf-vpeq5-fk5o7-yae)
* minter: [eqltq-xqaaa-aaaar-qb3vq-cai](https://dashboard.internetcomputer.org/canister/eqltq-xqaaa-aaaar-qb3vq-cai)
* ledger: [efmc5-wyaaa-aaaar-qb3wa-cai](https://dashboard.internetcomputer.org/canister/efmc5-wyaaa-aaaar-qb3wa-cai)
* index: [ecnej-3aaaa-aaaar-qb3wq-cai](https://dashboard.internetcomputer.org/canister/ecnej-3aaaa-aaaar-qb3wq-cai)

## Create canister IDs

### Minter

```bash
dfx canister --ic create minter --subnet pzp6e-ekpqk-3c5x7-2h6so-njoeq-mt45d-h3h6c-q3mxf-vpeq5-fk5o7-yae
```

### Ledger

```bash
dfx canister --ic create ledger --subnet pzp6e-ekpqk-3c5x7-2h6so-njoeq-mt45d-h3h6c-q3mxf-vpeq5-fk5o7-yae
```

### Index

```bash
dfx canister --ic create index --subnet pzp6e-ekpqk-3c5x7-2h6so-njoeq-mt45d-h3h6c-q3mxf-vpeq5-fk5o7-yae
```

## Set controller to NNS root

### Minter

```bash
dfx canister update-settings minter --set-controller r7inp-6aaaa-aaaaa-aaabq-cai --ic
```

### Ledger

```bash
dfx canister update-settings ledger --set-controller r7inp-6aaaa-aaaaa-aaabq-cai --ic
```

### Index

```bash
dfx canister update-settings index --set-controller r7inp-6aaaa-aaaaa-aaabq-cai --ic
```

Control the canister controllers with
```bash
for canister in minter ledger index; do dfx canister --ic info $canister; done
```

Which should return
```terminaloutput
Controllers: r7inp-6aaaa-aaaaa-aaabq-cai
Module hash: None
Controllers: r7inp-6aaaa-aaaaa-aaabq-cai
Module hash: None
Controllers: r7inp-6aaaa-aaaaa-aaabq-cai
Module hash: None
```
