# ckETH

This directory contains the deployed arguments and canister IDs related to ckSepliackSepoliaETH.

## Deploying the Ledger

### Locally

```shell
dfx canister create ledger
dfx deploy ledger --argument '(variant { Init = record { minting_account = record { owner = principal "MINTER_ID" }; feature_flags  = opt record { icrc2 = true }; decimals = opt 18; max_memo_length = opt 80; transfer_fee = 10_000_000_000; token_symbol = "ckSepoliaETH"; token_name = "Chain key Sepolia Ethereum"; metadata = vec {}; initial_balances = vec {}; archive_options = record { num_blocks_to_archive = 1000; trigger_threshold = 2000; max_message_size_bytes = null; cycles_for_archive_creation = opt 1_000_000_000_000; node_max_memory_size_bytes = opt 3_221_225_472; controller_id = principal "mf7xa-laaaa-aaaar-qaaaa-cai"; } }})'
```

### Mainnet

```
dfx deploy --network ic ledger --argument '(variant { Init = record { minting_account = record { owner = principal "jzenf-aiaaa-aaaar-qaa7q-cai" }; feature_flags  = opt record { icrc2 = true }; decimals = opt 18; max_memo_length = opt 80; transfer_fee = 10_000_000_000; token_symbol = "ckSepoliaETH"; token_name = "Chain key Sepolia Ethereum"; metadata = vec { record { "icrc1:logo"; variant { Text = "data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMTQ2IiBoZWlnaHQ9IjE0NiIgdmlld0JveD0iMCAwIDE0NiAxNDYiIGZpbGw9Im5vbmUiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyI+CjxnIGNsaXAtcGF0aD0idXJsKCNjbGlwMF84NjRfNjQpIj4KPHJlY3Qgd2lkdGg9IjE0NiIgaGVpZ2h0PSIxNDYiIHJ4PSI3MyIgZmlsbD0idXJsKCNwYWludDBfbGluZWFyXzg2NF82NCkiLz4KPHJlY3Qgd2lkdGg9IjE0NiIgaGVpZ2h0PSIxNDYiIHJ4PSI3MyIgZmlsbD0id2hpdGUiLz4KPHJlY3QgeD0iMC41IiB5PSIwLjUiIHdpZHRoPSIxNDUiIGhlaWdodD0iMTQ1IiByeD0iNzIuNSIgc3Ryb2tlPSJibGFjayIgc3Ryb2tlLW9wYWNpdHk9IjAuMSIvPgo8cGF0aCBmaWxsLXJ1bGU9ImV2ZW5vZGQiIGNsaXAtcnVsZT0iZXZlbm9kZCIgZD0iTTE2LjM4MzcgNzcuMjA1MkMxOC40MzQgMTA1LjIwNiA0MC43OTQgMTI3LjU2NiA2OC43OTQ5IDEyOS42MTZWMTM1Ljk0QzM3LjMwODcgMTMzLjg2NyAxMi4xMzMgMTA4LjY5MSAxMC4wNjA1IDc3LjIwNTJIMTYuMzgzN1oiIGZpbGw9InVybCgjcGFpbnQxX2xpbmVhcl84NjRfNjQpIi8+CjxwYXRoIGZpbGwtcnVsZT0iZXZlbm9kZCIgY2xpcC1ydWxlPSJldmVub2RkIiBkPSJNNjguNzY0NiAxNi4zNTM0QzQwLjc2MzggMTguNDAzNiAxOC40MDM3IDQwLjc2MzcgMTYuMzUzNSA2OC43NjQ2TDEwLjAzMDMgNjguNzY0NkMxMi4xMDI3IDM3LjI3ODQgMzcuMjc4NSAxMi4xMDI2IDY4Ljc2NDYgMTAuMDMwMkw2OC43NjQ2IDE2LjM1MzRaIiBmaWxsPSIjMjlBQkUyIi8+CjxwYXRoIGZpbGwtcnVsZT0iZXZlbm9kZCIgY2xpcC1ydWxlPSJldmVub2RkIiBkPSJNMTI5LjYxNiA2OC43MzQzQzEyNy41NjYgNDAuNzMzNCAxMDUuMjA2IDE4LjM3MzMgNzcuMjA1MSAxNi4zMjMxTDc3LjIwNTEgOS45OTk5OEMxMDguNjkxIDEyLjA3MjQgMTMzLjg2NyAzNy4yNDgxIDEzNS45MzkgNjguNzM0M0wxMjkuNjE2IDY4LjczNDNaIiBmaWxsPSJ1cmwoI3BhaW50Ml9saW5lYXJfODY0XzY0KSIvPgo8cGF0aCBmaWxsLXJ1bGU9ImV2ZW5vZGQiIGNsaXAtcnVsZT0iZXZlbm9kZCIgZD0iTTc3LjIzNTQgMTI5LjU4NkMxMDUuMjM2IDEyNy41MzYgMTI3LjU5NiAxMDUuMTc2IDEyOS42NDcgNzcuMTc0OUwxMzUuOTcgNzcuMTc0OUMxMzMuODk3IDEwOC42NjEgMTA4LjcyMiAxMzMuODM3IDc3LjIzNTQgMTM1LjkwOUw3Ny4yMzU0IDEyOS41ODZaIiBmaWxsPSIjMjlBQkUyIi8+CjxwYXRoIGQ9Ik03Mi40ODQxIDMxTDcxLjkyNzIgMzIuODkxNVY4Ny43NzNMNzIuNDg0MSA4OC4zMjg1TDk3Ljk1OSA3My4yNzAxTDcyLjQ4NDEgMzFaIiBmaWxsPSIjMzQzNDM0Ii8+CjxwYXRoIGQ9Ik03Mi40Nzg0IDMxTDQ3LjAwMjkgNzMuMjcwMUw3Mi40Nzg0IDg4LjMyODVWNjEuNjkwNlYzMVoiIGZpbGw9IiM4QzhDOEMiLz4KPHBhdGggZD0iTTcyLjQ4NDIgOTMuMTUxNUw3Mi4xNzA0IDkzLjUzNDJWMTEzLjA4NEw3Mi40ODQyIDExNEw5Ny45NzQ3IDc4LjEwMDlMNzIuNDg0MiA5My4xNTE1WiIgZmlsbD0iIzNDM0MzQiIvPgo8cGF0aCBkPSJNNzIuNDc4NCAxMTRWOTMuMTUxNUw0Ny4wMDI5IDc4LjEwMDlMNzIuNDc4NCAxMTRaIiBmaWxsPSIjOEM4QzhDIi8+CjxwYXRoIGQ9Ik03Mi40OTQ2IDg4LjMyNzZMOTcuOTY5NSA3My4yNjkyTDcyLjQ5NDYgNjEuNjg5NlY4OC4zMjc2WiIgZmlsbD0iIzE0MTQxNCIvPgo8cGF0aCBkPSJNNDcuMDAyOSA3My4yNjkyTDcyLjQ3ODQgODguMzI3NlY2MS42ODk2TDQ3LjAwMjkgNzMuMjY5MloiIGZpbGw9IiMzOTM5MzkiLz4KPGcgZmlsdGVyPSJ1cmwoI2ZpbHRlcjBfYl84NjRfNjQpIj4KPHBhdGggZD0iTTIxIDExMkMyMSAxMDIuMjA5IDI4LjkzNjggOTQuMjcyNyAzOC43MjczIDk0LjI3MjdIMTA3LjI3M0MxMTcuMDYzIDk0LjI3MjcgMTI1IDEwMi4yMDkgMTI1IDExMlYxMTJDMTI1IDEyMS43OSAxMTcuMDYzIDEyOS43MjcgMTA3LjI3MyAxMjkuNzI3SDM4LjcyNzNDMjguOTM2OCAxMjkuNzI3IDIxIDEyMS43OSAyMSAxMTJWMTEyWiIgZmlsbD0id2hpdGUiLz4KPHBhdGggZD0iTTM4LjcyNzMgOTQuNzcyN0gxMDcuMjczQzExNi43ODcgOTQuNzcyNyAxMjQuNSAxMDIuNDg2IDEyNC41IDExMkMxMjQuNSAxMjEuNTE0IDExNi43ODcgMTI5LjIyNyAxMDcuMjczIDEyOS4yMjdIMzguNzI3M0MyOS4yMTI5IDEyOS4yMjcgMjEuNSAxMjEuNTE0IDIxLjUgMTEyQzIxLjUgMTAyLjQ4NiAyOS4yMTI5IDk0Ljc3MjcgMzguNzI3MyA5NC43NzI3WiIgc3Ryb2tlPSJibGFjayIgc3Ryb2tlLW9wYWNpdHk9IjAuMDUiLz4KPC9nPgo8cGF0aCBkPSJNNTMuOTcxNiAxMDYuNjgyQzUyLjU4NDIgMTA2LjY4MiA1MS4wNzE4IDEwNy4zOTkgNDkuNDczMyAxMDguODExQzQ4LjcxNDkgMTA5LjQ4IDQ4LjA2IDExMC4xOTcgNDcuNTY4OCAxMTAuNzdDNDcuNTY4OCAxMTAuNzcgNDcuNTY4OCAxMTAuNzcgNDcuNTczMiAxMTAuNzc1VjExMC43N0M0Ny41NzMyIDExMC43NyA0OC4zNDg3IDExMS42MjIgNDkuMjA2MSAxMTIuNTM0QzQ5LjY2NzIgMTExLjk4MyA1MC4zMzA4IDExMS4yMzEgNTEuMDkzMyAxMTAuNTUzQzUyLjUxNTMgMTA5LjI5NyA1My40NDE2IDEwOS4wMzIgNTMuOTcxNiAxMDkuMDMyQzU1Ljk2NjcgMTA5LjAzMiA1Ny41ODY3IDExMC42MjcgNTcuNTg2NyAxMTIuNTg3QzU3LjU4NjcgMTE0LjUzMyA1NS45NjIzIDExNi4xMjggNTMuOTcxNiAxMTYuMTQxQzUzLjg4MTEgMTE2LjE0MSA1My43NjQ4IDExNi4xMjggNTMuNjE4MyAxMTYuMDk3QzU0LjIgMTE2LjM0OSA1NC44MjQ4IDExNi41MzIgNTUuNDE5NCAxMTYuNTMyQzU5LjA3MzIgMTE2LjUzMiA1OS43ODg1IDExNC4xMjkgNTkuODM1OSAxMTMuOTU1QzU5Ljk0MzYgMTEzLjUxNiA1OS45OTk2IDExMy4wNTYgNTkuOTk5NiAxMTIuNTgyQzU5Ljk5OTYgMTA5LjMzMiA1Ny4yOTM3IDEwNi42ODIgNTMuOTcxNiAxMDYuNjgyWiIgZmlsbD0idXJsKCNwYWludDNfbGluZWFyXzg2NF82NCkiLz4KPHBhdGggZD0iTTQxLjIwOTYgMTE4LjVDNDIuNTk3IDExOC41IDQ0LjEwOTQgMTE3Ljc4MyA0NS43MDggMTE2LjM3MUM0Ni40NjYzIDExNS43MDIgNDcuMTIxMyAxMTQuOTg1IDQ3LjYxMjQgMTE0LjQxMUM0Ny42MTI0IDExNC40MTEgNDcuNjEyNCAxMTQuNDExIDQ3LjYwODEgMTE0LjQwN1YxMTQuNDExQzQ3LjYwODEgMTE0LjQxMSA0Ni44MzI2IDExMy41NiA0NS45NzUxIDExMi42NDdDNDUuNTE0MSAxMTMuMTk5IDQ0Ljg1MDUgMTEzLjk1MSA0NC4wODc5IDExNC42MjlDNDIuNjY2IDExNS44ODQgNDEuNzM5NiAxMTYuMTQ5IDQxLjIwOTYgMTE2LjE0OUMzOS4yMTQ2IDExNi4xNDUgMzcuNTk0NiAxMTQuNTUxIDM3LjU5NDYgMTEyLjU5MUMzNy41OTQ2IDExMC42NDQgMzkuMjE5IDEwOS4wNSA0MS4yMDk2IDEwOS4wMzdDNDEuMzAwMSAxMDkuMDM3IDQxLjQxNjQgMTA5LjA1IDQxLjU2MjkgMTA5LjA4QzQwLjk4MTMgMTA4LjgyOCA0MC4zNTY1IDEwOC42NDYgMzkuNzYxOSAxMDguNjQ2QzM2LjEwOCAxMDguNjQ2IDM1LjM5NzEgMTExLjA0OSAzNS4zNDU0IDExMS4yMThDMzUuMjM3NyAxMTEuNjYxIDM1LjE4MTYgMTEyLjExNyAzNS4xODE2IDExMi41OTFDMzUuMTgxNiAxMTUuODUgMzcuODg3NSAxMTguNSA0MS4yMDk2IDExOC41WiIgZmlsbD0idXJsKCNwYWludDRfbGluZWFyXzg2NF82NCkiLz4KPHBhdGggZD0iTTU1LjQxMTIgMTE2LjQ4QzUzLjU0MTEgMTE2LjQzMiA1MS41OTc5IDExNC45NDYgNTEuMjAxNSAxMTQuNTc2QzUwLjE3NjEgMTEzLjYyMSA0Ny44MTA0IDExMS4wMzUgNDcuNjI1MyAxMTAuODMxQzQ1Ljg5MzEgMTA4Ljg3MiA0My41NDQ4IDEwNi42ODIgNDEuMjA5NSAxMDYuNjgySDQxLjIwNTFINDEuMjAwOEMzOC4zNjU3IDEwNi42OTUgMzUuOTgyOSAxMDguNjMzIDM1LjM0NTIgMTExLjIxOEMzNS4zOTI2IDExMS4wNDggMzYuMzI3NiAxMDguNTk4IDM5Ljc1NzQgMTA4LjY4NUM0MS42Mjc0IDEwOC43MzMgNDMuNTc5MyAxMTAuMjQgNDMuOTggMTEwLjYxQzQ1LjAwNTUgMTExLjU2NSA0Ny4zNzEgMTE0LjE1MSA0Ny41NTYzIDExNC4zNTVDNDkuMjg4NCAxMTYuMzEgNTEuNjM2NyAxMTguNSA1My45NzIgMTE4LjVINTMuOTc2M0g1My45ODA2QzU2LjgxNTggMTE4LjQ4NyA1OS4yMDI5IDExNi41NDkgNTkuODM2MyAxMTMuOTY0QzU5Ljc4NDYgMTE0LjEzMyA1OC44NDUyIDExNi41NjIgNTUuNDExMiAxMTYuNDhaIiBmaWxsPSIjMjlBQkUyIi8+CjxwYXRoIGQ9Ik03OS44NDMxIDEwOS4wMjhINzYuMTM2OVYxMTguNTkxSDczLjgzNzFWMTA5LjAyOEg3MC4xMzA5VjEwNi44Nkg3OS44NDMxVjEwOS4wMjhaTTg5LjE2MDUgMTE4LjU5MUg4MS44MTQzVjEwNi44Nkg4OS4xNjA1VjEwOS4wMTFIODQuMDk3NlYxMTEuNjkxSDg4LjY4MDdWMTEzLjcyN0g4NC4wOTc2VjExNi40NEg4OS4xNjA1VjExOC41OTFaTTk5LjYzNTQgMTA5LjY1Nkw5Ny41ODM4IDExMC4yODVDOTcuNDY4IDEwOS42NCA5Ni45Mzg1IDEwOC42MzEgOTUuNDQ5NCAxMDguNjMxQzk0LjM0MDkgMTA4LjYzMSA5My42MTI5IDEwOS4zNDIgOTMuNjEyOSAxMTAuMTJDOTMuNjEyOSAxMTAuNzY1IDk0LjAyNjUgMTExLjI3OCA5NC44ODY5IDExMS40NDNMOTYuNTI0OSAxMTEuNzU4Qzk4LjY1OTMgMTEyLjE3MSA5OS44MDA5IDExMy41NjEgOTkuODAwOSAxMTUuMjE2Qzk5LjgwMDkgMTE3LjAxOSA5OC4yOTUzIDExOC44MzkgOTUuNTY1MyAxMTguODM5QzkyLjQ1NDcgMTE4LjgzOSA5MS4wODE0IDExNi44MzcgOTAuODk5NCAxMTUuMTY2TDkzLjAxNzMgMTE0LjYwM0M5My4xMTY1IDExNS43NjIgOTMuOTI3MyAxMTYuODA0IDk1LjU4MTggMTE2LjgwNEM5Ni44MDYyIDExNi44MDQgOTcuNDg0NSAxMTYuMTkyIDk3LjQ4NDUgMTE1LjM2NUM5Ny40ODQ1IDExNC42ODYgOTYuOTcxNiAxMTQuMTU3IDk2LjA2MTYgMTEzLjk3NUw5NC40MjM2IDExMy42NDRDOTIuNTU0IDExMy4yNjMgOTEuMzQ2MiAxMTIuMDU1IDkxLjM0NjIgMTEwLjI4NUM5MS4zNDYyIDEwOC4yIDkzLjIxNTggMTA2LjYxMiA5NS40MzI5IDEwNi42MTJDOTguMjc4NyAxMDYuNjEyIDk5LjM3MDcgMTA4LjMzMyA5OS42MzU0IDEwOS42NTZaTTExMC43NzYgMTA5LjAyOEgxMDcuMDdWMTE4LjU5MUgxMDQuNzdWMTA5LjAyOEgxMDEuMDY0VjEwNi44NkgxMTAuNzc2VjEwOS4wMjhaIiBmaWxsPSIjMTgxODE4Ii8+CjwvZz4KPGRlZnM+CjxmaWx0ZXIgaWQ9ImZpbHRlcjBfYl84NjRfNjQiIHg9Ii0yNi4yNzI3IiB5PSI0NyIgd2lkdGg9IjE5OC41NDUiIGhlaWdodD0iMTMwIiBmaWx0ZXJVbml0cz0idXNlclNwYWNlT25Vc2UiIGNvbG9yLWludGVycG9sYXRpb24tZmlsdGVycz0ic1JHQiI+CjxmZUZsb29kIGZsb29kLW9wYWNpdHk9IjAiIHJlc3VsdD0iQmFja2dyb3VuZEltYWdlRml4Ii8+CjxmZUdhdXNzaWFuQmx1ciBpbj0iQmFja2dyb3VuZEltYWdlRml4IiBzdGREZXZpYXRpb249IjIzLjYzNjQiLz4KPGZlQ29tcG9zaXRlIGluMj0iU291cmNlQWxwaGEiIG9wZXJhdG9yPSJpbiIgcmVzdWx0PSJlZmZlY3QxX2JhY2tncm91bmRCbHVyXzg2NF82NCIvPgo8ZmVCbGVuZCBtb2RlPSJub3JtYWwiIGluPSJTb3VyY2VHcmFwaGljIiBpbjI9ImVmZmVjdDFfYmFja2dyb3VuZEJsdXJfODY0XzY0IiByZXN1bHQ9InNoYXBlIi8+CjwvZmlsdGVyPgo8bGluZWFyR3JhZGllbnQgaWQ9InBhaW50MF9saW5lYXJfODY0XzY0IiB4MT0iMTUiIHkxPSItNzUuNSIgeDI9IjkyIiB5Mj0iMTI1LjUiIGdyYWRpZW50VW5pdHM9InVzZXJTcGFjZU9uVXNlIj4KPHN0b3Agc3RvcC1jb2xvcj0iI0Q5RDlEOSIvPgo8c3RvcCBvZmZzZXQ9IjAuNTg4NTQyIiBzdG9wLWNvbG9yPSJ3aGl0ZSIvPgo8L2xpbmVhckdyYWRpZW50Pgo8bGluZWFyR3JhZGllbnQgaWQ9InBhaW50MV9saW5lYXJfODY0XzY0IiB4MT0iNTMuNDczNiIgeTE9IjEyMi43OSIgeDI9IjE0LjAzNjIiIHkyPSI4OS41Nzg2IiBncmFkaWVudFVuaXRzPSJ1c2VyU3BhY2VPblVzZSI+CjxzdG9wIG9mZnNldD0iMC4yMSIgc3RvcC1jb2xvcj0iI0VEMUU3OSIvPgo8c3RvcCBvZmZzZXQ9IjEiIHN0b3AtY29sb3I9IiM1MjI3ODUiLz4KPC9saW5lYXJHcmFkaWVudD4KPGxpbmVhckdyYWRpZW50IGlkPSJwYWludDJfbGluZWFyXzg2NF82NCIgeDE9IjEyMC42NSIgeTE9IjU1LjYwMjEiIHgyPSI4MS4yMTMiIHkyPSIyMi4zOTE0IiBncmFkaWVudFVuaXRzPSJ1c2VyU3BhY2VPblVzZSI+CjxzdG9wIG9mZnNldD0iMC4yMSIgc3RvcC1jb2xvcj0iI0YxNUEyNCIvPgo8c3RvcCBvZmZzZXQ9IjAuNjg0MSIgc3RvcC1jb2xvcj0iI0ZCQjAzQiIvPgo8L2xpbmVhckdyYWRpZW50Pgo8bGluZWFyR3JhZGllbnQgaWQ9InBhaW50M19saW5lYXJfODY0XzY0IiB4MT0iNTAuODMzNyIgeTE9IjEwNy40NjEiIHgyPSI1OS4xMDAyIiB5Mj0iMTE1Ljk1IiBncmFkaWVudFVuaXRzPSJ1c2VyU3BhY2VPblVzZSI+CjxzdG9wIG9mZnNldD0iMC4yMSIgc3RvcC1jb2xvcj0iI0YxNUEyNCIvPgo8c3RvcCBvZmZzZXQ9IjAuNjg0MSIgc3RvcC1jb2xvcj0iI0ZCQjAzQiIvPgo8L2xpbmVhckdyYWRpZW50Pgo8bGluZWFyR3JhZGllbnQgaWQ9InBhaW50NF9saW5lYXJfODY0XzY0IiB4MT0iNDQuMzQ3NSIgeTE9IjExNy43MjEiIHgyPSIzNi4wODEiIHkyPSIxMDkuMjMyIiBncmFkaWVudFVuaXRzPSJ1c2VyU3BhY2VPblVzZSI+CjxzdG9wIG9mZnNldD0iMC4yMSIgc3RvcC1jb2xvcj0iI0VEMUU3OSIvPgo8c3RvcCBvZmZzZXQ9IjAuODkyOSIgc3RvcC1jb2xvcj0iIzUyMjc4NSIvPgo8L2xpbmVhckdyYWRpZW50Pgo8Y2xpcFBhdGggaWQ9ImNsaXAwXzg2NF82NCI+CjxyZWN0IHdpZHRoPSIxNDYiIGhlaWdodD0iMTQ2IiByeD0iNzMiIGZpbGw9IndoaXRlIi8+CjwvY2xpcFBhdGg+CjwvZGVmcz4KPC9zdmc+" }}}; initial_balances = vec {}; archive_options = record { num_blocks_to_archive = 1000; trigger_threshold = 2000; max_message_size_bytes = null; cycles_for_archive_creation = opt 1_000_000_000_000; node_max_memory_size_bytes = opt 3_221_225_472; controller_id = principal "mf7xa-laaaa-aaaar-qaaaa-cai"; } }})' --mode reinstall --wallet mf7xa-laaaa-aaaar-qaaaa-cai
```

## Deploying the Minter

### Locally

```shell
dfx canister create minter
dfx deploy minter --argument '(variant {InitArg = record { ethereum_network = variant {Sepolia} ; ecdsa_key_name = "key_1"; ethereum_contract_address = opt "CONTRACT_ADDRESS" ; ledger_id = principal "'"$(dfx canister id ledger)"'"; ethereum_block_height = variant {Finalized} ; minimum_withdrawal_amount = 10_000_000_000_000_000; next_transaction_nonce = NEXT_NONCE }})'
```

### Mainnet

```
dfx deploy --network ic minter --argument '(variant {InitArg = record { ethereum_network = variant {Sepolia} ; ecdsa_key_name = "key_1"; ethereum_contract_address = opt "0xb44B5e756A894775FC32EDdf3314Bb1B1944dC34" ; ledger_id = principal "'"$(dfx canister --network ic id ledger)"'"; ethereum_block_height = variant {Finalized} ; minimum_withdrawal_amount = 10_000_000_000_000_000; next_transaction_nonce = NEXT_NONCE; last_scraped_block_number = 4_775_280 }})' --mode reinstall --wallet mf7xa-laaaa-aaaar-qaaaa-cai
```

### Upgrading for ckERC20
```shell
dfx deploy minter --network ic --argument "(variant {UpgradeArg = record {ledger_suite_orchestrator_id = opt principal \"$(dfx canister --network ic id orchestrator)\"; erc20_helper_contract_address = opt \"0x674Cdbe64Df412DA9bAb1596e00c1520979B5A23\"; last_erc20_scraped_block_number = opt 5680659;}})" --wallet mf7xa-laaaa-aaaar-qaaaa-cai
```

Note: you can query the next nonce using:

```
curl -X POST 'https://ethereum-sepolia.publicnode.com' \
    --header 'Content-Type: application/json' \
    --data '{
        "jsonrpc":"2.0",
        "method":"eth_getTransactionCount",
        "params":[
            "0x1789F79e95324A47c5Fd6693071188e82E9a3558",
            "latest"
        ],
        "id":1
    }'
```


## Deploying the index

### Mainnet

```
dfx deploy --network ic index --argument '(opt variant {Init = record { ledger_id = principal "apia6-jaaaa-aaaar-qabma-cai" }})' --mode reinstall --wallet mf7xa-laaaa-aaaar-qaaaa-cai
```

## Deploying the Orchestrator

### Locally

```shell
dfx canister create orchestrator
dfx deploy orchestrator --network ic --argument "(variant { InitArg = record { more_controller_ids = vec { principal \"mf7xa-laaaa-aaaar-qaaaa-cai\"; }; minter_id = opt principal \"$(dfx canister --network ic id minter)\"; cycles_management = opt record { cycles_for_ledger_creation = 2_000_000_000_000 ; cycles_for_archive_creation = 1_000_000_000_000; cycles_for_index_creation = 1_000_000_000_000; cycles_top_up_increment = 500_000_000_000 } }})"
```

### Mainnet

```shell
dfx deploy orchestrator --network ic --argument "(variant { InitArg = record { more_controller_ids = vec { principal \"mf7xa-laaaa-aaaar-qaaaa-cai\"; }; minter_id = opt principal \"$(dfx canister --network ic id minter)\"; cycles_management = opt record { cycles_for_ledger_creation = 2_000_000_000_000 ; cycles_for_archive_creation = 1_000_000_000_000; cycles_for_index_creation = 1_000_000_000_000; cycles_top_up_increment = 500_000_000_000 } }})"
```

# ckERC20

## Add ckSepoliaUSDC

```shell
dfx deploy orchestrator --network ic --argument "(variant { AddErc20Arg = record { contract = record { chain_id = 11155111; address = \"0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238\" }; ledger_init_arg = record { minting_account = record { owner = principal \"$(dfx canister --network ic id minter)\" }; feature_flags  = opt record { icrc2 = true }; decimals = opt 6; max_memo_length = opt 80; transfer_fee = 4_000; token_symbol = \"ckSepoliaUSDC\"; token_name = \"Chain key Sepolia USDC\"; token_logo = \"\"; initial_balances = vec {}; }; git_commit_hash = \"3924e543af04d30a0b601d749721af239a10dff6\";  ledger_compressed_wasm_hash = \"57e2a728f9ffcb1a7d9e101dbd1260f8b9f3246bf5aa2ad3e2c750e125446838\"; index_compressed_wasm_hash = \"6fb62c7e9358ca5c937a5d25f55700459ed09a293d0826c09c631b64ba756594\"; }})" --upgrade-unchanged --wallet mf7xa-laaaa-aaaar-qaaaa-cai
```

## Add ckSepoliaLINK

```shell
dfx deploy orchestrator --network ic --argument "(variant { AddErc20Arg = record { contract = record { chain_id = 11155111; address = \"0x779877A7B0D9E8603169DdbD7836e478b4624789\" }; ledger_init_arg = record { minting_account = record { owner = principal \"$(dfx canister --network ic id minter)\" }; feature_flags  = opt record { icrc2 = true }; decimals = opt 18; max_memo_length = opt 80; transfer_fee = 200_000_000_000_000; token_symbol = \"ckSepoliaLINK\"; token_name = \"Chain key Sepolia LINK\"; token_logo = \"\"; initial_balances = vec {}; }; git_commit_hash = \"3924e543af04d30a0b601d749721af239a10dff6\";  ledger_compressed_wasm_hash = \"57e2a728f9ffcb1a7d9e101dbd1260f8b9f3246bf5aa2ad3e2c750e125446838\"; index_compressed_wasm_hash = \"6fb62c7e9358ca5c937a5d25f55700459ed09a293d0826c09c631b64ba756594\"; }})" --upgrade-unchanged --wallet mf7xa-laaaa-aaaar-qaaaa-cai
```

## Add ckSepoliaPEPE

```shell
dfx deploy orchestrator --network ic --argument "(variant { AddErc20Arg = record { contract = record { chain_id = 11155111; address = \"0x560eF9F39E4B08f9693987cad307f6FBfd97B2F6\" }; ledger_init_arg = record { minting_account = record { owner = principal \"$(dfx canister --network ic id minter)\" }; feature_flags  = opt record { icrc2 = true }; decimals = opt 18; max_memo_length = opt 80; transfer_fee = 100_000_000_000_000_000_000; token_symbol = \"ckSepoliaPEPE\"; token_name = \"Chain key Sepolia PEPE\"; token_logo = \"\"; initial_balances = vec {}; }; git_commit_hash = \"3924e543af04d30a0b601d749721af239a10dff6\";  ledger_compressed_wasm_hash = \"57e2a728f9ffcb1a7d9e101dbd1260f8b9f3246bf5aa2ad3e2c750e125446838\"; index_compressed_wasm_hash = \"6fb62c7e9358ca5c937a5d25f55700459ed09a293d0826c09c631b64ba756594\"; }})" --upgrade-unchanged --wallet mf7xa-laaaa-aaaar-qaaaa-cai
```
