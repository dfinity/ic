# VetKD Password Manager frontend
Uses the defaults provided by the devkit to implement a VetKD-based password
manager. This utilizes the encrypted maps canister example to realize the
password manager, i.e., there is no dedicated canister implementation, only the
frontend implementation that uses all defaults from the SDK.

## Step 1: Deploy `encrypted_maps_example` canister and the internet identity canister.

## Step 2: Tell `frontend` what canisters to communicate with, so the following environment variables must be defined. For a local deployment, one can run `deploy_locally.sh` from that folder.
* `CANISTER_ID_IC_VETKEYS_ENCRYPTED_MAPS_CANISTER`

## Step 3: Deploy frontend. This returns a link that can be used to access the frontend from the asset canister.
```shell
dfx deploy www
```
Note: if this returns a URL with the IP `0.0.0.0` and the fronetned does not
work, a potential fix is to replace it with `localhost`.