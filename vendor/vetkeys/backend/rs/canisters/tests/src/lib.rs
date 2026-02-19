use ic_cdk::{
    management_canister::{VetKDDeriveKeyArgs, VetKDKeyId, VetKDPublicKeyArgs},
    update,
};

#[update]
async fn sign_with_bls(input: Vec<u8>, context: Vec<u8>, key_id: VetKDKeyId) -> Vec<u8> {
    ic_vetkeys::management_canister::sign_with_bls(input, context, key_id)
        .await
        .expect("sign_with_bls call failed")
}

#[update]
async fn bls_public_key(context: Vec<u8>, key_id: VetKDKeyId) -> Vec<u8> {
    ic_vetkeys::management_canister::bls_public_key(None, context, key_id)
        .await
        .expect("bls_public_key call failed")
}

#[update]
async fn vetkd_derive_key(
    input: Vec<u8>,
    context: Vec<u8>,
    key_id: VetKDKeyId,
    transport_public_key: Vec<u8>,
) -> Vec<u8> {
    let request = VetKDDeriveKeyArgs {
        input,
        context,
        key_id,
        transport_public_key,
    };

    let reply = ic_cdk::management_canister::vetkd_derive_key(&request)
        .await
        .expect("vetkd_derive_key call failed");

    reply.encrypted_key
}

#[update]
async fn vetkd_public_key(context: Vec<u8>, key_id: VetKDKeyId) -> Vec<u8> {
    let request = VetKDPublicKeyArgs {
        canister_id: None,
        context,
        key_id,
    };

    let reply = ic_cdk::management_canister::vetkd_public_key(&request)
        .await
        .expect("vetkd_public_key call failed");

    reply.public_key
}
