use candid::Principal;
use prost::Message;

mod canister {
    include!(concat!(env!("OUT_DIR"), "/canister.rs"));
}
use canister::*;

mod test_utilities;
use test_utilities::{cargo_build_canister, pic_base, update};

#[test]
fn call_macros() {
    let wasm = cargo_build_canister("macros");
    let pic = pic_base().build();
    let canister_id = pic.create_canister();
    pic.add_cycles(canister_id, 100_000_000_000_000);
    pic.install_canister(canister_id, wasm, vec![], None);
    let _: () = update(&pic, canister_id, "arg0", ()).unwrap();
    let _: () = update(&pic, canister_id, "arg1", (1u32,)).unwrap();
    let _: () = update(&pic, canister_id, "arg2", (1u32, 2u32)).unwrap();
    let sender = Principal::anonymous();
    let res = pic
        .update_call(canister_id, sender, "ret0", vec![])
        .unwrap();
    assert_eq!(res, vec![0]);
    let res = pic
        .update_call(canister_id, sender, "ret1", vec![])
        .unwrap();
    assert_eq!(res, vec![42]);
    let res = pic
        .update_call(canister_id, sender, "ret2", vec![])
        .unwrap();
    assert_eq!(res, vec![1, 2]);
    let res = pic
        .update_call(
            canister_id,
            sender,
            "method_one",
            MethodOneRequest {
                input: "Hello".to_string(),
            }
            .encode_to_vec(),
        )
        .unwrap();
    assert_eq!(res, MethodOneResponse { result: 5i32 }.encode_to_vec());
    let res = pic
        .update_call(
            canister_id,
            sender,
            "method_two",
            MethodTwoRequest { values: vec![1.0] }.encode_to_vec(),
        )
        .unwrap();
    assert_eq!(
        res,
        MethodTwoResponse {
            success: true,
            message: "Hello world!".to_string()
        }
        .encode_to_vec()
    );
    let _: (u32,) = update(&pic, canister_id, "manual_reply", ()).unwrap();
    let (res,): (u32,) = update(&pic, canister_id, "generic", (1u32,)).unwrap();
    assert_eq!(res, 2);

    let rej = pic
        .update_call(canister_id, sender, "with_guards", vec![1])
        .unwrap_err();
    assert_eq!(rej.reject_message, "guard1 failed");
    let rej = pic
        .update_call(canister_id, sender, "with_guards", vec![3])
        .unwrap_err();
    assert_eq!(rej.reject_message, "guard2 failed");
    let _res = pic
        .update_call(canister_id, sender, "with_guards", vec![15])
        .unwrap();

    // The entry-point expects an `opt nat32` value.
    // Here we send some blob that decoder need to skip.
    // The call is expected to:
    // * succeed: when the blob is relatively small
    // * fail: when the blob is too large
    let _: () = update(
        &pic,
        canister_id,
        "default_skipping_quota",
        (vec![42; 1400],),
    )
    .unwrap();
    let res: Result<(), _> = update(
        &pic,
        canister_id,
        "default_skipping_quota",
        (vec![42; 1500],),
    );
    assert!(res
        .unwrap_err()
        .reject_message
        .contains("Skipping cost exceeds the limit"));
}
