use super::*;
use std::str::FromStr;

#[test]
fn test_try_from_principal_id() {
    // Happy case.
    let canister_id = CanisterId::from_u64(42);
    let principal_id: PrincipalId = canister_id.get();
    assert_eq!(CanisterId::try_from_principal_id(principal_id), Ok(canister_id));

    // Typical sad case: not even opaque (here, self-authenticating).
    let definitely_not_a_canister_id = PrincipalId::from_str(
        "ubktz-haghv-fqsdh-23fhi-3urex-bykoz-pvpfd-5rs6w-qpo3t-nf2dv-oae"
    )
    .unwrap();
    match CanisterId::try_from_principal_id(definitely_not_a_canister_id) {
        Err(CanisterIdError::InvalidPrincipalId(description)) => {
            let description = description.to_lowercase();
            for key_word in ["opaque", "self", "authenticating", "class"] {
                assert!(description.contains(key_word), "{} not in {:?}", key_word, description);
            }
        }
        wrong => panic!("{:?}", wrong),
    }

    // Opaque, but wrong length.
    match CanisterId::try_from_principal_id(PrincipalId::new_opaque(&[0xDE, 0xAD, 0xBE, 0xEF][..])) {
        Err(CanisterIdError::InvalidPrincipalId(description)) => {
            let description = description.to_lowercase();
            for key_word in ["10", "5", "bytes"] {
                assert!(description.contains(key_word), "{} not in {:?}", key_word, description);
            }
        }
        wrong => panic!("{:?}", wrong),
    }

    // Near miss: opaque, length 10, but penultimate is not 0x01 (?!).
    match CanisterId::try_from_principal_id(PrincipalId::new_opaque(&[0,1,2,3,4,5,6,7,8][..])) {
        Err(CanisterIdError::InvalidPrincipalId(description)) => {
            let description = description.to_lowercase();
            for key_word in ["byte", "8", "0x01"] {
                assert!(description.contains(key_word), "{} not in {:?}", key_word, description);
            }
        }
        wrong => panic!("{:?}", wrong),
    }
}
