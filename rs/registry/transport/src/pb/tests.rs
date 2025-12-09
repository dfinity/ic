use super::*;
use ic_nervous_system_common_test_keys::TEST_USER1_PRINCIPAL;
use ic_registry_keys::make_node_operator_record_key;

fn principal(i: u64) -> PrincipalId {
    PrincipalId::try_from(format!("SID{i}").as_bytes().to_vec()).unwrap()
}

#[test]
fn registry_mutation_display() {
    assert_eq!(
        format!("{}", v1::RegistryMutation::default()),
        "RegistryMutation { mutation_type: insert, key: , value:  }"
    );

    assert_eq!(
        format!(
            "{}",
            v1::RegistryMutation {
                mutation_type: Type::Delete as i32,
                key: make_node_operator_record_key(principal(1)).into_bytes(),
                value: vec![],
            }
        ),
        "RegistryMutation { mutation_type: delete, key: node_operator_record_ij6eg-jctjf-cdc, value:  }"
    );

    assert_eq!(
        format!(
            "{}",
            v1::RegistryMutation {
                mutation_type: Type::Update as i32,
                key: make_node_operator_record_key(principal(1)).into_bytes(),
                value: (*TEST_USER1_PRINCIPAL).to_vec(),
            }
        ),
        "RegistryMutation { mutation_type: update, key: node_operator_record_ij6eg-jctjf-cdc, value: [178, 106, 186, 245, 220, 132, 246, 155, 74, 29, 140, 79, 172, 68, 231, 10, 94, 93, 81, 204, 109, 25, 21, 213, 213, 75, 120, 108, 2] (possibly PrincipalId: vpysv-v5snk-5plxe-e62nu-uhmmj-6wejz-yklzo-vdtdn-dek5l-vklpb-wae) }"
    );

    assert_eq!(
        format!(
            "{}",
            v1::RegistryMutation {
                mutation_type: Type::Upsert as i32,
                key: (200..205).collect::<Vec<u8>>(),
                value: (205..210).collect::<Vec<u8>>(), // Short sequences of bytes can be converted into a PrincipalId
            }
        ),
        "RegistryMutation { mutation_type: upsert, key: [200, 201, 202, 203, 204], value: [205, 206, 207, 208, 209] (possibly PrincipalId: vmvli-ywnz3-h5bui) }"
    );
}
