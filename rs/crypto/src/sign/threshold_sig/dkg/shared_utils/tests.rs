use super::*;

mod csp_keys {
    use super::*;
    use crate::sign::threshold_sig::dkg::test_utils::{csp_enc_pk, csp_pop, enc_pk_with_pop};
    use ic_test_utilities::types::ids::{NODE_1, NODE_2, NODE_3, NODE_4};

    #[test]
    fn should_return_empty_vec_if_nodes_empty() {
        let nodes = &[];
        let verified_keys = BTreeMap::new();

        let csp_keys = csp_keys_for_optional_node_ids(nodes, &verified_keys);

        assert_eq!(csp_keys, &[]);
    }

    #[test]
    fn should_return_vec_of_none_if_verified_keys_empty() {
        let nodes = &[Some(NODE_1), Some(NODE_2), None];
        let verified_keys = BTreeMap::new();

        let csp_keys = csp_keys_for_optional_node_ids(nodes, &verified_keys);

        assert_eq!(csp_keys, &[None, None, None]);
    }

    #[test]
    fn should_return_none_for_nodes_that_are_none() {
        let nodes = &[None, Some(NODE_1), None];
        let mut verified_keys = BTreeMap::new();
        let (pk_1, pop_1) = (csp_enc_pk(42), csp_pop(43));
        verified_keys.insert(NODE_1, enc_pk_with_pop(pk_1, pop_1));

        let csp_keys = csp_keys_for_optional_node_ids(nodes, &verified_keys);

        assert_eq!(csp_keys, &[None, Some((pk_1, pop_1)), None]);
    }

    #[test]
    fn should_return_none_for_nodes_that_are_none_and_for_keys_that_are_not_present() {
        let nodes = &[None, Some(NODE_1), Some(NODE_2)];
        let mut verified_keys = BTreeMap::new();
        let (pk_1, pop_1) = (csp_enc_pk(42), csp_pop(43));
        verified_keys.insert(NODE_1, enc_pk_with_pop(pk_1, pop_1));

        let csp_keys = csp_keys_for_optional_node_ids(nodes, &verified_keys);

        assert_eq!(csp_keys, &[None, Some((pk_1, pop_1)), None]);
    }

    #[test]
    fn should_return_multiple_keys() {
        let nodes = &[None, Some(NODE_1), Some(NODE_2), Some(NODE_3)];
        let mut verified_keys = BTreeMap::new();
        let (pk_1, pop_1) = (csp_enc_pk(42), csp_pop(43));
        verified_keys.insert(NODE_1, enc_pk_with_pop(pk_1, pop_1));
        let (pk_3, pop_3) = (csp_enc_pk(44), csp_pop(45));
        verified_keys.insert(NODE_3, enc_pk_with_pop(pk_3, pop_3));

        let csp_keys = csp_keys_for_optional_node_ids(nodes, &verified_keys);

        assert_eq!(
            csp_keys,
            &[None, Some((pk_1, pop_1)), None, Some((pk_3, pop_3))]
        );
    }

    #[test]
    fn should_convert_nodes_to_some_in_csp_keys() {
        let nodes = &[NODE_1, NODE_2, NODE_3, NODE_4];
        let mut verified_keys = BTreeMap::new();
        let (pk_1, pop_1) = (csp_enc_pk(42), csp_pop(43));
        verified_keys.insert(NODE_1, enc_pk_with_pop(pk_1, pop_1));
        let (pk_3, pop_3) = (csp_enc_pk(44), csp_pop(45));
        verified_keys.insert(NODE_3, enc_pk_with_pop(pk_3, pop_3));

        let csp_keys = csp_keys(nodes, &verified_keys);

        assert_eq!(
            csp_keys,
            &[Some((pk_1, pop_1)), None, Some((pk_3, pop_3)), None]
        );
    }
}
