#![allow(clippy::unwrap_used)]
mod allowed_clients {
    use crate::{AllowedClients, ClientsEmptyError, SomeOrAllNodes};
    use ic_protobuf::registry::crypto::v1::X509PublicKeyCert;
    use ic_types::{NodeId, PrincipalId};
    use maplit::btreeset;
    use std::collections::BTreeSet;

    #[test]
    fn should_correctly_construct_with_new() {
        let nodes = SomeOrAllNodes::Some(btreeset! {node_id(1)});
        let certs = vec![X509PublicKeyCert {
            certificate_der: b"cert1".to_vec(),
        }];

        let allowed_clients = AllowedClients::new(nodes.clone(), certs.clone()).unwrap();

        assert_eq!(allowed_clients.nodes(), &nodes);
        assert_eq!(allowed_clients.certs(), &certs);
    }

    #[test]
    fn should_correctly_construct_with_new_with_all_nodes_and_certs() {
        let all_nodes = SomeOrAllNodes::All;
        let certs = vec![X509PublicKeyCert {
            certificate_der: b"cert1".to_vec(),
        }];

        let allowed_clients = AllowedClients::new(all_nodes.clone(), certs.clone()).unwrap();

        assert_eq!(allowed_clients.nodes(), &all_nodes);
        assert_eq!(allowed_clients.certs(), &certs);
    }

    #[test]
    fn should_correctly_construct_with_new_with_all_nodes_without_certs() {
        let all_nodes = SomeOrAllNodes::All;
        let certs = vec![];

        let allowed_clients = AllowedClients::new(all_nodes.clone(), certs.clone()).unwrap();

        assert_eq!(allowed_clients.nodes(), &all_nodes);
        assert_eq!(allowed_clients.certs(), &certs);
    }

    #[test]
    fn should_correctly_construct_with_new_with_nodes() {
        let nodes = btreeset! {node_id(1)};

        let allowed_clients = AllowedClients::new_with_nodes(nodes.clone()).unwrap();

        assert_eq!(allowed_clients.nodes(), &SomeOrAllNodes::Some(nodes));
        assert_eq!(allowed_clients.certs(), &vec![]);
    }

    #[test]
    fn should_fail_on_new_if_nodes_and_certs_empty() {
        let allowed_clients = AllowedClients::new(SomeOrAllNodes::Some(BTreeSet::new()), vec![]);
        assert_eq!(allowed_clients.unwrap_err(), ClientsEmptyError {});
    }

    #[test]
    fn should_fail_on_new_with_nodes_if_nodes_empty() {
        let allowed_clients = AllowedClients::new_with_nodes(BTreeSet::new());
        assert_eq!(allowed_clients.unwrap_err(), ClientsEmptyError {});
    }

    fn node_id(id: u64) -> NodeId {
        NodeId::from(PrincipalId::new_node_test_id(id))
    }
}
