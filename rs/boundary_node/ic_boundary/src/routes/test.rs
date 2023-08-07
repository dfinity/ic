use super::*;

use crate::persist::test::node;
use ic_types::messages::Blob;

struct ProxyRouter {
    node: Node,
    root_key: Vec<u8>,
}

#[async_trait]
impl Proxier for ProxyRouter {
    async fn proxy(
        &self,
        request_type: RequestType,
        request: Request<Body>,
        node: Node,
        canister_id: Principal,
    ) -> Result<Response, ErrorCause> {
        Ok("foobar".into_response())
    }

    fn lookup_node(&self, canister_id: Principal) -> Result<Node, ErrorCause> {
        Ok(self.node.clone())
    }

    fn health(&self) -> ReplicaHealthStatus {
        ReplicaHealthStatus::Healthy
    }

    fn get_root_key(&self) -> &Vec<u8> {
        &self.root_key
    }
}

#[tokio::test]
async fn test_status() -> Result<(), Error> {
    let node = node(0, Principal::from_text("f7crg-kabae").unwrap());
    let root_key = vec![8, 6, 7, 5, 3, 0, 9];
    let state = ProxyRouter {
        node,
        root_key: root_key.clone(),
    };

    let resp = status(State(Arc::new(state))).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let (parts, body) = resp.into_parts();
    let body = hyper::body::to_bytes(body).await.unwrap().to_vec();

    let health: HttpStatusResponse = serde_cbor::from_slice(&body)?;
    assert_eq!(
        health.replica_health_status,
        Some(ReplicaHealthStatus::Healthy)
    );
    assert_eq!(health.root_key.as_deref(), Some(&root_key),);

    Ok(())
}

#[tokio::test]
async fn test_query() -> Result<(), Error> {
    let node = node(0, Principal::from_text("f7crg-kabae").unwrap());
    let root_key = vec![8, 6, 7, 5, 3, 0, 9];
    let state = ProxyRouter {
        node: node.clone(),
        root_key,
    };

    let sender = Principal::from_text("sqjm4-qahae-aq").unwrap();
    let canister_id = Principal::from_text("sxiki-5ygae-aq").unwrap();

    let content = HttpQueryContent::Query {
        query: HttpUserQuery {
            canister_id: Blob(canister_id.as_slice().to_vec()),
            method_name: "foobar".to_string(),
            arg: Blob(vec![]),
            sender: Blob(sender.as_slice().to_vec()),
            nonce: None,
            ingress_expiry: 1234,
        },
    };

    let envelope = HttpRequestEnvelope::<HttpQueryContent> {
        content,
        sender_delegation: None,
        sender_pubkey: None,
        sender_sig: None,
    };

    let body = serde_cbor::to_vec(&envelope).unwrap();

    let mut ctx = RequestContext::default();
    parse_body(&mut ctx, &body)?;
    ctx.canister_id = Some(canister_id);
    ctx.node = Some(node);

    let mut request = Request::builder().body(Body::from(body)).unwrap();

    let resp = query(State(Arc::new(state)), Extension(ctx), request).await;

    assert!(resp.is_ok());
    let resp = resp.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let (parts, body) = resp.into_parts();
    let body = hyper::body::to_bytes(body).await.unwrap().to_vec();
    let body = String::from_utf8_lossy(&body);
    assert_eq!(body, "foobar");

    Ok(())
}
