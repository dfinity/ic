use std::io::{BufWriter, Write};

use anyhow::Error;
use async_trait::async_trait;

use crate::{
    registry::{Node, RoutingTable},
    routes::Routes,
};

#[async_trait]
pub trait Encode: Send + Sync {
    async fn encode(&self, rt: &RoutingTable) -> Result<Vec<u8>, Error>;
}

pub struct RoutesEncoder;

#[async_trait]
impl Encode for RoutesEncoder {
    async fn encode(&self, rt: &RoutingTable) -> Result<Vec<u8>, Error> {
        let mut inner: Vec<u8> = Vec::new();
        let mut buf = BufWriter::new(&mut inner);

        buf.write_all("let routes = ".as_bytes())?;
        serde_json::to_writer(&mut buf, &Routes::from(rt))?;
        buf.write_all("; export default routes;".as_bytes())?;

        buf.flush()?;
        drop(buf);

        Ok(inner)
    }
}

pub struct UpstreamEncoder;

#[async_trait]
impl Encode for UpstreamEncoder {
    async fn encode(&self, rt: &RoutingTable) -> Result<Vec<u8>, Error> {
        let mut inner: Vec<u8> = Vec::new();
        let mut buf = BufWriter::new(&mut inner);

        for subnet in &rt.subnets {
            for node in &subnet.nodes {
                let Node {
                    node_id,
                    socket_addr,
                    ..
                } = node;

                buf.write_all(
                    format!(
                        r#"
upstream {node_id} {{
    server {socket_addr};
}}
upstream {node_id}-query {{
    server {socket_addr} max_conns=50;
}}
"#
                    )
                    .as_bytes(),
                )?;
            }
        }

        buf.flush()?;
        drop(buf);

        Ok(inner)
    }
}

pub struct TrustedCertsEncoder;

#[async_trait]
impl Encode for TrustedCertsEncoder {
    async fn encode(&self, rt: &RoutingTable) -> Result<Vec<u8>, Error> {
        let mut inner: Vec<u8> = Vec::new();
        let mut buf = BufWriter::new(&mut inner);

        for subnet in &rt.subnets {
            for node in &subnet.nodes {
                buf.write_all(node.tls_certificate_pem.as_bytes())?;
            }
        }

        buf.flush()?;
        drop(buf);

        Ok(inner)
    }
}
