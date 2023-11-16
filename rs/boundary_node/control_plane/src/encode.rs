use std::{
    io::{BufWriter, Write},
    net::SocketAddr,
    str::FromStr,
};

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
    keepalive 50;
}}
upstream {node_id}-query {{
    server {socket_addr} max_conns=50;
    keepalive 50;
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

pub struct SystemReplicasEncoder(pub String);

#[async_trait]
impl Encode for SystemReplicasEncoder {
    async fn encode(&self, rt: &RoutingTable) -> Result<Vec<u8>, Error> {
        let mut inner: Vec<u8> = Vec::new();
        let mut buf = BufWriter::new(&mut inner);

        // Filter to system subnets only
        let subnets = rt
            .subnets
            .iter()
            .filter(|&subnet| subnet.subnet_type == "system");

        buf.write_all(format!("define {} = {{\n", self.0).as_bytes())?;
        for subnet in subnets {
            for node in &subnet.nodes {
                buf.write_all(
                    format!(
                        "  {}, # {} / {}\n",
                        SocketAddr::from_str(&node.socket_addr)?.ip(), // ip
                        subnet.subnet_id,                              // subnet_id
                        node.node_id                                   // node_id
                    )
                    .as_bytes(),
                )?;
            }
        }
        buf.write_all("}".as_bytes())?;

        buf.flush()?;
        drop(buf);

        Ok(inner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::registry::Subnet;

    #[tokio::test]
    async fn system_subnets_encoder_ok() -> Result<(), Error> {
        let enc = SystemReplicasEncoder("ipv6_system_replica_ips".into());

        let out = enc
            .encode(&RoutingTable {
                registry_version: 0,
                nns_subnet_id: "".into(),
                canister_routes: vec![],
                subnets: vec![
                    Subnet {
                        subnet_id: "subnet-1".into(),
                        subnet_type: "system".into(),
                        nodes: vec![Node {
                            node_id: "node-1".into(),
                            socket_addr: "[::1]:1234".into(),
                            tls_certificate_pem: "".into(),
                        }],
                    },
                    Subnet {
                        subnet_id: "subnet-1".into(),
                        subnet_type: "application".into(),
                        nodes: vec![Node {
                            node_id: "node-2".into(),
                            socket_addr: "[::2]:1234".into(),
                            tls_certificate_pem: "".into(),
                        }],
                    },
                    Subnet {
                        subnet_id: "subnet-3".into(),
                        subnet_type: "system".into(),
                        nodes: vec![Node {
                            node_id: "node-3".into(),
                            socket_addr: "[::3]:1234".into(),
                            tls_certificate_pem: "".into(),
                        }],
                    },
                ],
            })
            .await?;

        let out = String::from_utf8(out)?;

        assert_eq!(
            out,
            r#"define ipv6_system_replica_ips = {
  ::1, # subnet-1 / node-1
  ::3, # subnet-3 / node-3
}"#
        );

        Ok(())
    }
}
