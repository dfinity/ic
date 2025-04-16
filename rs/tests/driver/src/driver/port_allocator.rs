#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub enum AddrType {
    P2P,
    Xnet,
    PublicApi,
    Prometheus,
    OrchestratorPrometheus,
}

impl From<AddrType> for u16 {
    fn from(a: AddrType) -> Self {
        use AddrType::*;
        match a {
            P2P => 4100,
            Xnet => 2497,
            PublicApi => 8080,
            Prometheus => 9090,
            OrchestratorPrometheus => 9100,
        }
    }
}
