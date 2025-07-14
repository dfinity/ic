use lazy_static::lazy_static;
use maplit::btreemap;
use std::collections::BTreeMap;

lazy_static! {
    pub static ref MISSING_NODE_TYPES_MAP: BTreeMap<String, String> = btreemap! {
        "xexdo-rsh52-bcci4-xrieo-3lazn-mws2u-xv4j2-egawj-gh5ps-t3oww-bae" => "type3",
        "phgey-5cyzw-2ype7-y5q7w-yce6j-3yvg7-tlkfe-quvvy-pqpt4-252od-fqe" => "type3.1",
        "jognp-ct5lo-tobx4-fpaio-gwwh6-7aybl-cmmlw-x4oo4-zut5y-rdrfj-6qe" => "type3",
        "eteye-hwqyn-n36jd-isvcm-qxddm-jyai6-r5zvb-xnmd4-p7gye-x6cyz-7ae" => "type3",
    }
    .into_iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect();
}
