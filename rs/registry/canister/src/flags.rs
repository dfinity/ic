use std::{
    cell::{Cell, RefCell},
    str::FromStr,
};

use ic_nervous_system_feature_access_policy::FeatureAccessPolicy;
#[cfg(any(test, feature = "canbench-rs"))]
use ic_nervous_system_temporary::Temporary;
use ic_types::{PrincipalId, SubnetId};

#[cfg(target_arch = "wasm32")]
use dfn_core::println;

use crate::common::LOG_PREFIX;

thread_local! {
    static IS_CHUNKIFYING_LARGE_VALUES_ENABLED: Cell<bool> = const { Cell::new(true) };
    static IS_NODE_SWAPPING_ENABLED: Cell<bool> = const { Cell::new(true) };

    // Temporary flags related to the node swapping feature.
    //
    // These are needed for the phased rollout approach in order
    // allow granular rolling out of the feature to specific subnets
    // to specific subset of callers.
    static NODE_SWAPPING_CALLERS_POLICY: RefCell<FeatureAccessPolicy<PrincipalId>> = RefCell::new(FeatureAccessPolicy::allow_only(
        [
            "xph6u-z3z2t-s7hh7-gtlxh-bbgbx-aatlm-eab4o-bsank-nqruh-3ub4q-sae",
            "lgp6d-brhlv-35izu-khc6p-rfszo-zdwng-xbtkh-xyvjg-y3due-7ha7t-uae",
            "byspq-73pbj-e44pb-5gq3o-a6sqa-p3p3l-blq2j-dtjup-77zyx-k26zh-aae",
            "db7fe-oft52-pi5du-za72s-sh5oy-6wmnv-hje7y-i5k2l-txseu-anq6c-rqe",
            "pi3wm-ofu73-5wyma-gec6p-lplqp-6euwt-c5jjb-pwaey-gxmlr-rzqmk-xqe",
            "rzskv-pde6u-albub-bojhe-odunj-k3nnf-j2eag-akkjm-o3ydz-z5tcy-vae",
            "s7dud-dfedw-dmrax-rjvop-5k4qw-htm4w-gj7ak-j2itz-txwwn-o5ymv-tae",
            "vqe65-zvwhc-x7bw7-76c74-3dc6v-v6uzb-nyfvb-6wgnv-nhiew-fkoug-oqe",
            "wqyl3-uvtrm-5lhi3-rjcas-ntrhs-bimkv-viu7b-2tff6-ervao-u2cjg-wqe",
            "xcne4-m67do-bnrkt-ny5xy-gxepb-5jycf-kcuvt-bdmh6-w565c-fvmdo-oae",
            "y4c7z-5wyt7-h4dtr-s77cd-t5pue-ajl7h-65ct4-ab5dr-fjaqa-x63kh-xqe",
        ]
        .iter()
        .filter_map(|p| match PrincipalId::from_str(p) {
            Ok(p) => Some(p),
            Err(e) => {
                println!("{LOG_PREFIX}Coudln't parse {p} as a PrincipalId due to error: {e:?}",);
                None
            }
        }),
    ));

    static NODE_SWAPPING_SUBNETS_POLICY: RefCell<FeatureAccessPolicy<SubnetId>> = RefCell::new(FeatureAccessPolicy::allow_only(
        [
            "2fq7c-slacv-26cgz-vzbx2-2jrcs-5edph-i5s2j-tck77-c3rlz-iobzx-mqe",
            "2zs4v-uoqha-xsuun-lveyr-i4ktc-5y3ju-aysud-niobd-gxnqa-ctqem-hae",
            "3hhby-wmtmw-umt4t-7ieyg-bbiig-xiylg-sblrt-voxgt-bqckd-a75bf-rqe",
            "4ecnw-byqwz-dtgss-ua2mh-pfvs7-c3lct-gtf4e-hnu75-j7eek-iifqm-sqe",
            "4utr6-xo2fz-v7fsb-t3wsg-k7sfl-cj2ba-ghdnd-kcrfo-xavdb-ebean-mqe",
            "4zbus-z2bmt-ilreg-xakz4-6tyre-hsqj4-slb4g-zjwqo-snjcc-iqphi-3qe",
            "5kdm2-62fc6-fwnja-hutkz-ycsnm-4z33i-woh43-4cenu-ev7mi-gii6t-4ae",
            "6excn-doq5g-bmrxd-3774i-hjnn2-3ovbo-xjwz7-3yozt-fsbzx-bethy-bae",
            "6pbhf-qzpdk-kuqbr-pklfa-5ehhf-jfjps-zsj6q-57nrl-kzhpd-mu7hc-vae",
            "bkfrj-6k62g-dycql-7h53p-atvkj-zg4to-gaogh-netha-ptybj-ntsgw-rqe",
            "brlsh-zidhj-3yy3e-6vqbz-7xnih-xeq2l-as5oc-g32c4-i5pdn-2wwof-oae",
            "c4isl-65rwf-emhk5-5ta5m-ngl73-rgrl3-tcc56-2hkja-4erqd-iivmy-7ae",
            "csyj4-zmann-ys6ge-3kzi6-onexi-obayx-2fvak-zersm-euci4-6pslt-lae",
            "cv73p-6v7zi-u67oy-7jc3h-qspsz-g5lrj-4fn7k-xrax3-thek2-sl46v-jae",
            "e66qm-3cydn-nkf4i-ml4rb-4ro6o-srm5s-x5hwq-hnprz-3meqp-s7vks-5qe",
            "ejbmu-grnam-gk6ol-6irwa-htwoj-7ihfl-goimw-hlnvh-abms4-47v2e-zqe",
            "eq6en-6jqla-fbu5s-daskr-h6hx2-376n5-iqabl-qgrng-gfqmv-n3yjr-mqe",
            "fuqsr-in2lc-zbcjj-ydmcw-pzq7h-4xm2z-pto4i-dcyee-5z4rz-x63ji-nae",
            "gmq5v-hbozq-uui6y-o55wc-ihop3-562wb-3qspg-nnijg-npqp5-he3cj-3ae",
            "io67a-2jmkw-zup3h-snbwi-g6a5n-rm5dn-b6png-lvdpl-nqnto-yih6l-gqe",
            "jtdsg-3h6gi-hs7o5-z2soi-43w3z-soyl3-ajnp3-ekni5-sw553-5kw67-nqe",
            "k44fs-gm4pv-afozh-rs7zw-cg32n-u7xov-xqyx3-2pw5q-eucnu-cosd4-uqe",
            "kp5jj-kpgmn-f4ohx-uqot6-wtbbr-lmtqv-kpkaf-gcksv-snkwm-43kmy-iae",
            "lhg73-sax6z-2zank-6oer2-575lz-zgbxx-ptudx-5korm-fy7we-kh4hl-pqe",
            "lspz2-jx4pu-k3e7p-znm7j-q4yum-ork6e-6w4q6-pijwq-znehu-4jabe-kqe",
            "mkbc3-fzim5-s5pye-pbnzo-uj5yv-raphe-ceecn-ejd6g-5poxm-dzuot-iae",
            "mpubz-g52jc-grhjo-5oze5-qcj74-sex34-omprz-ivnsm-qvvhr-rfzpv-vae",
            "nl6hn-ja4yw-wvmpy-3z2jx-ymc34-pisx3-3cp5z-3oj4a-qzzny-jbsv3-4qe",
            "o3ow2-2ipam-6fcjo-3j5vt-fzbge-2g7my-5fz2m-p4o2t-dwlc4-gt2q7-5ae",
            "opn46-zyspe-hhmyp-4zu6u-7sbrh-dok77-m7dch-im62f-vyimr-a3n2c-4ae",
            "pae4o-o6dxf-xki7q-ezclx-znyd6-fnk6w-vkv5z-5lfwh-xym2i-otrrw-fqe",
            "pjljw-kztyl-46ud4-ofrj6-nzkhm-3n4nt-wi3jt-ypmav-ijqkt-gjf66-uae",
            "pzp6e-ekpqk-3c5x7-2h6so-njoeq-mt45d-h3h6c-q3mxf-vpeq5-fk5o7-yae",
            "qdvhd-os4o2-zzrdw-xrcv4-gljou-eztdp-bj326-e6jgr-tkhuc-ql6v2-yqe",
            "qxesv-zoxpm-vc64m-zxguk-5sj74-35vrb-tbgwg-pcird-5gr26-62oxl-cae",
            "rtvil-s5u5d-jbj7o-prlhw-bzlr5-3j5kn-2iu7a-jq2hl-avkhn-w7oa7-6ae",
            "shefu-t3kr5-t5q3w-mqmdq-jabyv-vyvtf-cyyey-3kmo4-toyln-emubw-4qe",
            "snjp4-xlbw4-mnbog-ddwy6-6ckfd-2w5a2-eipqo-7l436-pxqkh-l6fuv-vae",
            "vcpt7-niq42-6snup-7kcgy-cndz6-srq6n-h6vwi-oswri-a3guc-v5ssd-5qe",
            "w4asl-4nmyj-qnr7c-6cqq4-tkwmt-o26di-iupkq-vx4kt-asbrx-jzuxh-4ae",
            "x33ed-h457x-bsgyx-oqxqf-6pzwv-wkhzr-rm2j3-npodi-purzm-n66cg-gae",
            "xlkub-3thlm-uha3c-hqmfw-qykp5-6rldi-hpfxy-nwyxy-w6bbk-tpg5h-vqe",
            "xok3w-cnepj-fg6aa-cjitt-uoxod-4ddsy-nc7dq-zwudz-o6jar-rzstb-gqe",
            "yinp6-35cfo-wgcd2-oc4ty-2kqpf-t4dul-rfk33-fsq3r-mfmua-m2ngh-jqe",
        ]
        .iter()
        .filter_map(|p| match PrincipalId::from_str(p) {
            Ok(p) => Some(SubnetId::new(p)),
            Err(e) => {
                println!("{LOG_PREFIX}Coudln't parse {p} as a SubnetId due to error: {e:?}",);
                None
            }
        }),
    ));
}

pub(crate) fn is_chunkifying_large_values_enabled() -> bool {
    IS_CHUNKIFYING_LARGE_VALUES_ENABLED.get()
}

#[cfg(any(test, feature = "canbench-rs"))]
pub fn temporarily_enable_chunkifying_large_values() -> Temporary {
    Temporary::new(&IS_CHUNKIFYING_LARGE_VALUES_ENABLED, true)
}

#[cfg(test)]
pub(crate) fn temporarily_disable_chunkifying_large_values() -> Temporary {
    Temporary::new(&IS_CHUNKIFYING_LARGE_VALUES_ENABLED, false)
}

pub(crate) fn is_node_swapping_enabled() -> bool {
    IS_NODE_SWAPPING_ENABLED.get()
}

#[cfg(test)]
pub(crate) fn temporarily_disable_node_swapping() -> Temporary {
    Temporary::new(&IS_NODE_SWAPPING_ENABLED, false)
}

#[cfg(test)]
pub(crate) fn temporarily_enable_node_swapping() -> Temporary {
    Temporary::new(&IS_NODE_SWAPPING_ENABLED, true)
}

#[cfg(any(test, feature = "test"))]
pub mod temporary_overrides {
    use super::*;

    pub fn test_set_swapping_status(override_value: bool) {
        IS_NODE_SWAPPING_ENABLED.replace(override_value);
    }

    pub fn test_set_swapping_whitelisted_callers(override_callers: Vec<PrincipalId>) {
        let policy = FeatureAccessPolicy::allow(override_callers);
        NODE_SWAPPING_CALLERS_POLICY.replace(policy);
    }

    pub fn test_set_swapping_enabled_subnets(override_subnets: Vec<SubnetId>) {
        let policy = FeatureAccessPolicy::allow(override_subnets);
        NODE_SWAPPING_SUBNETS_POLICY.replace(policy);
    }
}

pub(crate) fn is_node_swapping_enabled_on_subnet(subnet_id: SubnetId) -> bool {
    NODE_SWAPPING_SUBNETS_POLICY.with_borrow(|subnet_policy| subnet_policy.is_allowed(&subnet_id))
}

pub(crate) fn is_node_swapping_enabled_for_caller(caller: PrincipalId) -> bool {
    NODE_SWAPPING_CALLERS_POLICY.with_borrow(|caller_policy| caller_policy.is_allowed(&caller))
}
