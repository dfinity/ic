use crate::certification::recertify_registry;
use crate::mutations::node_management::common::find_subnet_for_node;
use crate::{pb::v1::RegistryCanisterStableStorage, registry::Registry};
use ic_base_types::PrincipalId;
use ic_protobuf::registry::node::v1::{NodeRecord, NodeRewardType};
use ic_protobuf::registry::node_operator::v1::NodeOperatorRecord;
use ic_protobuf::registry::subnet::v1::SubnetListRecord;
use ic_registry_keys::{
    make_node_operator_record_key, make_node_record_key, make_subnet_list_record_key,
};
use ic_registry_transport::{pb::v1::RegistryMutation, update};
use ic_types::NodeId;
use maplit::btreemap;
use prost::Message;
use std::str::FromStr;

pub fn canister_post_upgrade(
    registry: &mut Registry,
    registry_storage: RegistryCanisterStableStorage,
) {
    // Purposefully fail the upgrade if we can't find authz information.
    // Best to have a broken canister, which we can reinstall, than a
    // canister without authz information.

    registry.from_serializable_form(
        registry_storage
            .registry
            .expect("Error decoding from stable"),
    );

    // Registry data migrations should be implemented as follows:
    let mutation_batches_due_to_data_migrations = {
        let mut total_batches = 0;

        let mutations = fix_node_operators_corrupted(registry);
        if !mutations.is_empty() {
            registry.maybe_apply_mutation_internal(mutations);
            total_batches += 1;
        }

        let mutations = convert_type1dot1_nodes_to_type4dot5(registry);
        if !mutations.is_empty() {
            registry.maybe_apply_mutation_internal(mutations);
            total_batches += 1;
        }

        total_batches
    };
    //
    // When there are no migrations, `mutation_batches_due_to_data_migrations` should be set to `0`.
    // let mutation_batches_due_to_data_migrations = 0;

    registry.check_global_state_invariants(&[]);
    // Registry::from_serializable_from guarantees this always passes in this function
    // because it fills in missing versions to maintain that invariant
    registry.check_changelog_version_invariants();

    // This is no-op outside Canister environment, and is therefore not under unit-test coverage
    recertify_registry(registry);

    // ANYTHING BELOW THIS LINE SHOULD NOT MUTATE STATE

    if let Some(pre_upgrade_version) = registry_storage.pre_upgrade_version {
        assert_eq!(
            pre_upgrade_version + mutation_batches_due_to_data_migrations,
            registry.latest_version(),
            "The serialized last version watermark doesn't match what's found in the records. \
                     Watermark: {:?}, Last version: {:?}",
            pre_upgrade_version,
            registry.latest_version()
        );
    }
}

fn create_node_operator_mutation(
    registry: &Registry,
    principal_id_str: &str,
    modify_record: fn(&mut NodeOperatorRecord, PrincipalId),
) -> Result<RegistryMutation, String> {
    let node_operator_id = PrincipalId::from_str(principal_id_str)
        .map_err(|e| format!("Failed to parse principal ID {}: {}", principal_id_str, e))?;

    let registry_value = registry
        .get(
            make_node_operator_record_key(node_operator_id).as_bytes(),
            registry.latest_version(),
        )
        .ok_or(format!(
            "Failed to find NodeOperatorRecord for operator {}",
            node_operator_id
        ))?;

    let mut record = NodeOperatorRecord::decode(registry_value.value.as_slice()).map_err(|e| {
        format!(
            "Failed to decode NodeOperatorRecord for operator {}: {}",
            node_operator_id, e
        )
    })?;

    modify_record(&mut record, node_operator_id);

    Ok(update(
        make_node_operator_record_key(node_operator_id),
        record.encode_to_vec(),
    ))
}

fn fix_node_operators_corrupted(registry: &Registry) -> Vec<RegistryMutation> {
    let mut mutations = Vec::new();

    // 3nu7r - ujq4k -------------------------------------------------------------------------------

    match create_node_operator_mutation(
        registry,
        "3nu7r-l6i5c-jlmhi-fmmhm-4wcw4-ndlwb-yovrx-o3wxh-suzew-hvbbo-7qe",
        |record, principal_id_key| {
            record.node_operator_principal_id = principal_id_key.to_vec();
            record.max_rewardable_nodes = btreemap! {
                NodeRewardType::Type1dot1.to_string() => 19
            };
        },
    ) {
        Ok(mutation) => mutations.push(mutation),
        Err(e) => ic_cdk::println!("Error creating mutation for 3nu7r: {}", e),
    }

    match create_node_operator_mutation(
        registry,
        "ujq4k-55epc-pg2bt-jt2f5-6vaq3-diru7-edprm-42rd2-j7zzd-yjaai-2qe",
        // Dummy mutation used to increase the registry version for this record so that clients
        // can reconcile the record with the last record present in the registry
        |_, _| {},
    ) {
        Ok(mutation) => mutations.push(mutation),
        Err(e) => ic_cdk::println!("Error creating mutation for ujq4k: {}", e),
    }

    // bmlhw - spsu4 -------------------------------------------------------------------------------

    match create_node_operator_mutation(
        registry,
        "bmlhw-kinr6-7cyv5-3o3v6-ic6tw-pnzk3-jycod-6d7sw-owaft-3b6k3-kqe",
        |record, principal_id_key| {
            record.node_operator_principal_id = principal_id_key.to_vec();
            record.max_rewardable_nodes = btreemap! {
                NodeRewardType::Type1.to_string() => 14
            };
        },
    ) {
        Ok(mutation) => mutations.push(mutation),
        Err(e) => ic_cdk::println!("Error creating mutation for bmlhw: {}", e),
    }

    match create_node_operator_mutation(
        registry,
        "spsu4-5hl4t-bfubp-qvoko-jprw4-wt7ou-nlnbk-gb5ib-aqnoo-g4gl6-kae",
        // Dummy mutation used to increase the registry version for this record so that clients
        // can reconcile the record with the last record present in the registry
        |_, _| {},
    ) {
        Ok(mutation) => mutations.push(mutation),
        Err(e) => ic_cdk::println!("Error creating mutation for spsu4: {}", e),
    }

    // redpf - 2rqo7 -------------------------------------------------------------------------------

    match create_node_operator_mutation(
        registry,
        "redpf-rrb5x-sa2it-zhbh7-q2fsp-bqlwz-4mf4y-tgxmj-g5y7p-ezjtj-5qe",
        |record, principal_id_key| {
            record.node_operator_principal_id = principal_id_key.to_vec();
        },
    ) {
        Ok(mutation) => mutations.push(mutation),
        Err(e) => ic_cdk::println!("Error creating mutation for redpf: {}", e),
    }

    match create_node_operator_mutation(
        registry,
        "2rqo7-ot2kv-upof3-odw3y-sjckb-qeibt-n56vj-7b4pt-bvrtg-zay53-4qe",
        |record, _| {
            record.rewardable_nodes = btreemap! {
                NodeRewardType::Type1dot1.to_string() => 28
            };
        },
    ) {
        Ok(mutation) => mutations.push(mutation),
        Err(e) => ic_cdk::println!("Error creating mutation for 2rqo7: {}", e),
    }

    mutations
}

/// One-time migration converting the reward type of a fixed set of 100
/// currently unassigned nodes from `type1.1` to `type4.5` (a cloud-engine
/// sub-variant). The node ids were selected with the DRE tool among the
/// healthy, unassigned `type1.1` nodes.
///
/// The migration is idempotent and self-guarding: a node is only mutated while
/// its reward type is still `type1.1`, so re-running it on a subsequent upgrade
/// produces no mutations (and therefore no extra changelog batch).
fn convert_type1dot1_nodes_to_type4dot5(registry: &Registry) -> Vec<RegistryMutation> {
    const NODE_IDS_TO_CONVERT: [&str; 100] = [
        "2h77x-ywmcq-vxt3r-t2ml4-43px2-wdn6u-kqus7-hmdzo-eu4qm-4afbe-pqe",
        "2klnm-d2wrs-tnn3k-mphtu-fgdmq-e2bny-juyda-ww7hv-l6pzx-35tkm-kae",
        "4mdc3-dywcq-5uuj5-uv4z7-otsmu-pb4sq-iu3eo-4b7z2-5a7rl-xzpcm-gae",
        "5efad-ubiwy-ejsis-o2cfe-7atnx-lzy7j-mu6pe-wig7g-e426v-wrn5p-5qe",
        "6cknu-fqcy2-2keuj-gicsk-6ecfx-bwcjo-ppw7m-ler7z-bwjah-jvdbj-fqe",
        "2aked-uorat-s6ubw-kqnnf-lp3ep-ykinc-xcare-wws7l-pzhim-ixk7p-zae",
        "2ric4-rm3mb-x4rc4-xv7f3-o3fq6-oryc6-oyn4x-cpiyz-woh7c-eyorf-qae",
        "6imhm-ocz2z-gn6x5-hpx3k-52pjt-5roy5-uc3ua-mmi42-onrf2-yq3ie-qqe",
        "6souc-qqdhe-7rxo2-fvtpn-suxfz-dnvtb-k2q2h-n3pvf-ttjvc-b4lj7-uqe",
        "7klzr-dpt77-vylqj-ji5lh-5zlrb-kwlis-3d7wy-dj2kw-fjlyt-7jjts-bqe",
        "364us-2y667-wg3qr-zordv-pqlou-bra44-gjhhv-2jtnc-mr6xr-kmenh-4qe",
        "3hmzi-i26ng-ckcmj-lev6h-ssbbl-3qsft-p6kyo-3e5rz-2qfsj-nsbjk-kae",
        "52ykw-kxabl-twia6-x24hj-4last-tmdmd-4v3tf-fwtkh-mrdat-3vcpn-dqe",
        "5lwhb-2a5za-eatmy-3e7hy-otnjn-h3c6l-ov53b-qpt7u-cutea-wcxiv-kqe",
        "5nkgj-r45dd-5qojg-ecnqn-ig7uo-hqndz-v5udk-gxygg-bfigl-r6lh3-jae",
        "24fsy-32ewt-f447o-7p5th-njgys-2qawz-gk5iw-k4qzj-7opkx-ofbm3-5qe",
        "4nldz-xzkm4-2y6gi-nw2s4-wuz54-xonqo-alj57-tgeqb-hbeyf-epcgh-kqe",
        "5ezcu-l5n6q-3ddda-ap3qi-ir7gl-zvksq-lsino-d3uji-h66zk-53u6m-3qe",
        "5krcu-e3t4g-aa2al-x6tzs-o4a4p-ulx3p-sbk2n-fregk-xswvx-yrueq-eqe",
        "5u7le-tmied-z6u52-adg7a-mo3wa-yry7m-awfv7-rbiax-o3oc3-le4q6-oae",
        "2kvun-y7qfw-krhhm-aftvi-ll56o-yvkuj-noc5w-xozic-mnewn-i47x5-tqe",
        "5v2bn-uoktd-3ne5o-lxcws-askra-k4iyq-fxt2j-3gdpc-t2gxb-hiybx-4ae",
        "6kuom-ucaom-u7xm5-s556x-3rnyk-hdjzd-wkxnx-wsejf-vpnhz-lniqi-nae",
        "7jjmd-p43kv-2h3bp-yrcuv-gc3ia-zaess-2rj6p-p4xgr-f43xy-6hk55-xqe",
        "aid27-4kobq-rsaze-7bvbc-pwg2a-nrhj3-uhpne-yjdis-3rrx4-chcxm-rae",
        "25o6i-sdjsl-vjlfn-6duch-vskdu-26pf5-cwibg-zooqk-sdn2e-cgugm-tae",
        "3tbjz-erih4-dfm4f-ul544-mgyqe-eeesn-hhggl-ooq2x-czsh2-nuy6n-cae",
        "7g3hi-3ypt3-4u3qa-6jmvf-eptxu-loh2i-poiih-fmgxl-7vlyd-g5hy3-nqe",
        "d2ffc-r2mqq-yx3u5-f5j47-davp4-lske5-57oal-ilwph-o2hex-tqaz2-7qe",
        "dgul7-oxqwq-uvafn-evmwt-mjrzb-okeie-rykhk-wgrmv-o6kkb-kpco3-qqe",
        "22pkm-wfc33-m326g-x2gug-3admr-sxeaf-foujt-3c4jw-uksvc-dglgf-gae",
        "33s7q-wsjbb-6iyyw-bwfuz-lq2yr-lu7gt-qhc7s-oyxrq-vhfnm-wbaxb-dqe",
        "467sz-tjcqd-k2nce-vrhe7-juh6s-2oohm-3ydhi-cms7g-lzo5o-7zyzs-aqe",
        "4l7la-7zmuq-ois3n-leowc-2xvrh-3vozh-iutqe-ev2xx-nkgni-atitg-5qe",
        "545fc-ouac2-s7etx-5oiuv-2beh3-s3n7u-xxkvm-6abvp-c6aue-nypdg-2ae",
        "4lqcl-tzzs3-jztya-ro7ak-ew5ue-l3tlc-5cxk3-4jt7m-z66st-ad5ld-aae",
        "4u2d3-qciqq-qqjkh-q3dbm-gyvu3-6syso-consf-5i2n2-hglur-c6tuj-jae",
        "dcuji-4bkgh-7easb-dlrne-hsa4w-nomdq-dponk-3ksec-5s6dk-7ljmr-eae",
        "dvjhp-rndgl-zxrkg-aspaw-2iaif-r4t5j-u5pg2-qhzqh-vspzd-dqzr5-tae",
        "ega5w-ekfo7-lejfc-fve6j-vnml3-2nmxj-flw2p-564o4-rhier-bz73x-aae",
        "2r7p2-nll7a-gipvg-6wtpt-pgss2-lge3d-gylsc-bvo3n-7u4am-xeom5-nqe",
        "5zrsg-qcrev-mm3cc-km55r-kk2ug-w6dkh-ljlnk-vj26z-yqmez-ftbfk-xqe",
        "6qzmz-5jtwm-kuv6j-wa3dv-n7yse-ex5rl-vmbx5-suunp-hdqxe-bnerj-iqe",
        "6ucn7-aiavt-uucq2-cvnjf-nwmr5-vetsg-q73h7-uzqjt-klm5x-e7qxu-mqe",
        "77ugi-5645h-z5227-mqssl-mqbhp-cgsko-y2bmc-nqecb-plpuv-orjek-lae",
        "2ew2x-bmzxs-o6sw6-xbxv6-efhzc-47y5k-vy5ce-luaqo-lecdi-33z4i-gqe",
        "3s6fj-wulzc-ml7vo-vpvhj-4loap-25asb-m6efr-f52qf-ehpxb-7mh3k-vae",
        "3smci-63tqe-6q5xc-wpdmj-pnhan-own4t-6km2r-77mfh-c2h7d-xzunk-cqe",
        "4txlq-o5ukt-if4pj-adxtx-jwp42-jch73-z5nfy-77gi5-4lll7-eou2p-rqe",
        "53p5r-qqup5-e2z7n-eeg65-kzklr-ekrsa-6g3hc-vrmqu-wtows-6q2t7-6ae",
        "4ql5c-ky7on-eceuo-hqkl7-lzxvo-mrjco-znpn5-hfs4b-kuel6-35hmg-qqe",
        "5oph7-csqih-dxfky-syp3w-fvcpv-2vfmy-gh3i6-mcpko-j2cmp-radto-wae",
        "bkic5-dprya-cwsyz-jcgow-pz2ks-khwuq-n3uoa-a6m2a-ohtkf-gdjpu-xae",
        "blcw7-64reu-4kwke-es7l7-v5uel-hi4ll-a4oki-uw2n7-3dbdy-vdzgh-oqe",
        "c6on3-qhvg5-k5v5v-wcson-2wek7-blvc7-xnr54-gyakg-6etp7-khw33-qqe",
        "7gdir-f577j-c4hmo-nowiq-uwgp3-7n3br-q6d3m-7uqi6-643jo-kosf3-wae",
        "awhiz-gcfjf-z7376-6sohx-tafjb-om2yt-wbneu-qhkqz-ukjcs-vj3uq-bae",
        "d732t-exzjy-lo3r4-vzxtz-nldaw-v7azx-4nktr-klpsx-hxfhj-2tsur-7qe",
        "drzg7-h3kkr-xhdkp-4lxzs-2fxkt-a4y6t-vlhwz-syroq-qm5bc-fti7s-wqe",
        "eq4pj-hov4w-yqrfn-dcmqu-4vhge-ehqcb-2jwk4-xlj5x-6wiiy-fq34w-zqe",
        "3bcpj-2mjor-ykckj-5m2ya-i4zn3-rdtfi-vofgu-elihb-53mje-fpywx-dae",
        "4fxl5-7naq3-jw64y-qyetj-27kir-bi4r4-tdyyo-h64th-rqssm-u6ua6-2ae",
        "bs7jr-2hrlr-krdlk-qmuzs-hkphr-3jzx5-f5smp-6xwyp-inleo-xg4qg-iqe",
        "gby4c-h4c2r-r6kl3-uecfq-itfw7-muowp-e5imq-d7w5o-5hat7-zuwya-3ae",
        "jbriu-rwv4a-4pvxu-grmsy-2lnbj-7t4o2-j2lbe-gkf3c-i73ir-klskz-rae",
        "3k35b-gsfkj-bbcx5-35roy-ixma5-yn6ug-3btuq-6qdoj-zzt4v-vgpze-wqe",
        "4aarv-httc6-rtrjt-mbswg-nplqa-sbyuw-jiniq-vjz4l-yhb3p-af3hy-hae",
        "blwrh-vy7in-z6m26-cvugi-ra7fw-spp4m-rpuca-3xt7e-6srkk-qxlgi-rqe",
        "chlz3-enuar-5oa26-wloxe-pat7q-6xxdo-v7ipr-utdst-s6y42-jczmb-6ae",
        "fsm34-pu4a7-dpo5w-efe3l-s633z-wfvua-sbzid-nsoca-4mrrt-23ice-zae",
        "3ejbg-pmmzm-fojb3-cmzip-arbvm-q427h-73ej5-7cvx7-nmp4n-zfdfc-iqe",
        "3rmvo-jfqce-2ajpr-fghze-uc46m-innjh-aay5p-xlfml-2hipo-gatov-7qe",
        "5bw5k-uuvti-kxds2-knvoo-rbkpw-wy6us-fgpua-mzssx-pq5tp-udbap-6ae",
        "5tsiv-4llva-2eh4y-zjheg-s2upy-umawn-zdw4m-hhy43-a6bvc-rmnqf-rqe",
        "5wqk6-vib2n-2363t-b4nnb-vxyx5-tf2lm-4pmd2-d656p-xxvte-lkhh6-5ae",
        "2qlts-dmxtt-ly45j-m2qcg-tde6r-i337l-shimz-mtshu-tp3ir-hkbyt-dae",
        "36vim-qv27i-6j52j-aaezj-s4lgp-ex65o-3j2ho-rdvl6-odnhe-32k7e-jae",
        "3h65u-r2zrh-ydt5b-sura7-p3tdl-d2xcx-4kvwe-x464t-cug7r-uzlvr-vae",
        "4tm5f-kojws-d53sx-t26bm-lgpwi-zspap-bepp6-3jl7c-rxg3p-iwhh2-eqe",
        "55aa5-j6ipq-ypfns-k6qjr-zncgq-6q7xm-5oyri-mwswh-thrpu-jxo2i-hae",
        "2qclu-jxgmm-cjrng-h2wwe-i6ku5-dmj6p-e5qzy-ktplm-yu6kw-zkao2-xae",
        "4vpak-qnqtn-vggke-um4f2-zkk2m-awc6p-bkhi5-cm22y-zhdiz-yx5rt-cqe",
        "4whgz-3ksfr-4rroh-dluex-fptua-mrxjo-uzmgg-lvuws-oe72b-aynhj-fae",
        "5kc7d-5fv6m-3ps2z-n4gf2-vm63s-a3nyz-7g4gv-rkgg2-nkccw-arwq3-wae",
        "62pbm-psjwv-sf3fc-hyisj-5qsoh-fvpac-tacne-jotrs-owsmo-3j7jo-wqe",
        "24iqu-pqcde-wwgok-6sndd-lfhaj-gyjhu-zg73l-sqvwi-xbevy-kcuqp-4ae",
        "2k7jv-zmube-yklqn-i3z46-mdvk6-xshpb-gb5jz-kkg7z-vlqh4-xmqyw-hae",
        "5dfvs-7jxus-lmnm7-4o3jm-buisw-55hay-6eofd-i27dk-ecrd4-4evso-hae",
        "76mrs-zalfr-lfsvi-6vdnf-aqk3j-uaajm-2vo7c-mqez7-7y4oe-srw5e-zae",
        "7prmk-rel7w-5znpq-ir3y6-7twqb-zh2t5-buguy-sdu27-fjdw3-dg6xl-fae",
        "2bicw-jtnmv-rjuil-2p4px-npmif-w37em-qreuq-4lxof-7wkcl-a3gan-oqe",
        "3c6dj-5mjuu-imudt-5z457-prrqe-f5m7r-axjky-ocoix-kf6de-xgi6u-2ae",
        "3iqf7-6febz-vfgsb-z6ryj-c2vwi-n54ss-5zmjo-52ldz-z5are-aabr3-fqe",
        "42rj3-7tytn-gbyte-cyj5m-tkzta-pkezr-ijl6a-larzs-cjo2r-r3lhz-bqe",
        "4l2e6-g2ujv-ksiel-cfrww-zwyhq-26nbr-f2jik-xhxfp-2xkd3-hmx23-6ae",
        "4e2ty-mcqal-loqca-j2d5b-qgou4-n6y6h-yojne-kvqlg-ld4jx-rjree-3qe",
        "63bsb-jbwja-suy6t-ftoim-ooxag-jiytd-rayru-4kgx5-tx5gb-2b2hj-qae",
        "aj6th-bkul5-ehzbh-mylom-bf3uf-ei3vi-u5kqb-cpy3h-yegi7-cbzrx-wqe",
        "c4wpu-73dyn-hmm33-sfkz3-pioei-nylbz-loegx-up6uj-nvqvu-d7zsq-iae",
        "ccosg-l4vd4-wl6t2-jmrbs-zai42-zctdm-svvgu-fb3zg-jmot3-cjn64-2qe",
    ];

    // Fetched defensively: a registry without a subnet list record (e.g. in
    // tests) means no node is assigned, so we treat it as empty rather than
    // panicking like `Registry::get_subnet_list_record`.
    let subnet_list_record = registry
        .get(
            make_subnet_list_record_key().as_bytes(),
            registry.latest_version(),
        )
        .map(|registry_value| {
            SubnetListRecord::decode(registry_value.value.as_slice())
                .expect("Failed to decode SubnetListRecord")
        })
        .unwrap_or_default();
    let mut mutations = Vec::new();

    for node_id_str in NODE_IDS_TO_CONVERT {
        let node_id = match PrincipalId::from_str(node_id_str) {
            Ok(principal_id) => NodeId::from(principal_id),
            Err(e) => {
                ic_cdk::println!("Failed to parse node id '{node_id_str}': {e}. Skipping.");
                continue;
            }
        };

        let node_key = make_node_record_key(node_id);
        let registry_value = match registry.get(node_key.as_bytes(), registry.latest_version()) {
            Some(value) => value,
            None => {
                ic_cdk::println!("Node {node_id} not found in registry, skipping");
                continue;
            }
        };

        let mut node_record = match NodeRecord::decode(registry_value.value.as_slice()) {
            Ok(record) => record,
            Err(e) => {
                ic_cdk::println!("Error decoding NodeRecord for node {node_id}: {e}");
                continue;
            }
        };

        // Self-guarding: only convert nodes that are still `type1.1`.
        if node_record.node_reward_type != Some(NodeRewardType::Type1dot1 as i32) {
            continue;
        }

        // Safety guard: only convert nodes that are still unassigned. If a node
        // from the fixed list got assigned to a subnet between selection and
        // upgrade, we skip it to keep this migration scoped to unassigned nodes
        // and to avoid violating the `check_node_type4_iff_cloud_engine` invariant
        // (e.g. if it was assigned to a non-cloud-engine subnet).
        if find_subnet_for_node(registry, node_id, &subnet_list_record).is_some() {
            ic_cdk::println!("Node {node_id} is assigned to a subnet, skipping type4.5 conversion");
            continue;
        }

        node_record.node_reward_type = Some(NodeRewardType::Type4dot5 as i32);
        mutations.push(update(node_key, node_record.encode_to_vec()));
    }

    mutations
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        common::test_helpers::{
            empty_mutation, get_invariant_compliant_subnet_record, invariant_compliant_registry,
        },
        registry::{EncodedVersion, Version},
        registry_lifecycle::Registry,
    };
    use ic_base_types::PrincipalId;
    use ic_registry_keys::{make_subnet_list_record_key, make_subnet_record_key};
    use ic_registry_transport::{insert, upsert};
    use ic_test_utilities_types::ids::{node_test_id, subnet_test_id};
    use maplit::btreemap;
    use std::str::FromStr;

    fn stable_storage_from_registry(
        registry: &Registry,
        override_version: Option<Version>,
    ) -> Vec<u8> {
        let mut serialized = Vec::new();
        let ss = RegistryCanisterStableStorage {
            registry: Some(registry.serializable_form()),
            pre_upgrade_version: override_version.or_else(|| Some(registry.latest_version())),
        };
        ss.encode(&mut serialized)
            .expect("Error serializing to stable.");
        serialized
    }

    #[test]
    fn post_upgrade_succeeds_with_valid_registry() {
        // given valid registry state encoded for stable storage
        let registry = invariant_compliant_registry(0);
        let stable_storage_bytes = stable_storage_from_registry(&registry, None);

        // we can use canister_post_upgrade to initialize a new registry correctly
        let mut new_registry = Registry::new();
        let registry_storage =
            RegistryCanisterStableStorage::decode(stable_storage_bytes.as_slice())
                .expect("Error decoding from stable.");
        canister_post_upgrade(&mut new_registry, registry_storage);

        // and the version is right
        assert_eq!(new_registry.latest_version(), 1);
    }

    #[test]
    #[should_panic(expected = "Error decoding from stable.")]
    fn post_upgrade_fails_when_stable_storage_fails_decoding() {
        let mut registry = Registry::new();
        // try with garbage to check first error condition
        let stable_storage_bytes = [1, 2, 3];
        let registry_storage =
            RegistryCanisterStableStorage::decode(stable_storage_bytes.as_slice())
                .expect("Error decoding from stable.");
        canister_post_upgrade(&mut registry, registry_storage);
    }

    #[test]
    #[should_panic(expected = "Error decoding from stable")]
    fn post_upgrade_fails_when_registry_missing_from_storage() {
        // Given stable storage that's missing a registry
        let mut serialized = Vec::new();
        let ss = RegistryCanisterStableStorage {
            registry: None,
            pre_upgrade_version: Some(1_u64),
        };
        ss.encode(&mut serialized)
            .expect("Error serializing to stable.");

        let mut registry = Registry::new();

        // When we try to run canister_post_upgrade
        // Then we panic
        let registry_storage = RegistryCanisterStableStorage::decode(serialized.as_slice())
            .expect("Error decoding from stable.");
        canister_post_upgrade(&mut registry, registry_storage);
    }

    #[test]
    #[should_panic(expected = "[Registry] invariant check failed with message: no system subnet")]
    fn post_upgrade_fails_on_global_state_invariant_check_failure() {
        // We only check a single failure mode here,
        // since the rest should be under other test coverage
        let registry = Registry::new();
        let stable_storage_bytes = stable_storage_from_registry(&registry, None);

        // with our bad mutation, this should throw
        let mut new_registry = Registry::new();
        let registry_storage =
            RegistryCanisterStableStorage::decode(stable_storage_bytes.as_slice())
                .expect("Error decoding from stable.");
        canister_post_upgrade(&mut new_registry, registry_storage);
    }

    #[test]
    fn post_upgrade_fills_in_missing_versions_to_maintain_invariant() {
        // We only check a single failure mode, since the rest should be under other test coverage
        let mut registry = invariant_compliant_registry(0);
        registry
            .changelog
            .insert(EncodedVersion::from(7), empty_mutation());
        let stable_storage_bytes = stable_storage_from_registry(&registry, Some(7_u64));

        let mut new_registry = Registry::new();
        let registry_storage =
            RegistryCanisterStableStorage::decode(stable_storage_bytes.as_slice())
                .expect("Error decoding from stable.");
        canister_post_upgrade(&mut new_registry, registry_storage);

        // missing versions are added by the deserializer
        let mut sorted_changelog_versions = new_registry
            .changelog()
            .iter()
            .map(|(encoded_version, _)| encoded_version.as_version())
            .collect::<Vec<u64>>();
        sorted_changelog_versions.sort_unstable();
        // we expect all intermediate versions to be present
        assert_eq!(sorted_changelog_versions, vec![1, 2, 3, 4, 5, 6, 7]);
    }

    #[test]
    #[should_panic(
        expected = "The serialized last version watermark doesn't match what's found in the records. \
                     Watermark: 100, Last version: 1"
    )]
    fn post_upgrade_fails_when_registry_decodes_different_version() {
        // Given a mismatched stable storage version from the registry
        let registry = invariant_compliant_registry(0);
        let stable_storage_bytes = stable_storage_from_registry(&registry, Some(100_u64));
        // then we panic when decoding
        let mut new_registry = Registry::new();
        let registry_storage =
            RegistryCanisterStableStorage::decode(stable_storage_bytes.as_slice())
                .expect("Error decoding from stable.");
        canister_post_upgrade(&mut new_registry, registry_storage);
    }

    #[test]
    fn test_fix_all_and_only_node_operators_corrupted() {
        let mut registry = invariant_compliant_registry(0);
        let mut node_operator_additions = Vec::new();

        // This is a good record that should be left untouched
        let node_operator_good = PrincipalId::from_str(
            "2aemz-63apz-bds45-nypax-oj52g-fyl6i-sjhtv-ysu5t-hqvve-ygtcr-yae",
        )
        .unwrap();
        let record_good = NodeOperatorRecord {
            node_operator_principal_id: node_operator_good.to_vec(),
            dc_id: "dummy_dc_id_1".to_string(),
            ipv6: Some("dummy_ipv6_1".to_string()),
            max_rewardable_nodes: btreemap! { "type3.1".to_string() => 6},
            ..NodeOperatorRecord::default()
        };
        node_operator_additions.push(insert(
            make_node_operator_record_key(node_operator_good),
            record_good.encode_to_vec(),
        ));

        // 3nu7r is corrupted and should be fixed
        let node_operator_3nu7r_k = PrincipalId::from_str(
            "3nu7r-l6i5c-jlmhi-fmmhm-4wcw4-ndlwb-yovrx-o3wxh-suzew-hvbbo-7qe",
        )
        .unwrap();
        let node_operator_3nu7r_v = PrincipalId::from_str(
            "ujq4k-55epc-pg2bt-jt2f5-6vaq3-diru7-edprm-42rd2-j7zzd-yjaai-2qe",
        )
        .unwrap();
        let record_3nu7r = NodeOperatorRecord {
            node_operator_principal_id: node_operator_3nu7r_v.to_vec(),
            dc_id: "dummy_dc_id_3nu7r".to_string(),
            ipv6: Some("dummy_ipv6_3nu7r".to_string()),
            // Empty max rewardable nodes, should be filled in by the migration
            ..NodeOperatorRecord::default()
        };
        node_operator_additions.push(insert(
            make_node_operator_record_key(node_operator_3nu7r_k),
            record_3nu7r.encode_to_vec(),
        ));

        // ujq4k should be left untouched
        let node_operator_ujq4k = PrincipalId::from_str(
            "ujq4k-55epc-pg2bt-jt2f5-6vaq3-diru7-edprm-42rd2-j7zzd-yjaai-2qe",
        )
        .unwrap();
        let record_ujq4k = NodeOperatorRecord {
            node_operator_principal_id: node_operator_ujq4k.to_vec(),
            dc_id: "dummy_dc_id_ujq4k".to_string(),
            ipv6: Some("dummy_ipv6_ujq4k".to_string()),
            rewardable_nodes: btreemap! {"type1.1".to_string() => 9},
            max_rewardable_nodes: btreemap! {"type1.1".to_string() => 9},
            ..NodeOperatorRecord::default()
        };
        node_operator_additions.push(insert(
            make_node_operator_record_key(node_operator_ujq4k),
            record_ujq4k.encode_to_vec(),
        ));

        // bmlhw is corrupted and should be fixed
        let node_operator_bmlhw = PrincipalId::from_str(
            "bmlhw-kinr6-7cyv5-3o3v6-ic6tw-pnzk3-jycod-6d7sw-owaft-3b6k3-kqe",
        )
        .unwrap();
        let record_bmlhw = NodeOperatorRecord {
            node_operator_principal_id: node_operator_bmlhw.to_vec(),
            dc_id: "dummy_dc_id_bmlhw".to_string(),
            ipv6: Some("dummy_ipv6_bmlhw".to_string()),
            // Empty max rewardable nodes, should be filled in by the migration
            ..NodeOperatorRecord::default()
        };
        node_operator_additions.push(insert(
            make_node_operator_record_key(node_operator_bmlhw),
            record_bmlhw.encode_to_vec(),
        ));

        // spsu4 should be left untouched
        let node_operator_spsu4 = PrincipalId::from_str(
            "spsu4-5hl4t-bfubp-qvoko-jprw4-wt7ou-nlnbk-gb5ib-aqnoo-g4gl6-kae",
        )
        .unwrap();
        let record_spsu4 = NodeOperatorRecord {
            node_operator_principal_id: node_operator_spsu4.to_vec(),
            dc_id: "dummy_dc_id_spsu4".to_string(),
            ipv6: Some("dummy_ipv6_spsu4".to_string()),
            rewardable_nodes: btreemap! {"type1".to_string() => 14},
            max_rewardable_nodes: btreemap! {"type1.1".to_string() => 14},
            ..NodeOperatorRecord::default()
        };
        node_operator_additions.push(insert(
            make_node_operator_record_key(node_operator_spsu4),
            record_spsu4.encode_to_vec(),
        ));

        // redpf is corrupted and should be fixed
        let node_operator_redpf_k = PrincipalId::from_str(
            "redpf-rrb5x-sa2it-zhbh7-q2fsp-bqlwz-4mf4y-tgxmj-g5y7p-ezjtj-5qe",
        )
        .unwrap();
        let node_operator_redpf_v = PrincipalId::from_str(
            "2rqo7-ot2kv-upof3-odw3y-sjckb-qeibt-n56vj-7b4pt-bvrtg-zay53-4qe",
        )
        .unwrap();
        let record_redpf = NodeOperatorRecord {
            node_operator_principal_id: node_operator_redpf_v.to_vec(), // WRONG principal ID
            dc_id: "dummy_dc_id_redpf".to_string(),
            ipv6: Some("dummy_ipv6_redpf".to_string()),
            ..NodeOperatorRecord::default()
        };
        node_operator_additions.push(insert(
            make_node_operator_record_key(node_operator_redpf_k),
            record_redpf.encode_to_vec(),
        ));

        // 2rqo7 needs rewardable_nodes restored
        let node_operator_2rqo7 = PrincipalId::from_str(
            "2rqo7-ot2kv-upof3-odw3y-sjckb-qeibt-n56vj-7b4pt-bvrtg-zay53-4qe",
        )
        .unwrap();
        let record_2rqo7 = NodeOperatorRecord {
            node_operator_principal_id: node_operator_2rqo7.to_vec(),
            dc_id: "dummy_dc_id_2rqo7".to_string(),
            ipv6: Some("dummy_ipv6_2rqo7".to_string()),
            // Wrong rewardable nodes, should be fixed by the migration
            rewardable_nodes: btreemap! {},
            max_rewardable_nodes: btreemap! {"type1.1".to_string() => 28},
            ..NodeOperatorRecord::default()
        };
        node_operator_additions.push(insert(
            make_node_operator_record_key(node_operator_2rqo7),
            record_2rqo7.encode_to_vec(),
        ));

        registry.apply_mutations_for_test(node_operator_additions);
        let mutations = fix_node_operators_corrupted(&registry);
        // We expect 6 fixes: 3nu7r, ujq4k (dummy), bmlhw, spsu4 (dummy), redpf, 2rqo7
        assert_eq!(mutations.len(), 6);
        registry.apply_mutations_for_test(mutations);

        // Good record should be left untouched
        let record_good_got = registry.get_node_operator_or_panic(node_operator_good);
        let expected_record_good = record_good;
        assert_eq!(
            record_good_got, expected_record_good,
            "Assertion for NodeOperator good failed"
        );

        // 3nu7r should be fixed
        let record_3nu7r_got = registry.get_node_operator_or_panic(node_operator_3nu7r_k);
        let expected_record_3nu7r = NodeOperatorRecord {
            node_operator_principal_id: node_operator_3nu7r_k.to_vec(),
            max_rewardable_nodes: btreemap! {"type1.1".to_string() => 19},
            ..record_3nu7r
        };
        assert_eq!(
            record_3nu7r_got, expected_record_3nu7r,
            "Assertion for NodeOperator {node_operator_3nu7r_k} failed"
        );

        // bmlhw should be fixed
        let record_bmlhw_got = registry.get_node_operator_or_panic(node_operator_bmlhw);
        let expected_record_bmlhw = NodeOperatorRecord {
            node_operator_principal_id: node_operator_bmlhw.to_vec(),
            max_rewardable_nodes: btreemap! {"type1".to_string() => 14},
            ..record_bmlhw
        };
        assert_eq!(
            record_bmlhw_got, expected_record_bmlhw,
            "Assertion for NodeOperator {node_operator_bmlhw} failed"
        );

        // spsu4 should have a dummy mutation - record should remain unchanged
        let record_spsu4_got = registry.get_node_operator_or_panic(node_operator_spsu4);
        let expected_record_spsu4 = record_spsu4.clone();
        assert_eq!(
            record_spsu4_got, expected_record_spsu4,
            "Assertion for NodeOperator {node_operator_spsu4} failed - dummy mutation should not change record"
        );

        // ujq4k should have a dummy mutation - record should remain unchanged
        let record_ujq4k_got = registry.get_node_operator_or_panic(node_operator_ujq4k);
        let expected_record_ujq4k = record_ujq4k.clone();
        assert_eq!(
            record_ujq4k_got, expected_record_ujq4k,
            "Assertion for NodeOperator {node_operator_ujq4k} failed - dummy mutation should not change record"
        );

        // redpf should be fixed
        let record_redpf_got = registry.get_node_operator_or_panic(node_operator_redpf_k);
        let expected_record_redpf = NodeOperatorRecord {
            node_operator_principal_id: node_operator_redpf_k.to_vec(),
            ..record_redpf
        };
        assert_eq!(
            record_redpf_got, expected_record_redpf,
            "Assertion for NodeOperator {node_operator_redpf_k} failed"
        );

        // 2rqo7 should be fixed
        let record_2rqo7_got = registry.get_node_operator_or_panic(node_operator_2rqo7);
        let expected_record_2rqo7 = NodeOperatorRecord {
            node_operator_principal_id: node_operator_2rqo7.to_vec(),
            rewardable_nodes: btreemap! {"type1.1".to_string() => 28},
            ..record_2rqo7
        };
        assert_eq!(
            record_2rqo7_got, expected_record_2rqo7,
            "Assertion for NodeOperator {node_operator_2rqo7} failed"
        );
    }

    #[test]
    fn test_convert_type1dot1_nodes_to_type4dot5() {
        let mut registry = invariant_compliant_registry(0);

        // A node that is in the conversion list and currently `type1.1`.
        let listed_node = NodeId::from(
            PrincipalId::from_str(
                "22pkm-wfc33-m326g-x2gug-3admr-sxeaf-foujt-3c4jw-uksvc-dglgf-gae",
            )
            .unwrap(),
        );
        let listed_record = NodeRecord {
            node_reward_type: Some(NodeRewardType::Type1dot1 as i32),
            ..NodeRecord::default()
        };

        // A node that is in the conversion list but already has a different
        // reward type, so the self-guard must leave it untouched.
        let listed_other_type_node = NodeId::from(
            PrincipalId::from_str(
                "24fsy-32ewt-f447o-7p5th-njgys-2qawz-gk5iw-k4qzj-7opkx-ofbm3-5qe",
            )
            .unwrap(),
        );
        let listed_other_type_record = NodeRecord {
            node_reward_type: Some(NodeRewardType::Type3dot1 as i32),
            ..NodeRecord::default()
        };

        // A `type1.1` node that is NOT in the conversion list, so it must be
        // left untouched.
        let unlisted_node = node_test_id(424242);
        let unlisted_record = NodeRecord {
            node_reward_type: Some(NodeRewardType::Type1dot1 as i32),
            ..NodeRecord::default()
        };

        // A listed `type1.1` node that has since been assigned to a
        // (non-cloud-engine) subnet. The safety guard must leave it untouched,
        // because converting an assigned node to `type4.5` would violate the
        // `check_node_type4_iff_cloud_engine` invariant.
        let listed_assigned_node = NodeId::from(
            PrincipalId::from_str(
                "2h77x-ywmcq-vxt3r-t2ml4-43px2-wdn6u-kqus7-hmdzo-eu4qm-4afbe-pqe",
            )
            .unwrap(),
        );
        let listed_assigned_record = NodeRecord {
            node_reward_type: Some(NodeRewardType::Type1dot1 as i32),
            ..NodeRecord::default()
        };

        registry.apply_mutations_for_test(vec![
            insert(
                make_node_record_key(listed_node),
                listed_record.encode_to_vec(),
            ),
            insert(
                make_node_record_key(listed_other_type_node),
                listed_other_type_record.encode_to_vec(),
            ),
            insert(
                make_node_record_key(unlisted_node),
                unlisted_record.encode_to_vec(),
            ),
            insert(
                make_node_record_key(listed_assigned_node),
                listed_assigned_record.encode_to_vec(),
            ),
        ]);

        // Assign `listed_assigned_node` to a (non-cloud-engine) subnet by
        // inserting a subnet record whose membership contains it and listing
        // the subnet in the subnet list. We bypass `add_fake_subnet` (and its
        // NI-DKG/CUP setup) because the guard only reads subnet membership.
        let assigned_subnet_id = subnet_test_id(2024);
        let mut subnet_list_record = registry.get_subnet_list_record();
        subnet_list_record
            .subnets
            .push(assigned_subnet_id.get().into_vec());
        registry.apply_mutations_for_test(vec![
            insert(
                make_subnet_record_key(assigned_subnet_id),
                get_invariant_compliant_subnet_record(vec![listed_assigned_node]).encode_to_vec(),
            ),
            upsert(
                make_subnet_list_record_key(),
                subnet_list_record.encode_to_vec(),
            ),
        ]);

        let mutations = convert_type1dot1_nodes_to_type4dot5(&registry);
        // Only the unassigned listed `type1.1` node should be mutated; the
        // assigned one is skipped by the safety guard.
        assert_eq!(mutations.len(), 1);
        registry.apply_mutations_for_test(mutations);

        assert_eq!(
            registry.get_node_or_panic(listed_node).node_reward_type,
            Some(NodeRewardType::Type4dot5 as i32),
            "Listed type1.1 node should have been converted to type4.5"
        );
        assert_eq!(
            registry
                .get_node_or_panic(listed_other_type_node)
                .node_reward_type,
            Some(NodeRewardType::Type3dot1 as i32),
            "Listed node with a non-type1.1 reward type should be untouched"
        );
        assert_eq!(
            registry.get_node_or_panic(unlisted_node).node_reward_type,
            Some(NodeRewardType::Type1dot1 as i32),
            "Unlisted type1.1 node should be untouched"
        );
        assert_eq!(
            registry
                .get_node_or_panic(listed_assigned_node)
                .node_reward_type,
            Some(NodeRewardType::Type1dot1 as i32),
            "Listed type1.1 node assigned to a subnet should be untouched"
        );

        // Idempotency: a second run produces no further mutations.
        assert!(convert_type1dot1_nodes_to_type4dot5(&registry).is_empty());
    }
}
