use crate::certification::recertify_registry;
use crate::{pb::v1::RegistryCanisterStableStorage, registry::Registry};
use ic_base_types::PrincipalId;
use ic_protobuf::registry::node::v1::{NodeRecord, NodeRewardType};
use ic_protobuf::registry::node_operator::v1::NodeOperatorRecord;
use ic_protobuf::registry::subnet::v1::SubnetRecord as SubnetRecordPb;
use ic_protobuf::types::v1::master_public_key_id::KeyId;
use ic_registry_keys::{
    make_node_operator_record_key, make_node_record_key, make_subnet_record_key,
};
use ic_registry_transport::{pb::v1::RegistryMutation, update};
use ic_types::{NodeId, SubnetId};
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

        let mutations = fix_vetkd_pre_signatures_field(registry);
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

fn fix_vetkd_pre_signatures_field(registry: &Registry) -> Vec<RegistryMutation> {
    let mut mutations = Vec::new();

    let subnets_with_vetkeys: Vec<&str> = vec![
        // Subnet holding vetkd:Bls12_381_G2:key_1
        "pzp6e-ekpqk-3c5x7-2h6so-njoeq-mt45d-h3h6c-q3mxf-vpeq5-fk5o7-yae",
        // Subnet holding vetkd:Bls12_381_G2:key_1 backup
        "uzr34-akd3s-xrdag-3ql62-ocgoh-ld2ao-tamcv-54e7j-krwgb-2gm4z-oqe",
        // Subnet holding vetkd:Bls12_381_G2:test_key_1
        "fuqsr-in2lc-zbcjj-ydmcw-pzq7h-4xm2z-pto4i-dcyee-5z4rz-x63ji-nae",
        // Subnet holding vetkd:Bls12_381_G2:key_1 backup
        "2fq7c-slacv-26cgz-vzbx2-2jrcs-5edph-i5s2j-tck77-c3rlz-iobzx-mqe",
    ];

    for subnet_id_str in subnets_with_vetkeys {
        let subnet_id_principal = match PrincipalId::from_str(subnet_id_str) {
            Ok(pid) => pid,
            Err(e) => {
                ic_cdk::println!(
                    "Warning: Failed to parse subnet ID '{subnet_id_str}': {e}. Skipping.",
                );
                continue;
            }
        };
        let subnet_id = SubnetId::new(subnet_id_principal);

        let subnet_key = make_subnet_record_key(subnet_id);
        let registry_value = match registry.get(subnet_key.as_bytes(), registry.latest_version()) {
            Some(value) => value,
            None => {
                ic_cdk::println!("Warning: Subnet {subnet_id} not found in registry, skipping",);
                continue;
            }
        };

        let mut subnet_record_pb = match SubnetRecordPb::decode(&registry_value.value[..]) {
            Ok(record) => record,
            Err(e) => {
                ic_cdk::println!("Error decoding SubnetRecord for subnet {subnet_id}: {e}",);
                continue;
            }
        };

        // Check if chain_key_config exists and needs modification
        let mut subnet_record_needs_update = false;
        if let Some(ref mut chain_key_config) = subnet_record_pb.chain_key_config {
            for key_config in &mut chain_key_config.key_configs {
                // Skip if not a valid vetKD key.
                match &key_config.key_id {
                    Some(key_id) => {
                        match &key_id.key_id {
                            Some(KeyId::Vetkd(_)) => { /* proceed */ }
                            Some(_) => continue,
                            None => {
                                ic_cdk::println!(
                                    "Warning: KeyConfig::key_id.key_id in \
                                     subnet {subnet_id} is unexpectedly `None`. \
                                     Skipping"
                                );
                                continue;
                            }
                        }
                    }
                    None => {
                        ic_cdk::println!(
                            "Warning: KeyConfig::key_id in subnet {subnet_id} \
                            is unexpectedly `None`. Skipping."
                        );
                        continue;
                    }
                };

                if key_config.pre_signatures_to_create_in_advance == Some(0) {
                    key_config.pre_signatures_to_create_in_advance = None;
                    subnet_record_needs_update = true;
                    ic_cdk::println!(
                        "Migrating vetKD key in subnet {subnet_id}: changing pre_signatures_to_create_in_advance from Some(0) to None",
                    );
                }
            }
        }

        if subnet_record_needs_update {
            mutations.push(update(subnet_key, subnet_record_pb.encode_to_vec()));
        }
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
        "22pkm-wfc33-m326g-x2gug-3admr-sxeaf-foujt-3c4jw-uksvc-dglgf-gae",
        "24fsy-32ewt-f447o-7p5th-njgys-2qawz-gk5iw-k4qzj-7opkx-ofbm3-5qe",
        "24iqu-pqcde-wwgok-6sndd-lfhaj-gyjhu-zg73l-sqvwi-xbevy-kcuqp-4ae",
        "25o6i-sdjsl-vjlfn-6duch-vskdu-26pf5-cwibg-zooqk-sdn2e-cgugm-tae",
        "2aked-uorat-s6ubw-kqnnf-lp3ep-ykinc-xcare-wws7l-pzhim-ixk7p-zae",
        "2bicw-jtnmv-rjuil-2p4px-npmif-w37em-qreuq-4lxof-7wkcl-a3gan-oqe",
        "2ew2x-bmzxs-o6sw6-xbxv6-efhzc-47y5k-vy5ce-luaqo-lecdi-33z4i-gqe",
        "2h77x-ywmcq-vxt3r-t2ml4-43px2-wdn6u-kqus7-hmdzo-eu4qm-4afbe-pqe",
        "2htd7-tusvn-5az76-uabki-trilh-egfi4-5t2tv-z4j7e-bcgbj-dkxru-sae",
        "2k7jv-zmube-yklqn-i3z46-mdvk6-xshpb-gb5jz-kkg7z-vlqh4-xmqyw-hae",
        "2klnm-d2wrs-tnn3k-mphtu-fgdmq-e2bny-juyda-ww7hv-l6pzx-35tkm-kae",
        "2kvun-y7qfw-krhhm-aftvi-ll56o-yvkuj-noc5w-xozic-mnewn-i47x5-tqe",
        "2mjgp-xtlo2-elgwk-onn5k-7uhh7-erq34-vr24g-imzfx-pr72w-mewn6-aqe",
        "2n6eu-vv67p-bvuwq-eqfwb-r6jdi-wp3fo-jcodd-a7jtx-frju7-3sh3j-zqe",
        "2p4i3-ukstx-utpts-btuau-lidyg-c76us-nfcvp-a32u2-k5jtx-cz7i4-bae",
        "2qclu-jxgmm-cjrng-h2wwe-i6ku5-dmj6p-e5qzy-ktplm-yu6kw-zkao2-xae",
        "2qlts-dmxtt-ly45j-m2qcg-tde6r-i337l-shimz-mtshu-tp3ir-hkbyt-dae",
        "2r7p2-nll7a-gipvg-6wtpt-pgss2-lge3d-gylsc-bvo3n-7u4am-xeom5-nqe",
        "2ric4-rm3mb-x4rc4-xv7f3-o3fq6-oryc6-oyn4x-cpiyz-woh7c-eyorf-qae",
        "33s7q-wsjbb-6iyyw-bwfuz-lq2yr-lu7gt-qhc7s-oyxrq-vhfnm-wbaxb-dqe",
        "364us-2y667-wg3qr-zordv-pqlou-bra44-gjhhv-2jtnc-mr6xr-kmenh-4qe",
        "36vim-qv27i-6j52j-aaezj-s4lgp-ex65o-3j2ho-rdvl6-odnhe-32k7e-jae",
        "3bcpj-2mjor-ykckj-5m2ya-i4zn3-rdtfi-vofgu-elihb-53mje-fpywx-dae",
        "3c6dj-5mjuu-imudt-5z457-prrqe-f5m7r-axjky-ocoix-kf6de-xgi6u-2ae",
        "3ejbg-pmmzm-fojb3-cmzip-arbvm-q427h-73ej5-7cvx7-nmp4n-zfdfc-iqe",
        "3h65u-r2zrh-ydt5b-sura7-p3tdl-d2xcx-4kvwe-x464t-cug7r-uzlvr-vae",
        "3hmzi-i26ng-ckcmj-lev6h-ssbbl-3qsft-p6kyo-3e5rz-2qfsj-nsbjk-kae",
        "3iqf7-6febz-vfgsb-z6ryj-c2vwi-n54ss-5zmjo-52ldz-z5are-aabr3-fqe",
        "3jfof-q5mok-apuqv-du4j7-jqe6i-iga26-zim7o-fcmxg-la35o-5hnqj-tqe",
        "3k35b-gsfkj-bbcx5-35roy-ixma5-yn6ug-3btuq-6qdoj-zzt4v-vgpze-wqe",
        "3kg25-3ikga-ufves-caaly-5pbz6-4rwjo-r6twb-ptje6-bxb33-lacj4-qqe",
        "3m2d5-52oby-jp4xs-sregv-o2wo7-xgkgd-4senp-3lbhm-7norh-f3k7g-pae",
        "3o5rr-5acje-r4kun-h2deq-fbv6e-gyujh-222t2-b4ob6-rukpb-kmjn7-hae",
        "3rmvo-jfqce-2ajpr-fghze-uc46m-innjh-aay5p-xlfml-2hipo-gatov-7qe",
        "3s3yn-g6jbs-ybsmx-aq7la-nueos-xxrci-zhxif-vj7gw-4dbos-kbbhu-oqe",
        "3s6fj-wulzc-ml7vo-vpvhj-4loap-25asb-m6efr-f52qf-ehpxb-7mh3k-vae",
        "3smci-63tqe-6q5xc-wpdmj-pnhan-own4t-6km2r-77mfh-c2h7d-xzunk-cqe",
        "3tbjz-erih4-dfm4f-ul544-mgyqe-eeesn-hhggl-ooq2x-czsh2-nuy6n-cae",
        "42rj3-7tytn-gbyte-cyj5m-tkzta-pkezr-ijl6a-larzs-cjo2r-r3lhz-bqe",
        "467sz-tjcqd-k2nce-vrhe7-juh6s-2oohm-3ydhi-cms7g-lzo5o-7zyzs-aqe",
        "4aarv-httc6-rtrjt-mbswg-nplqa-sbyuw-jiniq-vjz4l-yhb3p-af3hy-hae",
        "4e2ty-mcqal-loqca-j2d5b-qgou4-n6y6h-yojne-kvqlg-ld4jx-rjree-3qe",
        "4fssn-4vi43-2qufr-hlrfz-hfohd-jgrwc-7l7ok-uatwb-ukau7-lwmoz-tae",
        "4fxl5-7naq3-jw64y-qyetj-27kir-bi4r4-tdyyo-h64th-rqssm-u6ua6-2ae",
        "4jw4w-tfndm-owhae-xvmpp-cy6z4-6oyia-yi47r-3bmlb-ok557-hlfzc-rqe",
        "4l2e6-g2ujv-ksiel-cfrww-zwyhq-26nbr-f2jik-xhxfp-2xkd3-hmx23-6ae",
        "4l7la-7zmuq-ois3n-leowc-2xvrh-3vozh-iutqe-ev2xx-nkgni-atitg-5qe",
        "4lqcl-tzzs3-jztya-ro7ak-ew5ue-l3tlc-5cxk3-4jt7m-z66st-ad5ld-aae",
        "4mdc3-dywcq-5uuj5-uv4z7-otsmu-pb4sq-iu3eo-4b7z2-5a7rl-xzpcm-gae",
        "4nldz-xzkm4-2y6gi-nw2s4-wuz54-xonqo-alj57-tgeqb-hbeyf-epcgh-kqe",
        "4ql5c-ky7on-eceuo-hqkl7-lzxvo-mrjco-znpn5-hfs4b-kuel6-35hmg-qqe",
        "4tm5f-kojws-d53sx-t26bm-lgpwi-zspap-bepp6-3jl7c-rxg3p-iwhh2-eqe",
        "4txlq-o5ukt-if4pj-adxtx-jwp42-jch73-z5nfy-77gi5-4lll7-eou2p-rqe",
        "4u2d3-qciqq-qqjkh-q3dbm-gyvu3-6syso-consf-5i2n2-hglur-c6tuj-jae",
        "4vpak-qnqtn-vggke-um4f2-zkk2m-awc6p-bkhi5-cm22y-zhdiz-yx5rt-cqe",
        "4whgz-3ksfr-4rroh-dluex-fptua-mrxjo-uzmgg-lvuws-oe72b-aynhj-fae",
        "4zicz-ohols-jcrpg-ynkpt-aww4h-bukgr-hrru7-a3iaq-cih37-mwij2-cqe",
        "52ykw-kxabl-twia6-x24hj-4last-tmdmd-4v3tf-fwtkh-mrdat-3vcpn-dqe",
        "53caz-qstwb-e4nak-dtune-7wtlc-4eyyr-xmnmw-2fghu-r6ili-z5qls-qqe",
        "53h2m-5b2dv-hdppe-wpzyl-apwor-3snhm-44dh5-rplxd-m2u7p-sr6n7-6ae",
        "53p5r-qqup5-e2z7n-eeg65-kzklr-ekrsa-6g3hc-vrmqu-wtows-6q2t7-6ae",
        "545fc-ouac2-s7etx-5oiuv-2beh3-s3n7u-xxkvm-6abvp-c6aue-nypdg-2ae",
        "55aa5-j6ipq-ypfns-k6qjr-zncgq-6q7xm-5oyri-mwswh-thrpu-jxo2i-hae",
        "5ab5z-6tgb7-aoafe-n6nnb-etesx-h6xt7-pu3ul-gfgjd-7uv3m-dth3x-jqe",
        "5bw5k-uuvti-kxds2-knvoo-rbkpw-wy6us-fgpua-mzssx-pq5tp-udbap-6ae",
        "5dfvs-7jxus-lmnm7-4o3jm-buisw-55hay-6eofd-i27dk-ecrd4-4evso-hae",
        "5dpkp-lfhr2-j7mfz-gavpn-puej5-wdfzg-fw42o-zupnu-izvk3-ubzzi-6ae",
        "5efad-ubiwy-ejsis-o2cfe-7atnx-lzy7j-mu6pe-wig7g-e426v-wrn5p-5qe",
        "5ezcu-l5n6q-3ddda-ap3qi-ir7gl-zvksq-lsino-d3uji-h66zk-53u6m-3qe",
        "5kc7d-5fv6m-3ps2z-n4gf2-vm63s-a3nyz-7g4gv-rkgg2-nkccw-arwq3-wae",
        "5krcu-e3t4g-aa2al-x6tzs-o4a4p-ulx3p-sbk2n-fregk-xswvx-yrueq-eqe",
        "5lwhb-2a5za-eatmy-3e7hy-otnjn-h3c6l-ov53b-qpt7u-cutea-wcxiv-kqe",
        "5nkgj-r45dd-5qojg-ecnqn-ig7uo-hqndz-v5udk-gxygg-bfigl-r6lh3-jae",
        "5oph7-csqih-dxfky-syp3w-fvcpv-2vfmy-gh3i6-mcpko-j2cmp-radto-wae",
        "5qfrp-jovqw-wjlmz-apmeg-vgumc-nzhpi-k3g4d-lzeju-o2mcj-3iffn-yae",
        "5qmio-5ls3e-yujlz-eqt7k-qk5ys-bscfd-7w2rn-2q3fq-6smjq-n7asc-xae",
        "5qrvh-zivm6-xblci-b3xzm-le2tg-fvubr-52bqk-6qiz3-5cyid-7cg35-lae",
        "5rlin-3oohc-lsgxy-hacdm-64my5-7y3p4-22nhe-2e36h-dlvjt-2nkuh-wqe",
        "5sabo-gkucg-7krz7-oxmyj-ylifc-w2r6u-bt62i-eqq2x-47rwh-gmjph-hae",
        "5tsiv-4llva-2eh4y-zjheg-s2upy-umawn-zdw4m-hhy43-a6bvc-rmnqf-rqe",
        "5u7le-tmied-z6u52-adg7a-mo3wa-yry7m-awfv7-rbiax-o3oc3-le4q6-oae",
        "5v2bn-uoktd-3ne5o-lxcws-askra-k4iyq-fxt2j-3gdpc-t2gxb-hiybx-4ae",
        "5wqk6-vib2n-2363t-b4nnb-vxyx5-tf2lm-4pmd2-d656p-xxvte-lkhh6-5ae",
        "5zldm-3rijx-6pp6q-twp65-b34xz-6iitk-kqzov-flbdh-ekkx3-3an4a-eqe",
        "5zrsg-qcrev-mm3cc-km55r-kk2ug-w6dkh-ljlnk-vj26z-yqmez-ftbfk-xqe",
        "62pbm-psjwv-sf3fc-hyisj-5qsoh-fvpac-tacne-jotrs-owsmo-3j7jo-wqe",
        "63bsb-jbwja-suy6t-ftoim-ooxag-jiytd-rayru-4kgx5-tx5gb-2b2hj-qae",
        "6a7nv-kllgd-pgq3t-nnv2w-miosm-g7kzz-4ozr4-pzq2e-iozln-ufbpr-mqe",
        "6bbgn-jvexd-25pja-q5wgj-spyfw-lfm3g-pjf2t-x3zmf-7llwq-p63wm-rqe",
        "6cknu-fqcy2-2keuj-gicsk-6ecfx-bwcjo-ppw7m-ler7z-bwjah-jvdbj-fqe",
        "6imhm-ocz2z-gn6x5-hpx3k-52pjt-5roy5-uc3ua-mmi42-onrf2-yq3ie-qqe",
        "6jidn-uqgyz-hl2l3-ou2rg-slu73-iztvd-yhdu7-hjfuz-cy4wc-jvoqc-uae",
        "6jkz4-2yffr-w3ywl-iji2o-zopfz-jbboh-l3bho-6rrws-4syul-elii5-rae",
        "6joub-fk2lr-mcxa6-lo2x5-e3alk-lrgf5-6slof-x7yxi-m6ceb-up5wv-qqe",
        "6kuom-ucaom-u7xm5-s556x-3rnyk-hdjzd-wkxnx-wsejf-vpnhz-lniqi-nae",
        "6pueo-uz4kt-quvid-v3q7y-pyqsb-wmv5o-qi6ay-jd3ex-ypddd-3vysx-eae",
        "6qf6k-fjcct-wl47g-3onza-lzdjg-5z2mp-u6n7c-hbirw-ovirx-izl67-iae",
        "6qzmz-5jtwm-kuv6j-wa3dv-n7yse-ex5rl-vmbx5-suunp-hdqxe-bnerj-iqe",
        "6souc-qqdhe-7rxo2-fvtpn-suxfz-dnvtb-k2q2h-n3pvf-ttjvc-b4lj7-uqe",
        "6ucn7-aiavt-uucq2-cvnjf-nwmr5-vetsg-q73h7-uzqjt-klm5x-e7qxu-mqe",
    ];

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
            add_fake_subnet, empty_mutation, get_invariant_compliant_subnet_record,
            invariant_compliant_registry, prepare_registry_with_nodes,
        },
        registry::{EncodedVersion, Version},
        registry_lifecycle::Registry,
    };
    use ic_base_types::PrincipalId;
    use ic_protobuf::registry::subnet::v1::{
        ChainKeyConfig as ChainKeyConfigPb, KeyConfig as KeyConfigPb,
        SubnetRecord as SubnetRecordPb,
    };
    use ic_protobuf::types::v1::{
        EcdsaCurve as EcdsaCurvePb, EcdsaKeyId as EcdsaKeyIdPb,
        MasterPublicKeyId as MasterPublicKeyIdPb, VetKdCurve as VetKdCurvePb,
        VetKdKeyId as VetKdKeyIdPb, master_public_key_id::KeyId,
    };
    use ic_registry_keys::make_subnet_record_key;
    use ic_registry_subnet_features::DEFAULT_ECDSA_MAX_QUEUE_SIZE;
    use ic_registry_transport::insert;
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
    fn test_fix_vetkd_pre_signatures_field() {
        let mut registry = invariant_compliant_registry(0);
        let (mutate_request, node_ids_and_dkg_pks) = prepare_registry_with_nodes(1, 4);
        registry.maybe_apply_mutation_internal(mutate_request.mutations);

        // Create a subnet that is in the migration list with a vetKD key that has pre_signatures_to_create_in_advance == Some(0)
        let subnet_id_1 = SubnetId::new(
            PrincipalId::from_str(
                "pzp6e-ekpqk-3c5x7-2h6so-njoeq-mt45d-h3h6c-q3mxf-vpeq5-fk5o7-yae",
            )
            .unwrap(),
        );
        let mut subnet_list_record = registry.get_subnet_list_record();
        let mut subnet_record_1 = get_invariant_compliant_subnet_record(
            node_ids_and_dkg_pks.keys().take(1).cloned().collect(),
        );
        subnet_record_1.chain_key_config = Some(ChainKeyConfigPb {
            key_configs: vec![KeyConfigPb {
                key_id: Some(MasterPublicKeyIdPb {
                    key_id: Some(KeyId::Vetkd(VetKdKeyIdPb {
                        curve: VetKdCurvePb::Bls12381G2 as i32,
                        name: "key_1".to_string(),
                    })),
                }),
                pre_signatures_to_create_in_advance: Some(0), // This should be migrated to None
                max_queue_size: Some(50),
            }],
            signature_request_timeout_ns: None,
            idkg_key_rotation_period_ms: None,
            max_parallel_pre_signature_transcripts_in_creation: None,
        });
        registry.maybe_apply_mutation_internal(add_fake_subnet(
            subnet_id_1,
            &mut subnet_list_record,
            subnet_record_1.clone(),
            &node_ids_and_dkg_pks
                .iter()
                .take(1)
                .map(|(k, v)| (*k, v.clone()))
                .collect(),
        ));

        // Create a subnet that is NOT in the migration list (should not be affected)
        let subnet_id_2 = subnet_test_id(2000);
        let mut subnet_record_2 = get_invariant_compliant_subnet_record(
            node_ids_and_dkg_pks
                .keys()
                .skip(1)
                .take(1)
                .cloned()
                .collect(),
        );
        subnet_record_2.chain_key_config = Some(ChainKeyConfigPb {
            key_configs: vec![KeyConfigPb {
                key_id: Some(MasterPublicKeyIdPb {
                    key_id: Some(KeyId::Vetkd(VetKdKeyIdPb {
                        curve: VetKdCurvePb::Bls12381G2 as i32,
                        name: "other_key".to_string(),
                    })),
                }),
                pre_signatures_to_create_in_advance: Some(0), // This should NOT be migrated
                max_queue_size: Some(50),
            }],
            signature_request_timeout_ns: None,
            idkg_key_rotation_period_ms: None,
            max_parallel_pre_signature_transcripts_in_creation: None,
        });
        registry.maybe_apply_mutation_internal(add_fake_subnet(
            subnet_id_2,
            &mut subnet_list_record,
            subnet_record_2.clone(),
            &node_ids_and_dkg_pks
                .iter()
                .skip(1)
                .take(1)
                .map(|(k, v)| (*k, v.clone()))
                .collect(),
        ));

        // Create a subnet in the migration list with a vetKD key that has a different value (not 0)
        let subnet_id_3 = SubnetId::new(
            PrincipalId::from_str(
                "uzr34-akd3s-xrdag-3ql62-ocgoh-ld2ao-tamcv-54e7j-krwgb-2gm4z-oqe",
            )
            .unwrap(),
        );
        let mut subnet_record_3 = get_invariant_compliant_subnet_record(
            node_ids_and_dkg_pks
                .keys()
                .skip(2)
                .take(1)
                .cloned()
                .collect(),
        );
        subnet_record_3.chain_key_config = Some(ChainKeyConfigPb {
            key_configs: vec![KeyConfigPb {
                key_id: Some(MasterPublicKeyIdPb {
                    key_id: Some(KeyId::Vetkd(VetKdKeyIdPb {
                        curve: VetKdCurvePb::Bls12381G2 as i32,
                        name: "key_1".to_string(),
                    })),
                }),
                pre_signatures_to_create_in_advance: Some(10), // This should NOT be migrated (not 0)
                max_queue_size: Some(50),
            }],
            signature_request_timeout_ns: None,
            idkg_key_rotation_period_ms: None,
            max_parallel_pre_signature_transcripts_in_creation: None,
        });
        registry.maybe_apply_mutation_internal(add_fake_subnet(
            subnet_id_3,
            &mut subnet_list_record,
            subnet_record_3.clone(),
            &node_ids_and_dkg_pks
                .iter()
                .skip(2)
                .take(1)
                .map(|(k, v)| (*k, v.clone()))
                .collect(),
        ));

        // Create a subnet in the migration list with a non-vetKD key (should not be affected)
        let subnet_id_4 = SubnetId::new(
            PrincipalId::from_str(
                "fuqsr-in2lc-zbcjj-ydmcw-pzq7h-4xm2z-pto4i-dcyee-5z4rz-x63ji-nae",
            )
            .unwrap(),
        );
        let mut subnet_record_4 = get_invariant_compliant_subnet_record(
            node_ids_and_dkg_pks
                .keys()
                .skip(3)
                .take(1)
                .cloned()
                .collect(),
        );
        subnet_record_4.chain_key_config = Some(ChainKeyConfigPb {
            key_configs: vec![KeyConfigPb {
                key_id: Some(MasterPublicKeyIdPb {
                    key_id: Some(KeyId::Ecdsa(EcdsaKeyIdPb {
                        curve: EcdsaCurvePb::Secp256k1 as i32,
                        name: "test_key".to_string(),
                    })),
                }),
                pre_signatures_to_create_in_advance: Some(10), // This should NOT be migrated (not vetKD, and not zero)
                max_queue_size: Some(DEFAULT_ECDSA_MAX_QUEUE_SIZE),
            }],
            signature_request_timeout_ns: None,
            idkg_key_rotation_period_ms: None,
            max_parallel_pre_signature_transcripts_in_creation: None,
        });
        registry.maybe_apply_mutation_internal(add_fake_subnet(
            subnet_id_4,
            &mut subnet_list_record,
            subnet_record_4.clone(),
            &node_ids_and_dkg_pks
                .iter()
                .skip(3)
                .take(1)
                .map(|(k, v)| (*k, v.clone()))
                .collect(),
        ));

        // Run the migration
        let mutations = fix_vetkd_pre_signatures_field(&registry);
        // We expect 1 mutation: subnet_id_1 has a vetKD key with pre_signatures_to_create_in_advance == Some(0)
        assert_eq!(mutations.len(), 1);
        registry.apply_mutations_for_test(mutations);

        // Verify subnet_id_1 was migrated (pre_signatures_to_create_in_advance changed from Some(0) to None)
        let subnet_key_1 = make_subnet_record_key(subnet_id_1);
        let registry_value_1 = registry
            .get(subnet_key_1.as_bytes(), registry.latest_version())
            .unwrap();
        let subnet_record_1_after = SubnetRecordPb::decode(&registry_value_1.value[..]).unwrap();
        let expected_subnet_record_1 = {
            let mut subnet_record_1_clone = subnet_record_1.clone();
            subnet_record_1_clone
                .chain_key_config
                .as_mut()
                .unwrap()
                .key_configs
                .get_mut(0)
                .unwrap()
                .pre_signatures_to_create_in_advance = None;
            subnet_record_1_clone
        };
        assert_eq!(subnet_record_1_after, expected_subnet_record_1);

        // Verify subnet_id_2 was NOT migrated (not in the migration list)
        let subnet_key_2 = make_subnet_record_key(subnet_id_2);
        let registry_value_2 = registry
            .get(subnet_key_2.as_bytes(), registry.latest_version())
            .unwrap();
        let subnet_record_2_after = SubnetRecordPb::decode(&registry_value_2.value[..]).unwrap();
        assert_eq!(
            subnet_record_2_after, subnet_record_2,
            "Subnet not in migration list should not be affected"
        );

        // Verify subnet_id_3 was NOT migrated (pre_signatures_to_create_in_advance is not 0)
        let subnet_key_3 = make_subnet_record_key(subnet_id_3);
        let registry_value_3 = registry
            .get(subnet_key_3.as_bytes(), registry.latest_version())
            .unwrap();
        let subnet_record_3_after = SubnetRecordPb::decode(&registry_value_3.value[..]).unwrap();
        assert_eq!(
            subnet_record_3_after, subnet_record_3,
            "Subnet with vetKD key having non-zero value should not be affected"
        );

        // Verify subnet_id_4 was NOT migrated (not a vetKD key)
        let subnet_key_4 = make_subnet_record_key(subnet_id_4);
        let registry_value_4 = registry
            .get(subnet_key_4.as_bytes(), registry.latest_version())
            .unwrap();
        let subnet_record_4_after = SubnetRecordPb::decode(&registry_value_4.value[..]).unwrap();
        assert_eq!(
            subnet_record_4_after, subnet_record_4,
            "Subnet with non-vetKD key should not be affected"
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
        ]);

        let mutations = convert_type1dot1_nodes_to_type4dot5(&registry);
        // Only the listed `type1.1` node should be mutated.
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

        // Idempotency: a second run produces no further mutations.
        assert!(convert_type1dot1_nodes_to_type4dot5(&registry).is_empty());
    }
}
