use anyhow::anyhow;
use candid::{Decode, Encode};
use flate2::read::GzDecoder;
use ic_base_types::PrincipalId;
use ic_cdk::api::stable::WASM_PAGE_SIZE_IN_BYTES;
use ic_nervous_system_string::clamp_debug_len;
use ic_nns_constants::GOVERNANCE_CANISTER_ID;
use ic_nns_governance_api::pb::v1::ListNeurons;
use ic_nns_test_utils::state_test_helpers::{get_profiling, list_neurons, unwrap_wasm_result};
use ic_nns_test_utils_golden_nns_state::new_state_machine_with_golden_nns_state_or_panic;
use std::{
    collections::BTreeMap,
    io::Read, // For flate2.
    path::PathBuf,
    str::FromStr,
};
// TODO: Figure out how to implement read_custom_sections using the walrus
// library so that we are not using two WASM libraries.
use wasmparser::{Parser, Payload};

fn decompress_gz(buffer: &[u8]) -> Vec<u8> {
    let mut result = vec![];
    let mut decoder = GzDecoder::new(buffer);
    decoder.read_to_end(&mut result).unwrap();
    result
}

fn read_custom_section(wasm_bytes: &[u8], query_name: &str) -> Vec<u8> {
    let parser = Parser::new(0);
    let mut custom_section_data = None;

    for payload in parser.parse_all(wasm_bytes) {
        match payload.unwrap() {
            Payload::CustomSection(custom_section) => {
                if custom_section.name() == query_name {
                    custom_section_data = Some(custom_section.data().to_vec());
                    // This assumes that there are no more custom sections with
                    // the same name.
                    break;
                }
            }
            _ => continue, // Ignore other payloads
        }
    }

    custom_section_data.unwrap()
}

#[test]
fn test_why_list_neurons_expensive() {
    // Load golden nns state into a StateMachine.
    let state_machine = new_state_machine_with_golden_nns_state_or_panic();

    // Install governance WASM built from working copy. The main thing this does
    // is allocate some stable memory that will be used to store profiling data
    // that can be used to generate a flame graph. This space will be used by
    // ic-wasm instrument.

    println!("\nAllocating stable memory for profiling...\n");
    let governance_wasm_gz: Vec<u8> = canister_test::Project::cargo_bin_maybe_from_env(
        "governance-canister",
        /* features = */ &[],
    )
    .bytes();
    state_machine
        .upgrade_canister(
            GOVERNANCE_CANISTER_ID,
            governance_wasm_gz.clone(),
            vec![], // args
        )
        .unwrap();
    let (start_page, page_limit) = Decode!(
        &unwrap_wasm_result(state_machine.query(
            GOVERNANCE_CANISTER_ID,
            "where_ic_wasm_instrument_memory",
            Encode!().unwrap(),
        )),
        u64,
        u64
    )
    .unwrap();
    let start_address = start_page * WASM_PAGE_SIZE_IN_BYTES as u64;
    println!("");
    println!("Result from ic_wasm_instrument_memory:");
    println!(
        "  start_page = {} (start_address = {})",
        start_page, start_address
    );
    println!("  page_limit = {}", page_limit);
    println!("");

    // Grab a sample of principals that have "associated" neurons. More
    // precisely, these principals either control or are a hotkey of some
    // (nonzero number of) neurons. These will later be used as callers of the
    // list_neurons method.
    let principal_id_to_neuron_count = state_machine.execute_ingress(
        GOVERNANCE_CANISTER_ID,
        "principal_id_to_neuron_count",
        Encode!().unwrap(),
    )
    .unwrap();
    let principal_id_to_neuron_count = match principal_id_to_neuron_count {
        ic_types::ingress::WasmResult::Reply(ok) => ok,
        doh => panic!("{:?}", doh),
    };
    let principal_id_to_neuron_count = Decode!(
        &principal_id_to_neuron_count,
        Vec<(PrincipalId, (u64, u64))>
    )
    .unwrap();
    {
        let len = principal_id_to_neuron_count.len();
        println!("");
        println!("principal_id_to_neuron_count:");
        println!("{:#?}", &principal_id_to_neuron_count[0..7]);
        println!("...");
        println!("{:#?}", &principal_id_to_neuron_count[(len - 7)..len]);
        println!("");
    }

    // DO NOT MERGE: THIS IS A HACK
    let page_limit = page_limit / 2;

    // Enable profiling of the governance canister.

    // Have ic-wasm instrument the governance WASM for profiling.
    let mut instrumented_governance_wasm =
        walrus::Module::from_buffer(&decompress_gz(&governance_wasm_gz))
            .expect("walrus cannot cope with our WASM.");
    ic_wasm::instrumentation::instrument(
        &mut instrumented_governance_wasm,
        ic_wasm::instrumentation::Config {
            trace_only_funcs: vec![],
            start_address: Some(i64::try_from(start_address).unwrap()),
            page_limit: Some(i32::try_from(page_limit).unwrap()),
        },
    )
    .unwrap();
    let instrumented_governance_wasm = instrumented_governance_wasm.emit_wasm();

    // Read some metadata from the profiling-enabled governance WASM. This
    // metadata will later be used to visualize where instructions are consumed.
    // This is based on
    // https://sourcegraph.com/github.com/dfinity/ic-repl@746bea25ddd4cc98709f6b9eaa283f32a21ac30d/-/blob/src/helper.rs?L504
    let name_custom_section_payload = Decode!(
        &read_custom_section(&instrumented_governance_wasm, "icp:public name"),
        BTreeMap<u16, String>
    )
    .unwrap();

    // Install the profiling-enabled governance WASM.
    println!("");
    println!("Installing governance WITH ic-wasm profiling ENABLED...");
    println!("");
    state_machine
        .upgrade_canister(
            GOVERNANCE_CANISTER_ID,
            instrumented_governance_wasm,
            vec![], // args
        )
        .unwrap();
    println!("");
    println!("Done installing governance WITH ic-wasm profiling ENABLED.");
    println!("Ready for fine-grained performance measurement 👍");
    println!("");

    // Measure a variety of list_neuron calls.
    for (caller, (heap_neuron_count, stable_memory_neuron_count)) in principal_id_to_neuron_count {
        let is_principal_too_heavy = [
            PrincipalId::from_str("dies2-up6x4-i42et-avcop-xvl3v-it2mm-hqeuj-j4hyu-vz7wl-ewndz-dae").unwrap(),
            PrincipalId::from_str("renrk-eyaaa-aaaaa-aaada-cai").unwrap(),
        ].contains(&caller);
        if is_principal_too_heavy {
            continue;
        }

        // Call code being measured.
        let _result = list_neurons(
            &state_machine,
            caller,
            ListNeurons {
                include_neurons_readable_by_caller: true,
                include_public_neurons_in_full_neurons: Some(false),
                include_empty_neurons_readable_by_caller: Some(true),
                neuron_ids: vec![],
            },
        );

        // Fetch measurement.
        let profiling = get_profiling(&state_machine, GOVERNANCE_CANISTER_ID);

        // Visualize where instructions get consumed.
        let title = format!(
            "{}/{} neurons ({})",
            heap_neuron_count, stable_memory_neuron_count, caller,
        );
        let destination = format!(
            "list_neurons_{:0>4}_heap_neurons_{:0>4}_stable_memory_neurons_{}.svg",
            heap_neuron_count, stable_memory_neuron_count, caller,
        );
        let cost = render_profiling( // DO NOT MERGE
            profiling,
            &name_custom_section_payload,
            &title,
            PathBuf::from(destination),
        )
        .unwrap();

        // Print data that can be copied into a spreadsheet for further analysis.
        println!(
            "{},{},{},{}",
            caller, heap_neuron_count, stable_memory_neuron_count, unwrap_cost(cost),
        );
    }
}

fn unwrap_cost(cost: CostValue) -> u64 {
    if let CostValue::Complete(ok) = cost {
        return ok;
    }

    panic!("{:?}", cost);
}

#[allow(unused)]
#[derive(Debug)]
enum CostValue {
    Complete(u64),
    StartCost(u64),
}

// Copied from https://github.com/dfinity/ic-repl/blob/746bea25ddd4cc98709f6b9eaa283f32a21ac30d/src/profiling.rs#L85C1-L162C2
fn render_profiling(
    input: Vec<(i32, i64)>,
    names: &BTreeMap<u16, String>,
    title: &str,
    filename: PathBuf,
) -> anyhow::Result<CostValue> {
    use inferno::flamegraph::{from_reader, Options};
    let mut stack = Vec::new();
    let mut prefix = Vec::new();
    let mut result = Vec::new();
    let mut total = 0;
    let mut prev = None;
    let start_cost = input.first().map(|(_, count)| *count);
    for (id, count) in input.into_iter() {
        if id >= 0 {
            stack.push((id, count, 0));
            let name = match names.get(&(id as u16)) {
                Some(name) => name.clone(),
                None => "func_".to_string() + &id.to_string(),
            };
            prefix.push(name);
        } else {
            match stack.pop() {
                None => return Err(anyhow!("pop empty stack")),
                Some((start_id, start, children)) => {
                    if start_id != -id {
                        return Err(anyhow!("func id mismatch"));
                    }
                    let cost = count - start;
                    let frame = prefix.join(";");
                    prefix.pop().unwrap();
                    if let Some((parent, parent_cost, children_cost)) = stack.pop() {
                        stack.push((parent, parent_cost, children_cost + cost));
                    } else {
                        total += cost as u64;
                    }
                    match prev {
                        Some(prev) if prev == frame => {
                            // Add an empty spacer to avoid collapsing adjacent same-named calls
                            // See https://github.com/jonhoo/inferno/issues/185#issuecomment-671393504
                            result.push(format!("{};spacer 0", prefix.join(";")));
                        }
                        _ => (),
                    }
                    result.push(format!("{} {}", frame, cost - children));
                    prev = Some(frame);
                }
            }
        }
    }
    let cost = if !stack.is_empty() {
        eprintln!("A trap occured or trace is too large");
        CostValue::StartCost(start_cost.unwrap() as u64)
    } else {
        CostValue::Complete(total)
    };
    //println!("Cost: {} Wasm instructions", total);
    let mut opt = Options::default();
    opt.count_name = "instructions".to_string();
    let title = if matches!(cost, CostValue::StartCost(_)) {
        title.to_string() + " (incomplete)"
    } else {
        title.to_string()
    };
    opt.title = title;
    opt.image_width = Some(1024);
    opt.flame_chart = true;
    opt.no_sort = true;
    // Reserve result order to make flamegraph from left to right.
    // See https://github.com/jonhoo/inferno/issues/236
    result.reverse();
    let logs = result.join("\n");
    let reader = std::io::Cursor::new(logs);
    let mut writer = std::fs::File::create(&filename)?;
    from_reader(&mut opt, reader, &mut writer)?;
    // println!("Flamegraph written to {}", filename.display());
    Ok(cost)
}
