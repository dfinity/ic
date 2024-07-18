#[export_name = "canister_query decode"]
pub fn decode() {
    let bytes = ic_cdk::api::call::arg_data_raw();
    let _ = candid_parser::IDLArgs::from_bytes(&bytes);
    let instructions = ic_cdk::api::performance_counter(0) as u64;
    ic_cdk::api::call::reply_raw(&instructions.to_le_bytes());
}

fn main() {}
