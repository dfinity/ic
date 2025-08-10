use dfn_core::api::now;
use dfn_core::endpoint::over;
use dfn_json::json;

#[export_name = "canister_query what_time_is_it"]
fn main() {
    over(json, |()| now())
}
