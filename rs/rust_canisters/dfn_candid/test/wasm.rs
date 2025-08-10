use dfn_candid::candid;
use dfn_core::over;

#[export_name = "canister_query greeting"]
fn greeting() {
    over(candid, |(name, age): (String, u16)| {
        format!("Hello {}, you are {} years old", name, age)
    })
}

#[export_name = "canister_query sum"]
fn combine() {
    over(candid, |(a, b, c, d): (u16, u16, u16, u16)| {
        let x = a + b;
        let y = c + d;
        (x, y)
    })
}

fn main() {}
