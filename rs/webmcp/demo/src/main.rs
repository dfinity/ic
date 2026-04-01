use demo_backend_lib::{AddToCartResult, Cart, CartItem, CheckoutResult, Product};
use ic_cdk::api::msg_caller;

fn main() {}

#[ic_cdk::init]
fn init() {
    demo_backend_lib::init_products();
}

/// Serialise mutable state to stable memory before an upgrade.
#[ic_cdk::pre_upgrade]
fn pre_upgrade() {
    let stable = demo_backend_lib::take_stable_state();
    ic_cdk::storage::stable_save((stable,)).expect("pre_upgrade: stable_save failed");
}

/// Restore state from stable memory after an upgrade.
#[ic_cdk::post_upgrade]
fn post_upgrade() {
    let (stable,): (demo_backend_lib::StableState,) =
        ic_cdk::storage::stable_restore().expect("post_upgrade: stable_restore failed");
    demo_backend_lib::restore_stable_state(stable);
}

#[ic_cdk::query]
fn list_products() -> Vec<Product> {
    demo_backend_lib::list_products()
}

#[ic_cdk::query]
fn get_product(id: u32) -> Option<Product> {
    demo_backend_lib::get_product(id)
}

#[ic_cdk::query]
fn get_cart() -> Cart {
    demo_backend_lib::get_cart(msg_caller())
}

#[ic_cdk::update]
fn add_to_cart(item: CartItem) -> AddToCartResult {
    demo_backend_lib::add_to_cart(msg_caller(), item)
}

#[ic_cdk::update]
fn remove_from_cart(product_id: u32) -> Cart {
    demo_backend_lib::remove_from_cart(msg_caller(), product_id)
}

#[ic_cdk::update]
fn checkout() -> CheckoutResult {
    demo_backend_lib::checkout(msg_caller())
}
