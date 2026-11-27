//! WebMCP Demo Canister — e-commerce backend.
//!
//! Demonstrates exposing IC canister methods as WebMCP tools.
//! Each caller (principal) gets their own cart; products are hard-coded
//! at init time so the demo works without any external dependencies.

use candid::{CandidType, Principal};
use serde::Deserialize;
use std::cell::RefCell;
use std::collections::BTreeMap;

// ── Types (mirror backend.did) ───────────────────────────────────────

#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct Product {
    pub id: u32,
    pub name: String,
    pub description: String,
    pub price_e8s: u64,
    pub in_stock: bool,
}

#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct CartItem {
    pub product_id: u32,
    pub quantity: u32,
}

#[derive(CandidType, Deserialize, Clone, Debug, Default)]
pub struct Cart {
    pub items: Vec<CartItem>,
    pub total_e8s: u64,
}

#[derive(CandidType, Deserialize, Clone, Debug)]
pub enum AddToCartResult {
    Ok(Cart),
    Err(String),
}

#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct OrderConfirmation {
    pub order_id: u64,
    pub total_paid_e8s: u64,
}

#[derive(CandidType, Deserialize, Clone, Debug)]
pub enum CheckoutResult {
    Ok(OrderConfirmation),
    Err(String),
}

// ── State ─────────────────────────────────────────────────────────────

#[derive(Default)]
pub struct State {
    pub products: Vec<Product>,
    /// Per-caller carts: principal → cart
    pub carts: BTreeMap<Principal, Cart>,
    /// Monotonically increasing order counter
    pub next_order_id: u64,
}

thread_local! {
    static STATE: RefCell<State> = RefCell::new(State::default());
}

/// Seed the product catalog. Called from `#[init]`.
pub fn init_products() {
    STATE.with(|s| {
        s.borrow_mut().products = vec![
            Product {
                id: 1,
                name: "ICP T-Shirt".to_string(),
                description: "100% organic cotton, infinity logo on the front".to_string(),
                price_e8s: 500_000_000, // 5 ICP
                in_stock: true,
            },
            Product {
                id: 2,
                name: "Neuron Hoodie".to_string(),
                description: "Warm hoodie with NNS neuron diagram on the back".to_string(),
                price_e8s: 1_500_000_000, // 15 ICP
                in_stock: true,
            },
            Product {
                id: 3,
                name: "DFINITY Sticker Pack".to_string(),
                description: "10 high-quality vinyl stickers for your laptop".to_string(),
                price_e8s: 100_000_000, // 1 ICP
                in_stock: true,
            },
            Product {
                id: 4,
                name: "IC Coffee Mug".to_string(),
                description: "Ceramic mug with the Internet Computer logo".to_string(),
                price_e8s: 300_000_000, // 3 ICP
                in_stock: false,        // out of stock — agents should notice
            },
        ];
    });
}

// ── Canister methods ─────────────────────────────────────────────────
//
// The public functions take `caller: Principal` explicitly so they can
// be called from both the canister entry point (`main.rs`, which passes
// `ic_cdk::api::msg_caller()`) and from unit tests (which pass a fixed
// test principal). This avoids requiring the IC host environment in tests.

/// List all available products.
pub fn list_products() -> Vec<Product> {
    STATE.with(|s| s.borrow().products.clone())
}

/// Get a single product by ID. Returns `None` if not found.
pub fn get_product(id: u32) -> Option<Product> {
    STATE.with(|s| s.borrow().products.iter().find(|p| p.id == id).cloned())
}

/// Get the given caller's current cart.
pub fn get_cart(caller: Principal) -> Cart {
    STATE.with(|s| s.borrow().carts.get(&caller).cloned().unwrap_or_default())
}

/// Add a product to the given caller's cart.
pub fn add_to_cart(caller: Principal, item: CartItem) -> AddToCartResult {
    if item.quantity == 0 {
        return AddToCartResult::Err("Quantity must be at least 1".to_string());
    }

    let product = match get_product(item.product_id) {
        Some(p) => p,
        None => return AddToCartResult::Err(format!("Product {} not found", item.product_id)),
    };

    if !product.in_stock {
        return AddToCartResult::Err(format!("Product \"{}\" is out of stock", product.name));
    }

    let cart = STATE.with(|s| {
        let mut state = s.borrow_mut();
        // Clone products first to avoid simultaneous mutable + immutable borrow of state
        let products = state.products.clone();
        let cart = state.carts.entry(caller).or_default();

        if let Some(existing) = cart
            .items
            .iter_mut()
            .find(|i| i.product_id == item.product_id)
        {
            existing.quantity += item.quantity;
        } else {
            cart.items.push(item);
        }

        cart.total_e8s = compute_total(&cart.items, &products);
        cart.clone()
    });

    AddToCartResult::Ok(cart)
}

/// Remove a product from the given caller's cart.
pub fn remove_from_cart(caller: Principal, product_id: u32) -> Cart {
    STATE.with(|s| {
        let mut state = s.borrow_mut();
        let products = state.products.clone();
        let cart = state.carts.entry(caller).or_default();
        cart.items.retain(|i| i.product_id != product_id);
        cart.total_e8s = compute_total(&cart.items, &products);
        cart.clone()
    })
}

/// Check out the given caller's cart, clearing it and returning an order confirmation.
pub fn checkout(caller: Principal) -> CheckoutResult {
    let cart = STATE.with(|s| s.borrow().carts.get(&caller).cloned().unwrap_or_default());

    if cart.items.is_empty() {
        return CheckoutResult::Err("Cart is empty".to_string());
    }

    let total_paid_e8s = cart.total_e8s;

    let order_id = STATE.with(|s| {
        let mut state = s.borrow_mut();
        let id = state.next_order_id;
        state.next_order_id += 1;
        state.carts.remove(&caller);
        id
    });

    CheckoutResult::Ok(OrderConfirmation {
        order_id,
        total_paid_e8s,
    })
}

// ── Stable memory: upgrade hooks ─────────────────────────────────────

/// Serialisable snapshot of the mutable parts of canister state.
///
/// Products are hard-coded at init and do not need to survive upgrades;
/// only carts and the order counter do.
#[derive(CandidType, Deserialize)]
pub struct StableState {
    pub carts: BTreeMap<Principal, Cart>,
    pub next_order_id: u64,
}

/// Extract the state that must survive a canister upgrade.
pub fn take_stable_state() -> StableState {
    STATE.with(|s| {
        let state = s.borrow();
        StableState {
            carts: state.carts.clone(),
            next_order_id: state.next_order_id,
        }
    })
}

/// Restore state after a canister upgrade and re-seed the product catalog.
pub fn restore_stable_state(stable: StableState) {
    STATE.with(|s| {
        let mut state = s.borrow_mut();
        state.carts = stable.carts;
        state.next_order_id = stable.next_order_id;
    });
    init_products();
}

// ── Helpers ──────────────────────────────────────────────────────────

fn compute_total(items: &[CartItem], products: &[Product]) -> u64 {
    items.iter().fold(0_u64, |acc, item| {
        let price = products
            .iter()
            .find(|p| p.id == item.product_id)
            .map(|p| p.price_e8s)
            .unwrap_or(0);
        acc.saturating_add(price.saturating_mul(item.quantity as u64))
    })
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn alice() -> Principal {
        Principal::from_text("aaaaa-aa").unwrap()
    }

    fn setup() {
        STATE.with(|s| *s.borrow_mut() = State::default());
        init_products();
    }

    #[test]
    fn test_list_products_returns_all() {
        setup();
        assert_eq!(list_products().len(), 4);
        assert!(list_products().iter().any(|p| p.name == "ICP T-Shirt"));
    }

    #[test]
    fn test_get_product_found() {
        setup();
        let p = get_product(1).expect("product 1 should exist");
        assert_eq!(p.name, "ICP T-Shirt");
        assert_eq!(p.price_e8s, 500_000_000);
    }

    #[test]
    fn test_get_product_not_found() {
        setup();
        assert!(get_product(999).is_none());
    }

    #[test]
    fn test_add_to_cart_success() {
        setup();
        match add_to_cart(
            alice(),
            CartItem {
                product_id: 1,
                quantity: 2,
            },
        ) {
            AddToCartResult::Ok(cart) => {
                assert_eq!(cart.items.len(), 1);
                assert_eq!(cart.items[0].quantity, 2);
                assert_eq!(cart.total_e8s, 1_000_000_000); // 2 × 5 ICP
            }
            AddToCartResult::Err(e) => panic!("unexpected error: {e}"),
        }
    }

    #[test]
    fn test_add_to_cart_out_of_stock() {
        setup();
        // product 4 (mug) is out of stock
        assert!(matches!(
            add_to_cart(
                alice(),
                CartItem {
                    product_id: 4,
                    quantity: 1
                }
            ),
            AddToCartResult::Err(_)
        ));
    }

    #[test]
    fn test_add_to_cart_zero_quantity() {
        setup();
        assert!(matches!(
            add_to_cart(
                alice(),
                CartItem {
                    product_id: 1,
                    quantity: 0
                }
            ),
            AddToCartResult::Err(_)
        ));
    }

    #[test]
    fn test_add_to_cart_unknown_product() {
        setup();
        assert!(matches!(
            add_to_cart(
                alice(),
                CartItem {
                    product_id: 999,
                    quantity: 1
                }
            ),
            AddToCartResult::Err(_)
        ));
    }

    #[test]
    fn test_add_same_product_twice_merges_quantity() {
        setup();
        add_to_cart(
            alice(),
            CartItem {
                product_id: 1,
                quantity: 1,
            },
        );
        match add_to_cart(
            alice(),
            CartItem {
                product_id: 1,
                quantity: 2,
            },
        ) {
            AddToCartResult::Ok(cart) => {
                assert_eq!(cart.items.len(), 1);
                assert_eq!(cart.items[0].quantity, 3);
            }
            AddToCartResult::Err(e) => panic!("unexpected error: {e}"),
        }
    }

    #[test]
    fn test_remove_from_cart() {
        setup();
        add_to_cart(
            alice(),
            CartItem {
                product_id: 1,
                quantity: 1,
            },
        );
        add_to_cart(
            alice(),
            CartItem {
                product_id: 2,
                quantity: 1,
            },
        );
        let cart = remove_from_cart(alice(), 1);
        assert_eq!(cart.items.len(), 1);
        assert_eq!(cart.items[0].product_id, 2);
    }

    #[test]
    fn test_checkout_success() {
        setup();
        add_to_cart(
            alice(),
            CartItem {
                product_id: 1,
                quantity: 1,
            },
        );
        add_to_cart(
            alice(),
            CartItem {
                product_id: 3,
                quantity: 2,
            },
        );
        match checkout(alice()) {
            CheckoutResult::Ok(order) => {
                assert_eq!(order.order_id, 0);
                // 1 T-shirt (5 ICP) + 2 sticker packs (1 ICP each) = 7 ICP
                assert_eq!(order.total_paid_e8s, 700_000_000);
            }
            CheckoutResult::Err(e) => panic!("unexpected error: {e}"),
        }
        assert!(get_cart(alice()).items.is_empty());
    }

    #[test]
    fn test_checkout_empty_cart() {
        setup();
        assert!(matches!(checkout(alice()), CheckoutResult::Err(_)));
    }

    #[test]
    fn test_order_ids_increment() {
        setup();
        add_to_cart(
            alice(),
            CartItem {
                product_id: 1,
                quantity: 1,
            },
        );
        let first = checkout(alice());
        add_to_cart(
            alice(),
            CartItem {
                product_id: 1,
                quantity: 1,
            },
        );
        let second = checkout(alice());
        match (first, second) {
            (CheckoutResult::Ok(a), CheckoutResult::Ok(b)) => {
                assert_eq!(b.order_id, a.order_id + 1);
            }
            _ => panic!("both checkouts should succeed"),
        }
    }

    #[test]
    fn test_carts_are_per_caller() {
        setup();
        let bob = Principal::from_text("2vxsx-fae").unwrap();
        add_to_cart(
            alice(),
            CartItem {
                product_id: 1,
                quantity: 1,
            },
        );
        add_to_cart(
            bob,
            CartItem {
                product_id: 2,
                quantity: 3,
            },
        );

        let alice_cart = get_cart(alice());
        let bob_cart = get_cart(bob);
        assert_eq!(alice_cart.items.len(), 1);
        assert_eq!(alice_cart.items[0].product_id, 1);
        assert_eq!(bob_cart.items.len(), 1);
        assert_eq!(bob_cart.items[0].product_id, 2);
    }
}
