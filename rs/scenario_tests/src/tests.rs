use crate::api::handle::Ic;
use candid::{CandidType, Deserialize, Principal};
use canister_test::{Canister, Runtime};
use dfn_candid::candid;
use futures::{future::join_all, Future};
use ic_base_types::{CanisterId, PrincipalId, SubnetId};
use std::collections::BTreeMap;
use std::iter::FromIterator;
use std::str::FromStr;
use std::time::Duration;

pub mod e2e;
pub mod testcase_4_3_xnet_slo;
pub mod testcase_5_2_does_not_stop;

/// A handle that wraps information identifying a canister.
#[derive(Clone)]
enum CanisterHandle<'a> {
    CanisterId(CanisterId),
    Canister(Canister<'a>),
}

impl<'a> CanisterHandle<'a> {
    fn canister(&'a self, api: &'a Runtime) -> Canister<'a> {
        match self {
            CanisterHandle::CanisterId(id) => Canister::new(api, *id),
            CanisterHandle::Canister(canister) => canister.clone(),
        }
    }

    fn canister_id(&self) -> CanisterId {
        match self {
            CanisterHandle::CanisterId(id) => *id,
            CanisterHandle::Canister(canister) => canister.canister_id(),
        }
    }
}

impl From<CanisterId> for CanisterHandle<'_> {
    fn from(canister_id: CanisterId) -> Self {
        CanisterHandle::CanisterId(canister_id)
    }
}

impl<'a> From<Canister<'a>> for CanisterHandle<'a> {
    fn from(canister: Canister<'a>) -> Self {
        CanisterHandle::Canister(canister)
    }
}

/// A struct that wraps a canister together with an optional associated wallet
/// plus a runtime that allows to communicate with the canister.
pub struct CanisterLocator<'a> {
    canister: CanisterHandle<'a>,
    wallet: Option<CanisterHandle<'a>>,
    api: Runtime,
}

impl<'a> CanisterLocator<'a> {
    fn new_from_ic(
        canister: CanisterHandle<'a>,
        wallet: Option<CanisterHandle<'a>>,
        ic: &'a dyn Ic,
    ) -> Self {
        let subnet_id = ic.route(canister.canister_id().get());
        if let Some(subnet_id) = subnet_id {
            let api = ic.subnet(subnet_id).node_by_idx(0).api();
            Self::new(canister, wallet, api)
        } else {
            panic!(
                "Could not find subnet id for canister {}.",
                canister.canister_id()
            );
        }
    }

    fn new(canister: CanisterHandle<'a>, wallet: Option<CanisterHandle<'a>>, api: Runtime) -> Self {
        Self {
            canister,
            wallet,
            api,
        }
    }

    fn canister(&self) -> Canister {
        self.canister.canister(&self.api)
    }

    fn wallet(&self) -> Option<Canister> {
        self.wallet
            .as_ref()
            .map(|handle| handle.canister(&self.api))
    }
}

/// For all `canisters` concurrently attempts to first refund the remaining
/// cycles to the used wallet canisters, then attempts to stop the canisters
/// where refunding was successful, and finally attempts to delete the
/// successfully stopped canisters. If there are no wallets provided it
/// will directly stop and delete the given canisters.
pub async fn cleanup(canisters: Vec<CanisterLocator<'_>>) {
    pub async fn return_cycles<'a, 'b>(
        src: Canister<'a>,
        dst: Canister<'b>,
    ) -> Result<Canister<'a>, String> {
        #[derive(CandidType, Deserialize, Debug)]
        struct DepositCycleArgs {
            canister_id: Principal,
        }

        let res: Result<String, String> = src
            .update_(
                "return_cycles",
                candid,
                (DepositCycleArgs {
                    canister_id: Principal::from_str(&dst.canister_id().to_string()).unwrap(),
                },),
            )
            .await;

        res.map(|_| src)
    }
    fn print_error<'a>(
        action: &str,
        i: usize,
        result: Result<Canister<'a>, String>,
    ) -> Result<Canister<'a>, String> {
        if let Err(e) = result.as_ref() {
            println!("{} {} failed: {}", action, i, e);
        }
        result
    }
    pub async fn stop_canister(canister: Canister<'_>) -> Result<Canister<'_>, String> {
        canister.stop().await.map(|_| canister)
    }

    pub async fn delete_canister(canister: Canister<'_>) -> Result<Canister<'_>, String> {
        canister.delete().await.map(|_| canister)
    }

    let canisters_to_wallets = canisters
        .iter()
        .map(|locator| (locator.canister(), locator.wallet()))
        .filter(|(_, wallet)| wallet.is_some())
        .map(|(canister, wallet)| (canister, wallet.unwrap()))
        .collect::<Vec<(Canister, Canister)>>();

    let canisters: Vec<Canister> = if !canisters_to_wallets.is_empty() {
        println!("Sleeping 120s to give canisters a chance to catch up with the backlog");
        std::thread::sleep(Duration::from_secs(120));
        println!("Refunding remaining cycles");
        let refunded: Vec<Result<Canister, String>> = parallel_async(
            canisters_to_wallets,
            |(canister, wallet)| return_cycles(canister, wallet),
            |i, res| print_error("Refunding cycles for canister", i, res),
        )
        .await;

        refunded
            .into_iter()
            .filter(|x| x.is_ok())
            .map(|x| x.unwrap())
            .collect()
    } else {
        canisters.iter().map(|locator| locator.canister()).collect()
    };

    println!("Stopping canisters");
    let canisters: Vec<Result<Canister, String>> =
        parallel_async(canisters, stop_canister, |i, res| {
            print_error("Stopping canister", i, res)
        })
        .await;

    println!("Deleting canisters");
    let _: Vec<Result<Canister, String>> = parallel_async(
        canisters
            .into_iter()
            .filter(|x| x.is_ok())
            .map(|x| x.unwrap())
            .collect::<Vec<Canister>>(),
        delete_canister,
        |i, res| print_error("Deleting canister", i, res),
    )
    .await;
}

/// Performs `cleanup` based on `canister_ids` represented as strings
pub async fn cleanup_canister_ids(
    canister_ids: Vec<String>,
    wallet_canisters: Vec<String>,
    ic: &dyn Ic,
) {
    let canisters = locate_canister_ids(canister_ids, wallet_canisters, ic);
    cleanup(canisters).await;
}

/// Locates the canisters on the network relative to the given wallets and
/// returns a vector of canister locators.
pub fn locate_canisters<'a>(
    canisters: &[Canister<'a>],
    wallets: &BTreeMap<SubnetId, CanisterId>,
    ic: &'a dyn Ic,
) -> Vec<CanisterLocator<'a>> {
    locate_canisters_internal(
        canisters
            .iter()
            .map(|canister| canister.clone().into())
            .collect(),
        wallets
            .iter()
            .map(|(_, canister_id)| (*canister_id).into())
            .collect(),
        ic,
    )
}

/// Locates the canister ids on the network relative to the given wallet ids and
/// returns a vector of canister locators.
pub fn locate_canister_ids(
    canister_ids: Vec<String>,
    wallet_ids: Vec<String>,
    ic: &dyn Ic,
) -> Vec<CanisterLocator> {
    fn into_canister_id(canister_id: &str) -> CanisterId {
        CanisterId::new(
            PrincipalId::from_str(canister_id)
                .unwrap_or_else(|_| panic!("Could not create PrincipalId from {}", canister_id)),
        )
        .unwrap_or_else(|_| panic!("Could not convert {} into canister id.", canister_id))
    }
    fn into_canister_ids<'a>(canister_ids: &'_ [String]) -> Vec<CanisterHandle<'a>> {
        canister_ids
            .iter()
            .map(|id| into_canister_id(id).into())
            .collect()
    }

    locate_canisters_internal(
        into_canister_ids(&canister_ids),
        into_canister_ids(&wallet_ids),
        ic,
    )
}

fn locate_canisters_internal<'a>(
    canisters: Vec<CanisterHandle<'a>>,
    wallets: Vec<CanisterHandle<'a>>,
    ic: &'a dyn Ic,
) -> Vec<CanisterLocator<'a>> {
    fn route(canister_id: CanisterId, ic: &dyn Ic) -> SubnetId {
        ic.route(canister_id.get())
            .unwrap_or_else(|| panic!("Could not map canister {} to subnet.", canister_id))
    }

    let wallets = wallets
        .into_iter()
        .map(|wallet_handle| (route(wallet_handle.canister_id(), ic), wallet_handle))
        .collect::<BTreeMap<_, _>>();

    canisters
        .into_iter()
        .map(|canister_handle| {
            let canister_id = canister_handle.canister_id();
            CanisterLocator::new_from_ic(
                canister_handle,
                wallets.get(&route(canister_id, ic)).cloned(),
                ic,
            )
        })
        .collect()
}

/// Concurrently executes the `call` async closure for every item in `targets`,
/// postprocessing each result with `post` and collecting them.
pub async fn parallel_async<I, F, Pre, Post, P, O>(targets: I, call: Pre, post: Post) -> O
where
    I: IntoIterator,
    F: Future,
    Pre: Fn(I::Item) -> F,
    Post: Fn(usize, F::Output) -> P,
    O: FromIterator<P>,
{
    let futures = targets.into_iter().map(|target| call(target));
    join_all(futures)
        .await
        .into_iter()
        .enumerate()
        .map(|(i, res)| post(i, res))
        .collect()
}
