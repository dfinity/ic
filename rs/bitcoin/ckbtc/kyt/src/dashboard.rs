use crate::Event;
use askama::Template;
use candid::Principal;

#[derive(Template)]
#[template(path = "dashboard.html")]
pub struct DashboardTemplate {
    pub minter_id: Principal,
    pub maintainers: Vec<Principal>,
    pub events: Vec<Event>,
}
