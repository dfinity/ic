use crate::Event;
use crate::KytMode;
use askama::Template;
use candid::Principal;

#[derive(Template)]
#[template(path = "dashboard.html")]
pub struct DashboardTemplate {
    pub minter_id: Principal,
    pub maintainers: Vec<Principal>,
    pub events: Vec<Event>,
    pub mode: KytMode,
    pub last_api_key_update_date: String,
}
