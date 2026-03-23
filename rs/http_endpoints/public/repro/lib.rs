//! Module that serves the human-readable replica dashboard, which provide
//! information about the state of the replica.

use askama::Template;

#[derive(Template)]
#[template(path = "dashboard.html", escape = "html")]
struct Dashboard {
    foo: u8,

}

