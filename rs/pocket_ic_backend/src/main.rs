use axum::{extract::Query, routing::get, Router, Server};
use serde::Deserialize;

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/", get(up))
        .route("/test", get(handle_tup));

    Server::bind(&"0.0.0.0:3000".parse().expect("Failed to parse address"))
        .serve(app.into_make_service())
        .await
        .expect("Failed to run app");
}

#[derive(Deserialize)]
struct Tup {
    first: u32,
    second: u32,
}

async fn up() {}

async fn handle_tup(Query(input): Query<Tup>) -> String {
    println!("handling tup");
    format!("ok {}", input.first * input.second)
}
