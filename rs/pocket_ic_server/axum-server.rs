use axum::{body::to_bytes, http::Request, response::Html, routing::get, Router};

async fn handler() -> Html<&'static str> {
    Html("<h1>Hello, World!</h1>\n")
}

#[tokio::main]
async fn main() {
    // build our application with a route
    let app = Router::new().route("/index.html", get(handler));
    // run it
    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000")
        .await
        .unwrap();
    println!("listening on {}", listener.local_addr().unwrap());
    axum::serve(listener, app).await.unwrap();
}
