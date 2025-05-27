use axum::{response::Html, routing::get, Router};
use http_body_util::{BodyExt, Empty};
use hyper::body::{Buf, Bytes};
use hyper_util::rt::TokioIo;
use std::io::Read;
use tokio::net::TcpStream;

async fn handler() -> Html<&'static str> {
    let agent = ic_agent::Agent::builder()
        .with_url("http://localhost:3000")
        .build()
        .unwrap();
    let err = agent.fetch_root_key().await.unwrap_err();
    assert!(matches!(err, ic_agent::AgentError::InvalidCborData(_)));
    Html("<h1>Hello, World!</h1>")
}

async fn status_handler() -> Html<&'static str> {
    Html("<h1>status</h1>")
}

#[tokio::test]
async fn hyper_issue() {
    // spawn a webserver
    tokio::spawn(async {
        // build our application with a route
        let app = Router::new()
            .route("/api/v2/status", get(status_handler))
            .route("/index.html", get(handler));

        // run it
        let listener = tokio::net::TcpListener::bind("127.0.0.1:3000")
            .await
            .unwrap();
        println!("listening on {}", listener.local_addr().unwrap());
        axum::serve(listener, app).await.unwrap();
    });

    // wait until the server starts up
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;

    // send an HTTP request to the webserver
    let stream = TcpStream::connect("127.0.0.1:3000").await.unwrap();
    let io = TokioIo::new(stream);

    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await.unwrap();
    tokio::task::spawn(conn);

    let req = hyper::Request::builder()
        .uri("http://127.0.0.1:3000/index.html")
        .body(Empty::<Bytes>::new())
        .unwrap();

    let res = sender.send_request(req).await.unwrap();
    println!("hyper response: {:?}", res);

    // asynchronously aggregate the chunks of the body
    let mut body = res.collect().await.unwrap().aggregate().reader();
    let mut buffer = Vec::new();
    body.read_to_end(&mut buffer).unwrap();
    let body = String::from_utf8(buffer).unwrap();

    println!("hyper body: {}", body);
    assert!(body.contains("Hello, World!"));
}
