use bytes::Bytes;
use http_body_util::{BodyExt, Empty};
use hyper::body::Buf;
use hyper_util::rt::TokioIo;
use std::io::Read;
use tokio::net::TcpStream;

#[tokio::main]
async fn main() {
    // send an HTTP request to the webserver
    let stream = TcpStream::connect("127.0.0.1:3000").await.unwrap();
    let io = TokioIo::new(stream);

    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await.unwrap();
    tokio::task::spawn(async move {
        if let Err(err) = conn.await {
            println!("Connection failed: {:?}", err);
        }
    });
    let req = hyper::Request::builder()
        .uri("/index.html")
        .version(http::Version::HTTP_2)
        .body(Empty::<Bytes>::new())
        .unwrap();

    println!("hyper request: {:?}", req);

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
