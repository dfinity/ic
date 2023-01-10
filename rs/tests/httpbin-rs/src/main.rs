// TODO(VER-2077): drop the `drip` endpoint and move to a high-level HTTP server API

use clap::Parser;
use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod, SslStream};
use serde::Serialize;
use std::collections::BTreeMap;
use std::io::Read;
use std::io::Write;
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

const MAX_REQUEST_BYTES: usize = 4 * 1024 * 1024;
const MAX_REQUEST_HEADERS: usize = 100;

#[derive(Serialize)]
struct Request {
    method: String,
    headers: BTreeMap<String, String>,
    data: String,
    url: String,
}

struct Response {
    status: u64,
    reason: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Response {
    fn as_bytes(&self) -> Vec<u8> {
        let hdrs: Vec<String> = self
            .headers
            .iter()
            .map(|h| format!("{}: {}", h.0, h.1))
            .collect();
        let r = format!(
            "HTTP/1.1 {} {}\r\n{}\r\n\r\n",
            self.status,
            self.reason,
            hdrs.join("\r\n")
        );
        vec![r.as_bytes().to_vec(), self.body.clone()].concat()
    }
    fn set_content_length(&mut self) {
        self.headers
            .push(("Content-Length".to_string(), self.body.len().to_string()));
    }
    fn set_binary_content_type(&mut self) {
        self.headers.push((
            "Content-Type".to_string(),
            "application/octet-stream".to_string(),
        ));
    }
    fn set_utf8_content_type(&mut self) {
        self.headers.push((
            "Content-Type".to_string(),
            "text/plain; charset=utf-8".to_string(),
        ));
    }
    fn set_html_content_type(&mut self) {
        self.headers.push((
            "Content-Type".to_string(),
            "text/html; charset=utf-8".to_string(),
        ));
    }
    fn set_aux_headers(&mut self) {
        self.headers
            .push(("Connection".to_string(), "keep-alive".to_string()));
        self.headers
            .push(("Access-Control-Allow-Origin".to_string(), "*".to_string()));
        self.headers.push((
            "Access-Control-Allow-Credentials".to_string(),
            "true".to_string(),
        ));
    }
}

fn bad_request() -> Response {
    let mut r = Response {
        status: 400,
        reason: "BAD REQUEST".to_string(),
        headers: vec![],
        body: "Bad request".as_bytes().to_vec(),
    };
    r.set_utf8_content_type();
    r.set_content_length();
    r.set_aux_headers();
    r
}

fn compute_response(stream: &mut SslStream<TcpStream>) -> Option<Option<Response>> {
    let mut buffer = vec![];
    let mut e = 0;
    loop {
        let mut headers = [httparse::EMPTY_HEADER; MAX_REQUEST_HEADERS];
        let mut req = httparse::Request::new(&mut headers);
        let mut aux = vec![];
        aux.resize(MAX_REQUEST_BYTES + 1, 0);
        e = match stream.read(&mut aux) {
            Ok(n) => {
                buffer.extend(aux.to_vec()[0..n].to_vec());
                e + n
            }
            Err(_) => {
                return None;
            }
        };
        if req.parse(&buffer).is_err() {
            continue;
        }
        if let httparse::Status::Complete(s) = req.parse(&buffer).ok()? {
            let mut buffer = buffer.clone();
            let n: usize = String::from_utf8(
                req.headers
                    .to_vec()
                    .iter()
                    .find(|h| h.name.to_lowercase() == "content-length")
                    .unwrap_or(&httparse::Header {
                        name: "content-length",
                        value: "0".as_bytes(),
                    })
                    .value
                    .to_vec(),
            )
            .ok()?
            .parse()
            .ok()?;
            while e < s + n {
                let mut aux = vec![];
                aux.resize(MAX_REQUEST_BYTES + 1, 0);
                e = match stream.read(&mut aux) {
                    Ok(n) => {
                        buffer.extend(aux.to_vec()[0..n].to_vec());
                        e + n
                    }
                    Err(_) => {
                        return None;
                    }
                };
            }
            let segs: Vec<_> = req.path?.split('/').collect();
            if segs.len() < 2 || !segs[0].is_empty() {
                return None;
            }
            return match segs[1] {
                "" => {
                    if segs.len() != 2 {
                        return None;
                    }
                    let mut r = Response {
                        status: 200,
                        reason: "OK".to_string(),
                        headers: vec![],
                        body: "<!DOCTYPE html>
<html lang=\"en\">
<head>
  <title>httpbin</title>
</head>
<body>
  <h1>httpbin</h1>
</body>
</html>"
                            .to_string()
                            .as_bytes()
                            .to_vec(),
                    };
                    r.set_html_content_type();
                    r.set_content_length();
                    r.set_aux_headers();
                    Some(Some(r))
                }
                "drip" => {
                    if segs.len() != 4 {
                        return None;
                    }
                    let duration: u64 = segs[2].parse().ok()?;
                    let num_bytes: u64 = segs[3].parse().ok()?;
                    let mut r = Response {
                        status: 200,
                        reason: "OK".to_string(),
                        headers: vec![("Content-Length".to_string(), num_bytes.to_string())],
                        body: vec![],
                    };
                    r.set_binary_content_type();
                    stream.write_all(&r.as_bytes()).unwrap();
                    stream.flush().unwrap();
                    let pause = duration * 1_000_000_u64 / num_bytes;
                    for _ in 0..num_bytes {
                        stream.write_all(&[b'x'; 1]).unwrap();
                        stream.flush().unwrap();
                        thread::sleep(Duration::from_micros(pause));
                    }
                    Some(None)
                }
                "bytes" | "equal_bytes" => {
                    if segs.len() != 3 {
                        return None;
                    }
                    let b: usize = segs[2].parse().ok()?;
                    let mut r = Response {
                        status: 200,
                        reason: "OK".to_string(),
                        headers: vec![],
                        body: "x".repeat(b).as_bytes().to_vec(),
                    };
                    r.set_binary_content_type();
                    r.set_content_length();
                    r.set_aux_headers();
                    Some(Some(r))
                }
                "ascii" => {
                    if segs.len() != 3 {
                        return None;
                    }
                    let b: String = segs[2].to_string();
                    let mut r = Response {
                        status: 200,
                        reason: "OK".to_string(),
                        headers: vec![],
                        body: b.as_bytes().to_vec(),
                    };
                    r.set_binary_content_type();
                    r.set_content_length();
                    r.set_aux_headers();
                    Some(Some(r))
                }
                "delay" => {
                    if segs.len() != 3 {
                        return None;
                    }
                    let d: u64 = segs[2].parse().ok()?;
                    thread::sleep(Duration::from_secs(d));
                    let mut r = Response {
                        status: 200,
                        reason: "OK".to_string(),
                        headers: vec![],
                        body: vec![],
                    };
                    r.set_binary_content_type();
                    r.set_content_length();
                    r.set_aux_headers();
                    Some(Some(r))
                }
                "redirect" | "relative-redirect" => {
                    if segs.len() != 3 {
                        return None;
                    }
                    let n: u64 = segs[2].parse().ok()?;
                    if n == 0 {
                        return None;
                    }
                    let loc = if n == 1 {
                        "/anything".to_string()
                    } else {
                        format!("/relative-redirect/{}", n - 1)
                    };
                    let body = format!("<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 3.2 Final//EN\">
<title>Redirecting...</title>
<h1>Redirecting...</h1>
<p>You should be redirected automatically to target URL: <a href=\"{}\">{}</a>.  If not click the link.</p>", loc, loc);
                    let mut r = Response {
                        status: 302,
                        reason: "FOUND".to_string(),
                        headers: vec![("Location".to_string(), loc)],
                        body: body.as_bytes().to_vec(),
                    };
                    r.set_binary_content_type();
                    r.set_content_length();
                    r.set_aux_headers();
                    Some(Some(r))
                }
                "anything" | "post" => {
                    if segs[1] == "post" && (segs.len() != 2 || req.method? != "POST") {
                        return None;
                    }
                    let data = String::from_utf8(buffer.to_vec()[s..e].to_vec()).ok()?;
                    let host = String::from_utf8(
                        req.headers
                            .to_vec()
                            .iter()
                            .find(|h| h.name.to_lowercase() == "host")
                            .unwrap_or(&httparse::Header {
                                name: "host",
                                value: "".as_bytes(),
                            })
                            .value
                            .to_vec(),
                    )
                    .ok()?;
                    let request = Request {
                        method: req.method?.to_string(),
                        headers: req
                            .headers
                            .iter()
                            .map(|h| Ok((h.name.to_string(), String::from_utf8(h.value.to_vec())?)))
                            .collect::<Result<Vec<_>, std::string::FromUtf8Error>>()
                            .ok()?
                            .into_iter()
                            .collect(),
                        data,
                        url: format!("https://{}{}", host, req.path?),
                    };
                    let json = serde_json::to_string(&request).ok()?;
                    let mut r = Response {
                        status: 200,
                        reason: "OK".to_string(),
                        headers: vec![],
                        body: json.as_bytes().to_vec(),
                    };
                    r.set_binary_content_type();
                    r.set_content_length();
                    r.set_aux_headers();
                    Some(Some(r))
                }
                "request_size" => {
                    if segs.len() != 2 {
                        return None;
                    }
                    let headers_size: usize = req
                        .headers
                        .iter()
                        .map(|h| h.name.len() + h.value.len())
                        .sum();
                    let body_size: usize = e - s;
                    let total_size = headers_size + body_size;
                    let mut r = Response {
                        status: 200,
                        reason: "OK".to_string(),
                        headers: vec![],
                        body: format!("{}", total_size).as_bytes().to_vec(),
                    };
                    r.set_utf8_content_type();
                    r.set_content_length();
                    r.set_aux_headers();
                    Some(Some(r))
                }
                "many_response_headers" => {
                    if segs.len() != 3 {
                        return None;
                    }
                    let n: u64 = segs[2].parse().ok()?;
                    let mut r = Response {
                        status: 200,
                        reason: "OK".to_string(),
                        headers: (0..n)
                            .collect::<Vec<_>>()
                            .iter()
                            .map(|i| (format!("Name{:?}", i), format!("value{:?}", i)))
                            .collect(),
                        body: vec![],
                    };
                    r.set_utf8_content_type();
                    r.set_content_length();
                    r.set_aux_headers();
                    Some(Some(r))
                }
                "long_response_header_name" => {
                    if segs.len() != 3 {
                        return None;
                    }
                    let n: usize = segs[2].parse().ok()?;
                    let mut r = Response {
                        status: 200,
                        reason: "OK".to_string(),
                        headers: vec![("x".repeat(n), "value".to_string())],
                        body: vec![],
                    };
                    r.set_utf8_content_type();
                    r.set_content_length();
                    r.set_aux_headers();
                    Some(Some(r))
                }
                "long_response_header_value" => {
                    if segs.len() != 3 {
                        return None;
                    }
                    let n: usize = segs[2].parse().ok()?;
                    let mut r = Response {
                        status: 200,
                        reason: "OK".to_string(),
                        headers: vec![("name".to_string(), "x".repeat(n))],
                        body: vec![],
                    };
                    r.set_utf8_content_type();
                    r.set_content_length();
                    r.set_aux_headers();
                    Some(Some(r))
                }
                "large_response_total_header_size" => {
                    if segs.len() != 4 {
                        return None;
                    }
                    let n: usize = segs[2].parse().ok()?;
                    let m: usize = segs[3].parse().ok()?;
                    if n < 8 {
                        return None;
                    }
                    let mut r = Response {
                        status: 200,
                        reason: "OK".to_string(),
                        headers: vec![],
                        body: vec![],
                    };
                    r.set_utf8_content_type();
                    r.set_content_length();
                    r.set_aux_headers();
                    let mut total_size: usize =
                        r.headers.iter().map(|h| h.0.len() + h.1.len()).sum();
                    let mut i = 0;
                    while total_size < m {
                        let mut name = format!("{:08}{}", i, "x".repeat(n - 8));
                        name.truncate(m - total_size);
                        total_size += name.len();
                        let value = "x".repeat(n.min(m - total_size));
                        total_size += value.len();
                        r.headers.push((name, value));
                        i += 1;
                    }
                    Some(Some(r))
                }
                _ => None,
            };
        }
    }
}

fn handle_client(mut stream: SslStream<TcpStream>) {
    let response = compute_response(&mut stream);

    match response {
        Some(Some(r)) => {
            stream.write_all(&r.as_bytes()).unwrap();
            stream.flush().unwrap();
        }
        Some(None) => {}
        None => {
            stream.write_all(&bad_request().as_bytes()).unwrap();
            stream.flush().unwrap();
        }
    };
}

#[derive(Parser)]
struct Cli {
    /// The port to listen on.
    #[clap(long)]
    port: u64,
    /// The path to cert.pem file.
    #[clap(long)]
    cert_file: std::path::PathBuf,
    /// The path to key.pem file.
    #[clap(long)]
    key_file: std::path::PathBuf,
}

fn main() {
    let args = Cli::parse();

    let mut acceptor = SslAcceptor::mozilla_modern(SslMethod::tls()).unwrap();
    acceptor
        .set_private_key_file(args.key_file, SslFiletype::PEM)
        .unwrap();
    acceptor
        .set_certificate_file(args.cert_file, SslFiletype::PEM)
        .unwrap();
    acceptor.check_private_key().unwrap();
    let acceptor = Arc::new(acceptor.build());

    let listener = TcpListener::bind(format!("[::]:{}", args.port)).unwrap();

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let acceptor = acceptor.clone();
                thread::spawn(move || match acceptor.accept(stream) {
                    Ok(stream) => handle_client(stream),
                    Err(e) => println!("Error: {:?}", e),
                });
            }
            Err(_) => {
                println!("Error");
            }
        }
    }
}
