use dfn_http::*;

#[export_name = "canister_query http_query"]
pub fn main() {
    http(handler)
}

const BODY: &str = "
<html>
<body>
<h1>Hello, World!</h1>
</body>
</html>";

fn handler(http: RequestWrapper) -> Response {
    let req = http.request;
    match (req.method, &req.path[..]) {
        (Method::Get, "/index.html") => Response::from_status_code(200)
            .set_body(BODY)
            .push_header("Content-Type", "text/html"),
        _ => Response::from_status_code(404).set_body("Page not found"),
    }
}
