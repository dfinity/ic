include!(concat!(env!("OUT_DIR"), "/templates.rs"));

fn main() {
    let mut buf = Vec::new();
    templates::test(&mut buf, "world").unwrap();
    println!("{}", String::from_utf8_lossy(&buf));
}
