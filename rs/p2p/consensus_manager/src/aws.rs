fn main() {
    println!("{}", std::env::var("RUNNER_BIN").unwrap());
}
