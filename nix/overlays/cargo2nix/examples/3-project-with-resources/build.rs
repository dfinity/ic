use ructe::Ructe;

fn main() {
    Ructe::from_env()
        .expect("ructe")
        .compile_templates("templates")
        .unwrap();
}
