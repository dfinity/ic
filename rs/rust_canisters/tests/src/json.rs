use dfn_macro::query;

unsafe(#[query])
fn reverse_words(words: Vec<String>) -> Vec<String> {
    let mut a = words;
    a.reverse();
    a
}

unsafe(#[query])
fn test_multi_args(a: i32, b: i32) -> i32 {
    a + b
}

fn main() {}
