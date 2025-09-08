use dfn_macro::query;

#[query]
fn reverse_words(words: Vec<String>) -> Vec<String> {
    let mut a = words;
    a.reverse();
    a
}

#[query]
fn test_multi_args(a: i32, b: i32) -> i32 {
    a + b
}

fn main() {}
