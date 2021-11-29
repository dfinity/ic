
fn main() {
    println!("Hello, world!");
}

#[cfg(test)]
mod tests {
    use serde::{Serialize, Deserialize};
    use json5;

    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    struct S {
        value: String
    }

    #[test]
    fn roundtrip_u2028() {
        let original = S {
            value: "\u{2028}".to_string()
        };

        let serialized = json5::to_string(&original).unwrap();
        serialized.chars().into_iter().for_each(|c| println!("{:x}", c as u32));
        println!("{}", serialized);
        let deserialized = json5::from_str::<S>(&serialized).unwrap();

        assert_eq!(deserialized, original);
    }
}
