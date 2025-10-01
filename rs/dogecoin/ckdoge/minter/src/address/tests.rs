use crate::address::DogecoinAddress;
use crate::lifecycle::init::Network;

#[test]
fn should() {
    let address =
        DogecoinAddress::parse("DD4KSSuBJqcjuTcvUg1CgUKeurPUFeEZkE", &Network::Mainnet).unwrap();
    let expected_bytes = hex::decode("56d9b1d684d5abef32134ebc6883d75d3a53e9be").unwrap();

    assert_eq!(address.as_bytes(), expected_bytes);

}
