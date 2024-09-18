use super::*;

#[test]
fn test_fetch_guard() {
    use super::*;
    let txid = Txid::from([0u8; 32]);
    let max = MAX_CONCURRENT;
    {
        let _guard = FetchGuard::new(txid).unwrap();
        assert_eq!(OUTCALL_CAPACITY.with(|c| *c.borrow()), max - 1);
        assert!(matches!(
            get_fetch_status(txid),
            Some(FetchTxStatus::PendingOutcall)
        ));
    }
    assert!(get_fetch_status(txid).is_none());
    assert_eq!(OUTCALL_CAPACITY.with(|c| *c.borrow()), max);

    {
        let mut guards = Vec::new();
        for i in 0..max {
            assert_eq!(OUTCALL_CAPACITY.with(|c| *c.borrow()), max - i);
            let txid = Txid::from([(i + 1) as u8; 32]);
            guards.push(FetchGuard::new(txid).unwrap());
        }
        assert!(FetchGuard::new(txid).is_err());
        assert_eq!(OUTCALL_CAPACITY.with(|c| *c.borrow()), 0);
    }
    assert_eq!(OUTCALL_CAPACITY.with(|c| *c.borrow()), max);
}

#[test]
fn test_fetch_status() {
    let txid_0 = Txid::from([0u8; 32]);
    assert!(get_fetch_status(txid_0).is_none());
    set_fetch_status(txid_0, FetchTxStatus::PendingOutcall);
    assert!(matches!(
        get_fetch_status(txid_0),
        Some(FetchTxStatus::PendingOutcall)
    ));

    let bytes = b"\
\x02\x00\x00\x00\x01\x17\x34\x3a\xab\xa9\x67\x67\x2f\x17\xef\x0a\xbf\x4b\xb1\x14\xad\x19\x63\xe0\
\x7d\xd2\xf2\x05\xaa\x25\xa4\xda\x50\x3e\xdb\x01\xab\x01\x00\x00\x00\x6a\x47\x30\x44\x02\x20\x21\
\x81\xb5\x9c\xa7\xed\x7e\x2c\x8e\x06\x96\x52\xb0\x7e\xd2\x10\x24\x9e\x83\x37\xec\xc5\x35\xca\x6b\
\x75\x3c\x02\x44\x89\xe4\x5d\x02\x20\x2a\xc7\x55\xcb\x55\x97\xf1\xcc\x2c\xad\x32\xb8\xa4\x33\xf1\
\x79\x6b\x5f\x51\x76\x71\x6d\xa9\x22\x2c\x65\xf9\x44\xaf\xd1\x3d\xa8\x01\x21\x02\xc4\xc6\x9e\x4d\
\x36\x4b\x3e\xdf\x84\xb5\x20\xa0\x18\xd5\x7e\x71\xfa\xce\x19\x7e\xc8\xf9\x46\x43\x60\x7e\x4a\xca\
\x70\xdc\x82\xc1\xfd\xff\xff\xff\x02\x10\x27\x00\x00\x00\x00\x00\x00\x19\x76\xa9\x14\x11\xb3\x66\
\xed\xfc\x0a\x8b\x66\xfe\xeb\xae\x5c\x2e\x25\xa7\xb6\xa5\xd1\xcf\x31\x88\xac\x7c\x2e\x00\x00\x00\
\x00\x00\x00\x19\x76\xa9\x14\xb9\x73\x68\xd8\xbf\x0a\x37\x69\x00\x85\x16\x57\xf3\x7f\xbe\x73\xa6\
\x56\x61\x33\x88\xac\x14\xa4\x0c\x00";
    use bitcoin::consensus::Decodable;
    use bitcoin::Network;
    let tx = Transaction::consensus_decode(&mut bytes.to_vec().as_slice()).unwrap();
    let txid_1 = Txid::from(*(tx.compute_txid().as_ref() as &[u8; 32]));
    set_fetch_status(
        txid_1,
        FetchTxStatus::Fetched(FetchedTx {
            tx: tx.clone(),
            input_addresses: vec![None; 2],
        }),
    );
    assert!(matches!(
        get_fetch_status(txid_1),
        Some(FetchTxStatus::Fetched(_))
    ));
    let address = Address::from_script(&tx.output[0].script_pubkey, Network::Bitcoin).unwrap();
    set_fetched_address(txid_1, 0, address.clone());
    match get_fetch_status(txid_1) {
        Some(FetchTxStatus::Fetched(fetched)) => {
            assert_eq!(fetched.input_addresses[0], Some(address))
        }
        _ => {
            panic!("txid {} is not found", txid_1)
        }
    }
    clear_fetch_status(txid_1);
    assert!(get_fetch_status(txid_1).is_none());
}
