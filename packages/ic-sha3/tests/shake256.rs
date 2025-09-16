use ic_sha3::Shake256;

/// Checks a subset of the NIST test vectors in SHAKE256VariableOut.rsp from
/// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/sha3/shakebytetestvectors.zip
#[test]
fn should_pass_nist_variable_output_test_vectors() {
    let input_file = include_str!("../test_resources/SHAKE256VariableOut_subset.rsp");
    let mut lines = input_file
        .lines()
        .filter(|line| {
            !(line.is_empty()
                || line.starts_with("# ")
                || (line.starts_with('[') && line.ends_with(']')))
        })
        .peekable();

    while lines.peek().is_some() {
        let (count, outputlen, msg, output) = {
            let l1 = lines.next().expect("no more lines");
            let l2 = lines.next().expect("no more lines");
            let l3 = lines.next().expect("no more lines");
            let l4 = lines.next().expect("no more lines");

            let count = l1.strip_prefix("COUNT = ").expect("no `COUNT = `");
            let outputlen = l2.strip_prefix("Outputlen = ").expect("no `Outputlen = `");
            let msg = l3.strip_prefix("Msg = ").expect("no `Msg = `");
            let output = l4.strip_prefix("Output = ").expect("no `Output = `");

            let count = count.parse::<i16>().expect("not i16");
            let outputlen = outputlen.parse::<usize>().expect("not usize");
            let msg = hex::decode(msg).expect("not hex");
            let output = hex::decode(output).expect("not hex");

            (count, outputlen, msg, output)
        };

        let mut shake256 = Shake256::new();
        shake256.update(msg);
        let mut xof_reader = shake256.finalize_xof();
        let buf = &mut vec![0u8; outputlen / 8];
        xof_reader.read(buf);

        assert_eq!(buf, &output, "test vec with COUNT = {count} failed");
    }
}

/// Checks a subset of the NIST test vectors in SHAKE256ShortMsg.rsp from
/// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/sha3/shakebytetestvectors.zip
#[test]
fn should_pass_nist_short_msg_test_vectors() {
    let input_file = include_str!("../test_resources/SHAKE256ShortMsg_subset.rsp");
    let mut lines = input_file
        .lines()
        .filter(|line| {
            !(line.is_empty()
                || line.starts_with("# ")
                || line.starts_with('[') && line.ends_with(']'))
        })
        .peekable();

    while lines.peek().is_some() {
        let (len, msg, output) = {
            let l1 = lines.next().expect("no more lines");
            let l2 = lines.next().expect("no more lines");
            let l3 = lines.next().expect("no more lines");

            let len = l1.strip_prefix("Len = ").expect("no `Len = `");
            let msg = l2.strip_prefix("Msg = ").expect("no `Msg = `");
            let output = l3.strip_prefix("Output = ").expect("no `Output = `");

            let len = len.parse::<usize>().expect("not usize");
            let msg = hex::decode(msg).expect("not hex");
            let output = hex::decode(output).expect("not hex");

            (len, msg, output)
        };

        let mut shake256 = Shake256::new();
        if len > 0 {
            // We guard for `len > 0` because test vector for Len = 0 has a non-empty input and would fail
            shake256.update(msg);
        }
        let mut xof_reader = shake256.finalize_xof();
        let buf = &mut vec![0u8; output.len()];
        xof_reader.read(buf);

        assert_eq!(buf, &output, "test vec for Len = {len} failed");
    }
}
