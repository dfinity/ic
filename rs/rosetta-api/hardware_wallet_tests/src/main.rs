pub use ed25519_dalek::Keypair as EdKeypair;
use ed25519_dalek::Signer;
use ic_nns_constants::LEDGER_CANISTER_ID;
use ic_rosetta_api::{
    convert::{from_hex, from_public_key, to_arg, to_hex, to_model_account_identifier},
    make_sig_data, models,
    models::{CurveType, Signature, SignatureType, SigningPayload},
};
use ic_types::{
    messages::{
        Blob, HttpCanisterUpdate, HttpRequestEnvelope, HttpSubmitContent, SignedRequestBytes,
    },
    PrincipalId,
};
use ledger_canister::{AccountIdentifier, SendArgs, Subaccount, TimeStamp, Tokens};
use rand::{Rng, RngCore};
use rand_distr::Distribution;
use rand_distr::Uniform;
use serde::ser::SerializeSeq;
use serde::ser::Serializer;
use serde_json::json;
use std::iter::once;
use std::ops::BitAnd;
use std::{convert::TryFrom, fmt::Display};

fn zondex_icp_format(amount: Tokens) -> String {
    let int_part_reversed: String = amount
        .get_tokens()
        .to_string()
        // Insert "," separators every 3 chars, going right to left
        .chars()
        .rev()
        .enumerate()
        .flat_map(|(pos, c)| {
            (if pos % 3 == 0 && pos > 0 { "'" } else { "" })
                .chars()
                .chain(once(c))
        })
        .collect();
    let int_part: String = int_part_reversed.chars().rev().collect();
    let frac_part_untruncated = format!("{:08}", amount.get_remainder_e8s());
    let frac_part_truncated_rev: String = frac_part_untruncated
        .chars()
        .rev()
        .enumerate()
        .skip_while(|(pos, c)| *c == '0' && *pos < 6)
        .map(|(_, c)| c)
        .collect();
    let frac_part: String = frac_part_truncated_rev.chars().rev().collect();

    format!("{}.{}", int_part, frac_part)
}

pub fn generate_zondax_test(
    index: u32,
    keypair: EdKeypair,
    send_args: SendArgs,
) -> serde_json::Value {
    let public_key_der =
        ic_canister_client::ed25519_public_key_to_der(keypair.public.to_bytes().to_vec());

    let public_key =
        models::PublicKey::new(hex::encode(public_key_der.clone()), CurveType::Edwards25519);

    let pid = PrincipalId::new_self_authenticating(&public_key_der);

    let SendArgs {
        memo,
        amount,
        fee,
        from_subaccount,
        to,
        ..
    } = send_args;

    let update = HttpCanisterUpdate {
        canister_id: Blob(LEDGER_CANISTER_ID.get().to_vec()),
        method_name: "send_pb".to_string(),
        arg: Blob(to_arg(send_args)),
        // TODO work out whether Rosetta will accept us generating a nonce here
        // If we don't have a nonce it could cause one of those nasty bugs that
        // doesn't show it's face until you try to do two
        // identical transactions at the same time
        nonce: None,
        sender: Blob(pid.into_vec()),
        // sender: Blob(from.into_vec()),
        ingress_expiry: 0,
    };

    let from = AccountIdentifier::new(pid, from_subaccount);

    let account_identifier = to_model_account_identifier(&from);

    let request_id = update.id();

    let transaction_payload = SigningPayload {
        address: None,
        account_identifier: Some(account_identifier),
        hex_bytes: hex::encode(make_sig_data(&request_id)),
        signature_type: Some(SignatureType::Ed25519),
    };

    let bytes = from_hex(&transaction_payload.hex_bytes).unwrap();
    let signature_bytes = keypair.sign(&bytes).to_bytes();
    let hex_bytes = to_hex(&signature_bytes);

    let transaction_signature = Signature {
        signing_payload: transaction_payload,
        public_key,
        signature_type: SignatureType::Ed25519,
        hex_bytes,
    };

    let envelope = HttpRequestEnvelope::<HttpSubmitContent> {
        content: HttpSubmitContent::Call { update },
        sender_pubkey: Some(Blob(ic_canister_client::ed25519_public_key_to_der(
            from_public_key(&transaction_signature.public_key).unwrap(),
        ))),
        sender_sig: Some(Blob(from_hex(&transaction_signature.hex_bytes).unwrap())),
        sender_delegation: None,
    };

    let bytes: Vec<u8> = SignedRequestBytes::try_from(envelope).unwrap().into();

    let mut expert = Vec::new();
    expert.push("0 | Transaction type : Send ICP".to_string());
    expert.push(format!("1 | Sender [1/2] : {}", chunk_pid(pid, 0)));
    expert.push(format!("1 | Sender [2/2] : {}", chunk_pid(pid, 1)));
    match from_subaccount {
        Some(sa) => {
            expert.push(format!(
                "2 | Subaccount [1/2] : {} {}",
                row(sa, 0),
                row(sa, 1)
            ));
            expert.push(format!(
                "2 | Subaccount [2/2] : {} {}",
                row(sa, 2),
                row(sa, 3)
            ));
        }
        None => expert.push("2 | Subaccount  : Not set".to_string()),
    }

    expert.push(format!(
        "3 | From account[1/2] : {} {}",
        row(from, 0),
        row(from, 1)
    ));
    expert.push(format!(
        "3 | From account[2/2] : {} {}",
        row(from, 2),
        row(from, 3)
    ));
    expert.push(format!(
        "4 | To account [1/2] : {} {}",
        row(to, 0),
        row(to, 1)
    ));
    expert.push(format!(
        "4 | To account [2/2] : {} {}",
        row(to, 2),
        row(to, 3)
    ));
    expert.push(format!("5 | Payment (ICP) : {}", zondex_icp_format(amount)));
    expert.push(format!(
        "6 | Maximum fee (ICP) : {}",
        zondex_icp_format(fee)
    ));
    expert.push(format!("7 | Memo : {}", memo.0));

    json!({
        "index": index,
        "name": format!("Send tx index {}", index),
        "valid": true,
        "blob": hex::encode(&bytes),
        "request_id": hex::encode(&request_id),
        "output": [
            "0 | Transaction type : Send ICP",
            format!("1 | From account[1/2] : {} {}", row(from, 0), row(from, 1)),
            format!("1 | From account[2/2] : {} {}", row(from, 2), row(from, 3)),
            format!("2 | To account [1/2] : {} {}", row(to, 0), row(to, 1)),
            format!("2 | To account [2/2] : {} {}", row(to, 2), row(to, 3)),
            format!("3 | Payment (ICP) : {}", zondex_icp_format(amount)),
            format!("4 | Maximum fee (ICP) : {}", zondex_icp_format(fee)),
            format!("5 | Memo : {}", memo.0)
        ],
        "output_expert": expert
    })
}

/// Returns the requested row (0 to 3)
fn row<D: Display>(d: D, row: usize) -> String {
    let s = format!("{}", d);
    let chars: Vec<char> = s.chars().collect();
    assert!(chars.len() <= 64);
    let offset = row * 16;
    let space = ' ';
    (chars[offset..offset + 8])
        .iter()
        .chain(once(&space))
        .chain(chars[offset + 8..offset + 16].iter())
        .collect()
}

fn chunk_pid(pid: PrincipalId, chunk: usize) -> String {
    let s = format!("{}", pid);
    let chunks = s
        .chars()
        .collect::<Vec<char>>()
        .chunks(18)
        .map(|c| c.iter().take(17).collect::<String>())
        .collect::<Vec<String>>();

    let fst = chunks.get(2 * chunk).unwrap();
    let snd = chunks.get(2 * chunk + 1).unwrap();

    format!("{} {}", fst, snd)
}

#[test]
fn test_zondax_generator() {
    use rand::{prelude::StdRng, SeedableRng};

    use ledger_canister::{Memo, Tokens};

    let send_args = SendArgs {
        memo: Memo(0),
        amount: Tokens::from_tokens(10).unwrap(),
        fee: Tokens::from_e8s(137),
        from_subaccount: None,
        to: PrincipalId::new_anonymous().into(),
        created_at_time: None,
    };

    let mut rng = StdRng::seed_from_u64(1);
    let keypair = EdKeypair::generate(&mut rng);

    let s = generate_zondax_test(1, keypair, send_args);
    println!("{}", s);
}

#[test]
fn test_pretty_icp_format() {
    assert_eq!(zondex_icp_format(Tokens::from_e8s(0)), *"0.00");
    assert_eq!(zondex_icp_format(Tokens::from_e8s(1)), *"0.00000001");
    assert_eq!(zondex_icp_format(Tokens::from_e8s(10)), *"0.0000001");
    assert_eq!(zondex_icp_format(Tokens::from_e8s(100)), *"0.000001");
    assert_eq!(zondex_icp_format(Tokens::from_e8s(1000)), *"0.00001");
    assert_eq!(zondex_icp_format(Tokens::from_e8s(10000)), *"0.0001");
    assert_eq!(zondex_icp_format(Tokens::from_e8s(100000)), *"0.001");
    assert_eq!(zondex_icp_format(Tokens::from_e8s(1000000)), *"0.01");

    // Starting from 10^7 e8s, we need to add at least one "useless" zero
    assert_eq!(zondex_icp_format(Tokens::from_e8s(10_000_000)), *"0.10");
    assert_eq!(zondex_icp_format(Tokens::from_e8s(100_000_000)), *"1.00");

    // Full amount of ICPts are wlays formatted with ".00" at the end
    assert_eq!(zondex_icp_format(Tokens::from_tokens(1).unwrap()), *"1.00");
    assert_eq!(
        zondex_icp_format(Tokens::from_tokens(12).unwrap()),
        *"12.00"
    );
    assert_eq!(
        zondex_icp_format(Tokens::from_tokens(1234567890).unwrap()),
        *"1'234'567'890.00"
    );

    // Some arbitrary case
    assert_eq!(
        zondex_icp_format(Tokens::from_e8s(8151012345000)),
        *"81'510.12345"
    );

    // extreme case
    assert_eq!(
        zondex_icp_format(Tokens::from_e8s(u64::MAX)),
        *"184'467'440'737.09551615"
    );

    // largest power of ten below u64::MAX doms
    assert_eq!(
        zondex_icp_format(Tokens::from_tokens(100_000_000_000).unwrap()),
        *"100'000'000'000.00"
    );
}

struct PrincipalDistribution {}

impl Distribution<PrincipalId> for PrincipalDistribution {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> PrincipalId {
        let num_bytes = Uniform::from(0_usize..PrincipalId::MAX_LENGTH_IN_BYTES + 1).sample(rng);
        let mut buf: [u8; PrincipalId::MAX_LENGTH_IN_BYTES] = [0; PrincipalId::MAX_LENGTH_IN_BYTES];
        rng.fill_bytes(&mut buf[0..num_bytes]);
        PrincipalId::try_from(&buf[0..num_bytes]).unwrap()
    }
}

fn main() {
    use rand::{prelude::StdRng, SeedableRng};

    use ledger_canister::Memo;

    let mut rng = StdRng::seed_from_u64(1);

    let mut index = 0;

    let principal_distribution = PrincipalDistribution {};
    let mut serializer = serde_json::Serializer::pretty(std::io::stdout());
    let mut seq = serializer.serialize_seq(None).unwrap();

    for num_trailing_zeros in 0..11 {
        for magnitude in num_trailing_zeros..18 {
            for with_subaccount in &[false, true] {
                index += 1;
                let multiple_of = 10_u64.pow(num_trailing_zeros);
                // Dividing by, then multiply by, "multiple_of" has the effect of getting the
                // last decimal digits being zero, while keeping the magnitude unchanged.
                let amount = Tokens::from_e8s(
                    ((rng.next_u64() % 10_u64.pow(magnitude)) / multiple_of) * multiple_of,
                );

                // To avoid combinatorial explosion of test cases, we use the same parameters to
                // generate the fee.
                let fee = Tokens::from_e8s(
                    ((rng.next_u64() % 10_u64.pow(magnitude)) / multiple_of) * multiple_of,
                );

                // Memo: sample a number to have the whole range of lengths.
                let original_memo = rng.next_u64();
                let num_bits_distribution = Uniform::from(0_u32..65_u32);
                let shift = num_bits_distribution.sample(&mut rng);
                let bit_mask = u64::MAX.checked_shr(shift).unwrap_or_default();
                let memo = Memo(original_memo.bitand(bit_mask));

                let from_subaccount = if *with_subaccount {
                    let mut bytes: [u8; 32] = [0; 32];
                    rng.fill_bytes(&mut bytes);
                    Some(Subaccount(bytes))
                } else {
                    None
                };

                // created_at_time is optional and has no impact on the test vector
                // Set it with probability 1/2.
                let created_at_time = if rng.gen::<bool>() {
                    None
                } else {
                    Some(TimeStamp {
                        timestamp_nanos: rng.next_u64(),
                    })
                };

                let send_args = SendArgs {
                    memo,
                    amount,
                    fee,
                    from_subaccount,
                    to: principal_distribution.sample(&mut rng).into(),
                    created_at_time,
                };

                let keypair = EdKeypair::generate(&mut rng);

                let s = generate_zondax_test(index, keypair, send_args);
                seq.serialize_element(&s).unwrap();
            }
        }
    }
    seq.end().unwrap();
}
