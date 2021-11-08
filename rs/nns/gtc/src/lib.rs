pub mod init;
pub mod pb;

use crate::pb::v1::{AccountState, Gtc, TransferredNeuron};
use dfn_candid::candid;
use dfn_core::api::{call, now};
use dfn_core::println;
use ic_base_types::PrincipalId;
use ic_nns_common::pb::v1::NeuronId;
use ic_nns_constants::GOVERNANCE_CANISTER_ID;
use ic_nns_governance::pb::v1::GovernanceError;
use libsecp256k1::{PublicKey, PublicKeyFormat};
use sha3::{Digest, Keccak256};
use simple_asn1::ASN1Block::{BitString, ObjectIdentifier, Sequence};
use simple_asn1::{oid, to_der};
use std::collections::HashSet;
use std::time::SystemTime;

pub const LOG_PREFIX: &str = "[GTC] ";

/// The amount of time after the genesis of the IC that GTC neurons cannot be
/// claimed.
pub const SECONDS_UNTIL_CLAIM_NEURONS_CAN_BE_CALLED: u64 = 3 * 86400; // 3 days

/// The amount of time after the genesis of the IC that any user can call
/// `forward_whitelisted_unclaimed_accounts`. This allows the reclaiming of GTC
/// neurons that have not been claimed, so that these neurons don't exist in an
/// unclaimed state indefinitely.
pub const SECONDS_UNTIL_FORWARD_WHITELISTED_UNCLAIMED_ACCOUNTS_CAN_BE_CALLED: u64 = 188 * 86400; // 188 days

/// Return the current UNIX timestamp (in seconds) as a `u64`
fn now_secs() -> u64 {
    now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("Could not get duration since UNIX_EPOCH")
        .as_secs()
}

impl Gtc {
    /// Claim the caller's GTC neurons (on behalf of the caller) and return the
    /// IDs of these neurons
    pub async fn claim_neurons(
        &mut self,
        caller: &PrincipalId,
        public_key_hex: String,
    ) -> Result<Vec<NeuronId>, String> {
        self.assert_claim_neurons_can_be_called()?;

        let public_key = decode_hex_public_key(&public_key_hex)?;
        validate_public_key_against_caller(&public_key, caller)?;

        let address = public_key_to_gtc_address(&public_key);
        let account = self.get_account_mut(&address)?;
        account.authenticated_principal_id = Some(*caller);

        if account.has_donated {
            return Err("Account has previously donated its funds".to_string());
        }

        if account.has_forwarded {
            return Err("Account has previously forwarded its funds".to_string());
        }

        if account.has_claimed {
            return Ok(account.neuron_ids.clone());
        }

        GovernanceCanister::claim_gtc_neurons(caller, account.neuron_ids.clone()).await?;

        account.has_claimed = true;
        Ok(account.neuron_ids.clone())
    }

    /// Donates the stake of all GTC neurons owned by the caller to the Neuron
    /// given by `self.donate_account_recipient_neuron_id`. This GTC account
    /// will no longer be able to have its neurons claimed.
    pub async fn donate_account(
        &mut self,
        caller: &PrincipalId,
        public_key_hex: String,
    ) -> Result<(), String> {
        let public_key = decode_hex_public_key(&public_key_hex)?;
        validate_public_key_against_caller(&public_key, caller)?;

        let custodian_neuron_id = self.donate_account_recipient_neuron_id.clone();

        let address = public_key_to_gtc_address(&public_key);
        let account = self.get_account_mut(&address)?;
        account.authenticated_principal_id = Some(*caller);

        account.transfer(custodian_neuron_id).await?;
        account.has_donated = true;

        Ok(())
    }

    /// Forwards the stake of whitelisted GTC neurons that have not been claimed
    /// (or donated) to the Neuron given by
    /// `self.forward_whitelisted_unclaimed_accounts_recipient_neuron_id`.
    ///
    /// This method will be allowed to be called by anyone after
    /// `SECONDS_UNTIL_FORWARD_WHITELISTED_UNCLAIMED_ACCOUNTS_CAN_BE_CALLED` has
    /// elapsed.
    pub async fn forward_whitelisted_unclaimed_accounts(&mut self) -> Result<(), String> {
        self.assert_forward_whitelisted_unclaimed_accounts_can_be_called()?;
        let mut forward_whitelist = HashSet::new();

        for gtc_address in &self.whitelisted_accounts_to_forward {
            forward_whitelist.insert(gtc_address.to_string());
        }

        let custodian_neuron_id = self
            .forward_whitelisted_unclaimed_accounts_recipient_neuron_id
            .clone();

        for (gtc_address, account) in self.accounts.iter_mut() {
            if !account.has_claimed
                && !account.has_donated
                && !account.has_forwarded
                && forward_whitelist.contains(gtc_address)
            {
                match account.transfer(custodian_neuron_id.clone()).await {
                    Ok(_) => account.has_forwarded = true,
                    Err(error) => {
                        println!(
                            "Error forwarding gtc account: {}. Error: {}",
                            gtc_address, error
                        );
                    }
                }
            }
        }

        Ok(())
    }

    /// Return a mutable reference to the account associated with `address`,
    /// if one exists
    fn get_account_mut(&mut self, address: &str) -> Result<&mut AccountState, String> {
        self.accounts
            .get_mut(address)
            .ok_or_else(|| "Account not found".to_string())
    }

    /// Return the account associated with `address`, if one exists
    pub fn get_account(&self, address: &str) -> Result<AccountState, String> {
        self.accounts
            .get(address)
            .cloned()
            .ok_or_else(|| "Account not found".to_string())
    }

    /// Return an error if `claim_neurons` can't be called, else return `Ok`
    fn assert_claim_neurons_can_be_called(&self) -> Result<(), String> {
        if now_secs() - self.genesis_timestamp_seconds < SECONDS_UNTIL_CLAIM_NEURONS_CAN_BE_CALLED {
            Err("claim_neurons cannot be called yet".to_string())
        } else {
            Ok(())
        }
    }

    /// Return an error if `forward_all_unclaimed_accounts` can't be called,
    /// else return `Ok`
    fn assert_forward_whitelisted_unclaimed_accounts_can_be_called(&self) -> Result<(), String> {
        if now_secs() - self.genesis_timestamp_seconds
            < SECONDS_UNTIL_FORWARD_WHITELISTED_UNCLAIMED_ACCOUNTS_CAN_BE_CALLED
        {
            Err("forward_all_unclaimed_accounts cannot be called yet".to_string())
        } else {
            Ok(())
        }
    }
}

impl AccountState {
    /// Transfer the stake of all unclaimed neurons (associated with this
    /// account) to the neuron given by `custodian_neuron_id`.
    pub async fn transfer(&mut self, custodian_neuron_id: Option<NeuronId>) -> Result<(), String> {
        if self.has_claimed {
            return Err("Neurons already claimed".to_string());
        } else if self.has_donated {
            return Err("Account has already donated its funds".to_string());
        } else if self.has_forwarded {
            return Err("Account has already forwarded its funds".to_string());
        } else if custodian_neuron_id.is_none() {
            return Err("No custodian neuron ID is defined".to_string());
        }

        let custodian_neuron_id = custodian_neuron_id.unwrap();
        let neuron_ids = self.neuron_ids.clone();

        for neuron_id in neuron_ids {
            let result = GovernanceCanister::transfer_gtc_neuron(
                neuron_id.clone(),
                custodian_neuron_id.clone(),
            )
            .await;

            self.neuron_ids.retain(|id| id != &neuron_id);

            let mut donated_neuron = TransferredNeuron {
                neuron_id: Some(neuron_id),
                timestamp_seconds: now_secs(),
                error: None,
            };

            match result {
                Ok(_) => self.successfully_transferred_neurons.push(donated_neuron),
                Err(e) => {
                    donated_neuron.error = Some(e.to_string());
                    self.failed_transferred_neurons.push(donated_neuron)
                }
            }
        }

        Ok(())
    }
}

struct GovernanceCanister {}
impl GovernanceCanister {
    /// Call the `claim_gtc_neurons` method of the Governance canister
    pub async fn claim_gtc_neurons(
        caller: &PrincipalId,
        neuron_ids: Vec<NeuronId>,
    ) -> Result<(), String> {
        let result: Result<Result<(), GovernanceError>, (Option<i32>, String)> = call(
            GOVERNANCE_CANISTER_ID,
            "claim_gtc_neurons",
            candid,
            (*caller, neuron_ids),
        )
        .await;

        let result = result.map_err(|(code, msg)| {
            format!(
                "Error calling method 'claim_gtc_neurons' of the Governance canister. Code: {:?}. Message: {}",
                code, msg
            )
        })?;

        result.map_err(|e| {
            format!(
                "Error returned by 'claim_gtc_neurons' of the Governance canister: {:?}",
                e
            )
        })
    }

    /// Call the `transfer_gtc_neuron` method of the Governance canister
    pub async fn transfer_gtc_neuron(
        donor_neuron_id: NeuronId,
        recipient_neuron_id: NeuronId,
    ) -> Result<(), String> {
        let result: Result<Result<(), GovernanceError>, (Option<i32>, String)> = call(
            GOVERNANCE_CANISTER_ID,
            "transfer_gtc_neuron",
            candid,
            (donor_neuron_id, recipient_neuron_id),
        )
        .await;

        let result = result.map_err(|(code, msg)| {
            format!(
                "Error calling method 'transfer_gtc_neuron' of the Governance canister. \
                 Code: {:?}. Message: {}",
                code, msg
            )
        })?;

        result.map_err(|e| {
            format!(
                "Error returned by 'transfer_gtc_neuron' of the Governance canister: {:?}",
                e
            )
        })
    }
}

/// Attempt to convert a hex string into a `PublicKey`
fn decode_hex_public_key(public_key_hex: &str) -> Result<PublicKey, String> {
    let public_key_bytes =
        hex::decode(public_key_hex).map_err(|_| "Could not hex-decode public key".to_string())?;

    let format = Some(PublicKeyFormat::Full);

    PublicKey::parse_slice(&public_key_bytes, format)
        .map_err(|_| "Could not parse hex-decoded public key".to_string())
}

/// Return an error if the principal ID derived from `public_key` does not
/// equal `caller`
fn validate_public_key_against_caller(
    public_key: &PublicKey,
    caller: &PrincipalId,
) -> Result<(), String> {
    let public_key_principal = public_key_to_principal(public_key);

    if caller != &public_key_principal {
        Err("Public key does not match caller".to_string())
    } else {
        Ok(())
    }
}

/// Given a public key, return the associated GTC account address
fn public_key_to_gtc_address(public_key: &PublicKey) -> String {
    let mut hasher = Keccak256::new();
    hasher.update(&public_key.serialize()[1..]);
    let address_bytes = &hasher.finalize()[12..];
    hex::encode::<&[u8]>(address_bytes)
}

/// Convert a `PublicKey` to a `PrincipalId`
fn public_key_to_principal(public_key: &PublicKey) -> PrincipalId {
    PrincipalId::new_self_authenticating(&der_encode(public_key))
}

/// DER-encode the given `PublicKey`
pub fn der_encode(public_key: &PublicKey) -> Vec<u8> {
    let public_key_bytes = public_key.serialize().to_vec();
    let ec_public_key_id = ObjectIdentifier(0, oid!(1, 2, 840, 10045, 2, 1));
    let secp256k1_id = ObjectIdentifier(0, oid!(1, 3, 132, 0, 10));
    let metadata = Sequence(0, vec![ec_public_key_id, secp256k1_id]);
    let data = BitString(0, public_key_bytes.len() * 8, public_key_bytes);
    let envelope = Sequence(0, vec![metadata, data]);
    to_der(&envelope).expect("Cannot encode public key.")
}

pub mod test_constants {
    use super::{decode_hex_public_key, public_key_to_gtc_address, public_key_to_principal};
    use ic_base_types::PrincipalId;
    use ic_crypto_sha::Sha256;
    use libsecp256k1::{sign, Message};
    use libsecp256k1::{PublicKey, PublicKeyFormat, SecretKey};
    use std::str::FromStr;

    /// An identity used to make calls to the GTC canister in tests
    pub struct TestIdentity {
        pub public_key_bytes: [u8; 65],
        pub secret_key_bytes: [u8; 32],
        pub public_key_hex: &'static str,
        pub gtc_address: &'static str,
        pub principal_id_str: &'static str,
    }

    impl TestIdentity {
        pub fn public_key(&self) -> PublicKey {
            let format = Some(PublicKeyFormat::Full);
            PublicKey::parse_slice(&self.public_key_bytes, format).unwrap()
        }

        pub fn secret_key(&self) -> SecretKey {
            SecretKey::parse_slice(&self.secret_key_bytes).unwrap()
        }

        pub fn principal_id(&self) -> PrincipalId {
            PrincipalId::from_str(self.principal_id_str).unwrap()
        }

        pub fn sign(&self, msg: &[u8]) -> Vec<u8> {
            let hashed_msg = {
                let mut state = Sha256::new();
                state.write(msg);
                state.finish()
            };

            let message = Message::parse(&hashed_msg);
            let secret_key = self.secret_key();

            let (sig, _) = sign(&message, &secret_key);

            sig.serialize().to_vec()
        }

        /// Assert that `self.public_key_hex` is the hex-encoding of
        /// `self.public_key_bytes`
        pub fn check_public_key_hex(&self) {
            let decoded_public_key = decode_hex_public_key(self.public_key_hex).unwrap();
            assert_eq!(decoded_public_key, self.public_key());
        }

        /// Assert that `self.gtc_address` is the correct address derived
        /// from `self.public_key()`
        pub fn check_gtc_address(&self) {
            let address = public_key_to_gtc_address(&self.public_key());
            assert_eq!(&address, self.gtc_address);
        }

        /// Assert that `self.principal_id_str` is the correct principal
        /// derived from `self.public_key()`
        pub fn check_principal_id_str(&self) {
            let principal = PrincipalId::from_str(self.principal_id_str).unwrap();
            let derived_principal = public_key_to_principal(&self.public_key());

            assert_eq!(derived_principal, principal);
        }
    }

    pub const TEST_IDENTITY_1: TestIdentity = TestIdentity {
        public_key_bytes: [
            4, 0, 229, 123, 185, 10, 206, 137, 16, 214, 150, 255, 215, 39, 210, 238, 205, 59, 229,
            17, 18, 127, 155, 4, 38, 149, 57, 181, 129, 21, 64, 18, 237, 253, 49, 191, 176, 91, 78,
            153, 194, 234, 145, 8, 85, 62, 122, 104, 225, 241, 63, 99, 59, 139, 85, 165, 152, 130,
            68, 234, 30, 82, 167, 90, 120,
        ],
        secret_key_bytes: [
            106, 198, 184, 190, 240, 129, 88, 12, 243, 191, 110, 211, 48, 131, 165, 138, 249, 177,
            104, 152, 155, 174, 217, 134, 41, 28, 152, 222, 123, 151, 136, 243,
        ],
        public_key_hex: "04\
            00e57bb90ace8910d696ffd727d2eecd3be511127f9b04269539b581154012ed\
            fd31bfb05b4e99c2ea9108553e7a68e1f13f633b8b55a5988244ea1e52a75a78",
        gtc_address: "bdf51dc6fbb698be9c2ce5a6e91ada4d987cd5f0",
        principal_id_str: "as6dy-hbwc2-lefgs-wqiwi-7m5i4-kpjpj-nhy2i-w2k67-a6ksz-zmusg-xae",
    };

    pub const TEST_IDENTITY_2: TestIdentity = TestIdentity {
        public_key_bytes: [
            4, 66, 222, 154, 99, 60, 61, 135, 94, 131, 127, 244, 170, 152, 216, 224, 25, 34, 195,
            73, 243, 231, 117, 74, 106, 230, 83, 109, 250, 166, 238, 224, 51, 167, 91, 47, 111,
            253, 12, 90, 107, 141, 3, 98, 148, 29, 230, 128, 106, 237, 97, 123, 38, 106, 219, 84,
            203, 134, 236, 7, 67, 220, 88, 53, 125,
        ],
        secret_key_bytes: [
            200, 197, 32, 81, 63, 88, 108, 34, 239, 71, 105, 48, 17, 81, 67, 9, 149, 151, 63, 40,
            236, 35, 139, 57, 234, 174, 4, 83, 49, 17, 37, 216,
        ],
        public_key_hex: "04\
            42de9a633c3d875e837ff4aa98d8e01922c349f3e7754a6ae6536dfaa6eee033\
            a75b2f6ffd0c5a6b8d0362941de6806aed617b266adb54cb86ec0743dc58357d",
        gtc_address: "160e571aa8b1a72c16aac36021240605c1dd1060",
        principal_id_str: "lofjl-ggxxp-ixf4b-63gsq-2qe73-vr2e7-3ybx2-y52l6-47fnl-mluhv-dae",
    };

    pub const TEST_IDENTITY_3: TestIdentity = TestIdentity {
        public_key_bytes: [
            4, 251, 211, 199, 21, 252, 39, 31, 152, 246, 186, 126, 148, 13, 216, 94, 240, 184, 127,
            63, 36, 110, 223, 120, 47, 60, 164, 57, 165, 14, 223, 122, 72, 116, 149, 2, 228, 66,
            66, 194, 100, 131, 69, 232, 32, 228, 34, 239, 230, 249, 157, 45, 103, 34, 53, 0, 16,
            148, 37, 114, 65, 25, 109, 218, 65,
        ],
        secret_key_bytes: [
            108, 71, 115, 25, 69, 48, 149, 137, 59, 46, 188, 40, 48, 99, 177, 65, 232, 187, 181,
            117, 165, 40, 209, 87, 51, 55, 149, 24, 241, 117, 160, 197,
        ],
        public_key_hex: "04\
            fbd3c715fc271f98f6ba7e940dd85ef0b87f3f246edf782f3ca439a50edf7a48\
            749502e44242c2648345e820e422efe6f99d2d672235001094257241196dda41",
        gtc_address: "92d2a394613fc33a764ded33f02d7623bf71097e",
        principal_id_str: "twfag-pne7v-llz63-t3og5-6q7yc-722rb-rlr4e-5hb4q-lxyxr-aczn2-uqe",
    };

    pub const TEST_IDENTITY_4: TestIdentity = TestIdentity {
        public_key_bytes: [
            4, 149, 17, 141, 157, 202, 205, 53, 103, 83, 71, 158, 47, 142, 145, 53, 1, 200, 253,
            21, 72, 124, 129, 51, 38, 66, 191, 176, 30, 216, 94, 84, 99, 68, 28, 155, 71, 3, 221,
            100, 247, 152, 218, 87, 11, 179, 40, 55, 206, 36, 212, 126, 222, 44, 45, 108, 237, 142,
            137, 240, 67, 110, 200, 193, 74,
        ],
        secret_key_bytes: [
            229, 64, 253, 40, 156, 53, 194, 27, 180, 25, 132, 235, 160, 29, 193, 9, 91, 8, 161,
            172, 88, 37, 1, 81, 200, 187, 158, 245, 56, 29, 46, 127,
        ],
        public_key_hex: "04\
            95118d9dcacd356753479e2f8e913501c8fd15487c81332642bfb01ed85e5463\
            441c9b4703dd64f798da570bb32837ce24d47ede2c2d6ced8e89f0436ec8c14a",
        gtc_address: "247c29646e80bf62ea20a67183d2df6e46a22f7c",
        principal_id_str: "rsk4t-gtywy-tsi35-lmtdr-ejx43-x6ptb-ejf6n-dlzrw-3yhlz-imgj3-yae",
    };
}

#[cfg(test)]
mod tests {
    use crate::test_constants::*;

    #[test]
    fn test_decode_hex_public_key() {
        TEST_IDENTITY_1.check_public_key_hex();
        TEST_IDENTITY_2.check_public_key_hex();
        TEST_IDENTITY_3.check_public_key_hex();
        TEST_IDENTITY_4.check_public_key_hex();
    }

    #[test]
    fn test_public_key_to_gtc_address() {
        TEST_IDENTITY_1.check_gtc_address();
        TEST_IDENTITY_2.check_gtc_address();
        TEST_IDENTITY_3.check_gtc_address();
        TEST_IDENTITY_4.check_gtc_address();
    }

    #[test]
    fn test_public_key_to_principal() {
        TEST_IDENTITY_1.check_principal_id_str();
        TEST_IDENTITY_2.check_principal_id_str();
        TEST_IDENTITY_3.check_principal_id_str();
        TEST_IDENTITY_4.check_principal_id_str();
    }
}
