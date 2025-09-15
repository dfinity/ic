use crate::CryptoComponentImpl;
use crate::sign::{get_log_id, log_err, log_ok_content};
use ic_crypto_internal_csp::CryptoServiceProvider;
use ic_interfaces::crypto::IDkgProtocol;
use ic_logger::{debug, new_logger, warn};
use ic_types::NodeId;
use ic_types::crypto::canister_threshold_sig::error::{
    IDkgCreateDealingError, IDkgCreateTranscriptError, IDkgLoadTranscriptError,
    IDkgOpenTranscriptError, IDkgRetainKeysError, IDkgVerifyComplaintError,
    IDkgVerifyDealingPrivateError, IDkgVerifyDealingPublicError, IDkgVerifyInitialDealingsError,
    IDkgVerifyOpeningError, IDkgVerifyTranscriptError,
};
use ic_types::crypto::canister_threshold_sig::idkg::{
    BatchSignedIDkgDealings, IDkgComplaint, IDkgOpening, IDkgTranscript, IDkgTranscriptId,
    IDkgTranscriptParams, InitialIDkgDealings, SignedIDkgDealing,
};
use std::collections::{BTreeMap, BTreeSet, HashSet};

mod complaint;
mod dealing;
mod retain_active_keys;
mod transcript;
mod utils;

#[cfg(test)]
mod tests;

use ic_crypto_internal_logmon::metrics::{MetricsDomain, MetricsResult, MetricsScope};
pub use utils::{MegaKeyFromRegistryError, retrieve_mega_public_key_from_registry};

/// Implementation of the [`IDkgProtocol`] for the crypto component.
///
/// # Examples
///
/// We detail the protocol execution for the use-cases mentioned in the documentation of [`IDkgProtocol`].
/// * The protocol tolerates less than 1/3 malicious nodes, so the minimal non-trivial settings consist of 4 nodes, denoted by `N_1`, `N_2`, `N_3` and `N_4`,
///   where at most 1 node could be malicious. For simplicity, all the examples described here will use these settings.
/// * The protocol uses an elliptic curve `EC` of prime order p.
///   The initial implementation of the protocol uses curve secp256k1 (aka K-256) but it can be extended to support multiple elliptic curves.
///   We consider two *distinct* generators of the chosen elliptic curve, denoted by `G` and `H`.
/// * We will denote group elements from the elliptic curve by capital letters while elements of Zₚ (i.e. scalars) will be denoted by lower-case letters.
///   The elliptic curve group operation will be written additively.
/// * Each node `N_i` is assumed to have the following keys:
///     * An idkg dealing encryption key pair denoted by `(IDKG_PK_i, idkg_sk_i) ∈ EC x Zₚ`, where the secret key is the discrete logarithm of the public key,
///       i.e. `IDKG_PK_i = G * idkg_sk_i`.
///       Node `n` is assumed to know the dealing encryption public keys of all other nodes.
///     * A signing secret key denoted by `node_signing_sk_i`.
///     * The public keys of a node are stored in the registry and locally by the node.
///       A node may have a different IDKG dealing encryption public key (and corresponding secret key stored locally) depending on the registry version.
///       Each run of the [`IDkgProtocol`] is bound to a particular registry version.
///
/// ## Master Threshold Key Pair Generation
/// * Goal: generate a public/private signing key pair where the public key is known to the receivers and the secret key is secret-shared among the receivers,
///   such that at least 2 shares are required to reconstruct the secret key  (`reconstruction_threshold ≥ 2`).
/// * Dealers: all 4 nodes (`N_1`, `N_2`, `N_3`, `N_4`)
/// * Receivers: same 4 nodes (`N_1`, `N_2`, `N_3`, `N_4`)
///
/// Steps:
/// 1. Run [`IDkgTranscriptOperation::Random`] to generate a new public/private key pair secret-shared among the receivers.
/// 2. Run [`IDkgTranscriptOperation::ReshareOfMasked`] to reshare the shares from step 1 to reveal the public key to all receivers.
///
/// ### [`IDkgTranscriptOperation::Random`]
///
/// #### Dealer
/// Dealer `d` creates a single dealing for all receivers (see [`IDkgProtocol::create_dealing`]):
/// * Pick a random polynomial of degree 1 (we need maximal number of malicious nodes +1 coefficients): `p(x) := p_0 + p_1 x`,
///   where the polynomial's coefficients are random over Zₚ.
/// * Commit to the polynomial coefficients using Pedersen commitments (see [`PedersenCommitment`]):
///     * Select another random polynomial of same degree: `q(x) := q_0 + q_1 x`,
///       where the polynomial's coefficients are random over Zₚ.
///     * Compute polynomial commitment `C(x) := C_0 + C_1 x`, where
///       `C_0 := G * p_0 + H * q_0 ∈ EC` and `C_1 := G * p_1 + H * q_1 ∈ EC`,
///       where `G` and `H` are distinct generators of `EC`.
///       Note that the part `H * q_i` is a random group element of `EC`, and thus the commitment `C_i` perfectly hides `p_i`.
/// * Compute shares for each receiver `N_r: (p(r), q(r))` by evaluating the polynomials `p(x)` and `q(x)` in a fixed point different from zero, e.g., their index `r in 1..=4`.
/// * Encrypt shares for all receivers (see [`MEGaCiphertextPair::encrypt`]):
///     * Generate ephemeral key: `EK := G * alpha`, for some random `alpha` over Zₚ
///     * Compute proof of possession of `alpha`: `pop_ek` (see [`ProofOfDLogEquivalence`])
///     * Encrypt all the shares: `(E_1, E_2, E_3, E_4) := (E_{IDKG_PK_1} [p(1), q(1)], E_{IDKG_PK_2} [p(2), q(2)], E_{IDKG_PK_3} [p(3), q(3)], E_{IDKG_PK_3} [p(4), q(4)])`,
///       where for each receiver `r` the encryption is computed as follows:
///         * Compute Diffie-Hellman tuple: `DH_r := (IDKG_PK_r, EK, IDKG_PK_r * alpha)`
///         * Set associated data: `AD_dr` identifies protocol instance, identity of dealer and receiver
///         * Hash `(h_0, h_1) := hash_to_scalars(DH_r, AD_dr)` (modeled in the paper as a random oracle, implemented using [`xmd`] and [`hash2curve`])
///         * `E_{IDKG_PK_r} [p(r), q(r)] := (h_0 + p(r), h_1 + q(r))`
///     * Construct a single dealing for all receivers: `Dealing_d := ((C_0, C_1), (EK, pop_ek, E_1, E_2, E_3, E_4))`
///     * Sign dealing: `signed_dealing_d := Dealing_d ||Sign_{node_signing_sk_d} [Dealing_d]`
///     * Broadcast `signed_dealing_d` to all receivers
///
/// #### Receiver
/// Receiver `r` receives `signed_dealing_d := Dealing_d ||Sign_{node_signing_sk_d} [Dealing_d]` from dealer d:
/// * Public verification (can be done by any receiver), see [`IDkgProtocol::verify_dealing_public`]
///     * Check signature of dealer `d`
///     * Check length of commitments == reconstruction_threshold (which is 2 here)
///     * Check length of ciphertexts: one pair of scalars for each receiver
///     * Check proof of possession of ephemeral key
///     * Check commitment type is Pedersen
/// * Private verification (can only be done by owner of `idkg_sk_r`), see [`IDkgProtocol::verify_dealing_private`]
///     * Pre-requisite: public verification was successful
///     * Decrypt ciphertext `(p(r), q(r))` using IDKG dealing encryption secret key `idkg_sk_r`:
///         * Compute `EK * idkg_sk_r`, since `EK * idkg_sk_r = (G * alpha) * idkg_sk_r = (G * idkg_sk_r) * alpha = IDKG_PK_r * alpha`. Then, the Diffie-Hellman tuple: `DH_r := (IDKG_PK_r, EK, IDKG_PK_r * alpha)` is known.
///         * Compute associated data `AD_dr`
///         * Compute Hash `(h_0, h_1) := hash_to_scalars(DH_r, AD_dr)` and its inverse `-h_0`, `-h_1` in Zₚ.
///         * `D_{idkg_sk_r} [p, q] := (p - h_0, q - h_1)`
///     * Check commitment of polynomial `C(r) = C_0 + C_1 r == G * p(r) + H * q(r)`
///     * If all ok, receiver supports received dealing by signing it `support_dealing_d := Sign_{node_signing_sk_r} [signed_dealing_d]`
///     * Broadcast supported dealing to all receivers
///
/// #### Reconstruction
///  * A receiver receives support for various dealings (issued by different dealers).
///  * For each dealing, a receiver needs to receive the support of 3 different receivers:
///    since we tolerate at most 1 malicious node, this guarantees that for each dealing included in a transcript there are at least 2 honest nodes supporting it, and thus they could reconstruct the secret shared by the dealer.
///    For `Random` a transcript needs to contain at least 2 dealings
///    (since at most one node is malicious the result is guaranteed to be random).
///  * A transcript consists in a collection of dealings, each having sufficient support and the combined commitment.
///    A transcript contains the following information
///      * Combined Commitment from `(C_0, C_1)` and `(C_0', C_1')`: `Combi_0 := C_0 + C_0'` and `Combi_1:=C_1 + C_1'`
///      * Dealing 1 `(EK, pop_ek, E_1, E_2, E_3, E_4)` and dealing 2 `(EK', pop_ek', E_1', E_2', E_3', E_4')`
///  * Nodes agree (via consensus) on valid transcript in case there are several candidates which will be saved (on the block-chain).
///    Transcript verification is as follows (see [`IDkgProtocol::create_transcript`]):
///     * The combined commitment was constructed correctly from the dealings
///     * The transcript contains enough dealings
///     * Each dealing has at least support of 3 distinct nodes
///     * Each support is a valid signature from the supporting node
///  * From a transcript a node r can reconstruct its shares as follows, see [`IDkgProtocol::load_transcript`]
///      * Decrypt shares from dealing 1: `(p(r), q(r))` and from dealing 2 `(p'(r), q'(r))`
///      * Combined shares: `p(r) + p'(r)` and `q(r) + q'(r)`
///      * If the receiver cannot decrypt, they issue a complaint against the dealing.
///      * Other nodes will open their shares so the complainer can reconstruct its shares, see [`IDkgProtocol::load_transcript_with_openings`]
///      * Combined shares will be stored in the node's node canister secret key store.
///      * The key ID used to insert the keys in the store is the hash of the combined commitment.
///
/// #### Complaint
/// The complaint mechanism allows a receiver to retrieve its shares in case of a corrupted dealer. The steps are as follows:
/// 1. Issue a complaint: If node `r` cannot load a transcript successfully because it cannot decrypt its shares or the decrypted shares do not match the combined commitment,
///    then it issues a complaint against the faulty dealing `d` (see [`IDkgProtocol::load_transcript`]):
///      * Reveal Diffie-Hellman tuple: `DH_r := (IDKG_PK_r, EK, DH)` and a proof that  `IDKG_PK_r=G * idkg_sk_r` and `DH=EK * idkg_sk_r` have the same discrete logarithm with respect to `G` and `EK`.
///      * Sign complaint (done by consensus)
///      * Broadcast complaint to all other receivers
/// 1. Verify complaint: another receiver `r'` verifies the broadcasted complaint (see [`IDkgProtocol::verify_complaint`]) as follows:
///      * Check signature
///      * Check proof
///      * Check that the dealing is indeed incorrect: note that `EK * idkg_sk_r = IDKG_PK_r * alpha`
///        which allows receiver `r'` to try to decrypt the shares of party `r` in dealing `d` in the same way receiver `r` tried to do.
///      * If complaint is valid, broadcast its shares for that particular dealing `(p(r'), q(r'))` (see [`IDkgProtocol::open_transcript`])
///      * Sign openings (done by consensus)
/// 1. Verify openings: the complainer `r` verifies each received opening (see [`IDkgProtocol::verify_opening`])
///      * Check signature
///      * Verify that the openings are correct against the commitment polynomial
/// 1. Load transcript with openings: at some the complainer `r` will eventually collect at least two shares (because dealing had support of 3 nodes) (see [`IDkgProtocol::load_transcript_with_openings`]):
///      * With enough correct shares, do polynomial interpolation to reconstruct the polynomial from the faulty dealing.      
///      * Compute own shares from reconstructed polynomial
///      * Combine reconstructed shares with shares from other dealing and store combined shares in canister secret key store.
///
/// ### [`IDkgTranscriptOperation::ReshareOfMasked`]
/// Reshare of masked assumes a previous masked transcript. Each receiver `r` in that transcript has in particular a share of a secret `p(r)`, where `p(0)` is the secret, and a share of a mask `q(r)`.
/// The goal at the end of `ReshareOfMasked` is for each receiver to be able to compute the public key `G * p(0)`.
///
/// #### Dealer
/// * Each receiver `r` in the initial masked transcript does the following:
///     * Based on the combined commitment contained in the masked transcript, retrieves his share of the secret `p(r)` and his share of the mask `q(r)` from the canister secret key store.
///     * Pick a random polynomial of degree 1 (we need maximal number of malicious nodes +1 coefficients): `r(x) := r_0 + r_1 x`, such that `r_0 = p(r)` which is the dealer's secret share and
///       where `r_1` is random over Zₚ.
///     * Feldman commitment to polynomial (see [`SimpleCommitment`]):
///         * Compute polynomial commitment `D(x) := D_0 + D_1 x` over the elliptic curve, where
///           `D_0 := G * r_0` and `D_1 := G * r_1`. Note that `D_0 = G * p(r)`.
///     * Compute shares for each receiver `s` in the resharing `r(s)`
///     * Encrypt shares for all receivers (similar to [`IDkgTranscriptOperation::Random`] for for a single element instead of a pair):
///         * Ephemeral key: `EK := G * alpha`, for some random `alpha` over Zₚ
///         * Proof of possession of `alpha`: `pop_ek`
///         * Encryption of shares: `(E_1, E_2, E_3, E_4) := (E_{IDKG_PK_1} [r(1)], E_{IDKG_PK_2} [r(2)], E_{IDKG_PK_3} [r(3)], E_{IDKG_PK_3} [r(4)])`,
///     * Construct zero-knowledge proof that the simple commitment `G * p(r)` and the Pedersen commitment `G * p(r) + H * q(r)` are committing to the same value (see [`ProofOfEqualOpenings`]).
///     * Construct a single dealing for all receivers: `Dealing_d := ((D_0, D_1), (EK, pop_ek, E_1, E_2, E_3, E_4), proof)`
///
/// #### Reconstruction
///  * A receiver receives support for various dealings (issued by different dealers).
///  * For each dealing, a receiver needs to receive the support of 3 different receivers
///    (we need 2 for reconstruction + 1 since at most one node could me malicious) to include it in a transcript.
///  * For `ReshareOfMasked` a transcript needs to contain at least 2 dealings
///    (number of coefficients of polynomial from previous transcript).
/// * Public verification verifies the [`ProofOfEqualOpenings`].
///   Otherwise, verification and complaint mechanism are as in [`IDkgTranscriptOperation::Random`] described above.
/// * From a transcript with 2 dealings a node reconstructs the public key as follows:
///     * Dealing 1 from dealer `d`: `D_0 = G * r_0 = G * p(d)`
///     * Dealing 2 from another dealer `d'`: `D_0' = G * r_0' = G * p(d')`
/// * Note that `P(x) := G * p(x) = G * p_0 + (G * p_1) *  x` is a polynomial of degree 1 over the group and by definition
///     * `P(d) = D_0`
///     * `P(d') = D_0'`
/// * We can therefore do Lagrange interpolation to recover the polynomial `P(x)` and compute `P(0) = G * p_0` which is the public key:
///     * `P(x) = P(d) * (d'-x)/(d'-d) + P(d') * (d-x)/(d-d')` and so
///     * `P(0) = P(d) * d'/(d'-d) + P(d') * d/(d-d')`
///
/// [`hash2curve`]: ic_crypto_internal_threshold_sig_canister_threshold_sig
/// [`IDkgTranscriptOperation::Random`]: ic_types::crypto::canister_threshold_sig::idkg::IDkgTranscriptOperation::Random
/// [`IDkgTranscriptOperation::ReshareOfMasked`]: ic_types::crypto::canister_threshold_sig::idkg::IDkgTranscriptOperation::ReshareOfMasked
/// [`MEGaCiphertextPair::encrypt`]: ic_crypto_internal_threshold_sig_canister_threshold_sig::MEGaCiphertextPair::encrypt
/// [`PedersenCommitment`]: ic_crypto_internal_threshold_sig_canister_threshold_sig::PedersenCommitment
/// [`ProofOfDLogEquivalence`]: ic_crypto_internal_threshold_sig_canister_threshold_sig::zk::ProofOfDLogEquivalence
/// [`ProofOfEqualOpenings`]: ic_crypto_internal_threshold_sig_canister_threshold_sig::zk::ProofOfEqualOpenings
/// [`SimpleCommitment`]: ic_crypto_internal_threshold_sig_canister_threshold_sig::SimpleCommitment
/// [`xmd`]: ic_crypto_internal_seed::xmd
impl<C: CryptoServiceProvider> IDkgProtocol for CryptoComponentImpl<C> {
    fn create_dealing(
        &self,
        params: &IDkgTranscriptParams,
    ) -> Result<SignedIDkgDealing, IDkgCreateDealingError> {
        let log_id = get_log_id(&self.logger);
        let logger = new_logger!(&self.logger;
            crypto.log_id => log_id,
            crypto.trait_name => "IDkgProtocol",
            crypto.method_name => "create_dealing",
        );
        debug!(logger;
            crypto.description => "start",
            crypto.dkg_config => format!("{:?}", params),
        );
        let start_time = self.metrics.now();
        let result = dealing::create_dealing(
            &self.csp,
            &self.vault,
            &self.node_id,
            self.registry_client.as_ref(),
            params,
        );
        self.metrics.observe_duration_seconds(
            MetricsDomain::IdkgProtocol,
            MetricsScope::Full,
            "create_dealing",
            MetricsResult::from(&result),
            start_time,
        );
        debug!(logger;
            crypto.description => "end",
            crypto.is_ok => result.is_ok(),
            crypto.error => log_err(result.as_ref().err()),
            crypto.dkg_dealing => log_ok_content(&result),
        );
        result
    }

    fn verify_dealing_public(
        &self,
        params: &IDkgTranscriptParams,
        signed_dealing: &SignedIDkgDealing,
    ) -> Result<(), IDkgVerifyDealingPublicError> {
        let log_id = get_log_id(&self.logger);
        let logger = new_logger!(&self.logger;
            crypto.log_id => log_id,
            crypto.trait_name => "IDkgProtocol",
            crypto.method_name => "verify_dealing_public",
        );
        debug!(logger;
            crypto.description => "start",
            crypto.dkg_config => format!("{:?}", params),
            crypto.dkg_dealing => format!("{:?}", signed_dealing),
        );
        let start_time = self.metrics.now();
        let result = dealing::verify_dealing_public(
            &self.csp,
            self.registry_client.as_ref(),
            params,
            signed_dealing,
        );
        self.metrics.observe_duration_seconds(
            MetricsDomain::IdkgProtocol,
            MetricsScope::Full,
            "verify_dealing_public",
            MetricsResult::from(&result),
            start_time,
        );
        debug!(logger;
            crypto.description => "end",
            crypto.is_ok => result.is_ok(),
            crypto.error => log_err(result.as_ref().err()),
        );
        result
    }

    fn verify_dealing_private(
        &self,
        params: &IDkgTranscriptParams,
        signed_dealing: &SignedIDkgDealing,
    ) -> Result<(), IDkgVerifyDealingPrivateError> {
        let log_id = get_log_id(&self.logger);
        let logger = new_logger!(&self.logger;
            crypto.log_id => log_id,
            crypto.trait_name => "IDkgProtocol",
            crypto.method_name => "verify_dealing_private",
        );
        debug!(logger;
            crypto.description => "start",
            crypto.dkg_config => format!("{:?}", params),
            crypto.dkg_dealing => format!("{:?}", signed_dealing),
        );
        let start_time = self.metrics.now();
        let result = dealing::verify_dealing_private(
            &self.vault,
            &self.node_id,
            self.registry_client.as_ref(),
            params,
            signed_dealing,
        );
        self.metrics.observe_duration_seconds(
            MetricsDomain::IdkgProtocol,
            MetricsScope::Full,
            "verify_dealing_private",
            MetricsResult::from(&result),
            start_time,
        );
        debug!(logger;
            crypto.description => "end",
            crypto.is_ok => result.is_ok(),
            crypto.error => log_err(result.as_ref().err()),
        );
        result
    }

    fn verify_initial_dealings(
        &self,
        params: &IDkgTranscriptParams,
        initial_dealings: &InitialIDkgDealings,
    ) -> Result<(), IDkgVerifyInitialDealingsError> {
        let log_id = get_log_id(&self.logger);
        let logger = new_logger!(&self.logger;
            crypto.log_id => log_id,
            crypto.trait_name => "IDkgProtocol",
            crypto.method_name => "verify_initial_dealings",
        );
        debug!(logger;
            crypto.description => "start",
            crypto.dkg_config => format!("{:?}", params),
            crypto.dkg_dealing => format!("{:?}", initial_dealings),
        );
        let start_time = self.metrics.now();
        let result = dealing::verify_initial_dealings(
            &self.csp,
            self.registry_client.as_ref(),
            params,
            initial_dealings,
        );
        self.metrics.observe_duration_seconds(
            MetricsDomain::IdkgProtocol,
            MetricsScope::Full,
            "verify_initial_dealings",
            MetricsResult::from(&result),
            start_time,
        );
        debug!(logger;
            crypto.description => "end",
            crypto.is_ok => result.is_ok(),
            crypto.error => log_err(result.as_ref().err()),
        );
        result
    }

    fn create_transcript(
        &self,
        params: &IDkgTranscriptParams,
        dealings: &BatchSignedIDkgDealings,
    ) -> Result<IDkgTranscript, IDkgCreateTranscriptError> {
        let log_id = get_log_id(&self.logger);
        let logger = new_logger!(&self.logger;
            crypto.log_id => log_id,
            crypto.trait_name => "IDkgProtocol",
            crypto.method_name => "create_transcript",
        );
        debug!(logger;
            crypto.description => "start",
            crypto.dkg_config => format!("{:?}", params),
            crypto.dkg_dealing => format!("dealings: {{ {:?} }}", dealings.dealer_ids().collect::<Vec<_>>()),
        );
        let start_time = self.metrics.now();
        let result = transcript::create_transcript(
            &self.csp,
            self.vault.as_ref(),
            self.registry_client.as_ref(),
            params,
            dealings,
        );
        self.metrics.observe_parameter_size(
            MetricsDomain::IdkgProtocol,
            "create_transcript",
            "internal_transcript_raw",
            result
                .as_ref()
                .map_or(0, |transcript| transcript.internal_transcript_raw.len()),
            MetricsResult::from(&result),
        );
        self.metrics.observe_duration_seconds(
            MetricsDomain::IdkgProtocol,
            MetricsScope::Full,
            "create_transcript",
            MetricsResult::from(&result),
            start_time,
        );
        debug!(logger;
            crypto.description => "end",
            crypto.is_ok => result.is_ok(),
            crypto.error => log_err(result.as_ref().err()),
            crypto.dkg_transcript => log_ok_content(&result),
        );
        result
    }

    fn verify_transcript(
        &self,
        params: &IDkgTranscriptParams,
        transcript: &IDkgTranscript,
    ) -> Result<(), IDkgVerifyTranscriptError> {
        let log_id = get_log_id(&self.logger);
        let logger = new_logger!(&self.logger;
            crypto.log_id => log_id,
            crypto.trait_name => "IDkgProtocol",
            crypto.method_name => "verify_transcript",
        );
        debug!(logger;
            crypto.description => "start",
            crypto.dkg_config => format!("{:?}", params),
            crypto.dkg_transcript => format!("{:?}", transcript),
        );
        let start_time = self.metrics.now();
        let result = transcript::verify_transcript(
            &self.csp,
            self.vault.as_ref(),
            self.registry_client.as_ref(),
            params,
            transcript,
        );
        self.metrics.observe_parameter_size(
            MetricsDomain::IdkgProtocol,
            "verify_transcript",
            "internal_transcript_raw",
            transcript.internal_transcript_raw.len(),
            MetricsResult::from(&result),
        );
        self.metrics.observe_duration_seconds(
            MetricsDomain::IdkgProtocol,
            MetricsScope::Full,
            "verify_transcript",
            MetricsResult::from(&result),
            start_time,
        );
        debug!(logger;
            crypto.description => "end",
            crypto.is_ok => result.is_ok(),
            crypto.error => log_err(result.as_ref().err()),
        );
        result
    }

    fn load_transcript(
        &self,
        transcript: &IDkgTranscript,
    ) -> Result<Vec<IDkgComplaint>, IDkgLoadTranscriptError> {
        let log_id = get_log_id(&self.logger);
        let logger = new_logger!(&self.logger;
            crypto.log_id => log_id,
            crypto.trait_name => "IDkgProtocol",
            crypto.method_name => "load_transcript",
        );
        debug!(logger;
            crypto.description => "start",
            crypto.dkg_transcript => format!("{:?}", transcript),
        );
        let start_time = self.metrics.now();
        let result = transcript::load_transcript(
            &self.vault,
            &self.node_id,
            self.registry_client.as_ref(),
            transcript,
        );
        if let Err(error) = &result {
            match error {
                IDkgLoadTranscriptError::PrivateKeyNotFound
                | IDkgLoadTranscriptError::InvalidArguments { .. }
                | IDkgLoadTranscriptError::MalformedPublicKey { .. }
                | IDkgLoadTranscriptError::SerializationError { .. }
                | IDkgLoadTranscriptError::PublicKeyNotFound { .. } => {
                    // Errors that may lead to the key being lost.
                    // If enough nodes on the same subnet report a failure, raise an alert.
                    warn!(
                        logger,
                        "iDKG load_transcript error: transcript_id={:?}, transcript_type={:?}, error={:?}",
                        transcript.transcript_id,
                        transcript.transcript_type,
                        error
                    );
                    self.metrics
                        .observe_idkg_load_transcript_error(transcript.transcript_id.id());
                }
                IDkgLoadTranscriptError::InsufficientOpenings { .. }
                | IDkgLoadTranscriptError::InternalError { .. }
                | IDkgLoadTranscriptError::UnsupportedAlgorithm { .. }
                | IDkgLoadTranscriptError::RegistryError(_)
                | IDkgLoadTranscriptError::TransientInternalError { .. } => {
                    // Errors that should not lead to the key being lost
                }
            }
        }
        self.metrics.observe_parameter_size(
            MetricsDomain::IdkgProtocol,
            "load_transcript",
            "internal_transcript_raw",
            transcript.internal_transcript_raw.len(),
            MetricsResult::from(&result),
        );
        self.metrics.observe_duration_seconds(
            MetricsDomain::IdkgProtocol,
            MetricsScope::Full,
            "load_transcript",
            MetricsResult::from(&result),
            start_time,
        );
        debug!(logger;
            crypto.description => "end",
            crypto.is_ok => result.is_ok(),
            crypto.error => log_err(result.as_ref().err()),
            crypto.complaint => if let Ok(ref content) = result {
                Some(format!("{content:?}"))
            } else {
                None
            },
        );
        result
    }

    fn verify_complaint(
        &self,
        transcript: &IDkgTranscript,
        complainer_id: NodeId,
        complaint: &IDkgComplaint,
    ) -> Result<(), IDkgVerifyComplaintError> {
        let log_id = get_log_id(&self.logger);
        let logger = new_logger!(&self.logger;
            crypto.log_id => log_id,
            crypto.trait_name => "IDkgProtocol",
            crypto.method_name => "verify_complaint",
        );
        debug!(logger;
            crypto.description => "start",
            crypto.dkg_transcript => format!("{:?}", transcript),
            crypto.complainer => format!("{:?}", complainer_id),
            crypto.complaint => format!("{:?}", complaint),
        );
        let start_time = self.metrics.now();
        let result = complaint::verify_complaint(
            self.registry_client.as_ref(),
            transcript,
            complaint,
            complainer_id,
        );
        self.metrics.observe_parameter_size(
            MetricsDomain::IdkgProtocol,
            "verify_complaint",
            "internal_transcript_raw",
            transcript.internal_transcript_raw.len(),
            MetricsResult::from(&result),
        );
        self.metrics.observe_duration_seconds(
            MetricsDomain::IdkgProtocol,
            MetricsScope::Full,
            "verify_complaint",
            MetricsResult::from(&result),
            start_time,
        );
        debug!(logger;
            crypto.description => "end",
            crypto.is_ok => result.is_ok(),
            crypto.error => log_err(result.as_ref().err()),
        );
        result
    }

    fn open_transcript(
        &self,
        transcript: &IDkgTranscript,
        complainer_id: NodeId,
        complaint: &IDkgComplaint,
    ) -> Result<IDkgOpening, IDkgOpenTranscriptError> {
        let log_id = get_log_id(&self.logger);
        let logger = new_logger!(&self.logger;
            crypto.log_id => log_id,
            crypto.trait_name => "IDkgProtocol",
            crypto.method_name => "open_transcript",
        );
        debug!(logger;
            crypto.description => "start",
            crypto.dkg_transcript => format!("{:?}", transcript),
            crypto.complainer => format!("{:?}", complainer_id),
            crypto.complaint => format!("{:?}", complaint),
        );
        let start_time = self.metrics.now();
        let result = transcript::open_transcript(
            &self.vault,
            &self.node_id,
            self.registry_client.as_ref(),
            transcript,
            complainer_id,
            complaint,
        );
        self.metrics.observe_parameter_size(
            MetricsDomain::IdkgProtocol,
            "open_transcript",
            "internal_transcript_raw",
            transcript.internal_transcript_raw.len(),
            MetricsResult::from(&result),
        );
        self.metrics.observe_duration_seconds(
            MetricsDomain::IdkgProtocol,
            MetricsScope::Full,
            "open_transcript",
            MetricsResult::from(&result),
            start_time,
        );
        debug!(logger;
            crypto.description => "end",
            crypto.is_ok => result.is_ok(),
            crypto.error => log_err(result.as_ref().err()),
            crypto.opening => log_ok_content(&result),
        );
        result
    }

    fn verify_opening(
        &self,
        transcript: &IDkgTranscript,
        opener: NodeId,
        opening: &IDkgOpening,
        complaint: &IDkgComplaint,
    ) -> Result<(), IDkgVerifyOpeningError> {
        let log_id = get_log_id(&self.logger);
        let logger = new_logger!(&self.logger;
            crypto.log_id => log_id,
            crypto.trait_name => "IDkgProtocol",
            crypto.method_name => "verify_opening",
        );
        debug!(logger;
            crypto.description => "start",
            crypto.dkg_transcript => format!("{:?}", transcript),
            crypto.opener => format!("{:?}", opener),
            crypto.opening => format!("{:?}", opening),
            crypto.complaint => format!("{:?}", complaint),
        );
        let start_time = self.metrics.now();
        let result = transcript::verify_opening(transcript, opener, opening, complaint);
        self.metrics.observe_parameter_size(
            MetricsDomain::IdkgProtocol,
            "verify_opening",
            "internal_transcript_raw",
            transcript.internal_transcript_raw.len(),
            MetricsResult::from(&result),
        );
        self.metrics.observe_duration_seconds(
            MetricsDomain::IdkgProtocol,
            MetricsScope::Full,
            "verify_opening",
            MetricsResult::from(&result),
            start_time,
        );
        debug!(logger;
            crypto.description => "end",
            crypto.is_ok => result.is_ok(),
            crypto.error => log_err(result.as_ref().err()),
        );
        result
    }

    fn load_transcript_with_openings(
        &self,
        transcript: &IDkgTranscript,
        openings: &BTreeMap<IDkgComplaint, BTreeMap<NodeId, IDkgOpening>>,
    ) -> Result<(), IDkgLoadTranscriptError> {
        let log_id = get_log_id(&self.logger);
        let logger = new_logger!(&self.logger;
            crypto.log_id => log_id,
            crypto.trait_name => "IDkgProtocol",
            crypto.method_name => "load_transcript_with_openings",
        );
        debug!(logger;
            crypto.description => "start",
            crypto.dkg_transcript => format!("{:?}", transcript),
            crypto.opening => format!("{:?}", openings),
        );
        let start_time = self.metrics.now();
        let result = transcript::load_transcript_with_openings(
            &self.vault,
            &self.node_id,
            self.registry_client.as_ref(),
            transcript,
            openings,
        );
        self.metrics.observe_parameter_size(
            MetricsDomain::IdkgProtocol,
            "load_transcript_with_openings",
            "internal_transcript_raw",
            transcript.internal_transcript_raw.len(),
            MetricsResult::from(&result),
        );
        self.metrics.observe_duration_seconds(
            MetricsDomain::IdkgProtocol,
            MetricsScope::Full,
            "load_transcript_with_openings",
            MetricsResult::from(&result),
            start_time,
        );
        debug!(logger;
            crypto.description => "end",
            crypto.is_ok => result.is_ok(),
            crypto.error => log_err(result.as_ref().err()),
        );
        result
    }

    fn retain_active_transcripts(
        &self,
        active_transcripts: &HashSet<IDkgTranscript>,
    ) -> Result<(), IDkgRetainKeysError> {
        let log_id = get_log_id(&self.logger);
        let logger = new_logger!(&self.logger;
            crypto.log_id => log_id,
            crypto.trait_name => "IDkgProtocol",
            crypto.method_name => "retain_active_transcripts",
        );
        debug!(logger;
            crypto.description => "start",
            crypto.dkg_transcript => format!("{:?}",
                active_transcripts
                .iter()
                .map(|transcript| transcript.transcript_id)
                .collect::<BTreeSet<IDkgTranscriptId>>()
            ),
        );
        let start_time = self.metrics.now();
        let mut transcripts_len = 0;
        for transcript in active_transcripts {
            transcripts_len += transcript.internal_transcript_raw.len();
        }
        let result = retain_active_keys::retain_keys_for_transcripts(
            &self.vault,
            &self.node_id,
            self.registry_client.as_ref(),
            &self.metrics,
            active_transcripts,
        );
        self.metrics.observe_parameter_size(
            MetricsDomain::IdkgProtocol,
            "retain_active_transcripts",
            "internal_transcript_raw",
            transcripts_len,
            MetricsResult::from(&result),
        );
        self.metrics.observe_duration_seconds(
            MetricsDomain::IdkgProtocol,
            MetricsScope::Full,
            "retain_active_transcripts",
            MetricsResult::from(&result),
            start_time,
        );
        debug!(logger;
            crypto.description => "end",
            crypto.is_ok => result.is_ok(),
            crypto.error => log_err(result.as_ref().err()),
        );
        result
    }
}
