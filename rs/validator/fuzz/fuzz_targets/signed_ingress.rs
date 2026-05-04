#![no_main]
use ic_types::messages::SignedIngress;
use ic_types::messages::SignedRequestBytes;
use libfuzzer_sys::fuzz_target;

// SignedIngress implements AsRef<HttpRequest<SignedIngressContent>>
// and so is also an entry point to validate_request
fuzz_target!(|data: &[u8]| {
    let _should_not_panic = SignedIngress::try_from(SignedRequestBytes::from(data.to_vec()));
});
