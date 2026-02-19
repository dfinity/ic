This document lists typical steps of a security review needed for production-ready IC dapps. We indicate whether the two backend implementations of Encrypted Notes comply with the corresponding requirements (marked as Done), do not yet comply (Future), or whether a particular requirement is not applicable to this backend (Not applicable). 

While this list might help creating better IC dapps, keep in mind that the list is potentially incomplete. In particular, each real-world dapp may have a different set of security requirements that depend on its target domain and intended use case. 

# 1. Authentication

### 1.1. Make sure any action that only a specific user should be able to do requires  authentication
* Motoko: Done
* Rust: Done

### 1.2. Disallow the anonymous principal in authenticated calls
* Motoko: Done
* Rust: Done

# 2. Consensus

Avoid using uncertified queries in public canister APIs. Instead, either use certified update methods or design an eventual certification approach for performance-critical dapps. 
* Motoko: Done (no query methods)
* Rust: Done (no query methods)

# 3. Input Validation

Each public API method should sanitize their arguments and gracefully handle exceptional situations. 
* Motoko: Done
* Rust: Done

# 4. Frontend security

### 4.1. Frontend input validation
* Motoko: Done
* Rust: Done

### 4.2. Avoid using deterministic encryption. 
For example, the initialization vector for AES-GCM encryption should be unique for each message (or chosen at random).
* Motoko: Done
* Rust: Done

### 4.3. Do not load untrusted assets like CSS or fonts
* Motoko: Done
* Rust: Done

### 4.4. Avoid logging sensitive data like private keys 
When generating the private key using `crypto.subtle.generateKey`, set `extractable=false`. Consider offloading the secret keys to a YubiKey or YubyHSM so that the secret keys never end up in the browser.
* Motoko: Done
* Rust: Done

### 4.5. Avoid reusing the same public/private key pair for every identity in the same browser
* Motoko: Future
* Rust: Future

### 4.6. Set reasonable session timeouts
For example, a security-sensitive dapp like Encrypted Notes should set `maxTimeToLive` for Internet Identity delegation to 30 min rather than 24 h. 
* Motoko: Future
* Rust: Future

### 4.7. Regularly refresh symmetric encryption keys
* Motoko: Future
* Rust: Future

# 5. Asset Certification

### 5.1. Use HTTP asset certification and avoid serving your dapp through raw.ic0.app
* Motoko: Done
* Rust: Done

# 6. Canister Storage

### 6.1. Use thread_local! with Cell/RefCell for state variables and put all your globals in one basket
* Motoko: Not applicable
* Rust: Done

### 6.2. Limit the amount of data that can be stored in a canister per user
* Motoko: Done
* Rust: Done

### 6.3. Consider using stable memory, version it, test it
* Motoko: Done (except versioning)
* Rust: Done (except versioning)

### 6.4. Don’t store sensitive data on canisters (unless it is encrypted)
* Motoko: Done
* Rust: Done

### 6.5. Create backups
* Motoko: Future
* Rust: Future

# 7. Inter-Canister Calls and Rollbacks

### 5.1. Don’t panic after await and don’t lock shared resources across await boundaries
* Motoko: Done (we don't use await)
* Rust: Done (we don't use await)

### 5.2. Be aware that state may change during inter-canister calls
* Motoko: Done (we have no inter-canister calls)
* Rust: Done (we have no inter-canister calls)

### 5.3. Only make inter-canister calls to trustworthy canisters
* Motoko: Done (we have no inter-canister calls)
* Rust: Done (we have no inter-canister calls)

### 5.4. Make sure there are no loops in call graphs
* Motoko: Done
* Rust: Done

# 8. Canister Upgrades

### 8.1. Don’t panic/trap during upgrades:   
* Motoko: Done, assuming that [`Iter.toArray`](https://github.com/dfinity/motoko-base/blob/master/src/Iter.mo) and [`Map.fromIter`](https://github.com/dfinity/motoko-base/blob/master/src/HashMap.mo) do not trap.
* Rust: Done, assuming that [`borrow_mut`](https://doc.rust-lang.org/std/borrow/trait.BorrowMut.html#tymethod.borrow_mut), [`std::mem::take`](https://doc.rust-lang.org/stable/std/mem/fn.take.html), and [`ic_cdk::storage::stable_save`](https://docs.rs/ic-cdk/latest/ic_cdk/storage/fn.stable_save.html) do not panic. 

### 8.2. Ensure upgradeability
If the canister storage becomes too big, the canister will no longer be upgradable because `pre_upgrade` will time out or the canister will run out of cycles. The recommended remedy is to use stable memory directly rather than serializing data upon upgrade. 
* Motoko: Future
* Rust: Future

# 9. Rust-specific issues

### 9.1. Don’t use unsafe Rust code: 
* Rust: Done

### 9.2. Avoid integer overflows: 
* Rust: Done

# 10. Miscellaneous

### 10.1. For expensive calls, consider using captchas or proof of work
* Motoko: Future
* Rust: Future

### 10.2. Test your canister code even in presence of System API calls
* Motoko: Future
* Rust: Future

### 10.3. Make canister builds reproducible
* Motoko: Done (via Docker)
* Rust: Done (via Docker)

### 10.4. Expose metrics from your canister
* Motoko: Future
* Rust: Future

### 10.5. Don’t rely on time being strictly monotonic
* Motoko: Done
* Rust: Done

### 10.6. Protect against draining the cycles balance
* Motoko: Future
* Rust: Future


# 11. Efficiency considerations

### 11.1. `submit_ciphertexts`
* Adding submit_ciphertexts is currently O(C*D) where `C =  ciphertexts.size()` and `D = store.device_list.size()`

# 12. Usability

### 12.1. Confirm user's intention before executing potentially irreversible actions like device removal
* Motoko: Future
* Rust: Future

### 12.2. Prevent account lockout scenarios
* Motoko: Future
* Rust: Future
