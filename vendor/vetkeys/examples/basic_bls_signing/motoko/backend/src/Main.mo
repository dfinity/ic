import Principal "mo:core/Principal";
import Text "mo:core/Text";
import Blob "mo:core/Blob";
import Nat64 "mo:core/Nat64";
import Time "mo:core/Time";
import Map "mo:core/Map";
import Array "mo:core/Array";
import List "mo:core/List";
import Nat8 "mo:core/Nat8";
import Runtime "mo:core/Runtime";
import Nat "mo:core/Nat";
import VetKeys "mo:ic-vetkeys";
import Order "mo:core/Order";

shared persistent actor class (keyName : Text) = {
    // Types
    type Signature = {
        message : Text;
        signature : Blob;
        timestamp : Nat64;
    };

    type SignatureKey = {
        signer : Principal;
        timestamp : Nat64;
    };

    type VetKdKeyid = {
        curve : { #bls12_381_g2 };
        name : Text;
    };

    // Compare function for SignatureKey
    private func signatureKeyCompare(a : SignatureKey, b : SignatureKey) : Order.Order {
        switch (Principal.compare(a.signer, b.signer)) {
            case (#equal) { Nat64.compare(a.timestamp, b.timestamp) };
            case (other) { other };
        }
    };

    // Stable storage for signatures
    private var signatures = Map.empty<SignatureKey, Signature>();

    // Helper function to get current timestamp
    private func getTimestamp() : Nat64 {
        Nat64.fromIntWrap(Time.now());
    };

    // Helper function to create context for vetKD
    private func context(signer : Principal) : Blob {
        // Domain separator for this dapp
        let domainSeparator : [Nat8] = Blob.toArray(Text.encodeUtf8("basic_bls_signing_dapp"));
        let domainSeparatorLength : [Nat8] = [Nat8.fromNat(domainSeparator.size())]; // Length of domain separator

        // Combine domain separator length, domain separator, and signer principal
        let signerBytes = Principal.toBlob(signer);
        let signerArray = Blob.toArray(signerBytes);

        let contextArray = Array.concat<Nat8>(
            Array.concat<Nat8>(domainSeparatorLength, domainSeparator),
            signerArray,
        );

        Blob.fromArray(contextArray);
    };

    // Helper function to get key ID
    private func keyId() : VetKdKeyid {
        {
            curve = #bls12_381_g2;
            name = keyName;
        };
    };

    // Sign a message using BLS
    public shared ({ caller }) func sign_message(message : Text) : async Blob {
        // TODO(CRP-2874): return only the signature bytes, not the entire vetKey bytes
        let bytes = await VetKeys.ManagementCanister.signWithBls(
            Text.encodeUtf8(message),
            context(caller),
            keyId(),
        );

        let BYTES_SIZE : Nat = 192;
        let SIGNATURE_SIZE : Nat = 48;

        if (bytes.size() != BYTES_SIZE) {
            Runtime.trap("Expected " # Nat.toText(BYTES_SIZE) # " signature bytes, but got " # Nat.toText(bytes.size()));
        };

        let signatureBytes = Blob.fromArray(Array.sliceToArray<Nat8>(Blob.toArray(bytes), BYTES_SIZE - SIGNATURE_SIZE, BYTES_SIZE));

        let timestamp = getTimestamp();
        let signature : Signature = {
            message = message;
            signature = signatureBytes;
            timestamp = timestamp;
        };

        // Handle potential timestamp collisions by incrementing until we find a free slot
        var timestampForMapKey = timestamp;
        while (Map.get(signatures, signatureKeyCompare, { signer = caller; timestamp = timestampForMapKey }) != null) {
            timestampForMapKey += 1;
        };

        ignore Map.insert(signatures, signatureKeyCompare, { signer = caller; timestamp = timestampForMapKey }, signature);

        signatureBytes;
    };

    // Get all signatures for the current caller
    public shared query ({ caller }) func get_my_signatures() : async [Signature] {
        var callerSignatures = List.empty<Signature>();

        for ((key, value) in Map.entries(signatures)) {
            if (Principal.equal(key.signer, caller)) {
                List.add(callerSignatures, value);
            };
        };

        List.toArray(callerSignatures);
    };

    // Get verification key for the current caller
    public shared ({ caller }) func get_my_verification_key() : async Blob {
        await VetKeys.ManagementCanister.blsPublicKey(
            null,
            context(caller),
            keyId(),
        );
    };
};
