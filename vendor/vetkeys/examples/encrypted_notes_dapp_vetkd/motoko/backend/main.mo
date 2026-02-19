import Map "mo:base/HashMap";
import Text "mo:base/Text";
import Array "mo:base/Array";
import Buffer "mo:base/Buffer";
import List "mo:base/List";
import Iter "mo:base/Iter";
import Nat "mo:base/Nat";
import Nat8 "mo:base/Nat8";
import Bool "mo:base/Bool";
import Principal "mo:base/Principal";
import Option "mo:base/Option";
import Debug "mo:base/Debug";
import Blob "mo:base/Blob";
import Hash "mo:base/Hash";
import Hex "./utils/Hex";

// Declare a shared actor class
// Bind the caller and the initializer
shared ({ caller = initializer }) persistent actor class (keyName: Text) {

    // Currently, a single canister smart contract is limited to 4 GB of heap size.
    // For the current limits see https://internetcomputer.org/docs/current/developer-docs/production/resource-limits.
    // To ensure that our canister does not exceed the limit, we put various restrictions (e.g., max number of users) in place.
    // This should keep us well below a memory usage of 2 GB because
    // up to 2x memory may be needed for data serialization during canister upgrades.
    // This is sufficient for this proof-of-concept, but in a production environment the actual
    // memory usage must be calculated or monitored and the various restrictions adapted accordingly.

    // Define dapp limits - important for security assurance
    private transient let MAX_USERS = 500;
    private transient let MAX_NOTES_PER_USER = 200;
    private transient let MAX_NOTE_CHARS = 1000;
    private transient let MAX_SHARES_PER_NOTE = 50;

    private type PrincipalName = Text;
    private type NoteId = Nat;

    // Define public types
    // Type of an encrypted note
    // Attention: This canister does *not* perform any encryption.
    //            Here we assume that the notes are encrypted end-
    //            to-end by the front-end (at client side).
    public type EncryptedNote = {
        encrypted_text : Text;
        id : Nat;
        owner : PrincipalName;
        // Principals with whom this note is shared. Does not include the owner.
        // Needed to be able to efficiently show in the UI with whom this note is shared.
        users : [PrincipalName];
    };

    // Define private fields
    // Stable actor fields are automatically retained across canister upgrades.
    // See https://internetcomputer.org/docs/current/motoko/main/upgrades/

    // Design choice: Use globally unique note identifiers for all users.
    //
    // The keyword `stable` makes this (scalar) variable keep its value across canister upgrades.
    //
    // See https://internetcomputer.org/docs/current/developer-docs/setup/manage-canisters#upgrade-a-canister
    private var nextNoteId : Nat = 1;

    // Store notes by their ID, so that note-specific encryption keys can be derived.
    private transient var notesById = Map.HashMap<NoteId, EncryptedNote>(0, Nat.equal, Hash.hash);
    // Store which note IDs are owned by a particular principal
    private transient var noteIdsByOwner = Map.HashMap<PrincipalName, List.List<NoteId>>(0, Text.equal, Text.hash);
    // Store which notes are shared with a particular principal. Does not include the owner, as this is tracked by `noteIdsByOwner`.
    private transient var noteIdsByUser = Map.HashMap<PrincipalName, List.List<NoteId>>(0, Text.equal, Text.hash);

    // While accessing _heap_ data is more efficient, we use the following _stable memory_
    // as a buffer to preserve data across canister upgrades.
    // Stable memory is currently 96GB. For the current limits see
    // https://internetcomputer.org/docs/current/developer-docs/production/resource-limits.
    // See also: [preupgrade], [postupgrade]
    private var stable_notesById : [(NoteId, EncryptedNote)] = [];
    private var stable_noteIdsByOwner : [(PrincipalName, List.List<NoteId>)] = [];
    private var stable_noteIdsByUser : [(PrincipalName, List.List<NoteId>)] = [];

    // Utility function that helps writing assertion-driven code more concisely.
    private func expect<T>(opt : ?T, violation_msg : Text) : T {
        switch (opt) {
            case (null) {
                Debug.trap(violation_msg);
            };
            case (?x) {
                x;
            };
        };
    };

    private func is_authorized(user : PrincipalName, note : EncryptedNote) : Bool {
        user == note.owner or Option.isSome(Array.find(note.users, func(x : PrincipalName) : Bool { x == user }));
    };

    public shared ({ caller }) func whoami() : async Text {
        return Principal.toText(caller);
    };

    // Shared functions, i.e., those specified with [shared], are
    // accessible to remote callers.
    // The extra parameter [caller] is the caller's principal
    // See https://internetcomputer.org/docs/current/motoko/main/actors-async

    // Add new empty note for this [caller].
    //
    // Returns:
    //      Future of ID of new empty note
    // Traps:
    //      [caller] is the anonymous identity
    //      [caller] already has [MAX_NOTES_PER_USER] notes
    //      This is the first note for [caller] and [MAX_USERS] is exceeded
    public shared ({ caller }) func create_note() : async NoteId {
        assert not Principal.isAnonymous(caller);
        let owner = Principal.toText(caller);

        let newNote : EncryptedNote = {
            id = nextNoteId;
            encrypted_text = "";
            owner = owner;
            users = [];
        };

        switch (noteIdsByOwner.get(owner)) {
            case (?owner_nids) {
                assert List.size(owner_nids) < MAX_NOTES_PER_USER;
                noteIdsByOwner.put(owner, List.push(newNote.id, owner_nids));
            };
            case null {
                assert noteIdsByOwner.size() < MAX_USERS;
                noteIdsByOwner.put(owner, List.make(newNote.id));
            };
        };

        notesById.put(newNote.id, newNote);
        nextNoteId += 1;
        newNote.id;
    };

    // Returns (a future of) this [caller]'s notes.
    //
    // --- Queries vs. Updates ---
    // Note that this method is declared as an *update* call (see `shared`) rather than *query*.
    //
    // While queries are significantly faster than updates, they are not certified by the IC.
    // Thus, we avoid using queries throughout this dapp, ensuring that the result of our
    // functions gets through consensus. Otherwise, this function could e.g. omit some notes
    // if it got executed by a malicious node. (To make the dapp more efficient, one could
    // use an approach in which both queries and updates are combined.)
    // See https://internetcomputer.org/docs/current/concepts/canisters-code#query-and-update-methods
    //
    // Returns:
    //      Future of array of EncryptedNote
    // Traps:
    //      [caller] is the anonymous identity
    public shared ({ caller }) func get_notes() : async [EncryptedNote] {
        assert not Principal.isAnonymous(caller);
        let user = Principal.toText(caller);

        let owned_notes = List.map(
            Option.get(noteIdsByOwner.get(user), List.nil()),
            func(nid : NoteId) : EncryptedNote {
                expect(notesById.get(nid), "missing note with ID " # Nat.toText(nid));
            },
        );
        let shared_notes = List.map(
            Option.get(noteIdsByUser.get(user), List.nil()),
            func(nid : NoteId) : EncryptedNote {
                expect(notesById.get(nid), "missing note with ID " # Nat.toText(nid));
            },
        );

        let buf = Buffer.Buffer<EncryptedNote>(List.size(owned_notes) + List.size(shared_notes));
        buf.append(Buffer.fromArray(List.toArray(owned_notes)));
        buf.append(Buffer.fromArray(List.toArray(shared_notes)));
        Buffer.toArray(buf);
    };

    // Replaces the encrypted text of note with ID [id] with [encrypted_text].
    //
    // Returns:
    //      Future of unit
    // Traps:
    //     [caller] is the anonymous identity
    //     note with ID [id] does not exist
    //     [caller] is not the note's owner and not a user with whom the note is shared
    //     [encrypted_text] exceeds [MAX_NOTE_CHARS]
    public shared ({ caller }) func update_note(id : NoteId, encrypted_text : Text) : async () {
        assert not Principal.isAnonymous(caller);
        let caller_text = Principal.toText(caller);
        let (?note_to_update) = notesById.get(id) else Debug.trap("note with id " # Nat.toText(id) # "not found");
        if (not is_authorized(caller_text, note_to_update)) {
            Debug.trap("unauthorized");
        };
        assert note_to_update.encrypted_text.size() <= MAX_NOTE_CHARS;
        notesById.put(id, { note_to_update with encrypted_text });
    };

    // Shares the note with ID [note_id] with the [user].
    // Has no effect if the note is already shared with that user.
    //
    // Returns:
    //      Future of unit
    // Traps:
    //     [caller] is the anonymous identity
    //     note with ID [id] does not exist
    //     [caller] is not the note's owner
    public shared ({ caller }) func add_user(note_id : NoteId, user : PrincipalName) : async () {
        assert not Principal.isAnonymous(caller);
        let caller_text = Principal.toText(caller);
        let (?note) = notesById.get(note_id) else Debug.trap("note with id " # Nat.toText(note_id) # "not found");
        if (caller_text != note.owner) {
            Debug.trap("unauthorized");
        };
        assert note.users.size() < MAX_SHARES_PER_NOTE;
        if (not Option.isSome(Array.find(note.users, func(u : PrincipalName) : Bool { u == user }))) {
            let users_buf = Buffer.fromArray<PrincipalName>(note.users);
            users_buf.add(user);
            let updated_note = { note with users = Buffer.toArray(users_buf) };
            notesById.put(note_id, updated_note);
        };
        switch (noteIdsByUser.get(user)) {
            case (?user_nids) {
                if (not List.some(user_nids, func(nid : NoteId) : Bool { nid == note_id })) {
                    noteIdsByUser.put(user, List.push(note_id, user_nids));
                };
            };
            case null {
                noteIdsByUser.put(user, List.make(note_id));
            };
        };
    };

    // Unshares the note with ID [note_id] with the [user].
    // Has no effect if the note is already shared with that user.
    //
    // Returns:
    //      Future of unit
    // Traps:
    //     [caller] is the anonymous identity
    //     note with ID [id] does not exist
    //     [caller] is not the note's owner
    public shared ({ caller }) func remove_user(note_id : NoteId, user : PrincipalName) : async () {
        assert not Principal.isAnonymous(caller);
        let caller_text = Principal.toText(caller);
        let (?note) = notesById.get(note_id) else Debug.trap("note with id " # Nat.toText(note_id) # "not found");
        if (caller_text != note.owner) {
            Debug.trap("unauthorized");
        };
        let users_buf = Buffer.fromArray<PrincipalName>(note.users);
        users_buf.filterEntries(func(i : Nat, u : PrincipalName) : Bool { u != user });
        let updated_note = { note with users = Buffer.toArray(users_buf) };
        notesById.put(note_id, updated_note);

        switch (noteIdsByUser.get(user)) {
            case (?user_nids) {
                let updated_nids = List.filter(user_nids, func(nid : NoteId) : Bool { nid != note_id });
                if (not List.isNil(updated_nids)) {
                    noteIdsByUser.put(user, updated_nids);
                } else {
                    let _ = noteIdsByUser.remove(user);
                };
            };
            case null {};
        };
    };

    // Delete the note with ID [id].
    //
    // Returns:
    //      Future of unit
    // Traps:
    //     [caller] is the anonymous identity
    //     note with ID [id] does not exist
    //     [caller] is not the note's owner
    public shared ({ caller }) func delete_note(note_id : NoteId) : async () {
        assert not Principal.isAnonymous(caller);
        let caller_text = Principal.toText(caller);
        let (?note_to_delete) = notesById.get(note_id) else Debug.trap("note with id " # Nat.toText(note_id) # "not found");
        let owner = note_to_delete.owner;
        if (owner != caller_text) {
            Debug.trap("unauthorized");
        };
        switch (noteIdsByOwner.get(owner)) {
            case (?owner_nids) {
                let updated_nids = List.filter(owner_nids, func(nid : NoteId) : Bool { nid != note_id });
                if (not List.isNil(updated_nids)) {
                    noteIdsByOwner.put(owner, updated_nids);
                } else {
                    let _ = noteIdsByOwner.remove(owner);
                };
            };
            case null {};
        };
        for (user in note_to_delete.users.vals()) {
            switch (noteIdsByUser.get(user)) {
                case (?user_nids) {
                    let updated_nids = List.filter(user_nids, func(nid : NoteId) : Bool { nid != note_id });
                    if (not List.isNil(updated_nids)) {
                        noteIdsByUser.put(user, updated_nids);
                    } else {
                        let _ = noteIdsByUser.remove(user);
                    };
                };
                case null {};
            };
        };
        let _ = notesById.remove(note_id);
    };

    // Only the vetKD methods in the IC management canister are required here.
    type VETKD_API = actor {
        vetkd_public_key : ({
            canister_id : ?Principal;
            context : Blob;
            key_id : { curve : { #bls12_381_g2 }; name : Text };
        }) -> async ({ public_key : Blob });
        vetkd_derive_key : ({
            input : Blob;
            context : Blob;
            key_id : { curve : { #bls12_381_g2 }; name : Text };
            transport_public_key : Blob;
        }) -> async ({ encrypted_key : Blob });
    };

    transient let management_canister : VETKD_API = actor ("aaaaa-aa");

    public shared func symmetric_key_verification_key_for_note() : async Text {
        let { public_key } = await management_canister.vetkd_public_key({
            canister_id = null;
            context = Text.encodeUtf8("note_symmetric_key");
            key_id = { curve = #bls12_381_g2; name = keyName };
        });
        Hex.encode(Blob.toArray(public_key));
    };

    public shared ({ caller }) func encrypted_symmetric_key_for_note(note_id : NoteId, transport_public_key : Blob) : async Text {
        let caller_text = Principal.toText(caller);
        let (?note) = notesById.get(note_id) else Debug.trap("note with id " # Nat.toText(note_id) # "not found");
        if (not is_authorized(caller_text, note)) {
            Debug.trap("unauthorized");
        };

        let buf = Buffer.Buffer<Nat8>(32);
        buf.append(Buffer.fromArray(natToBigEndianByteArray(16, note_id))); // fixed-size encoding
        buf.append(Buffer.fromArray(Blob.toArray(Text.encodeUtf8(note.owner))));
        let input = Blob.fromArray(Buffer.toArray(buf)); // prefix-free

        let { encrypted_key } = await (with cycles = 26_153_846_153) management_canister.vetkd_derive_key({
            input;
            context = Text.encodeUtf8("note_symmetric_key");
            key_id = { curve = #bls12_381_g2; name = keyName };
            transport_public_key;
        });
        Hex.encode(Blob.toArray(encrypted_key));
    };

    // Converts a nat to a fixed-size big-endian byte (Nat8) array
    private func natToBigEndianByteArray(len : Nat, n : Nat) : [Nat8] {
        let ith_byte = func(i : Nat) : Nat8 {
            assert (i < len);
            let shift : Nat = 8 * (len - 1 - i);
            Nat8.fromIntWrap(n / 2 ** shift);
        };
        Array.tabulate<Nat8>(len, ith_byte);
    };

    // Below, we implement the upgrade hooks for our canister.
    // See https://internetcomputer.org/docs/current/motoko/main/upgrades/

    // The work required before a canister upgrade begins.
    system func preupgrade() {
        Debug.print("Starting pre-upgrade hook...");
        stable_notesById := Iter.toArray(notesById.entries());
        stable_noteIdsByOwner := Iter.toArray(noteIdsByOwner.entries());
        stable_noteIdsByUser := Iter.toArray(noteIdsByUser.entries());
        Debug.print("pre-upgrade finished.");
    };

    // The work required after a canister upgrade ends.
    // See [nextNoteId], [stable_notesByUser]
    system func postupgrade() {
        Debug.print("Starting post-upgrade hook...");

        notesById := Map.fromIter<NoteId, EncryptedNote>(
            stable_notesById.vals(),
            stable_notesById.size(),
            Nat.equal,
            Hash.hash,
        );
        stable_notesById := [];

        noteIdsByOwner := Map.fromIter<PrincipalName, List.List<NoteId>>(
            stable_noteIdsByOwner.vals(),
            stable_noteIdsByOwner.size(),
            Text.equal,
            Text.hash,
        );
        stable_noteIdsByOwner := [];

        noteIdsByUser := Map.fromIter<PrincipalName, List.List<NoteId>>(
            stable_noteIdsByUser.vals(),
            stable_noteIdsByUser.size(),
            Text.equal,
            Text.hash,
        );
        stable_noteIdsByUser := [];

        Debug.print("post-upgrade finished.");
    };
};
