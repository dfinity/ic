import Principal "mo:core/Principal";
import Time "mo:core/Time";
import Map "mo:core/Map";
import Text "mo:core/Text";
import Blob "mo:core/Blob";
import Array "mo:core/Array";
import List "mo:core/List";
import Nat64 "mo:core/Nat64";
import Nat "mo:core/Nat";
import Result "mo:core/Result";
import Int "mo:core/Int";

persistent actor class (keyNameString : Text) {
  // Types
  type Message = {
    sender : Principal;
    encrypted_message : Blob;
    timestamp : Nat64;
  };

  type Inbox = {
    messages : [Message];
  };

  type SendMessageRequest = {
    receiver : Principal;
    encrypted_message : Blob;
  };

  type Result<T, E> = {
    #Ok : T;
    #Err : E;
  };

  type VetKdKeyId = {
    curve : { #bls12_381_g2 };
    name : Text;
  };

  type VetKdPublicKeyArgs = {
    canister_id : ?Principal;
    context : Blob;
    key_id : VetKdKeyId;
  };

  type VetKdDeriveKeyArgs = {
    context : Blob;
    input : Blob;
    key_id : VetKdKeyId;
    transport_public_key : Blob;
  };

  type VetKdSystemApi = actor {
    vetkd_public_key : (VetKdPublicKeyArgs) -> async { public_key : Blob };
    vetkd_derive_key : (VetKdDeriveKeyArgs) -> async {
      encrypted_key : Blob;
    };
  };

  // Constants
  let MAX_MESSAGES_PER_INBOX : Nat = 1000;
  let DOMAIN_SEPARATOR : Text = "basic_ibe_example_dapp";

  // State
  var inboxes = Map.empty<Principal, Inbox>();

  // Management canister actor
  let vetKdSystemApi : VetKdSystemApi = actor ("aaaaa-aa");

  // Send a message to a receiver
  public shared ({ caller }) func send_message(request : SendMessageRequest) : async Result<(), Text> {
    let message : Message = {
      sender = caller;
      encrypted_message = request.encrypted_message;
      timestamp = Nat64.fromNat(Int.abs(Time.now()));
    };

    let receiver = request.receiver;
    let current_inbox = switch (Map.get(inboxes, Principal.compare, receiver)) {
      case (?inbox) { inbox };
      case null { { messages = [] } };
    };

    if (current_inbox.messages.size() >= MAX_MESSAGES_PER_INBOX) {
      return #Err("Inbox for " # Principal.toText(receiver) # " is full");
    };
  
    let new_messages = Array.concat(current_inbox.messages, [message]);
    let new_inbox : Inbox = { messages = new_messages };
    ignore Map.insert(inboxes, Principal.compare, receiver, new_inbox);

    #Ok();
  };

  // Get the IBE public key
  public shared func get_ibe_public_key() : async Blob {
    let key_id : VetKdKeyId = {
      curve = #bls12_381_g2;
      name = keyNameString;
    };

    let context = Text.encodeUtf8(DOMAIN_SEPARATOR);
    let request : VetKdPublicKeyArgs = {
      canister_id = null;
      context = context;
      key_id = key_id;
    };

    let result = await vetKdSystemApi.vetkd_public_key(request);
    result.public_key;
  };

  // Get the caller's encrypted IBE key
  public shared ({ caller }) func get_my_encrypted_ibe_key(transport_key : Blob) : async Blob {
    let key_id : VetKdKeyId = {
      curve = #bls12_381_g2;
      name = keyNameString;
    };

    let context = Text.encodeUtf8(DOMAIN_SEPARATOR);
    let input = Principal.toBlob(caller);
    let request : VetKdDeriveKeyArgs = {
      context = context;
      input = input;
      key_id = key_id;
      transport_public_key = transport_key;
    };

    let result = await (with cycles = 26_153_846_153) vetKdSystemApi.vetkd_derive_key(request);
    result.encrypted_key;
  };

  // Get the caller's messages
  public shared query ({ caller }) func get_my_messages() : async Inbox {
    switch (Map.get(inboxes, Principal.compare, caller)) {
      case (?inbox) { inbox };
      case null { { messages = [] } };
    };
  };

  // Remove a message by index
  public shared ({ caller }) func remove_my_message_by_index(message_index : Nat64) : async Result<(), Text> {
    let current_inbox = switch (Map.get(inboxes, Principal.compare, caller)) {
      case (?inbox) { inbox };
      case null { { messages = [] } };
    };

    let index = Nat64.toNat(message_index);
    if (index >= current_inbox.messages.size()) {
      return #Err("Message index out of bounds");
    };

    // Create a new array without the specified index
    let messages = current_inbox.messages;
    let new_messages_list = List.empty<Message>();

    for (i in messages.keys()) {
      if (i != index) {
        List.add(new_messages_list, messages[i]);
      };
    };

    let new_messages = List.toArray(new_messages_list);
    let new_inbox : Inbox = { messages = new_messages };
    ignore Map.insert(inboxes, Principal.compare, caller, new_inbox);

    #Ok();
  };
};
