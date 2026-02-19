import Principal "mo:base/Principal";
import Blob "mo:base/Blob";
import Buffer "mo:base/Buffer";
import Array "mo:base/Array";
import OrderedMap "mo:base/OrderedMap";
import MotokoResult "mo:base/Result";
import Text "mo:base/Text";
import Time "mo:base/Time";
import Nat64 "mo:base/Nat64";
import Int "mo:base/Int";
import Debug "mo:base/Debug";
import VetKeys "mo:ic-vetkeys";

persistent actor class (keyName : Text) {

  // Global state
  let encryptedMapsState = VetKeys.EncryptedMaps.newEncryptedMapsState<VetKeys.AccessRights>({ curve = #bls12_381_g2; name = keyName }, "password_manager_example_dapp");
  transient let encryptedMaps = VetKeys.EncryptedMaps.EncryptedMaps<VetKeys.AccessRights>(encryptedMapsState, VetKeys.accessRightsOperations());

  func compareMetadataKeys(a : MetadataKey, b : MetadataKey) : {
    #less;
    #greater;
    #equal;
  } {
    let ownerCompare = Principal.compare(a.0, b.0);
    if (ownerCompare == #equal) {
      let nameCompare = Blob.compare(a.1, b.1);
      if (nameCompare == #equal) {
        Blob.compare(a.2, b.2);
      } else {
        nameCompare;
      };
    } else {
      ownerCompare;
    };
  };
  transient let metadataMapOps = OrderedMap.Make<MetadataKey>(compareMetadataKeys);
  var metadata : OrderedMap.Map<MetadataKey, PasswordMetadata> = metadataMapOps.empty<PasswordMetadata>();

  // Types
  public type PasswordMetadata = {
    creation_date : Nat64;
    last_modification_date : Nat64;
    number_of_modifications : Nat64;
    last_modified_principal : Principal;
    tags : [Text];
    url : Text;
  };

  type MapOwner = Principal;
  type MapName = Blob;
  type MapKey = Blob;
  type MapId = (MapOwner, MapName);
  type MetadataKey = (MapOwner, MapName, MapKey);
  type ByteBuf = { inner : Blob };
  type Result<T, E> = {
    #Ok : T;
    #Err : E;
  };

  // Helper function to create new PasswordMetadata
  func newPasswordMetadata(caller : Principal, tags : [Text], url : Text) : PasswordMetadata {
    let timeNow = Nat64.fromNat(Int.abs(Time.now()));
    {
      creation_date = timeNow;
      last_modification_date = timeNow;
      number_of_modifications = 0;
      last_modified_principal = caller;
      tags = tags;
      url = url;
    };
  };

  // Helper function to update PasswordMetadata
  func updatePasswordMetadata(metadata : PasswordMetadata, caller : Principal, tags : [Text], url : Text) : PasswordMetadata {
    let timeNow = Nat64.fromNat(Int.abs(Time.now()));
    {
      creation_date = metadata.creation_date;
      last_modification_date = timeNow;
      number_of_modifications = metadata.number_of_modifications + 1;
      last_modified_principal = caller;
      tags = tags;
      url = url;
    };
  };

  func convertResult<T, E>(result : MotokoResult.Result<T, E>) : Result<T, E> {
    switch (result) {
      case (#err(msg)) { #Err(msg) };
      case (#ok(value)) { #Ok(value) };
    };
  };

  public query ({ caller }) func get_accessible_shared_map_names() : async [(Principal, ByteBuf)] {
    let mapIds = encryptedMaps.getAccessibleSharedMapNames(caller);
    Array.map<MapId, (Principal, ByteBuf)>(
      mapIds,
      func(mapId) = (mapId.0, { inner = mapId.1 }),
    );
  };

  public query ({ caller }) func get_shared_user_access_for_map(
    map_owner : Principal,
    map_name : ByteBuf,
  ) : async Result<[(Principal, VetKeys.AccessRights)], Text> {
    let mapId = (map_owner, map_name.inner);
    convertResult(encryptedMaps.getSharedUserAccessForMap(caller, mapId));
  };

  public query ({ caller }) func get_encrypted_values_for_map_with_metadata(
    map_owner : Principal,
    map_name : ByteBuf,
  ) : async Result<[(ByteBuf, ByteBuf, PasswordMetadata)], Text> {
    let mapId = (map_owner, map_name.inner);

    switch (encryptedMaps.getEncryptedValuesForMap(caller, mapId)) {
      case (#err(msg)) { #Err(msg) };
      case (#ok(mapValues)) {
        let results = Buffer.Buffer<(ByteBuf, ByteBuf, PasswordMetadata)>(0);

        for ((key, encryptedValue) in mapValues.vals()) {
          let metadataKey = (map_owner, map_name.inner, key);
          switch (metadataMapOps.get(metadata, metadataKey)) {
            case (null) {
              Debug.trap("bug: inconsistent state: no metadata for key");
            };
            case (?metadataValue) {
              results.add(({ inner = key }, { inner = encryptedValue }, metadataValue));
            };
          };
        };

        #Ok(Buffer.toArray(results));
      };
    };
  };

  public query ({ caller }) func get_owned_non_empty_map_names() : async [ByteBuf] {
    Array.map<MapName, ByteBuf>(
      encryptedMaps.getOwnedNonEmptyMapNames(caller),
      func(mapName) = { inner = mapName },
    );
  };

  public shared ({ caller }) func insert_encrypted_value_with_metadata(
    map_owner : Principal,
    map_name : ByteBuf,
    map_key : ByteBuf,
    value : ByteBuf,
    tags : [Text],
    url : Text,
  ) : async Result<?(ByteBuf, PasswordMetadata), Text> {
    let mapId = (map_owner, map_name.inner);

    switch (encryptedMaps.insertEncryptedValue(caller, mapId, map_key.inner, value.inner)) {
      case (#err(msg)) { #Err(msg) };
      case (#ok(optPrevValue)) {
        let metadataKey = (map_owner, map_name.inner, map_key.inner);
        let prevMetadata = metadataMapOps.get(metadata, metadataKey);

        let metadataValue = switch (prevMetadata) {
          case (null) {
            newPasswordMetadata(caller, tags, url);
          };
          case (?existingMetadata) {
            updatePasswordMetadata(existingMetadata, caller, tags, url);
          };
        };

        metadata := metadataMapOps.put(metadata, metadataKey, metadataValue);

        switch (optPrevValue, prevMetadata) {
          case (null, null) { #Ok(null) };
          case (null, ?_) {
            Debug.trap("bug: inconsistent state: no previous value but some metadata");
          };
          case (?_, null) {
            Debug.trap("bug: inconsistent state: some previous value but no metadata");
          };
          case (?prevValue, ?m) { #Ok(?({ inner = prevValue }, m)) };
        };
      };
    };
  };

  public shared ({ caller }) func remove_encrypted_value_with_metadata(
    map_owner : Principal,
    map_name : ByteBuf,
    map_key : ByteBuf,
  ) : async Result<?(ByteBuf, PasswordMetadata), Text> {
    let mapId = (map_owner, map_name.inner);

    switch (encryptedMaps.removeEncryptedValue(caller, mapId, map_key.inner)) {
      case (#err(msg)) { #Err(msg) };
      case (#ok(optPrevValue)) {
        let metadataKey = (map_owner, map_name.inner, map_key.inner);
        let prevMetadata = metadataMapOps.get(metadata, metadataKey);

        metadata := metadataMapOps.delete(metadata, metadataKey);

        switch (optPrevValue, prevMetadata) {
          case (null, null) { #Ok(null) };
          case (null, ?_) {
            Debug.trap("bug: inconsistent state: no previous value but some metadata");
          };
          case (?_, null) {
            Debug.trap("bug: inconsistent state: some previous value but no metadata");
          };
          case (?prevValue, ?m) { #Ok(?({ inner = prevValue }, m)) };
        };
      };
    };
  };

  public shared func get_vetkey_verification_key() : async ByteBuf {
    { inner = await encryptedMaps.getVetkeyVerificationKey() };
  };

  public shared ({ caller }) func get_encrypted_vetkey(
    map_owner : Principal,
    map_name : ByteBuf,
    transport_key : ByteBuf,
  ) : async Result<ByteBuf, Text> {
    let mapId = (map_owner, map_name.inner);
    switch (await encryptedMaps.getEncryptedVetkey(caller, mapId, transport_key.inner)) {
      case (#err(msg)) { #Err(msg) };
      case (#ok(vetkey)) { #Ok({ inner = vetkey }) };
    };
  };

  public query ({ caller }) func get_user_rights(
    map_owner : Principal,
    map_name : ByteBuf,
    user : Principal,
  ) : async Result<?VetKeys.AccessRights, Text> {
    let mapId = (map_owner, map_name.inner);
    convertResult(encryptedMaps.getUserRights(caller, mapId, user));
  };

  public shared ({ caller }) func set_user_rights(
    map_owner : Principal,
    map_name : ByteBuf,
    user : Principal,
    access_rights : VetKeys.AccessRights,
  ) : async Result<?VetKeys.AccessRights, Text> {
    let mapId = (map_owner, map_name.inner);
    convertResult(encryptedMaps.setUserRights(caller, mapId, user, access_rights));
  };

  public shared ({ caller }) func remove_user(
    map_owner : Principal,
    map_name : ByteBuf,
    user : Principal,
  ) : async Result<?VetKeys.AccessRights, Text> {
    let mapId = (map_owner, map_name.inner);
    convertResult(encryptedMaps.removeUser(caller, mapId, user));
  };
};
