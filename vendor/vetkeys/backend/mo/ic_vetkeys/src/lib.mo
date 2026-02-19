import KeyManagerModule "key_manager/KeyManager";
import EncryptedMapsModule "encrypted_maps/EncryptedMaps";
import ManagementCanisterModule "ManagementCanister";
import Types "Types";

module {
    public type AccessControlOperations<T> = Types.AccessControlOperations<T>;
    public type AccessRights = Types.AccessRights;
    public let accessRightsOperations = Types.accessRightsOperations;

    public let KeyManager = KeyManagerModule;
    public let EncryptedMaps = EncryptedMapsModule;

    public let ManagementCanister = ManagementCanisterModule;
};
