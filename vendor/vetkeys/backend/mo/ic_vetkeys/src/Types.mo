module {
    public type AccessControlOperations<T> = {
        canRead : (t : T) -> Bool;
        canWrite : (t : T) -> Bool;
        canGetUserRights : (t : T) -> Bool;
        canSetUserRights : (t : T) -> Bool;
        ownerRights : () -> T;
        toText : (t : T) -> Text;
    };

    public type AccessRights = {
        #Read;
        #ReadWrite;
        #ReadWriteManage;
    };

    public func accessRightsOperations() : AccessControlOperations<AccessRights> {
        {
            canRead = func(accessRights : AccessRights) : Bool {
                switch (accessRights) {
                    case (#Read) { true };
                    case (#ReadWrite) { true };
                    case (#ReadWriteManage) { true };
                };
            };

            canWrite = func(accessRights : AccessRights) : Bool {
                switch (accessRights) {
                    case (#Read) { false };
                    case (#ReadWrite) { true };
                    case (#ReadWriteManage) { true };
                };
            };

            canGetUserRights = func(accessRights : AccessRights) : Bool {
                switch (accessRights) {
                    case (#Read) { false };
                    case (#ReadWrite) { false };
                    case (#ReadWriteManage) { true };
                };
            };

            canSetUserRights = func(accessRights : AccessRights) : Bool {
                switch (accessRights) {
                    case (#Read) { false };
                    case (#ReadWrite) { false };
                    case (#ReadWriteManage) { true };
                };
            };

            ownerRights = func() : AccessRights {
                #ReadWriteManage;
            };

            toText = func(accessRights : AccessRights) : Text {
                switch (accessRights) {
                    case (#Read) { "Read" };
                    case (#ReadWrite) { "ReadWrite" };
                    case (#ReadWriteManage) { "ReadWriteManage" };
                };
            };
        };
    };
};
