// Opcodes

/// Operands used in encoding UC payloads.
macro_rules! try_from_u8 {
    ($(#[$meta:meta])* $vis:vis enum $name:ident {
        $($(#[$vmeta:meta])* $vname:ident $(= $val:expr)?,)*
    }) => {
        $(#[$meta])*
        #[repr(u8)]
        $vis enum $name {
            $($(#[$vmeta])* $vname $(= $val)?,)*
        }

        impl std::convert::TryFrom<u8> for $name {
            type Error = ();

            fn try_from(v: u8) -> Result<Self, Self::Error> {
                match v {
                    $(x if x == $name::$vname as u8 => Ok($name::$vname),)*
                    _ => Err(()),
                }
            }
        }
    }
}

try_from_u8!(
    #[derive(Debug, Eq, PartialEq)]
    pub enum Ops {
        Noop = 0,
        Drop = 1,
        PushInt = 2,
        PushBytes = 3,
        ReplyDataAppend = 4,
        Reply = 5,
        Self_ = 6,
        Reject = 7,
        Caller = 8,
        InstructionCounterIsAtLeast = 9,
        RejectMessage = 10,
        RejectCode = 11,
        IntToBlob = 12,
        MessagePayload = 13,
        Concat = 14,
        StableSize = 15,
        StableGrow = 16,
        StableRead = 17,
        StableWrite = 18,
        DebugPrint = 19,
        Trap = 20,
        SetGlobal = 21,
        GetGlobal = 22,
        BadPrint = 23,
        SetPreUpgrade = 24,
        AppendGlobal = 25,
        Time = 26,
        CyclesAvailable = 27,
        CyclesBalance = 28,
        CyclesRefunded = 29,
        AcceptCycles = 30,
        PushInt64 = 31,
        CallNew = 32,
        CallDataAppend = 33,
        CallCyclesAdd = 34,
        CallPerform = 35,
        CertifiedDataSet = 36,
        DataCertificatePresent = 37,
        DataCertificate = 38,
        CanisterStatus = 39,
        SetHeartbeat = 40,
        AcceptMessage = 41,
        SetInspectMessage = 42,
        TrapIfEq = 43,
        CallOnCleanup = 44,
        StableFill = 45,
        StableSize64 = 46,
        StableGrow64 = 47,
        StableRead64 = 48,
        StableWrite64 = 49,
        Int64ToBlob = 50,
        CyclesAvailable128 = 51,
        CyclesBalance128 = 52,
        CyclesRefunded128 = 53,
        AcceptCycles128 = 54,
        CallCyclesAdd128 = 55,
        MsgArgDataSize = 56,
        MsgArgDataCopy = 57,
        MsgCallerSize = 58,
        MsgCallerCopy = 59,
        MsgRejectMsgSize = 60,
        MsgRejectMsgCopy = 61,
        SetGlobalTimerMethod = 62,
        ApiGlobalTimerSet = 63,
        IncGlobalCounter = 64,
        GetGlobalCounter = 65,
        GetPerformanceCounter = 66,
        MsgMethodName = 67,
        ParsePrincipal = 68,
        SetTransform = 69,
        GetHttpReplyWithBody = 70,
        GetHttpTransformContext = 71,
        StableFill64 = 72,
        CanisterVersion = 73,
        TrapIfNeq = 74,
        MintCycles = 75,
        OneWayCallNew = 76,
        IsController = 77,
        CyclesBurn128 = 78,
        BlobLength = 79,
        PushEqualBytes = 80,
        InReplicatedExecution = 81,
        CallWithBestEffortResponse = 82,
        MsgDeadline = 83,
        MemorySizeIsAtLeast = 84,
        CallCyclesAdd128UpTo = 85,
    }
);
