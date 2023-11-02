{-# LANGUAGE DeriveFunctor #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE TypeOperators #-}

module IC.Types where

import Control.Monad.Except
import Data.ByteString.Base32
import qualified Data.ByteString.Builder as BS
import qualified Data.ByteString.Lazy.Char8 as BS
import qualified Data.ByteString.UTF8 as BSU
import Data.Digest.CRC32
import Data.Int
import Data.List
import Data.List.Split (chunksOf)
import qualified Data.Map as M
import qualified Data.Set as S
import qualified Data.Text as T
import qualified Data.Word as W
import Numeric.Natural
import qualified Text.Hex as T hiding (Text)
import Text.Printf (printf)

type (↦) = M.Map

-- Basic types

type Blob = BS.ByteString

type PublicKey = Blob

newtype EntityId = EntityId {rawEntityId :: Blob}
  deriving (Show, Eq, Ord)

instance Read EntityId where
  readsPrec _ x =
    case parsePrettyID x of
      Just t -> return (t, "")
      Nothing -> fail "could not read EntityId"

type CanisterId = EntityId

type CanisterRange = (CanisterId, CanisterId)

type SubnetId = EntityId

type UserId = EntityId

type MethodName = String

type RequestID = Blob

type Cycles = Natural

prettyBlob :: Blob -> String
prettyBlob b = "0x" ++ T.unpack (T.encodeHex (BS.toStrict b))

prettyID :: EntityId -> String
prettyID (EntityId blob) =
  intercalate "-" (chunksOf 5 (base32 (checkbytes <> blob)))
  where
    checksum = crc32 (BS.toStrict blob)
    checkbytes = BS.toLazyByteString (BS.word32BE checksum)

    base32 = filter (/= '=') . T.unpack . T.toLower . encodeBase32 . BS.toStrict

parsePrettyID :: String -> Maybe EntityId
parsePrettyID b = case raw of
  Left _ -> Nothing
  Right x -> validate x
  where
    raw = decodeBase32Unpadded $ BSU.fromString $ filter (/= '-') b
    validate x
      | a == BS.toLazyByteString (BS.word32BE checksum) = Just $ EntityId b
      | otherwise = Nothing
      where
        checksum = crc32 (BS.toStrict b)
        y = BS.fromStrict x
        a = BS.take 4 y
        b = BS.drop 4 y

newtype NeedsToRespond = NeedsToRespond Bool
  deriving (Show, Eq)

newtype Timestamp = Timestamp Natural
  deriving (Show, Num, Ord, Eq)

data RejectCode
  = RC_SYS_FATAL
  | RC_SYS_TRANSIENT
  | RC_DESTINATION_INVALID
  | RC_CANISTER_REJECT
  | RC_CANISTER_ERROR
  deriving (Show)

rejectCode :: RejectCode -> Natural
rejectCode RC_SYS_FATAL = 1
rejectCode RC_SYS_TRANSIENT = 2
rejectCode RC_DESTINATION_INVALID = 3
rejectCode RC_CANISTER_REJECT = 4
rejectCode RC_CANISTER_ERROR = 5

data ErrorCode
  = EC_CANISTER_NOT_FOUND
  | EC_METHOD_NOT_FOUND
  | EC_CANISTER_EMPTY
  | EC_CANISTER_NOT_EMPTY
  | EC_CANISTER_STOPPED
  | EC_CANISTER_NOT_STOPPED
  | EC_CANISTER_NOT_RUNNING
  | EC_CANISTER_RESTARTED
  | EC_CANISTER_TRAPPED
  | EC_CANISTER_REJECTED
  | EC_CANISTER_DID_NOT_REPLY
  | EC_CANISTER_CONTRACT_VIOLATION
  | EC_INVALID_ENCODING
  | EC_INVALID_ARGUMENT
  | EC_INVALID_MODULE
  | EC_NOT_AUTHORIZED
  deriving (Show, Enum)

errorCode :: ErrorCode -> String
errorCode = printf "ICHS%04d" . fromEnum

data Response = Reply Blob | Reject (RejectCode, String)
  deriving (Show)

data SubnetType = Application | VerifiedApplication | System
  deriving (Eq)

peelOffPrefix :: [(a, String)] -> String -> Maybe (a, String)
peelOffPrefix xs y =
  foldl
    ( \z (a, x) -> case z of
        Nothing -> aux a x
        Just _ -> z
    )
    Nothing
    xs
  where
    aux a x = if isPrefixOf x y then Just (a, drop (length x) y) else Nothing

instance Read SubnetType where
  readsPrec _ x = do
    case peelOffPrefix [(Application, "application"), (VerifiedApplication, "verified_application"), (System, "system")] x of
      Just (t, s) -> return (t, s)
      Nothing -> fail "could not read SubnetType"

instance Show SubnetType where
  show Application = "application"
  show VerifiedApplication = "verified_application"
  show System = "system"

data SubnetConfig = SubnetConfig
  { subnet_type :: SubnetType,
    subnet_size :: W.Word64,
    nonce :: String,
    canister_ranges :: [(W.Word64, W.Word64)]
  }

type TestSubnetConfig = (EntityId, SubnetType, [EntityId], [(W.Word64, W.Word64)], [String])

-- Abstract canisters

-- | This data type contains all read-only data that should be available to the
-- canister almost always
data Status = Running | Stopping | Stopped

data Env = Env
  { env_self :: CanisterId,
    env_time :: Timestamp,
    env_balance :: Cycles,
    env_status :: Status,
    env_certificate :: Maybe Blob,
    env_canister_version :: Natural,
    env_global_timer :: Natural,
    env_controllers :: S.Set EntityId
  }

data TrapOr a = Trap String | Return a deriving (Functor)

data WasmClosure = WasmClosure
  { closure_idx :: Int32,
    closure_env :: Int32
  }
  deriving (Eq, Show)

data Callback = Callback
  { reply_callback :: WasmClosure,
    reject_callback :: WasmClosure,
    cleanup_callback :: Maybe WasmClosure
  }
  deriving (Eq, Show)

data MethodCall = MethodCall
  { call_callee :: CanisterId,
    call_method_name :: MethodName,
    call_arg :: Blob,
    call_callback :: Callback,
    call_transferred_cycles :: Cycles
  }
  deriving (Show)

type ExistingCanisters = [CanisterId]

-- Canister history

data ChangeOrigin
  = ChangeFromUser
      { from_user_id :: EntityId
      }
  | ChangeFromCanister
      { from_canister_id :: EntityId,
        from_canister_version :: Maybe W.Word64
      }
  deriving (Show)

data CanisterInstallMode
  = Install
  | Reinstall
  | Upgrade
  deriving (Show)

data ChangeDetails
  = Creation
      { creation_controllers :: [EntityId]
      }
  | CodeUninstall
  | CodeDeployment
      { deployment_mode :: CanisterInstallMode,
        deployment_module_hash :: Blob
      }
  | ControllersChange
      { new_controllers :: [EntityId]
      }
  deriving (Show)

data Change = Change
  { timestamp_nanos :: W.Word64,
    new_canister_version :: W.Word64,
    change_origin :: ChangeOrigin,
    change_details :: ChangeDetails
  }
  deriving (Show)

-- Canister actions (independent of calls)
data CanisterActions = CanisterActions
  { set_certified_data :: Maybe Blob,
    set_global_timer :: Maybe Natural
  }

instance Semigroup CanisterActions where
  ca1 <> ca2 = CanisterActions (set_certified_data ca1 `setter` set_certified_data ca2) (set_global_timer ca1 `setter` set_global_timer ca2)
    where
      setter _ (Just x) = Just x
      setter x Nothing = x

noCanisterActions :: CanisterActions
noCanisterActions = CanisterActions Nothing Nothing

-- Actions relative to a call context
data CallActions = CallActions
  { ca_new_calls :: [MethodCall],
    ca_accept :: Cycles,
    ca_mint :: Cycles,
    ca_response :: Maybe Response
  }

noCallActions :: CallActions
noCallActions = CallActions [] 0 0 Nothing

type UpdateResult = (CallActions, CanisterActions)

type StableMemory = Blob

-- Semantically relevant information from an envelope
--
--  * When is it valid
--  * Which users can it sign for
--  * Which canisters can it be used at
--
-- All represented as validation functions

type ValidityPred a = forall m. (MonadError T.Text m) => a -> m ()

data EnvValidity = EnvValidity
  { valid_when :: ValidityPred Timestamp,
    valid_for :: ValidityPred EntityId,
    valid_where :: ValidityPred EntityId
  }

instance Semigroup EnvValidity where
  ed1 <> ed2 =
    EnvValidity
      { valid_when = valid_when ed1 >>> valid_when ed2,
        valid_for = valid_for ed1 >>> valid_for ed2,
        valid_where = valid_where ed1 >>> valid_where ed2
      }
    where
      a >>> b = \x -> a x >> b x

instance Monoid EnvValidity where
  mempty = EnvValidity x x x
    where
      x :: ValidityPred a
      x = const (return ())

validWhen :: ValidityPred Timestamp -> EnvValidity
validWhen valid_when = mempty {valid_when}

validFor :: ValidityPred EntityId -> EnvValidity
validFor valid_for = mempty {valid_for}

validWhere :: ValidityPred EntityId -> EnvValidity
validWhere valid_where = mempty {valid_where}
