{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE NumericUnderscores #-}
{-# LANGUAGE OverloadedLabels #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TupleSections #-}
{-# LANGUAGE TypeApplications #-}

module IC.Test.Spec.Utils where

import Codec.Candid (Principal (..))
import qualified Codec.Candid as Candid
import Control.Monad
import qualified Data.Binary.Get as Get
import qualified Data.ByteString.Lazy as BS
import qualified Data.HashMap.Lazy as HM
import Data.IORef
import Data.List
import Data.Row as R
import qualified Data.Set as S
import qualified Data.Text as T
import qualified Data.Text.Encoding as T
import qualified Data.Text.Encoding.Error as T
import qualified Data.Vector as Vec
import Data.Word
import qualified Data.Word as W
import IC.Crypto
import qualified IC.HTTP.CBOR as CBOR
import IC.HTTP.GenR
import IC.HTTP.RequestId
import IC.Management (HttpHeader, HttpResponse)
import IC.Test.Agent
import IC.Test.Agent.SafeCalls
import IC.Test.Agent.UnsafeCalls
import IC.Test.Universal
import IC.Utils
import Network.HTTP.Client
import Numeric.Natural
import System.Directory
import System.Environment
import System.FilePath
import System.IO.Unsafe (unsafePerformIO)
import Test.Tasty
import Test.Tasty.HUnit

type Blob = BS.ByteString

-- * Equality assertions

is :: (HasCallStack, Eq a, Show a) => a -> a -> Assertion
is exp act = act @?= exp

isSet :: (HasCallStack, Ord a, Show a) => [a] -> [a] -> Assertion
isSet exp act = S.fromList exp @?= S.fromList act

isContainedIn :: (HasCallStack, Ord a, Show a) => a -> [(a, a)] -> Assertion
isContainedIn p ranges =
  assertBool (show p ++ " not contained in: " ++ show ranges) $
    any (\(l, r) -> l <= p && p <= r) ranges

-- * Simple Wasm

trivialWasmModule :: Blob
trivialWasmModule = "\0asm\1\0\0\0"

-- * Some test data related to standard requests

queryToNonExistent :: GenR
queryToNonExistent =
  rec
    [ "request_type" =: GText "query",
      "sender" =: GBlob anonymousUser,
      "canister_id" =: GBlob doesn'tExist,
      "method_name" =: GText "foo",
      "arg" =: GBlob "nothing to see here"
    ]

readStateEmpty :: GenR
readStateEmpty =
  rec
    [ "request_type" =: GText "read_state",
      "sender" =: GBlob defaultUser,
      "paths" =: GList []
    ]

badEnvelope :: GenR -> GenR
badEnvelope content =
  rec
    [ "sender_pubkey" =: GBlob (toPublicKey defaultSK),
      "sender_sig" =: GBlob (BS.replicate 64 0x42),
      "content" =: content
    ]

-- * Bad requests

noDomainSepEnv :: SecretKey -> GenR -> IO GenR
noDomainSepEnv sk content = do
  sig <- sign "" sk (requestId content)
  return $
    rec
      [ "sender_pubkey" =: GBlob (toPublicKey sk),
        "sender_sig" =: GBlob sig,
        "content" =: content
      ]

noExpiryEnv, pastExpiryEnv, futureExpiryEnv :: GenR -> GenR
noExpiryEnv = deleteField "ingress_expiry"
pastExpiryEnv = modNatField "ingress_expiry" (subtract 3600_000_000_000)
futureExpiryEnv = modNatField "ingress_expiry" (+ 3600_000_000_000)

deleteField :: T.Text -> GenR -> GenR
deleteField f (GRec hm) = GRec $ HM.delete f hm
deleteField _ _ = error "deleteField: not a record"

modNatField :: T.Text -> (Natural -> Natural) -> GenR -> GenR
modNatField f g (GRec hm) = GRec $ HM.adjust underNat f hm
  where
    underNat :: GenR -> GenR
    underNat (GNat n) = GNat (g n)
    underNat _ = error "modNatField: not a nat field"
modNatField _ _ _ = error "modNatField: not a record"

-- * Double request

awaitCallTwice :: (HasAgentConfig) => Blob -> GenR -> IO ReqResponse
awaitCallTwice cid req = do
  req <- addNonce req
  req <- addExpiry req
  res <- envelopeFor (senderOf req) req >>= postCallCBOR cid
  code202 res
  res <- envelopeFor (senderOf req) req >>= postCallCBOR cid
  code202 res
  assertBool "Response body not empty" (BS.null (responseBody res))
  awaitStatus (getRequestStatus' (senderOf req) cid (requestId req))

-- * CBOR decoding

asCBORBlobList :: Blob -> IO [Blob]
asCBORBlobList blob = do
  decoded <- asRight $ CBOR.decode blob
  case decoded of
    GList list -> mapM cborToBlob list
    _ -> assertFailure $ "Failed to decode as CBOR encoded list of blobs: " <> show decoded

cborToBlob :: GenR -> IO Blob
cborToBlob (GBlob blob) = return blob
cborToBlob r = assertFailure $ "Expected blob, got " <> show r

-- Interaction with aaaaa-aa via the universal canister

ic00viaWithCyclesSubnetImpl' :: (HasAgentConfig) => Prog -> Prog -> Blob -> Blob -> IC00WithCycles
ic00viaWithCyclesSubnetImpl' relayReply relayReject subnet_id cid cycles _ecid method_name arg = do
  resp <-
    call' cid $
      callNew
        (bytes subnet_id)
        (bytes (BS.fromStrict (T.encodeUtf8 method_name))) -- aaaaa-aa
        (callback relayReply)
        (callback relayReject)
        >>> callDataAppend (bytes arg)
        >>> callCyclesAdd (int64 cycles)
        >>> callPerform
  case resp of
    Reply r -> isRelay r
    _ -> return resp

ic00viaWithCyclesSubnet' :: (HasAgentConfig) => Blob -> Blob -> IC00WithCycles
ic00viaWithCyclesSubnet' = ic00viaWithCyclesSubnetImpl' relayReply relayReject

ic00via :: (HasAgentConfig) => Blob -> IC00
ic00via cid = ic00viaWithCycles cid 0

ic00viaWithCyclesSubnetImpl :: (HasAgentConfig) => Prog -> Prog -> Blob -> Blob -> IC00WithCycles
ic00viaWithCyclesSubnetImpl relayReply relayReject subnet_id cid cycles _ecid method_name arg =
  do
    call' cid $
      callNew
        (bytes subnet_id)
        (bytes (BS.fromStrict (T.encodeUtf8 method_name))) -- aaaaa-aa
        (callback relayReply)
        (callback relayReject)
        >>> callDataAppend (bytes arg)
        >>> callCyclesAdd (int64 cycles)
        >>> callPerform
    >>= isReply
    >>= isRelay

ic00viaWithCyclesSubnet :: (HasAgentConfig) => Blob -> Blob -> IC00WithCycles
ic00viaWithCyclesSubnet = ic00viaWithCyclesSubnetImpl relayReply relayReject

ic00viaWithCycles :: (HasAgentConfig) => Blob -> IC00WithCycles
ic00viaWithCycles = ic00viaWithCyclesSubnetImpl relayReply relayReject ""

ic00viaWithCyclesRefundSubnet :: (HasAgentConfig) => Word64 -> Blob -> Blob -> IC00WithCycles
ic00viaWithCyclesRefundSubnet amount = ic00viaWithCyclesSubnetImpl (relayReplyRefund amount) (relayRejectRefund amount)

ic00viaWithCyclesRefund :: (HasAgentConfig) => Word64 -> Blob -> IC00WithCycles
ic00viaWithCyclesRefund amount = ic00viaWithCyclesSubnetImpl (relayReplyRefund amount) (relayRejectRefund amount) ""

-- * Interacting with the universal canister

-- Some common operations on the universal canister
-- The primed variant (call') return the response record,
-- e.g. to check for error conditions.
-- The unprimed variant expect a reply.

install' :: (HasCallStack, HasAgentConfig) => Blob -> Prog -> IO ReqResponse
install' cid prog = do
  universal_wasm <- getTestWasm "universal_canister.wasm.gz"
  ic_install' ic00 (enum #install) cid universal_wasm (run prog)

installAt :: (HasCallStack, HasAgentConfig) => Blob -> Prog -> IO ()
installAt cid prog = do
  universal_wasm <- getTestWasm "universal_canister.wasm.gz"
  ic_install ic00 (enum #install) cid universal_wasm (run prog)

-- Also calls create, used default 'ic00'
install :: (HasCallStack, HasAgentConfig) => Blob -> Prog -> IO Blob
install ecid prog = do
  cid <- create ecid
  installAt cid prog
  return cid

create :: (HasCallStack, HasAgentConfig) => Blob -> IO Blob
create ecid = ic_provisional_create ic00 ecid Nothing (Just (2 ^ (60 :: Int))) Nothing

upgrade' :: (HasCallStack, HasAgentConfig) => Blob -> Prog -> IO ReqResponse
upgrade' cid prog = do
  universal_wasm <- getTestWasm "universal_canister.wasm.gz"
  ic_install' ic00 (enumNothing #upgrade) cid universal_wasm (run prog)

upgrade :: (HasCallStack, HasAgentConfig) => Blob -> Prog -> IO ()
upgrade cid prog = do
  universal_wasm <- getTestWasm "universal_canister.wasm.gz"
  ic_install ic00 (enumNothing #upgrade) cid universal_wasm (run prog)

reinstall' :: (HasCallStack, HasAgentConfig) => Blob -> Prog -> IO ReqResponse
reinstall' cid prog = do
  universal_wasm <- getTestWasm "universal_canister.wasm.gz"
  ic_install' ic00 (enum #reinstall) cid universal_wasm (run prog)

reinstall :: (HasCallStack, HasAgentConfig) => Blob -> Prog -> IO ()
reinstall cid prog = do
  universal_wasm <- getTestWasm "universal_canister.wasm.gz"
  ic_install ic00 (enum #reinstall) cid universal_wasm (run prog)

callRequestAs :: (HasCallStack, HasAgentConfig) => Blob -> Blob -> Prog -> GenR
callRequestAs user cid prog =
  rec
    [ "request_type" =: GText "call",
      "sender" =: GBlob user,
      "canister_id" =: GBlob cid,
      "method_name" =: GText "update",
      "arg" =: GBlob (run prog)
    ]

callToQueryRequestAs :: (HasCallStack, HasAgentConfig) => Blob -> Blob -> Prog -> GenR
callToQueryRequestAs user cid prog =
  rec
    [ "request_type" =: GText "call",
      "sender" =: GBlob user,
      "canister_id" =: GBlob cid,
      "method_name" =: GText "query",
      "arg" =: GBlob (run prog)
    ]

callRequest :: (HasCallStack, HasAgentConfig) => Blob -> Prog -> GenR
callRequest cid prog = callRequestAs defaultUser cid prog

callToQuery'' :: (HasCallStack, HasAgentConfig) => Blob -> Prog -> IO (HTTPErrOr ReqResponse)
callToQuery'' cid prog = awaitCall' cid $ callToQueryRequestAs defaultUser cid prog

stopRequest :: (HasCallStack, HasAgentConfig) => Blob -> GenR
stopRequest cid =
  rec
    [ "request_type" =: GText "call",
      "sender" =: GBlob defaultUser,
      "canister_id" =: GBlob "",
      "method_name" =: GText "stop_canister",
      "arg" =: GBlob (Candid.encode (#canister_id .== Principal cid))
    ]

-- The following variants of the call combinator differ in how much failure they allow:
--
--   call'' allows HTTP errors at `submit` time already
--   call'  requires submission to succeed, and allows reject responses
--   call   requires a reply response
--   call_  requires a reply response with an empty blob (a common case)

call'' :: (HasCallStack, HasAgentConfig) => Blob -> Prog -> IO (HTTPErrOr ReqResponse)
call'' cid prog = awaitCall' cid (callRequest cid prog)

call' :: (HasCallStack, HasAgentConfig) => Blob -> Prog -> IO ReqResponse
call' cid prog = call'' cid prog >>= is2xx

call :: (HasCallStack, HasAgentConfig) => Blob -> Prog -> IO Blob
call cid prog = call' cid prog >>= isReply

call_ :: (HasCallStack, HasAgentConfig) => Blob -> Prog -> IO ()
call_ cid prog = call cid prog >>= is ""

callTwice' :: (HasCallStack, HasAgentConfig) => Blob -> Prog -> IO ReqResponse
callTwice' cid prog = awaitCallTwice cid (callRequest cid prog)

counterRef :: IORef Word32
counterRef =
  unsafePerformIO (newIORef 0)
{-# NOINLINE counterRef #-}

incrementCount :: IO Word32
incrementCount =
  atomicModifyIORef' counterRef (\count -> (count + 1, count + 1))

query' :: (HasCallStack, HasAgentConfig) => Blob -> Prog -> IO (Blob, QueryResponse)
query' cid prog = do
  ctr <- incrementCount
  let cbor =
        rec
          [ "request_type" =: GText "query",
            "sender" =: GBlob defaultUser,
            "canister_id" =: GBlob cid,
            "method_name" =: GText "query",
            "arg" =: GBlob (run ((debugPrint $ i2b $ int ctr) >>> prog))
          ]
  (rid, res) <- queryCBOR cid cbor
  res <- queryResponse res
  return (rid, res)

query :: (HasCallStack, HasAgentConfig) => Blob -> Prog -> IO Blob
query cid prog = query' cid prog >>= isQueryReply cid

query_ :: (HasCallStack, HasAgentConfig) => Blob -> Prog -> IO ()
query_ cid prog = query cid prog >>= is ""

-- Predicates to handle the responses from relayReply and relayReject
isRelay :: (HasCallStack) => Blob -> IO ReqResponse
isRelay =
  runGet $
    Get.getWord32le >>= \case
      0 -> Reply <$> Get.getRemainingLazyByteString
      0x4c444944 -> fail "Encountered Candid when expecting relayed data. Did you forget to use isRelay?"
      c -> do
        msg <- Get.getRemainingLazyByteString
        return $ Reject (fromIntegral c) (T.decodeUtf8With T.lenientDecode (BS.toStrict msg)) Nothing

-- Shortcut for test cases that just need one canister.
simpleTestCase :: (HasCallStack, HasAgentConfig) => String -> Blob -> (Blob -> IO ()) -> TestTree
simpleTestCase name ecid act = testCase name $ install ecid noop >>= act

-- * Programmatic test generation

-- | Runs test once for each field with that field removed, including nested
-- fields
omitFields :: GenR -> (GenR -> Assertion) -> [TestTree]
omitFields (GRec hm) act =
  [ let hm' = HM.delete f hm
     in testCase ("omitting " ++ T.unpack f) $ act (GRec hm')
    | f <- fields
  ]
    ++ concat
      [ omitFields val $ \val' -> act (GRec (HM.insert f val' hm))
        | f <- fields,
          val@(GRec _) <- return $ hm HM.! f
      ]
  where
    fields = sort $ HM.keys hm
omitFields _ _ = error "omitFields needs a GRec"

-- * Test data access

getTestFile :: FilePath -> IO FilePath
getTestFile file =
  lookupEnv "IC_TEST_DATA" >>= \case
    Just fp -> return $ fp </> file
    Nothing -> do
      -- nix use
      exePath <- getExecutablePath
      let exeRelPath = takeDirectory exePath </> "../test-data"
      -- convenient for cabal new-run use
      try [exeRelPath, "test-data", "../test-data", "impl/test-data"]
  where
    try (d : ds) =
      doesFileExist (d </> file) >>= \case
        True -> return (d </> file)
        False -> try ds
    try [] = error $ "getTestDir: Could not read " ++ file ++ " from test-data/. Please consult README.md"

getTestWasm :: FilePath -> IO BS.ByteString
getTestWasm base = do
  fp <- getTestFile base
  BS.readFile fp

-- * Helper patterns

-- A barrier

-- This will stop and start all mentioned canisters. This guarantees
-- that all outstanding callbacks are handled
barrier :: (HasAgentConfig) => [Blob] -> IO ()
barrier cids = do
  mapM_ (ic_stop_canister ic00) cids
  mapM_ (ic_start_canister ic00) cids

-- A message hold
--
-- This allows the test driver to withhold the response to a message, and
-- control when they are released, in order to produce situations with
-- outstanding call contexts.
--
-- In an ideal world (from our pov), we could instrument and control the
-- system's scheduler this way, but we can't. So instead, we use some tricks.
-- Ideally, the details of this trick are irrelevant to the users of this
-- function (yay, abstraction), and if we find better tricks, we can swap them
-- out easily. We'll see if that holds water.
--
-- One problem with this approach is that a test failure could mean that the
-- system doesn't pass the test, but it could also mean that the system has a
-- bug that prevents this trick from working, so take care.
--
-- The current trick is: Create a canister (the "stopper"). Make it its own
-- controller. Tell the canister to stop itself. This call will now hang,
-- because a canister cannot stop itself. We can release the call (producing a
-- reject) by starting the canister again.
--
-- Returns a program to be executed by any canister, which will cause this
-- canister to send a message that will not be responded to, until the given
-- IO action is performed.
createMessageHold :: (HasAgentConfig) => Blob -> IO (Prog, IO ())
createMessageHold ecid = do
  cid <- install ecid noop
  ic_set_controllers ic00 cid [defaultUser, cid]
  let holdMessage =
        inter_update
          cid
          defArgs
            { other_side =
                callNew "" "stop_canister" (callback (trap "createMessageHold: stopping succeeded?")) (callback reply)
                  >>> callDataAppend (bytes (Candid.encode (#canister_id .== Principal cid)))
                  >>> callPerform,
              on_reply = reply
            }
  let release = ic_start_canister ic00 cid
  return (holdMessage, release)

vec_header_from_list_text :: [(T.Text, T.Text)] -> Vec.Vector HttpHeader
vec_header_from_list_text = Vec.fromList . map aux
  where
    aux (a, b) = empty .+ #name .== a .+ #value .== b

dummyResponse :: HttpResponse
dummyResponse =
  R.empty
    .+ #status
    .== 202
    .+ #headers
    .== vec_header_from_list_text [(T.pack "Content-Length", T.pack $ show $ length s)]
    .+ #body
    .== (toUtf8 $ T.pack s)
  where
    s = "Dummy!" :: String

bodyOfSize :: W.Word32 -> BS.ByteString
bodyOfSize n = toUtf8 $ T.pack $ take (fromIntegral n) $ repeat 'x'

-- maximum body size of HTTP response with status 200 and no headers such that the length of its Candid encoding does not exceed max_response_bytes_limit
maximumSizeResponseBodySize :: W.Word32
maximumSizeResponseBodySize = 1999950
