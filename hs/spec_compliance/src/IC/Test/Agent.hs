{-# LANGUAGE BlockArguments #-}
{-# LANGUAGE ConstraintKinds #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE ImplicitParams #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE NumericUnderscores #-}
{-# LANGUAGE OverloadedLabels #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE TypeOperators #-}

-- |
--
-- This module contains function to interact with an Internet Computer instance.
--
-- The primary customer here is IC.Test.Spec, i.e the test suite. Therefore, the
-- functions here give access to various levels of abstractions, and gives more control
-- than a “normal” agent library would do.
--
-- Also, because of the focus on testing, failures are repoted directly with HUnit’s 'assertFailure'.
--
-- As guidance: This modules does _not_ rely on the universal canister.
module IC.Test.Agent
  ( HTTPErrOr,
    HasAgentConfig,
    IC00,
    IC00WithCycles,
    IC00',
    ReqResponse (..),
    ReqStatus (..),
    NodeSignature (..),
    QueryResponse (..),
    AgentConfig (..),
    DelegationCanisterRangeCheck (..),
    addExpiry,
    addNonce,
    addNonceExpiryEnv,
    anonymousUser,
    as2Word64,
    asWord64Word128,
    asHex,
    asRight,
    asWord128,
    asWord32,
    asWord64,
    awaitCall',
    awaitCall,
    awaitKnown,
    awaitStatus,
    bothSame,
    callResponse,
    certValue,
    certValueAbsent,
    code202,
    code202_or_4xx,
    code2xx,
    code4xx,
    code403,
    decodeCert',
    defaultSK,
    defaultUser,
    delegationEnv,
    doesn'tExist,
    ecdsaSK,
    ecdsaUser,
    enum,
    enumNothing,
    envelope,
    envelopeFor,
    extractCertData,
    getRequestStatus',
    getRequestStatus,
    getStateCert',
    getStateCert,
    ic00,
    ic00as,
    ic00',
    ic00WithSubnetas',
    ingressDelay,
    is2xx,
    isErr4xx,
    isErrOrReject,
    isNoErrReject,
    isPendingOrProcessing,
    isReject,
    isQueryReject,
    isReply,
    isQueryReply,
    isResponded,
    okCBOR,
    otherSK,
    otherUser,
    makeAgentConfig,
    postCBOR,
    postCallCBOR,
    postQueryCBOR,
    postReadStateCBOR,
    preFlight,
    queryCBOR,
    queryResponse,
    runGet,
    secp256k1SK,
    secp256k1User,
    senderOf,
    shorten,
    submitCall,
    textual,
    validateStateCert,
    waitFor,
    webAuthnECDSASK,
    webAuthnECDSAUser,
    webAuthnRSASK,
    webAuthnRSAUser,
    withAgentConfig,
    -- TODO: these are needed by IC.Test.Agent.Calls. Consider moving them to an Internal module
    callIC,
    callIC',
    callIC'',
    callICWithSubnet'',
    callIC''',
    agentConfig,
  )
where

import Codec.Candid (Principal (..), prettyPrincipal)
import qualified Codec.Candid as Candid
import Control.Concurrent
import Control.Exception (Exception, catch, throw)
import Control.Monad
import Control.Monad.Except
import qualified Data.Binary as Get
import qualified Data.Binary.Get as Get
import qualified Data.ByteString as B
import qualified Data.ByteString.Builder as BS
import qualified Data.ByteString.Lazy as BS
import Data.Char
import Data.Default.Class (def)
import qualified Data.HashMap.Lazy as HM
import Data.List (find, nub)
import Data.Maybe (fromJust)
import Data.Row
import qualified Data.Row.Variants as V
import qualified Data.Text as T
import qualified Data.Text.Encoding as T
import qualified Data.Text.Encoding.Error as T
import Data.Time.Clock
import Data.Time.Clock.POSIX
import Data.Traversable
import Data.WideWord.Word128
import Data.Word
import qualified Data.Word as W
import qualified Data.X509.CertificateStore as C
import qualified Data.X509.Validation as C
import GHC.TypeLits
import IC.Certificate
import IC.Certificate.CBOR
import IC.Certificate.Value
import IC.Crypto
import qualified IC.Crypto.DER as DER
import qualified IC.Crypto.DER_BLS as DER_BLS
import qualified IC.Crypto.Ed25519 as Ed25519
import IC.HTTP.CBOR (decode, encode)
import IC.HTTP.GenR
import IC.HTTP.GenR.Parse
import IC.HTTP.RequestId
import IC.HashTree hiding (Blob, Label)
import IC.Id.Forms
import IC.Id.Fresh
import IC.Management
import IC.Test.Options
import IC.Types (rawEntityId)
import IC.Version
import Network.Connection
import Network.HTTP.Client
import Network.HTTP.Client.TLS
import Network.HTTP.Types
import Network.TLS
import Network.TLS.Extra.Cipher
import Numeric.Natural
import System.Exit
import System.Random
import System.Timeout
import Test.Tasty.HUnit
import Test.Tasty.Options
import qualified Text.Hex as H

-- * Exceptions

data DelegationCanisterRangeCheck = DelegationCanisterRangeCheck [(Blob, Blob)] Blob
  deriving (Show, Exception)

-- * CBOR decoding

asCBORBlobPairList :: Blob -> IO [(Blob, Blob)]
asCBORBlobPairList blob = do
  decoded <- asRight $ decode blob
  case decoded of
    GList list -> do
      mapM cborToBlobPair list
    _ -> assertFailure $ "Failed to decode as CBOR encoded list of blob pairs: " <> show decoded

cborToBlobPair :: GenR -> IO (Blob, Blob)
cborToBlobPair (GList [GBlob x, GBlob y]) = return (x, y)
cborToBlobPair r = assertFailure $ "Expected list of pairs, got: " <> show r

-- * Agent configuration

data AgentSubnetConfig = AgentSubnetConfig
  { tc_subnet_id :: Blob,
    tc_node_addresses :: [String],
    tc_canister_ranges :: [(W.Word64, W.Word64)]
  }

data AgentConfig = AgentConfig
  { tc_root_key :: Blob,
    tc_manager :: Manager,
    tc_endPoint :: String,
    tc_subnets :: [AgentSubnetConfig],
    tc_httpbin_proto :: String,
    tc_httpbin :: String,
    tc_timeout :: Int
  }

makeAgentConfig :: Bool -> String -> [AgentSubnetConfig] -> String -> String -> Int -> IO AgentConfig
makeAgentConfig allow_self_signed_certs ep' subnets httpbin_proto httpbin' to = do
  let validate = \ca_store -> if allow_self_signed_certs then \_ _ _ -> return [] else C.validateDefault (C.makeCertificateStore $ (C.listCertificates ca_store))
  let client_params =
        (defaultParamsClient "" B.empty)
          { clientHooks = def {onServerCertificate = validate},
            clientSupported = def {supportedCiphers = ciphersuite_default}
          }
  let manager_settings = mkManagerSettings (TLSSettings client_params) Nothing
  manager <-
    newTlsManagerWith $
      manager_settings
        { managerResponseTimeout = responseTimeoutMicro 300_000_000 -- 300s
        }
  request <- parseRequest $ ep ++ "/api/v2/status"
  putStrLn $ "Fetching endpoint status from " ++ show ep ++ "..."
  s <-
    (httpLbs request manager >>= okCBOR >>= statusResponse)
      `catch` (\(HUnitFailure _ r) -> putStrLn r >> exitFailure)

  putStrLn $ "Spec version tested:  " ++ T.unpack specVersion
  putStrLn $ "Spec version claimed: " ++ T.unpack (status_api_version s)

  return
    AgentConfig
      { tc_root_key = status_root_key s,
        tc_manager = manager,
        tc_endPoint = ep,
        tc_subnets = subnets,
        tc_httpbin_proto = httpbin_proto,
        tc_httpbin = httpbin,
        tc_timeout = to
      }
  where
    -- strip trailing slash
    ep = fixUrl "endpoint" ep'
    httpbin = fixUrl "httpbin" httpbin'

fixUrl :: String -> String -> String
fixUrl msg x
  | null x = error $ "empty " ++ msg
  | last x == '/' = init x
  | otherwise = x

preFlight :: OptionSet -> IO AgentConfig
preFlight os = do
  let Endpoint ep = lookupOption os
  let HttpbinProto httpbin_proto = lookupOption os
  let Httpbin httpbin = lookupOption os
  let PollTimeout to = lookupOption os
  let AllowSelfSignedCerts allow_self_signed_certs = lookupOption os
  let TestSubnet (test_id, _, _, test_ranges, test_nodes) = lookupOption os
  let test_agent_subnet_config = AgentSubnetConfig (rawEntityId test_id) (map (fixUrl "node") test_nodes) test_ranges
  let PeerSubnet (peer_id, _, _, peer_ranges, peer_nodes) = lookupOption os
  let peer_agent_subnet_config = AgentSubnetConfig (rawEntityId peer_id) (map (fixUrl "node") peer_nodes) peer_ranges
  makeAgentConfig allow_self_signed_certs ep [test_agent_subnet_config, peer_agent_subnet_config] httpbin_proto httpbin to

-- Yes, implicit arguments are frowned upon. But they are also very useful.

type HasAgentConfig = (?agentConfig :: AgentConfig)

withAgentConfig :: (forall. (HasAgentConfig) => a) -> AgentConfig -> a
withAgentConfig act tc = let ?agentConfig = tc in act

agentConfig :: (HasAgentConfig) => AgentConfig
agentConfig = ?agentConfig

endPoint :: (HasAgentConfig) => String
endPoint = tc_endPoint agentConfig

subnets :: (HasAgentConfig) => [AgentSubnetConfig]
subnets = tc_subnets agentConfig

root_subnet :: (HasAgentConfig) => AgentSubnetConfig
root_subnet = fromJust $ find (any (\(a, b) -> wordToId' a <= wordToId' 0 && wordToId' 0 <= wordToId' b) . tc_canister_ranges) subnets

agentManager :: (HasAgentConfig) => Manager
agentManager = tc_manager agentConfig

-- * Test data for some hardcoded user names

doesn'tExist :: Blob
doesn'tExist = "\xDE\xAD\xBE\xEF" -- hopefully no such canister/user exists

defaultSK :: SecretKey
defaultSK = createSecretKeyEd25519 "fixed32byteseedfortesting"

otherSK :: SecretKey
otherSK = createSecretKeyEd25519 "anotherfixed32byteseedfortesting"

webAuthnECDSASK :: SecretKey
webAuthnECDSASK = createSecretKeyWebAuthnECDSA "webauthnseed"

webAuthnRSASK :: SecretKey
webAuthnRSASK = createSecretKeyWebAuthnRSA "webauthnseed"

ecdsaSK :: SecretKey
ecdsaSK = createSecretKeyECDSA "ecdsaseed"

secp256k1SK :: SecretKey
secp256k1SK = createSecretKeySecp256k1 "secp256k1seed"

defaultUser :: Blob
defaultUser = mkSelfAuthenticatingId $ toPublicKey defaultSK

otherUser :: Blob
otherUser = mkSelfAuthenticatingId $ toPublicKey otherSK

webAuthnECDSAUser :: Blob
webAuthnECDSAUser = mkSelfAuthenticatingId $ toPublicKey webAuthnECDSASK

webAuthnRSAUser :: Blob
webAuthnRSAUser = mkSelfAuthenticatingId $ toPublicKey webAuthnRSASK

ecdsaUser :: Blob
ecdsaUser = mkSelfAuthenticatingId $ toPublicKey ecdsaSK

secp256k1User :: Blob
secp256k1User = mkSelfAuthenticatingId $ toPublicKey secp256k1SK

anonymousUser :: Blob
anonymousUser = "\x04"

-- * Request envelopes

addIfNotThere :: (Monad m) => T.Text -> m GenR -> GenR -> m GenR
addIfNotThere f _ (GRec hm) | f `HM.member` hm = return (GRec hm)
addIfNotThere f a (GRec hm) = do
  x <- a
  return $ GRec $ HM.insert f x hm
addIfNotThere _ _ _ = error "addIfNotThere: not a record"

addNonce :: GenR -> IO GenR
addNonce =
  addIfNotThere "nonce" $
    GBlob <$> getRand8Bytes

getRand8Bytes :: IO BS.ByteString
getRand8Bytes = BS.pack <$> replicateM 8 randomIO

-- Adds expiry 5 minutes
addExpiry :: GenR -> IO GenR
addExpiry = addIfNotThere "ingress_expiry" $ do
  t <- getPOSIXTime
  return $ GNat $ round ((t + 60 * 5) * 1000_000_000)

envelope :: SecretKey -> GenR -> IO GenR
envelope sk = delegationEnv sk []

delegationEnv :: SecretKey -> [(SecretKey, Maybe [Blob])] -> GenR -> IO GenR
delegationEnv sk1 dels content = do
  let sks = sk1 : map fst dels

  t <- getPOSIXTime
  let expiry = round ((t + 5 * 60) * 1000_000_000)
  delegations <- for (zip sks dels) $ \(sk1, (sk2, targets)) -> do
    let delegation =
          rec $
            [ "pubkey" =: GBlob (toPublicKey sk2),
              "expiration" =: GNat expiry
            ]
              ++ ["targets" =: GList (map GBlob ts) | Just ts <- pure targets]
    sig <- sign "ic-request-auth-delegation" sk1 (requestId delegation)
    return $ rec ["delegation" =: delegation, "signature" =: GBlob sig]
  sig <- sign "ic-request" (last sks) (requestId content)
  return $
    rec $
      [ "sender_pubkey" =: GBlob (toPublicKey sk1),
        "sender_sig" =: GBlob sig,
        "content" =: content
      ]
        ++ ["sender_delegation" =: GList delegations | not (null delegations)]

-- a little bit of smartness in our combinators: Adding correct envelope, nonce
-- and expiry if it is not already there

senderOf :: GenR -> Blob
senderOf (GRec hm) | Just (GBlob id) <- HM.lookup "sender" hm = id
senderOf _ = anonymousUser

addNonceExpiryEnv' :: GenR -> IO (Blob, GenR)
addNonceExpiryEnv' req = do
  req <- addNonce req >>= addExpiry
  env <- envelopeFor (senderOf req) req
  return (requestId req, env)

addNonceExpiryEnv :: GenR -> IO GenR
addNonceExpiryEnv req = do
  (_, req) <- addNonceExpiryEnv' req
  return req

envelopeFor :: Blob -> GenR -> IO GenR
envelopeFor u content | u == anonymousUser = return $ rec ["content" =: content]
envelopeFor u content = envelope key content
  where
    key :: SecretKey
    key
      | u == defaultUser = defaultSK
      | u == otherUser = otherSK
      | u == webAuthnECDSAUser = webAuthnECDSASK
      | u == webAuthnRSAUser = webAuthnRSASK
      | u == ecdsaUser = ecdsaSK
      | u == secp256k1User = secp256k1SK
      | u == anonymousUser = error "No key for the anonymous user"
      | otherwise = error $ "Don't know key for user " ++ show u

-- * HUnit error reporting integration

asRight :: (HasCallStack) => Either T.Text a -> IO a
asRight (Left err) = assertFailure (T.unpack err)
asRight (Right gr) = return gr

asExceptT :: (HasCallStack) => ExceptT T.Text IO a -> IO a
asExceptT act = runExceptT act >>= asRight

-- * Requests

-- | Posting a CBOR request, returning a raw bytestring
postCBOR' :: (HasCallStack, HasAgentConfig) => String -> String -> GenR -> IO (Response BS.ByteString)
postCBOR' ep path gr = do
  request <- parseRequest $ ep ++ path
  request <-
    return $
      request
        { method = "POST",
          requestBody = RequestBodyLBS $ BS.toLazyByteString $ encode gr,
          requestHeaders = [(hContentType, "application/cbor")]
        }
  waitFor $ do
    res <- httpLbs request agentManager
    if responseStatus res == tooManyRequests429
      then return Nothing
      else return $ Just res

-- | postCBOR with url based on effective canister id
postCBOR :: (HasCallStack, HasAgentConfig) => String -> GenR -> IO (Response BS.ByteString)
postCBOR = postCBOR' endPoint

postReadStateCBOR' :: (HasCallStack, HasAgentConfig) => String -> Blob -> GenR -> IO (Response BS.ByteString)
postReadStateCBOR' ep cid = postCBOR' ep $ "/api/v2/canister/" ++ textual cid ++ "/read_state"

postCallCBOR, postQueryCBOR, postReadStateCBOR :: (HasCallStack, HasAgentConfig) => Blob -> GenR -> IO (Response BS.ByteString)
postCallCBOR cid = (\r -> sync_height cid >> postCBOR ("/api/v2/canister/" ++ textual cid ++ "/call") r)
postQueryCBOR cid = (\r -> sync_height cid >> postCBOR ("/api/v2/canister/" ++ textual cid ++ "/query") r)
postReadStateCBOR cid = (\r -> sync_height cid >> postReadStateCBOR' endPoint cid r)

waitFor :: (HasAgentConfig) => IO (Maybe a) -> IO a
waitFor act = do
  result <- timeout (tc_timeout agentConfig * (10 :: Int) ^ (6 :: Int)) doActUntil
  case result of
    Nothing -> assertFailure "Polling timed out"
    Just r -> return r
  where
    doActUntil = do
      res <- act
      case res of
        Nothing -> (threadDelay 1000 *> doActUntil)
        Just r -> return r

sync_height :: (HasAgentConfig) => Blob -> IO [()]
sync_height cid = forM subnets $ \sub -> do
  let ranges = map (\(a, b) -> (wordToId' a, wordToId' b)) (tc_canister_ranges sub)
  when (any (\(a, b) -> a <= cid && cid <= b) ranges) $ do
    hs <- get_heights (tc_node_addresses sub)
    unless (length (nub hs) <= 1) $
      let h = maximum hs
       in waitFor $ do
            hs <- get_heights (tc_node_addresses sub)
            if h <= minimum hs then return (Just ()) else return Nothing
  where
    get_heights ns =
      mapM
        ( \n -> do
            Right cert <- getStateCert'' n defaultUser cid [["time"]]
            certValue @Natural cert ["time"]
        )
        ns

-- | Add envelope to CBOR request, add a nonce and expiry if it is not there,
-- post to "read", return decoded CBOR
queryCBOR :: (HasCallStack, HasAgentConfig) => Blob -> GenR -> IO (Blob, GenR)
queryCBOR cid req = do
  (rid, req) <- addNonceExpiryEnv' req
  res <- postQueryCBOR cid req >>= okCBOR
  return (rid, res)

type HTTPErrOr a = Either (Int, String) a

-- | Add envelope to CBOR, and a nonce and expiry if not there, post to
-- "submit". Returns either a HTTP Error code, or if the status is 2xx, the
-- request id.
submitCall' :: (HasCallStack, HasAgentConfig) => Blob -> GenR -> IO (HTTPErrOr (IO (HTTPErrOr ReqStatus)))
submitCall' cid req = do
  req <- addNonce req
  req <- addExpiry req
  res <- envelopeFor (senderOf req) req >>= postCallCBOR cid
  let code = statusCode (responseStatus res)
  if 200 <= code && code < 300
    then do
      if BS.null (responseBody res)
        then pure $ Right (getRequestStatus' (senderOf req) cid (requestId req))
        else do
          resp <- (asRight $ decode $ responseBody res) >>= callResponse
          pure $ Right (return $ Right $ Responded resp)
    else do
      let msg = T.unpack (T.decodeUtf8With T.lenientDecode (BS.toStrict (BS.take 1000 (responseBody res))))
      pure $ Left (code, msg)

submitCall :: (HasCallStack, HasAgentConfig) => Blob -> GenR -> IO (IO (HTTPErrOr ReqStatus))
submitCall cid req = submitCall' cid req >>= is2xx

-- | Add envelope to CBOR, and a nonce and expiry if not there, post to
-- "submit". Returns either a HTTP Error code, or if the status is 2xx, poll
-- for the request response, and return decoded CBOR
awaitCall' :: (HasCallStack, HasAgentConfig) => Blob -> GenR -> IO (HTTPErrOr ReqResponse)
awaitCall' cid req = do
  submitCall' cid req >>= \case
    Left e -> pure (Left e)
    Right getStatus -> awaitStatus' getStatus

-- | Add envelope to CBOR, and a nonce and expiry if not there, post to
-- "submit", poll for the request response, and return decoded CBOR
awaitCall :: (HasCallStack, HasAgentConfig) => Blob -> GenR -> IO ReqResponse
awaitCall cid req = awaitCall' cid req >>= is2xx

is2xx :: (HasCallStack) => HTTPErrOr a -> IO a
is2xx = \case
  Left (c, msg) -> assertFailure $ "Status " ++ show c ++ " is not 2xx:\n" ++ msg
  Right res -> pure res

getStateCert' :: (HasCallStack, HasAgentConfig) => Blob -> Blob -> [[Blob]] -> IO (HTTPErrOr Certificate)
getStateCert' sender ecid paths = do
  void $ sync_height ecid
  getStateCert'' endPoint sender ecid paths

decodeCert' :: (HasCallStack) => Blob -> IO Certificate
decodeCert' b = either (assertFailure . T.unpack) return $ decodeCert b

getStateCert'' :: (HasCallStack, HasAgentConfig) => String -> Blob -> Blob -> [[Blob]] -> IO (HTTPErrOr Certificate)
getStateCert'' ep sender ecid paths = do
  req <-
    addExpiry $
      rec
        [ "request_type" =: GText "read_state",
          "sender" =: GBlob sender,
          "paths" =: GList (map (GList . map GBlob) paths)
        ]
  response <- envelopeFor (senderOf req) req >>= postReadStateCBOR' ep ecid
  let c = statusCode (responseStatus response)
  if not (200 <= c && c < 300)
    then return $ Left (c, "Read_state request failed.")
    else do
      gr <- okCBOR response
      b <- asExceptT $ record (field blob "certificate") gr
      cert <- decodeCert' b
      validateStateCert ecid cert

      case wellFormed (cert_tree cert) of
        Left err -> assertFailure $ "Hash tree not well formed: " ++ err
        Right () -> return ()

      return $ Right cert

getStateCert :: (HasCallStack, HasAgentConfig) => Blob -> Blob -> [[Blob]] -> IO Certificate
getStateCert sender ecid paths = getStateCert' sender ecid paths >>= is2xx

extractCertData :: Blob -> Blob -> IO Blob
extractCertData cid b = do
  cert <- decodeCert' b
  case wellFormed (cert_tree cert) of
    Left err -> assertFailure $ "Hash tree not well formed: " ++ err
    Right () -> return ()
  certValue cert ["canister", cid, "certified_data"]

verboseVerify :: String -> Blob -> Blob -> Blob -> Blob -> IO ()
verboseVerify what domain_sep pk msg sig =
  case DER_BLS.verify domain_sep pk msg sig of
    Left err ->
      assertFailure $
        unlines
          [ "Signature verification failed on " ++ what,
            T.unpack err,
            "Domain separator:   " ++ prettyBlob domain_sep,
            "Public key (DER):   " ++ asHex pk,
            "Public key decoded: "
              ++ case DER.decode pk of
                Left err -> T.unpack err
                Right (suite, key) -> asHex key ++ " (" ++ show suite ++ ")",
            "Signature:          " ++ asHex sig,
            "Checked message:    " ++ prettyBlob msg
          ]
    Right () -> return ()

validateDelegation :: (HasCallStack, HasAgentConfig) => Blob -> Maybe Delegation -> IO Blob
validateDelegation _ Nothing = return (tc_root_key agentConfig)
validateDelegation cid (Just del) = do
  cert <- decodeCert' (del_certificate del)
  case wellFormed (cert_tree cert) of
    Left err -> assertFailure $ "Hash tree not well formed: " ++ err
    Right () -> return ()
  validateStateCert' "certificate delegation" cid cert

  ranges <- certValue @Blob cert ["subnet", del_subnet_id del, "canister_ranges"] >>= asCBORBlobPairList
  unless (checkCanisterIdInRanges' ranges cid) $ throw (DelegationCanisterRangeCheck ranges cid)

  certValue cert ["subnet", del_subnet_id del, "public_key"]

validateStateCert' :: (HasCallStack, HasAgentConfig) => String -> Blob -> Certificate -> IO ()
validateStateCert' what cid cert = do
  pk <- validateDelegation cid (cert_delegation cert)
  verboseVerify what "ic-state-root" pk (reconstruct (cert_tree cert)) (cert_sig cert)

validateStateCert :: (HasCallStack, HasAgentConfig) => Blob -> Certificate -> IO ()
validateStateCert = validateStateCert' "certificate"

data ReqResponse = Reply Blob | Reject Natural T.Text (Maybe T.Text)
  deriving (Eq, Show)

data ReqStatus = Processing | Pending | Responded ReqResponse | UnknownStatus
  deriving (Eq, Show)

data NodeSignature = NodeSignature {node_sig_timestamp :: Natural, node_sig_signature :: Blob, node_sig_identity :: Blob}
  deriving (Eq, Show)

data QueryResponse = QueryReply Blob [NodeSignature] | QueryReject Natural T.Text (Maybe T.Text) [NodeSignature]
  deriving (Eq, Show)

prettyPath :: [Blob] -> String
prettyPath = concatMap (("/" ++) . shorten 15 . prettyBlob)

prettyBlob :: Blob -> String
prettyBlob x =
  let s = map (chr . fromIntegral) (BS.unpack x)
   in if all isPrint s then s else asHex x

maybeCertValue :: (HasCallStack) => (CertVal a) => Certificate -> [Blob] -> IO (Maybe a)
maybeCertValue cert path = case lookupPath (cert_tree cert) path of
  Found b -> case fromCertVal b of
    Just x -> return (Just x)
    Nothing -> assertFailure $ "Cannot parse " ++ prettyPath path ++ " from " ++ show b
  Absent -> return Nothing
  x -> assertFailure $ "Expected to find " ++ prettyPath path ++ ", but got " ++ show x

certValue :: (HasCallStack) => (CertVal a) => Certificate -> [Blob] -> IO a
certValue cert path = case lookupPath (cert_tree cert) path of
  Found b -> case fromCertVal b of
    Just x -> return x
    Nothing -> assertFailure $ "Cannot parse " ++ prettyPath path ++ " from " ++ show b
  x -> assertFailure $ "Expected to find " ++ prettyPath path ++ ", but got " ++ show x

certValueAbsent :: (HasCallStack) => Certificate -> [Blob] -> IO ()
certValueAbsent cert path = case lookupPath (cert_tree cert) path of
  Absent -> return ()
  x -> assertFailure $ "Path " ++ prettyPath path ++ " should be absent, but got " ++ show x

getRequestStatus' :: (HasCallStack, HasAgentConfig) => Blob -> Blob -> Blob -> IO (HTTPErrOr ReqStatus)
getRequestStatus' sender cid rid = do
  response <- getStateCert' sender cid [["request_status", rid]]
  case response of
    Left x -> return $ Left x
    Right cert -> do
      case lookupPath (cert_tree cert) ["request_status", rid, "status"] of
        Absent -> return $ Right UnknownStatus
        Found "processing" -> return $ Right Processing
        Found "received" -> return $ Right Pending
        Found "replied" -> do
          b <- certValue cert ["request_status", rid, "reply"]
          certValueAbsent cert ["request_status", rid, "reject_code"]
          certValueAbsent cert ["request_status", rid, "reject_message"]
          return $ Right $ Responded (Reply b)
        Found "rejected" -> do
          certValueAbsent cert ["request_status", rid, "reply"]
          code <- certValue cert ["request_status", rid, "reject_code"]
          msg <- certValue cert ["request_status", rid, "reject_message"]
          errorCode <- maybeCertValue cert ["request_status", rid, "error_code"]
          return $ Right $ Responded (Reject code msg errorCode)
        Found s -> assertFailure $ "Unexpected status " ++ show s
        -- This case should not happen with a compliant IC, but let
        -- us be liberal here, and strict in a dedicated test
        Unknown -> return $ Right UnknownStatus
        x -> assertFailure $ "Unexpected request status, got " ++ show x

getRequestStatus :: (HasCallStack, HasAgentConfig) => Blob -> Blob -> Blob -> IO ReqStatus
getRequestStatus sender cid rid = getRequestStatus' sender cid rid >>= is2xx

isResponded :: ReqStatus -> Assertion
isResponded (Responded _) = return ()
isResponded _ = assertFailure "Request must be responded"

loop' :: (HasCallStack, HasAgentConfig) => IO (HTTPErrOr (Maybe a)) -> IO (HTTPErrOr a)
loop' act = getCurrentTime >>= go
  where
    go init =
      act >>= \case
        Left x -> return $ Left x
        Right (Just r) -> return $ Right r
        Right Nothing -> do
          now <- getCurrentTime
          if diffUTCTime now init > fromIntegral (tc_timeout agentConfig)
            then assertFailure "Polling timed out"
            else go init

awaitStatus' :: (HasAgentConfig) => IO (HTTPErrOr ReqStatus) -> IO (HTTPErrOr ReqResponse)
awaitStatus' get_status =
  loop' $
    pollDelay >> get_status >>= \case
      Left x -> return $ Left x
      Right (Responded x) -> return $ Right $ Just x
      _ -> return $ Right Nothing

awaitStatus :: (HasAgentConfig) => IO (HTTPErrOr ReqStatus) -> IO ReqResponse
awaitStatus get_status = awaitStatus' get_status >>= is2xx

-- Polls until status is not Unknown any more, and returns that status
-- even if Pending or Processing
awaitKnown' :: (HasAgentConfig) => IO (HTTPErrOr ReqStatus) -> IO (HTTPErrOr ReqStatus)
awaitKnown' get_status =
  loop' $
    pollDelay >> get_status >>= \case
      Left x -> return $ Left x
      Right UnknownStatus -> return $ Right Nothing
      Right x -> return $ Right $ Just x

awaitKnown :: (HasAgentConfig) => IO (HTTPErrOr ReqStatus) -> IO ReqStatus
awaitKnown get_status = awaitKnown' get_status >>= is2xx

isPendingOrProcessing :: ReqStatus -> IO ()
isPendingOrProcessing Pending = return ()
isPendingOrProcessing Processing = return ()
isPendingOrProcessing r = assertFailure $ "Expected pending or processing, got " <> show r

pollDelay :: IO ()
pollDelay = threadDelay $ 10 * 1000 -- 10 milliseconds

-- How long to wait before checking if a request that should _not_ show up on
-- the system indeed did not show up
ingressDelay :: IO ()
ingressDelay = threadDelay $ 2 * 1000 * 1000 -- 2 seconds

-- * HTTP Response predicates

codePred :: (HasCallStack) => String -> (Int -> Bool) -> Response Blob -> IO ()
codePred expt pred response =
  assertBool
    ("Status " ++ show c ++ " is not " ++ expt ++ "\n" ++ msg)
    (pred c)
  where
    c = statusCode (responseStatus response)
    msg = T.unpack (T.decodeUtf8With T.lenientDecode (BS.toStrict (BS.take 1000 (responseBody response))))

code2xx, code202, code4xx, code202_or_4xx :: (HasCallStack) => Response BS.ByteString -> IO ()
code2xx = codePred "2xx" $ \c -> 200 <= c && c < 300
code202 = codePred "202" $ \c -> c == 202
code4xx = codePred "4xx" $ \c -> 400 <= c && c < 500

code403 = codePred "403" $ \c -> c == 403

code202_or_4xx = codePred "202 or 4xx" $ \c -> c == 202 || 400 <= c && c < 500

-- * CBOR decoding

okCBOR :: (HasCallStack) => Response BS.ByteString -> IO GenR
okCBOR response = do
  code2xx response
  asRight $ decode $ responseBody response

-- * Response predicates and parsers

callResponse :: GenR -> IO ReqResponse
callResponse =
  asExceptT . record do
    code <- field nat "reject_code"
    msg <- field text "reject_message"
    error_code <- optionalField text "error_code"
    return $ Reject code msg error_code

queryResponse :: GenR -> IO QueryResponse
queryResponse =
  asExceptT . record do
    s <- field text "status"
    case s of
      "replied" -> do
        reply <- field (record (field blob "arg")) "reply"
        signatures <- field (listOf parseNodeSignature) "signatures"
        return $ QueryReply reply signatures
      "rejected" -> do
        code <- field nat "reject_code"
        msg <- field text "reject_message"
        error_code <- optionalField text "error_code"
        signatures <- field (listOf parseNodeSignature) "signatures"
        return $ QueryReject code msg error_code signatures
      _ -> throwError $ "Unexpected status " <> T.pack (show s)
  where
    parseNodeSignature :: Field NodeSignature
    parseNodeSignature = record $ do
      t <- field nat "timestamp"
      s <- field blob "signature"
      n <- field blob "identity"
      return $ NodeSignature t s n

isReject :: (HasCallStack) => [Natural] -> ReqResponse -> IO ()
isReject _ (Reply r) =
  assertFailure $ "Expected reject, got reply:" ++ prettyBlob r
isReject codes (Reject n msg _) = do
  assertBool
    ("Reject code " ++ show n ++ " not in " ++ show codes ++ "\n" ++ T.unpack msg)
    (n `elem` codes)

assertLen :: String -> Int -> BS.ByteString -> IO ()
assertLen what len bs
  | BS.length bs == fromIntegral len = return ()
  | otherwise = assertFailure $ what ++ " has wrong length " ++ show (BS.length bs) ++ ", expected " ++ show len

checkQueryResponse :: (HasCallStack, HasAgentConfig) => Blob -> Blob -> QueryResponse -> IO ()
checkQueryResponse cid rid r = do
  cert <- getStateCert defaultUser cid [["subnet"]]
  (subnet_id, ranges) <-
    case cert_delegation cert of
      Just d -> do
        let subnet_id = del_subnet_id d
        del_cert <- decodeCert' $ del_certificate d
        ranges <- certValue @Blob del_cert ["subnet", subnet_id, "canister_ranges"] >>= asCBORBlobPairList
        return (subnet_id, ranges)
      Nothing -> do
        let subnet_id = tc_subnet_id root_subnet
        ranges <- certValue @Blob cert ["subnet", subnet_id, "canister_ranges"] >>= asCBORBlobPairList
        return (subnet_id, ranges)
  unless (checkCanisterIdInRanges' ranges cid) $ assertFailure $ "Canister range check failed"
  let sigs = case r of
        QueryReply _ sigs -> sigs
        QueryReject _ _ _ sigs -> sigs
  void $ forM sigs $ \sig -> case sig of
    NodeSignature t s n -> do
      der_pk <- certValue @Blob cert ["subnet", subnet_id, "node", n, "public_key"]
      pk <- case DER.decode der_pk of
        Left err -> assertFailure $ "Node public key is not DER-encoded: " ++ show err
        Right (suite, pk) -> do
          assertBool "Node public key is not Ed25519" $ case suite of
            DER.Ed25519 -> True
            _ -> False
          return pk
      let hash = case r of
            QueryReply payload _ ->
              requestId $
                rec
                  [ "status" =: GText "replied",
                    "reply" =: rec ["arg" =: GBlob payload],
                    "timestamp" =: GNat t,
                    "request_id" =: GBlob rid
                  ]
            QueryReject code msg error_code _ -> do
              requestId $
                rec $
                  [ "status" =: GText "rejected",
                    "reject_code" =: GNat code,
                    "reject_message" =: GText msg,
                    "timestamp" =: GNat t,
                    "request_id" =: GBlob rid
                  ]
                    ++ ["error_code" =: GText err | Just err <- [error_code]]
      let msg = "\x0Bic-response" <> hash
      assertLen "Ed25519 public key length" 32 pk
      assertLen "Ed25519 signature length" 64 s
      assertBool "Node signature verification failed" $ Ed25519.verify pk msg s
      return ()

isQueryReject :: (HasCallStack, HasAgentConfig) => Blob -> [Natural] -> (Blob, QueryResponse) -> IO ()
isQueryReject cid codes (rid, r) = do
  checkQueryResponse cid rid r
  aux r
  where
    aux (QueryReply r _) =
      assertFailure $ "Expected reject, got reply:" ++ prettyBlob r
    aux (QueryReject n msg _ sigs) = do
      assertBool ("Number of signatures " ++ show (length sigs) ++ "is not equal to one") (length sigs == 1)
      assertBool
        ("Reject code " ++ show n ++ " not in " ++ show codes ++ "\n" ++ T.unpack msg)
        (n `elem` codes)

isErr4xx :: (HasCallStack) => HTTPErrOr a -> IO ()
isErr4xx (Left (c, msg))
  | 400 <= c && c < 500 = return ()
  | otherwise =
      assertFailure $
        "Status " ++ show c ++ " is not 4xx:\n" ++ msg
isErr4xx (Right _) = assertFailure "Got HTTP response, expected HTTP error"

isErrOrReject :: (HasCallStack) => [Natural] -> HTTPErrOr ReqResponse -> IO ()
isErrOrReject _codes (Left (c, msg))
  | 400 <= c && c < 600 = return ()
  | otherwise =
      assertFailure $
        "Status " ++ show c ++ " is not 4xx or 5xx:\n" ++ msg
isErrOrReject [] (Right _) = assertFailure "Got HTTP response, expected HTTP error"
isErrOrReject codes (Right res) = isReject codes res

isNoErrReject :: (HasCallStack) => [Natural] -> HTTPErrOr ReqResponse -> IO ()
isNoErrReject _ (Left (c, msg)) = assertFailure $ "Expected reject, got HTTP status " ++ show c ++ ": " ++ msg
isNoErrReject _ (Right (Reply r)) =
  assertFailure $ "Expected reject, got reply:" ++ prettyBlob r
isNoErrReject codes (Right (Reject n msg _)) = do
  assertBool
    ("Reject code " ++ show n ++ " not in " ++ show codes ++ "\n" ++ T.unpack msg)
    (n `elem` codes)

isReply :: (HasCallStack) => ReqResponse -> IO Blob
isReply (Reply b) = return b
isReply (Reject n msg error_code) =
  assertFailure $ "Unexpected reject (code " ++ show n ++ (maybe "" showErrCode error_code) ++ "): " ++ T.unpack msg
  where
    showErrCode ec = ", error_code: " ++ T.unpack ec

isQueryReply :: (HasCallStack, HasAgentConfig) => Blob -> (Blob, QueryResponse) -> IO Blob
isQueryReply cid (rid, r) = do
  checkQueryResponse cid rid r
  aux r
  where
    aux (QueryReply b sigs) = do
      assertBool ("Number of signatures " ++ show (length sigs) ++ "is not equal to one") (length sigs == 1)
      return b
    aux (QueryReject n msg error_code _) =
      assertFailure $ "Unexpected reject (code " ++ show n ++ (maybe "" showErrCode error_code) ++ "): " ++ T.unpack msg
    showErrCode ec = ", error_code: " ++ T.unpack ec

-- Convenience decoders

asWord32 :: (HasCallStack) => Blob -> IO Word32
asWord32 = runGet Get.getWord32le

asWord64 :: (HasCallStack) => Blob -> IO Word64
asWord64 = runGet Get.getWord64le

as2Word64 :: (HasCallStack) => Blob -> IO (Word64, Word64)
as2Word64 = runGet $ (,) <$> Get.getWord64le <*> Get.getWord64le

asWord64Word128 :: (HasCallStack) => Blob -> IO (Word64, Word128)
asWord64Word128 = runGet $ do
  word64 <- Get.getWord64le
  low <- Get.getWord64le
  high <- Get.getWord64le
  return (word64, Word128 high low)

asWord128 :: (HasCallStack) => Blob -> IO Word128
asWord128 = runGet $ do
  low <- Get.getWord64le
  high <- Get.getWord64le
  return $ Word128 high low

bothSame :: (Eq a, Show a) => (a, a) -> Assertion
bothSame (x, y) = x @?= y

runGet :: (HasCallStack) => Get.Get a -> Blob -> IO a
runGet a b = case Get.runGetOrFail (a <* done) b of
  Left (_, _, err) ->
    fail $ "Could not parse " ++ show b ++ ": " ++ err
  Right (_, _, x) -> return x
  where
    done = do
      nothing_left <- Get.isEmpty
      unless nothing_left (fail "left-over bytes")

-- * Status endpoint parsing

data StatusResponse = StatusResponse
  { status_api_version :: T.Text,
    status_root_key :: Blob
  }

statusResponse :: (HasCallStack) => GenR -> IO StatusResponse
statusResponse =
  asExceptT . record do
    v <- field text "ic_api_version"
    _ <- optionalField text "impl_source"
    _ <- optionalField text "impl_version"
    _ <- optionalField text "impl_revision"
    pk <- field blob "root_key"
    swallowAllFields -- More fields are explicitly allowed
    return StatusResponse {status_api_version = v, status_root_key = pk}

-- * Interacting with aaaaa-aa (via HTTP)

{-
The code below has some repetition. That’s because we have

 A) multiple ways of _calling_ the Management Canister
    (as default user, as specific user, via canister, with or without cycles),
 B) different things we want to know
    (just the Candid-decoded reply, or the response, or even the HTTP error)
 C) and then of course different methods (which affect response decoding)

So far, there is some duplication here because of that. Eventually, this should
be refactored so that the test can declarative pick A, B and C separately.
-}

-- how to reach the management canister
type IC00 = Blob -> T.Text -> Blob -> IO ReqResponse

type IC00WithCycles = Word64 -> IC00

type IC00' = Blob -> T.Text -> Blob -> IO (HTTPErrOr ReqResponse)

ic00as :: (HasAgentConfig, HasCallStack) => Blob -> IC00
ic00as user ecid method_name arg =
  awaitCall ecid $
    rec
      [ "request_type" =: GText "call",
        "sender" =: GBlob user,
        "canister_id" =: GBlob "",
        "method_name" =: GText method_name,
        "arg" =: GBlob arg
      ]

ic00 :: (HasAgentConfig) => IC00
ic00 = ic00as defaultUser

-- A variant that allows non-200 responses to submit
ic00WithSubnetas' :: (HasAgentConfig) => Blob -> Blob -> Blob -> T.Text -> Blob -> IO (HTTPErrOr ReqResponse)
ic00WithSubnetas' subnet_id user ecid method_name arg =
  awaitCall' ecid $
    rec
      [ "request_type" =: GText "call",
        "sender" =: GBlob user,
        "canister_id" =: GBlob subnet_id,
        "method_name" =: GText method_name,
        "arg" =: GBlob arg
      ]

ic00as' :: (HasAgentConfig) => Blob -> Blob -> T.Text -> Blob -> IO (HTTPErrOr ReqResponse)
ic00as' = ic00WithSubnetas' ""

ic00' :: (HasAgentConfig) => IC00'
ic00' = ic00as' defaultUser

-- Now wrapping the concrete calls
-- (using Candid.toCandidService is tricky because of all stuff like passing through the effective canister id)
--
callIC ::
  forall s a b.
  (HasCallStack, HasAgentConfig) =>
  (KnownSymbol s) =>
  (Candid.CandidArg a, Candid.CandidArg b) =>
  IC00 ->
  Blob ->
  Label s ->
  a ->
  IO b
callIC ic00 ecid l x = do
  r <- ic00 ecid (T.pack (symbolVal l)) (Candid.encode x) >>= isReply
  case Candid.decode r of
    Left err -> assertFailure $ "Candid decoding error: " ++ err
    Right y -> pure y

-- Primed variants return the response (reply or reject)
callIC' ::
  forall s a b.
  (HasAgentConfig) =>
  (KnownSymbol s) =>
  (Candid.CandidArg a) =>
  IC00 ->
  Blob ->
  Label s ->
  a ->
  IO ReqResponse
callIC' ic00 ecid l x = ic00 ecid (T.pack (symbolVal l)) (Candid.encode x)

-- Double primed variants are only for requests from users (so they take the user,
-- not a generic ic00 thing), and return the HTTP error code or the response
-- (reply or reject)

callICWithSubnet'' ::
  forall s a b.
  (HasAgentConfig) =>
  (KnownSymbol s) =>
  (Candid.CandidArg a) =>
  Blob ->
  Blob ->
  Blob ->
  Label s ->
  a ->
  IO (HTTPErrOr ReqResponse)
callICWithSubnet'' subnet_id user ecid l x = ic00WithSubnetas' subnet_id user ecid (T.pack (symbolVal l)) (Candid.encode x)

callIC'' ::
  forall s a b.
  (HasAgentConfig) =>
  (KnownSymbol s) =>
  (Candid.CandidArg a) =>
  Blob ->
  Blob ->
  Label s ->
  a ->
  IO (HTTPErrOr ReqResponse)
callIC'' = callICWithSubnet'' ""

-- Triple primed variants return the response (reply or reject) and allow HTTP errors
callIC''' ::
  forall s a b.
  (HasAgentConfig) =>
  (KnownSymbol s) =>
  (Candid.CandidArg a) =>
  IC00' ->
  Blob ->
  Label s ->
  a ->
  IO (HTTPErrOr ReqResponse)
callIC''' ic00' ecid l x = ic00' ecid (T.pack (symbolVal l)) (Candid.encode x)

-- Convenience around Data.Row.Variants used as enums

enum :: (AllUniqueLabels r, KnownSymbol l, (r .! l) ~ ()) => Label l -> Var r
enum l = V.IsJust l ()

enumNothing :: (AllUniqueLabels r, KnownSymbol l, (r .! l) ~ Maybe t) => Label l -> Var r
enumNothing l = V.IsJust l Nothing

-- Other utilities

asHex :: Blob -> String
asHex = T.unpack . H.encodeHex . BS.toStrict

textual :: Blob -> String
textual = T.unpack . prettyPrincipal . Principal

shorten :: Int -> String -> String
shorten n s = a ++ (if null b then "" else "...")
  where
    (a, b) = splitAt n s
