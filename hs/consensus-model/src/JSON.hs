{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE ImplicitParams #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE QuasiQuotes #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ViewPatterns #-}
{-# OPTIONS_GHC -Wno-orphans #-}

module JSON where

import Codec.Candid (Principal (..), parsePrincipal)
import qualified Crypto.Sign.Ed25519 as Ed25519
import Data.Aeson
import Data.Aeson.Types
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as B8
import qualified Data.ByteString.Lazy as BL
import Data.Foldable
import qualified Data.HashMap.Strict as M
import Data.Text (Text)
import qualified Data.Text.Encoding as T
import Lib
import System.IO (Handle, hIsEOF)
import System.IO.Unsafe
import Types

instance FromJSON Principal where
  parseJSON (Array xs) =
    Principal . BL.pack <$> mapM parseJSON (toList xs)
  parseJSON (Object _o) = pure $ Principal ""
  parseJSON v = fail $ "Unexpected PrincipalId: " ++ show v

instance FromJSON ReplicaId where
  parseJSON v = do
    replica_id <- parseJSON v
    let (replica_pk, replica_sk) = unsafePerformIO $ do
          (pk, sk) <- Ed25519.createKeypair
          pure (pk, sk)
    pure ReplicaId {..}

instance FromJSON ThresholdSignatureShare where
  parseJSON (Array xs) =
    ThresholdSignatureShare . BS.pack <$> mapM parseJSON (toList xs)
  parseJSON v = fail $ "Unexpected ThresholdSignatureShare: " ++ show v

instance FromJSON ThresholdSignature where
  parseJSON (Array xs) =
    ThresholdSignature . BS.pack <$> mapM parseJSON (toList xs)
  parseJSON v = fail $ "Unexpected ThresholdSignature: " ++ show v

instance FromJSON MultiSignature where
  parseJSON (Array xs) =
    MultiSignature . (: []) . Signature . BS.pack <$> mapM parseJSON (toList xs)
  parseJSON v = fail $ "Unexpected MultiSignature: " ++ show v

instance FromJSON Signature where
  parseJSON (Array xs) = Signature . BS.pack <$> mapM parseJSON (toList xs)
  parseJSON v = fail $ "Unexpected Signature: " ++ show v

instance FromJSON Hash where
  parseJSON (Array xs) = Hash . BS.pack <$> mapM parseJSON (toList xs)
  parseJSON v = fail $ "Unexpected Hash: " ++ show v

getSigner ::
  FromJSON a =>
  M.HashMap Text Value ->
  Parser (ReplicaId, a)
getSigner o = do
  signature <- o .: "signature"
  (,) <$> signature .: "signer" <*> signature .: "signature"

getSigners ::
  FromJSON a =>
  M.HashMap Text Value ->
  Parser ([ReplicaId], a)
getSigners o = do
  signature <- o .: "signature"
  (,) <$> signature .: "signers" <*> signature .: "signature"

instance FromJSON RandomBeaconShare where
  parseJSON (Object o) = do
    content <- o .: "content"
    -- rbs_registryVersion <- content .: "version"
    rbs_height <- content .: "height"
    (HashOfRandomBeacon -> rbs_parent) <- content .: "parent"
    ( rbs_replicaId,
      RandomBeaconShareSignature -> rbs_randomBeaconShareSignature
      ) <-
      getSigner o
    pure RandomBeaconShare {..}
  parseJSON v = fail $ "Unexpected RandomBeaconShare: " ++ show v

-- "RandomBeacon": {
--   "content": {
--     "version": {
--       "version_id": "0.1.0"
--     },
--     "height": 9,
--     "parent": [ <32 u8> ]
--   },
--   "signature": {
--     "signature": [ <64 u8> ],
--     "signer": {
--       "start_block_height": 0,
--       "dealer_subnet": [ <10 u8> ],
--       "dkg_tag": "LowThreshold",
--       "target_subnet": {
--         "Remote": [ <32 u8> ]
--       }
--     }
--   }
-- }
instance FromJSON RandomBeacon where
  parseJSON (Object o) = do
    content <- o .: "content"
    -- rb_registryVersion <- content .: "version"
    rb_height <- content .: "height"
    (HashOfRandomBeacon -> rb_parent) <- content .: "parent"
    ( _rb_replicaId, -- (2020-11-19): Why isn't this used?
      RandomBeaconSignature -> rb_randomBeaconSignature
      ) <-
      getSigner o
    pure RandomBeacon {..}
  parseJSON v = fail $ "Unexpected RandomBeacon: " ++ show v

-- {
--   "payload": {
--     "hash": [ <32 u8> ],
--     "value": {
--       "ingress": {
--         "id_and_pos": [],
--         "buffer": []
--       },
--       "xnet": {
--         "stream_slices": {
--         }
--       }
--     }
--   }
-- }
instance FromJSON Payload where
  parseJSON _ = pure $ Payload ""

-- {
--   "version": {
--     "version_id": "0.1.0"
--   },
--   "parent": [ <32 u8> ],
--   "payload": { <PayLoad>,
--   "dkg_payload": {
--     "Dealings": [
--       0,
--       []
--     ]
--   },
--   "height": 18,
--   "rank": 0,
--   "context": {
--     "registry_version": 1,
--     "certified_height": 16,
--     "time": 1605740358787001000
--   }
-- }
instance FromJSON Block where
  parseJSON (Object o) = do
    -- b_registryVersion <- o .: "version"
    b_height <- o .: "height"
    (HashOfBlock -> b_parent) <- o .: "parent"
    b_slot <- o .: "rank"
    b_payload <- o .: "payload"
    -- (2020-11-20): When do these come into play?
    -- b_dpkgPayload <- o .: "dkg_payload"
    -- b_context <- o .: "context"
    pure Block {..}
  parseJSON v = fail $ "Unexpected Block: " ++ show v

-- "BlockProposal": {
--   "content": {
--     "hash": [ <32 u8> ],
--     "value": <Block>,
--   },
--   "signature": {
--     "signature": [ <64 u8> ],
--     "signer": [ <10 u8> ]
--   }
-- }
instance FromJSON BlockProposal where
  parseJSON (Object o) = do
    content <- o .: "content"
    bp_block_hash <- HashOfBlock <$> content .: "hash"
    bp_block <- content .: "value"
    ( bp_replicaId,
      BlockSignature -> bp_signature
      ) <-
      getSigner o
    pure BlockProposal {..}
  parseJSON v = fail $ "Unexpected BlockProposal: " ++ show v

-- "NotarizationShare": {
--   "content": {
--     "version": {
--       "version_id": "0.1.0"
--     },
--     "height": 9,
--     "block": [ <32 u8> ]
--   },
--   "signature": {
--     "signature": [ <64 u8> ],
--     "signer": [ <10 u8> ]
--   }
-- }
instance FromJSON NotarizationShare where
  parseJSON (Object o) = do
    content <- o .: "content"
    -- ns_registryVersion <- content .: "version"
    ns_height <- content .: "height"
    (HashOfBlock -> ns_block) <- content .: "block"
    ( ns_replicaId,
      NotarizationShareSignature -> ns_notarizationShareSignature
      ) <-
      getSigner o
    pure NotarizationShare {..}
  parseJSON v = fail $ "Unexpected NotarizationShare: " ++ show v

-- "Notarization": {
--   "content": {
--     "version": {
--       "version_id": "0.1.0"
--     },
--     "height": 9,
--     "block": [ <32 u8> ]
--   },
--   "signature": {
--     "signature": [ <64 u8> ],
--     "signers": [ <10 u8> ]
--   }
-- }
instance FromJSON Notarization where
  parseJSON (Object o) = do
    content <- o .: "content"
    -- n_registryVersion <- content .: "version"
    n_height <- content .: "height"
    (HashOfBlock -> n_block) <- content .: "block"
    ( n_replicaIds,
      NotarizationSignature -> n_notarizationSignature
      ) <-
      getSigners o
    pure Notarization {..}
  parseJSON v = fail $ "Unexpected Notarization: " ++ show v

-- "FinalizationShare": {
--   "content": {
--     "version": {
--       "version_id": "0.1.0"
--     },
--     "height": 1,
--     "block": [ <32 u8> ]
--   },
--   "signature": {
--     "signature": [ <64 u8> ],
--     "signer": [ <10 u8> ]
--   }
-- }
instance FromJSON FinalizationShare where
  parseJSON (Object o) = do
    content <- o .: "content"
    -- fs_registryVersion <- content .: "version"
    fs_height <- content .: "height"
    (HashOfBlock -> fs_block) <- content .: "block"
    ( fs_replicaId,
      FinalizationShareSignature -> fs_finalizationShareSignature
      ) <-
      getSigner o
    pure FinalizationShare {..}
  parseJSON v = fail $ "Unexpected FinalizationShare: " ++ show v

-- "Finalization": {
--   "content": {
--     "version": {
--       "version_id": "0.1.0"
--     },
--     "height": 1,
--     "block": [ <32 u8> ]
--   },
--   "signature": {
--     "signature": [ <64 u8> ],
--     "signers": [ <10 u8> ]
--   }
-- }
instance FromJSON Finalization where
  parseJSON (Object o) = do
    content <- o .: "content"
    -- f_registryVersion <- content .: "version"
    f_height <- content .: "height"
    (HashOfBlock -> f_block) <- content .: "block"
    ( f_replicaIds,
      FinalizationSignature -> f_finalizationSignature
      ) <-
      getSigners o
    pure Finalization {..}
  parseJSON v = fail $ "Unexpected Finalization: " ++ show v

-- "RandomTapeShare": {
--   "content": {
--     "version": {
--       "version_id": "0.1.0"
--     },
--     "height": 9
--   },
--   "signature": {
--     "signature": [ <64 u8> ],
--     "signer": [ <10 u8> ]
--   }
-- }
instance FromJSON RandomTapeShare where
  parseJSON (Object o) = do
    content <- o .: "content"
    -- rts_registryVersion <- content .: "version"
    rts_height <- content .: "height"
    ( _rts_replicaId, -- (2020-11-19): Why not used?
      RandomTapeShareSignature -> rts_randomTapeShareSignature
      ) <-
      getSigner o
    pure RandomTapeShare {..}
  parseJSON v = fail $ "Unexpected RandomTapeShare: " ++ show v

-- "RandomTape": {
--   "content": {
--     "version": {
--       "version_id": "0.1.0"
--     },
--     "height": 9
--   },
--   "signature": {
--     "signature": [ <64 u8> ],
--     "signer": {
--       "start_block_height": 0,
--       "dealer_subnet": [ <10 u8> ],
--       "dkg_tag": "LowThreshold",
--       "target_subnet": {
--         "Remote": [ <32 u8> ]
--       }
--     }
--   }
-- }
instance FromJSON RandomTape where
  parseJSON (Object o) = do
    content <- o .: "content"
    -- rt_registryVersion <- content .: "version"
    rt_height <- content .: "height"
    ( rt_replicaId,
      RandomTapeSignature -> rt_randomTapeSignature
      ) <-
      getSigner o
    pure RandomTape {..}
  parseJSON v = fail $ "Unexpected RandomTape: " ++ show v

instance FromJSON CatchUpPackageShare where
  parseJSON (Object o) = do
    content <- o .: "content"
    -- cups_registryVersion <- content .: "version"
    cups_block <- content .: "block"
    cups_randomBeacon <- content .: "beacon"
    (HashOfState -> cups_state) <- content .: "state"
    ( cups_replicaId,
      StateShareSignature -> cups_stateShareSignature
      ) <-
      getSigner o
    pure CatchUpPackageShare {..}
  parseJSON v = fail $ "Unexpected CatchUpPackageShare: " ++ show v

instance FromJSON CatchUpPackage where
  parseJSON (Object o) = do
    content <- o .: "content"
    -- cup_registryVersion <- content .: "version"
    cup_block <- content .: "block"
    cup_randomBeacon <- content .: "beacon"
    (HashOfState -> cup_state) <- content .: "state"
    (StateSignature -> cup_stateSignature) <- content .: "signature"
    pure CatchUpPackage {..}
  parseJSON v = fail $ "Unexpected CatchUpPackage: " ++ show v

instance FromJSON EquivocationProof where
  parseJSON (Object o) = do
    content <- o .: "content"
    -- ep_registryVersion <- content .: "version"
    ep_replicaId <- content .: "signer"
    ep_height <- content .: "height"
    ep_blockProposal1 <- content .: "block1"
    ep_blockProposal2 <- content .: "block2"
    pure EquivocationProof {..}
  parseJSON v = fail $ "Unexpected EquivocationProof: " ++ show v

instance FromJSON ConsensusMessage where
  parseJSON (Object o)
    | Just v <- M.lookup "RandomBeaconShare" o =
      RandomBeaconShareMsg <$> parseJSON v
    | Just v <- M.lookup "RandomBeacon" o =
      RandomBeaconMsg <$> parseJSON v
    | Just v <- M.lookup "BlockProposal" o =
      BlockProposalMsg <$> parseJSON v
    | Just v <- M.lookup "NotarizationShare" o =
      NotarizationShareMsg <$> parseJSON v
    | Just v <- M.lookup "Notarization" o =
      NotarizationMsg <$> parseJSON v
    | Just v <- M.lookup "FinalizationShare" o =
      FinalizationShareMsg <$> parseJSON v
    | Just v <- M.lookup "Finalization" o =
      FinalizationMsg <$> parseJSON v
    | Just v <- M.lookup "RandomTapeShare" o =
      RandomTapeShareMsg <$> parseJSON v
    | Just v <- M.lookup "RandomTape" o =
      RandomTapeMsg <$> parseJSON v
    | Just v <- M.lookup "CatchUpPackageShare" o =
      CatchUpPackageShareMsg <$> parseJSON v
    | Just v <- M.lookup "CatchUpPackage" o =
      CatchUpPackageMsg <$> parseJSON v
    | Just v <- M.lookup "EquivocationProof" o =
      EquivocationProofMsg <$> parseJSON v
  parseJSON v = fail $ "Unexpected ConsensusMessage: " ++ show v

instance FromJSON ChangeAction where
  parseJSON (Object o)
    | Just v <- M.lookup "AddToValidated" o =
      AddToValidated <$> parseJSON v
    | Just v <- M.lookup "MoveToValidated" o =
      MoveToValidated <$> parseJSON v
    | Just v <- M.lookup "RemoveFromValidated" o =
      RemoveFromValidated <$> parseJSON v
    | Just v <- M.lookup "RemoveFromUnvalidated" o =
      RemoveFromUnvalidated <$> parseJSON v
    | Just v <- M.lookup "PurgeValidatedBelow" o =
      PurgeValidatedBelow <$> parseJSON v
    | Just v <- M.lookup "PurgeUnvalidatedBelow" o =
      PurgeUnvalidatedBelow <$> parseJSON v
    | Just v <- M.lookup "HandleInvalid" o =
      HandleInvalid <$> parseJSON v
  parseJSON v = fail $ "Unexpected ChangeAction: " ++ show v

data TraceEvent
  = ArtifactSeen !ConsensusMessage
  | ChangeActionSeen !ChangeAction
  | ApplyChanges !Time
  | FoundSubnets ![SubnetId]
  | FoundSubnet !SubnetId ![NodeId]
  deriving (Eq, Show)

readLogOutput :: Handle -> IO [TraceEvent]
readLogOutput = go (1 :: Int) []
  where
    go lnum !acc h = do
      b <- hIsEOF h
      if b
        then pure $ reverse acc
        else do
          line <- BS.hGetLine h
          let mres =
                splitLine
                  line
                  [ ( "process_change::change_action ",
                      decodeJsonAs ChangeActionSeen
                    ),
                    ( "process_change::artifact ",
                      decodeJsonAs ArtifactSeen
                    ),
                    ( "process_change::apply_changes ",
                      decodeJsonAs ApplyChanges
                    ),
                    ( "Found subnets ",
                      Just . decodeStringListAs FoundSubnets FoundSubnet
                    ),
                    ( "Found subnet ",
                      Just . decodeStringListAs FoundSubnets FoundSubnet
                    )
                  ]
          flip (go (lnum + 1)) h $ case mres of
            Nothing -> acc
            Just !x -> x : acc
      where
        decodeJsonAs f s =
          case eitherDecode (BL.fromStrict s) of
            Left err -> do
              _ <-
                error $
                  "Failed to decode, line "
                    ++ show lnum
                    ++ ": "
                    ++ err
                    ++ "\n"
                    ++ B8.unpack s
              Nothing
            Right x -> Just (f x)

        decodeStringListAs ::
          ([Principal] -> TraceEvent) ->
          (Principal -> [Principal] -> TraceEvent) ->
          ByteString ->
          TraceEvent
        decodeStringListAs f g s
          | BS.null s = error "decodeStringListAs fail on empty string"
          | BS.take 1 s == "[" =
            let lst = B8.takeWhile (\c -> c /= ']') (BS.drop 1 s)
                ids = B8.split ' ' lst
             in f (map principal ids)
          | otherwise =
            let (beg, BS.drop (BS.length " with nodes ") -> after) =
                  BS.breakSubstring " with nodes " s
             in decodeStringListAs (g (principal beg)) g after
          where
            principal = either error id . parsePrincipal . T.decodeUtf8

splitLine :: ByteString -> [(ByteString, ByteString -> Maybe a)] -> Maybe a
splitLine line rules =
  (\f -> foldr' f Nothing rules) $ \(pat, rule) -> \case
    Just x -> Just x
    Nothing ->
      if pat `BS.isInfixOf` line
        then do
          let (_, BS.drop (BS.length pat) -> after) =
                BS.breakSubstring pat line
          rule after
        else Nothing
