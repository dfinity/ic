{-# LANGUAGE OverloadedStrings #-}

module IC.CBOR.Parser where

import Codec.CBOR.Read
import Codec.CBOR.Term
import Data.Bifunctor
import qualified Data.ByteString.Lazy as BS
import Data.Text (Text)
import qualified Data.Text as T
import IC.CBOR.Patterns

decodeWithoutTag :: BS.ByteString -> Either Text Term
decodeWithoutTag s =
  first
    (\(DeserialiseFailure _ s) -> "CBOR decoding failure: " <> T.pack s)
    (deserialiseFromBytes decodeTerm s)
    >>= begin
  where
    begin (leftOver, _) | not (BS.null leftOver) = Left "Left-over bytes"
    begin (_, TTagged 55799 _) = Left "Did not expect semantic tag 55799 here"
    begin (_, t) = return t

decodeWithTag :: BS.ByteString -> Either Text Term
decodeWithTag s =
  first
    (\(DeserialiseFailure _ s) -> "CBOR decoding failure: " <> T.pack s)
    (deserialiseFromBytes decodeTerm s)
    >>= begin
  where
    begin (leftOver, _) | not (BS.null leftOver) = Left "Left-over bytes"
    begin (_, TTagged 55799 t) = return t
    begin (_, t) = Left $ "Expected certificate to begin with tag 55799, got " <> T.pack (show t) <> " in " <> T.pack (show s)

parseMap :: Text -> Term -> Either Text [(Term, Term)]
parseMap _ (TMap_ kv) = return kv
parseMap what t = Left $ "expected " <> what <> ", found " <> T.pack (show t)

parseBlob :: Text -> Term -> Either Text BS.ByteString
parseBlob _ (TBlob s) = return s
parseBlob what t = Left $ "expected " <> what <> ", found " <> T.pack (show t)

parseField :: Text -> [(Term, a)] -> Either Text a
parseField f kv = case lookup (TString f) kv of
  Just t -> return t
  Nothing -> Left $ "Missing expected field " <> f

optionalField :: Text -> [(Term, a)] -> Either Text (Maybe a)
optionalField f kv = return $ lookup (TString f) kv
