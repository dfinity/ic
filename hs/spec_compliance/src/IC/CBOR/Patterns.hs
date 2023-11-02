{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE PatternSynonyms #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ViewPatterns #-}

module IC.CBOR.Patterns where

import Codec.CBOR.Term
import qualified Data.ByteString.Lazy as BS
import Numeric.Natural

pattern TMap_ :: [(Term, Term)] -> Term
pattern TMap_ m <- (\case TMapI m -> Just m; TMap m -> Just m; _ -> Nothing -> Just m)

pattern TList_ :: [Term] -> Term
pattern TList_ m <- (\case TListI m -> Just m; TList m -> Just m; _ -> Nothing -> Just m)

pattern TNat :: Natural -> Term
pattern TNat m <-
  ( \case
      TInt m | m >= 0 -> Just (fromIntegral m)
      TInteger m | m >= 0 -> Just (fromIntegral m)
      _ -> Nothing ->
      Just m
    )

pattern TBlob :: BS.ByteString -> Term
pattern TBlob m <- TBytes (BS.fromStrict -> m)
  where
    TBlob m = TBytes (BS.toStrict m)
