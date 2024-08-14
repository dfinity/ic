{-# LANGUAGE ConstraintKinds #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RankNTypes #-}

-- |
-- Utilities to deconstruct a generic record.
module IC.HTTP.GenR.Parse where

import Control.Monad
import Control.Monad.Except
import Control.Monad.State
import Control.Monad.Writer
import qualified Data.ByteString.Lazy as BS
import qualified Data.HashMap.Lazy as HM
import qualified Data.Text as T
import GHC.Stack
import IC.HTTP.GenR
import Numeric.Natural

-- A monad to parse a record
-- (reading each field once, checking for left-over fields in the end)
type RecordM m = StateT (HM.HashMap T.Text GenR) m

type Field a = forall m. (HasCallStack) => (Parse m) => GenR -> m a

class (Monad m) => Parse m where parseError :: (HasCallStack) => T.Text -> m a

instance Parse (Either T.Text) where parseError = Left

instance (Monoid a, Parse m) => Parse (WriterT a m) where parseError = lift . parseError

instance (Monad m) => Parse (ExceptT T.Text m) where parseError = throwError

record :: (HasCallStack) => (Parse m) => RecordM m a -> GenR -> m a
record m (GRec hm) = (`evalStateT` hm) $ do
  x <- m
  -- Check for left-over fields
  hm <- get
  unless (HM.null hm) $
    lift $
      parseError $
        "Unexpected fields: " <> T.intercalate ", " (HM.keys hm)
  return x
record _ _ = parseError "Expected CBOR record"

field :: (HasCallStack) => (Parse m) => Field a -> T.Text -> RecordM m a
field parse name = do
  hm <- get
  put (HM.delete name hm)
  lift $ case HM.lookup name hm of
    Nothing -> parseError $ "Missing expected field \"" <> name <> "\""
    Just gr -> parse gr

optionalField :: (HasCallStack) => (Parse m) => Field a -> T.Text -> RecordM m (Maybe a)
optionalField parse name = do
  hm <- get
  put (HM.delete name hm)
  case HM.lookup name hm of
    Nothing -> return Nothing
    Just gr -> lift $ Just <$> parse gr

swallowAllFields :: (Monad m) => RecordM m ()
swallowAllFields = put HM.empty

anyType :: Field GenR
anyType = return

text :: Field T.Text
text (GText t) = return t
text _ = parseError "Expected text value"

blob :: Field BS.ByteString
blob (GBlob b) = return b
blob _ = parseError "Expected blob"

nat :: Field Natural
nat (GNat n) = return n
nat _ = parseError "Expected natural number"

percentage :: Field Natural
percentage gr = do
  n <- nat gr
  unless (0 <= n && n <= 100) $
    parseError "Expected a percentage (0..100)"
  return n

listOf :: Field a -> Field [a]
listOf f (GList xs) = mapM f xs
listOf _ _ = parseError "Expected a list"
