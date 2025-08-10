{-# LANGUAGE ScopedTypeVariables #-}

module IC.DRun.Parse where

import Control.Exception
import Data.ByteString.Base32
import qualified Data.ByteString.Lazy.Char8 as B
import qualified Data.Text as T
import qualified Text.Hex as H

type MethodName = String

type Payload = B.ByteString

type Id = B.ByteString

data Ingress
  = Create Id
  | Install Id FilePath Payload
  | Reinstall Id FilePath Payload
  | Upgrade Id FilePath Payload
  | Update Id MethodName Payload
  | Query Id MethodName Payload
  deriving (Show)

parseFile :: FilePath -> IO [Ingress]
parseFile input = do
  x <- parse <$> readFile input
  _ <- evaluate (show x) -- hack to evaluate until we have a proper parser
  return x

parse :: String -> [Ingress]
parse = map parseLine . lines

parseLine :: String -> Ingress
parseLine l = case words l of
  ["create", i] -> Create (parseId i)
  ["install", i, f, a] -> Install (parseId i) f (parseArg a)
  ["reinstall", i, f, a] -> Reinstall (parseId i) f (parseArg a)
  ["upgrade", i, f, a] -> Upgrade (parseId i) f (parseArg a)
  ["ingress", i, m, a] -> Update (parseId i) m (parseArg a)
  ["query", i, m, a] -> Query (parseId i) m (parseArg a)
  _ -> error $ "Cannot parse: " ++ show l

-- TODO: Implement proper and extract in own module
parseId :: String -> Id
parseId s = case B.fromStrict <$> decodeBase32Unpadded (B.toStrict (B.pack (filter (/= '-') s))) of
  Right bytes ->
    if B.length bytes >= 4
      then B.drop 4 bytes
      else error "Too short id"
  Left err -> error $ "Invalid canister id: " ++ T.unpack err

parseArg :: String -> Payload
parseArg ('0' : 'x' : xs)
  | Just x <- B.fromStrict <$> H.decodeHex (T.pack xs) = x
parseArg ('"' : xs) =
  B.pack $ go xs
  where
    go "" = error "Missing terminating \""
    go "\"" = []
    go ('\\' : 'x' : a : b : ys)
      | Just h <- H.decodeHex (T.pack [a, b]) =
          B.unpack (B.fromStrict h) ++ go ys
    go (c : ys) = c : go ys
parseArg x = error $ "Invalid argument " ++ x
