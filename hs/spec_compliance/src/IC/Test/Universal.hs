{-# LANGUAGE DataKinds #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE KindSignatures #-}
{-# LANGUAGE OverloadedStrings #-}

-- |
--
-- Helpers to program the “Universal module”. This is essentially a small,
-- type-safe DSL to produce the small stack-based programming language interpreted
-- by the universal canister.
--
-- This DSL is expression-based, not stack based; seems to suite all our needs and is
-- simpler to work with.
--
-- This language is not stable; therefore there is no separarte documentation of
-- specification than this file and `universal_canister/src/`
module IC.Test.Universal where

import Data.ByteString.Builder
import qualified Data.ByteString.Lazy as BS
import Data.String
import Data.Word

-- The types of our little language are i32, i64, pair of i64s and blobs

data T = I | I64 | B

-- We deal with expressions (return a value, thus have a type) and programs (do
-- something, but do not return a type). They are represented simply
-- by the encoded stack program; no need for an AST or something that complicated

newtype Exp (result :: T) where
  Exp :: Builder -> Exp a

newtype Prog where
  Prog :: Builder -> Prog

-- We extracting the actual stack program bytecode from a program.

run :: Prog -> BS.ByteString
run (Prog x) = toLazyByteString x

-- Programs can be sequenced using (>>>); this naturally forms a Monoid

(>>>) :: Prog -> Prog -> Prog
Prog a >>> Prog b = Prog (a <> b)

instance Semigroup Prog where
  (<>) = (>>>)

instance Monoid Prog where
  mempty = Prog mempty

-- A utility class to easily defined functions and programs of any arity
-- simply by specifying their type.

class Op a where
  mkOp :: Word8 -> Builder -> a

instance Op Prog where
  mkOp x args = Prog $ args <> word8 x

instance Op (Exp t) where
  mkOp x args = Exp $ args <> word8 x

instance (Op a) => Op (Exp t -> a) where
  mkOp x args (Exp a) = mkOp x (args <> a)

op :: (Op a) => Word8 -> a
op x = mkOp x mempty

-- Now, all the op codes defined by the universal canister.
-- Most can be simply be defined by specifying their type and using the 'op'
-- combinator

noop :: Prog
noop = op 0

ignore :: Exp t -> Prog
ignore = op 1

int :: Word32 -> Exp 'I
int x = Exp $ word8 2 <> word32LE x

bytes :: BS.ByteString -> Exp 'B
bytes bytes =
  Exp $
    word8 3
      <> word32LE (fromIntegral (BS.length bytes))
      <> lazyByteString bytes

replyDataAppend :: Exp 'B -> Prog
replyDataAppend = op 4

reply :: Prog
reply = op 5

self :: Exp 'B
self = op 6

reject :: Exp 'B -> Prog
reject = op 7

caller :: Exp 'B
caller = op 8

reject_msg :: Exp 'B
reject_msg = op 10

reject_code :: Exp 'I
reject_code = op 11

i2b :: Exp 'I -> Exp 'B
i2b = op 12

argData :: Exp 'B
argData = op 13

cat :: Exp 'B -> Exp 'B -> Exp 'B
cat = op 14

stableSize :: Exp 'I
stableSize = op 15

stableGrow :: Exp 'I -> Exp 'I
stableGrow = op 16

stableRead :: Exp 'I -> Exp 'I -> Exp 'B
stableRead = op 17

stableWrite :: Exp 'I -> Exp 'B -> Prog
stableWrite = op 18

debugPrint :: Exp 'B -> Prog
debugPrint = op 19

trap :: Exp 'B -> Prog
trap = op 20

setGlobal :: Exp 'B -> Prog
setGlobal = op 21

getGlobal :: Exp 'B
getGlobal = op 22

badPrint :: Prog
badPrint = op 23

onPreUpgrade :: Exp 'B -> Prog
onPreUpgrade = op 24

getTime :: Exp 'I64
getTime = op 26

getAvailableCycles :: Exp 'I64
getAvailableCycles = op 27

getBalance :: Exp 'I64
getBalance = op 28

getRefund :: Exp 'I64
getRefund = op 29

acceptCycles :: Exp 'I64 -> Exp 'I64
acceptCycles = op 30

int64 :: Word64 -> Exp 'I64
int64 x = Exp $ word8 31 <> word64LE x

callNew :: Exp 'B -> Exp 'B -> Exp 'B -> Exp 'B -> Prog
callNew = op 32

callDataAppend :: Exp 'B -> Prog
callDataAppend = op 33

callCyclesAdd :: Exp 'I64 -> Prog
callCyclesAdd = op 34

callPerform :: Prog
callPerform = op 35

setCertifiedData :: Exp 'B -> Prog
setCertifiedData = op 36

getCertificatePresent :: Exp 'I
getCertificatePresent = op 37

getCertificate :: Exp 'B
getCertificate = op 38

getStatus :: Exp 'I
getStatus = op 39

onHeartbeat :: Exp 'B -> Prog
onHeartbeat = op 40

acceptMessage :: Prog
acceptMessage = op 41

onInspectMessage :: Exp 'B -> Prog
onInspectMessage = op 42

trapIfEq :: Exp 'B -> Exp 'B -> Exp 'B -> Prog
trapIfEq = op 43

callOnCleanup :: Exp 'B -> Prog
callOnCleanup = op 44

stableFill :: Exp 'I -> Exp 'I -> Exp 'I -> Prog
stableFill = op 45

stable64Size :: Exp 'I64
stable64Size = op 46

stable64Grow :: Exp 'I64 -> Exp 'I64
stable64Grow = op 47

stable64Read :: Exp 'I64 -> Exp 'I64 -> Exp 'B
stable64Read = op 48

stable64Write :: Exp 'I64 -> Exp 'B -> Prog
stable64Write = op 49

i64tob :: Exp 'I64 -> Exp 'B
i64tob = op 50

getAvailableCycles128 :: Exp 'B
getAvailableCycles128 = op 51

getBalance128 :: Exp 'B
getBalance128 = op 52

getRefund128 :: Exp 'B
getRefund128 = op 53

acceptCycles128 :: Exp 'I64 -> Exp 'I64 -> Exp 'B
acceptCycles128 = op 54

callCyclesAdd128 :: Exp 'I64 -> Exp 'I64 -> Prog
callCyclesAdd128 = op 55

onGlobalTimer :: Exp 'B -> Prog
onGlobalTimer = op 62

apiGlobalTimerSet :: Exp 'I64 -> Exp 'I64
apiGlobalTimerSet = op 63

performanceCounter :: Exp 'I -> Exp 'I64
performanceCounter = op 66

methodName :: Exp 'B
methodName = op 67

parsePrincipal :: Exp 'B -> Exp 'B
parsePrincipal = op 68

onTransform :: Exp 'B -> Prog
onTransform = op 69

getHttpReplyWithBody :: Exp 'B -> Exp 'B
getHttpReplyWithBody = op 70

getHttpTransformContext :: Exp 'B -> Exp 'B
getHttpTransformContext = op 71

canisterVersion :: Exp 'I64
canisterVersion = op 73

trapIfNeq :: Exp 'B -> Exp 'B -> Exp 'B -> Prog
trapIfNeq = op 74

mintCycles :: Exp 'I64 -> Exp 'I64
mintCycles = op 75

oneWayCallNew :: Exp 'B -> Exp 'B -> Prog
oneWayCallNew = op 76

isController :: Exp 'B -> Exp 'I
isController = op 77

inReplicatedExecution :: Exp 'I
inReplicatedExecution = op 81

-- Some convenience combinators

-- This allows us to write byte expressions as plain string literals
instance IsString (Exp 'B) where
  fromString s = bytes (fromString s)

callback :: Prog -> Exp 'B
callback = bytes . run

replyData :: Exp 'B -> Prog
replyData a = replyDataAppend a >>> reply

-- Convenient inter-canister calling

data OneWayCallArgs = OneWayCallArgs
  { ow_arg :: BS.ByteString,
    ow_cycles :: Word64,
    ow_icpts :: Word64
  }

oneway_call :: BS.ByteString -> BS.ByteString -> OneWayCallArgs -> Prog
oneway_call callee method_name ca =
  oneWayCallNew (bytes callee) (bytes method_name)
    >>> callDataAppend (bytes $ ow_arg ca)
    >>> (if ow_cycles ca > 0 then callCyclesAdd (int64 (ow_cycles ca)) else noop)
    >>> callPerform

data UpdateCallArgs = UpdateCallArgs
  { uc_on_reply :: Prog,
    uc_on_reject :: Prog,
    uc_on_cleanup :: Maybe Prog,
    uc_arg :: BS.ByteString,
    uc_cycles :: Word64,
    uc_icpts :: Word64
  }

update_call :: BS.ByteString -> BS.ByteString -> UpdateCallArgs -> Prog
update_call callee method_name ca =
  callNew
    (bytes callee)
    (bytes method_name)
    (callback (uc_on_reply ca))
    (callback (uc_on_reject ca))
    >>> maybe noop (callOnCleanup . callback) (uc_on_cleanup ca)
    >>> callDataAppend (bytes $ uc_arg ca)
    >>> (if uc_cycles ca > 0 then callCyclesAdd (int64 (uc_cycles ca)) else noop)
    >>> callPerform

data CallArgs = CallArgs
  { on_reply :: Prog,
    on_reject :: Prog,
    on_cleanup :: Maybe Prog,
    other_side :: Prog,
    cycles :: Word64,
    icpts :: Word64
  }

inter_call :: BS.ByteString -> BS.ByteString -> CallArgs -> Prog
inter_call callee method_name ca =
  let uca = UpdateCallArgs (on_reply ca) (on_reject ca) (on_cleanup ca) (run (other_side ca)) (cycles ca) (icpts ca)
   in update_call callee method_name uca

inter_update :: BS.ByteString -> CallArgs -> Prog
inter_update callee = inter_call callee "update"

inter_query :: BS.ByteString -> CallArgs -> Prog
inter_query callee = inter_call callee "query"

-- | By default, the other side responds with some text
-- indicating caller and callee, and the callbacks reply with the response.
defOneWayArgs :: OneWayCallArgs
defOneWayArgs =
  OneWayCallArgs
    { ow_arg = "",
      ow_cycles = 0,
      ow_icpts = 0
    }

defUpdateArgs :: UpdateCallArgs
defUpdateArgs =
  UpdateCallArgs
    { uc_on_reply = relayReply,
      uc_on_reject = relayReject,
      uc_on_cleanup = Nothing,
      uc_arg = "",
      uc_cycles = 0,
      uc_icpts = 0
    }

defArgs :: CallArgs
defArgs =
  CallArgs
    { on_reply = relayReply,
      on_reject = relayReject,
      on_cleanup = Nothing,
      other_side = defaultOtherSide,
      cycles = 0,
      icpts = 0
    }

defaultOtherSide :: Prog
defaultOtherSide =
  replyDataAppend "Hello "
    >>> replyDataAppend caller
    >>> replyDataAppend " this is "
    >>> replyDataAppend self
    >>> reply

relayReplyImpl :: Prog
relayReplyImpl =
  replyDataAppend (i2b (int 0))
    >>> replyDataAppend argData

relayReply :: Prog
relayReply =
  relayReplyImpl
    >>> reply

relayReplyRefund :: Word64 -> Prog
relayReplyRefund amount =
  relayReplyImpl
    >>> trapIfNeq (i64tob getRefund) (i64tob $ int64 amount) (bytes $ fromString $ "The call should refund exactly " ++ show amount ++ " cycles.")
    >>> reply

relayRejectImpl :: Prog
relayRejectImpl =
  replyDataAppend (i2b reject_code)
    >>> replyDataAppend reject_msg

relayReject :: Prog
relayReject =
  relayRejectImpl
    >>> reply

relayRejectRefund :: Word64 -> Prog
relayRejectRefund amount =
  relayRejectImpl
    >>> trapIfNeq (i64tob getRefund) (i64tob $ int64 amount) (bytes $ fromString $ "The call should refund exactly " ++ show amount ++ " cycles.")
    >>> reply
