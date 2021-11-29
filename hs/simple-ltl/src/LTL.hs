{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveFunctor #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE LambdaCase #-}

-- | This module provides a simple way of applying LTL formulas to lists, or
--   streams of input, to determine if a given formula matches some or all of
--   that input.
--
--   Formulas are written exactly as you would in LTL, but using names instead
--   of the typical symbols, for example:
--
-- @
-- always (is even @`until@` is odd)
-- @
--
--   Use 'run' to apply a formula to a list of inputs, returning either 'Left'
--   if it needs more input to determine the truth of the formula, or 'Right'
--   if it could determine truth from some prefix of that input.
--
--   Use 'step' to advance a formula by a single input. The return value has
--   the same meaning as 'run', but allows you to apply it in cases whether
--   you don't necessarily have all the inputs at once, such as feeding input
--   gradually within a conduit to check for logic failures.
--
--   For the meaning of almost all the functions in the module, see
--   https://en.wikipedia.org/wiki/Linear_temporal_logic
module LTL
  ( LTL (..),
    Answer (..),
    PartialAnswer (..),
    Reason (..),
    run,
    neg,
    top,
    bottom,
    examine,
    end,
    LTL.and,
    LTL.or,
    next,
    weak,
    orNext,
    andNext,
    LTL.until,
    release,
    strongRelease,
    implies,
    eventually,
    always,
    truth,
    test,
    is,
    eq,
  )
where

import Control.DeepSeq
import Data.Function (fix)
import Data.List (foldl')
import GHC.Generics
import Prelude hiding (and, or, until)

data Reason a
  = HitBottom String
  | Rejected a
  | BothFailed (Reason a) (Reason a)
  | LeftFailed (Reason a)
  | RightFailed (Reason a)
  deriving (Show, Generic, NFData, Functor)

data PartialAnswer a
  = Abort (Reason a)
  | Failure (Reason a)
  | Continue (LTL a)
  | Success
  deriving (Generic)

instance Show a => Show (PartialAnswer a) where
  show (Continue _) = "<need input>"
  show (Abort res) = "Abort: " ++ show res
  show (Failure res) = "Failure: " ++ show res
  show Success = "Success"
  {-# INLINEABLE show #-}

data Answer a
  = Failed (Reason a)
  | Succeeded
  deriving (Generic, Functor)

finish :: PartialAnswer a -> Answer a
finish = \case
  Abort reason -> Failed reason
  Failure reason -> Failed reason
  Continue (LTL formula) -> case formula Nothing of
    Abort reason -> Failed reason
    Failure reason -> Failed reason
    -- Continue _ -> Succeeded
    Continue _ ->
      Failed (HitBottom "Failed to determine formula by end of stream")
    Success -> Succeeded
  Success -> Succeeded
{-# INLINEABLE finish #-}

newtype LTL a = LTL {step :: Maybe a -> PartialAnswer a}

run :: LTL a -> [a] -> Answer a
run formula xs =
  finish $
    foldl'
      ( \acc x -> case acc of
          Continue f -> step f (Just x)
          res -> res
      )
      (Continue formula)
      xs
{-# INLINEABLE run #-}

-- | ⊤, or "true"
top :: LTL a
top = stop Succeeded
{-# INLINE top #-}

-- | ⊥, or "false"
bottom :: String -> LTL a
bottom = stop . Failed . HitBottom
{-# INLINE bottom #-}

mapAnswer :: (PartialAnswer a -> PartialAnswer a) -> LTL a -> LTL a
mapAnswer f formula = LTL $ f . step formula
{-# INLINE mapAnswer #-}

-- | Negate a formula: ¬ p
neg :: LTL a -> LTL a
neg = mapAnswer invert
{-# INLINE neg #-}

invert :: PartialAnswer a -> PartialAnswer a
invert = \case
  Success -> Failure (HitBottom "neg")
  Failure _ -> Success
  Abort e -> Abort e
  Continue f -> Continue (neg f)
{-# INLINEABLE invert #-}

-- | Boolean conjunction: ∧
and :: LTL a -> LTL a -> LTL a
and (LTL f) g = LTL $ \el -> case f el of
  Abort e -> Abort (LeftFailed e)
  Failure e -> Failure (LeftFailed e)
  Success -> step g el
  Continue f' -> case step g el of
    Abort e -> Abort (RightFailed e)
    Failure e -> Failure (RightFailed e)
    Success -> Continue f'
    Continue g' -> Continue $! f' `and` g'
{-# INLINEABLE and #-}

andNext :: LTL a -> LTL a -> LTL a
andNext (LTL f) g = LTL $ \el -> case f el of
  Abort e -> Abort (LeftFailed e)
  Failure e -> Failure (LeftFailed e)
  Success -> Continue g
  Continue f' -> Continue $! f' `and` g
{-# INLINEABLE andNext #-}

-- | Boolean disjunction: ∨
or :: LTL a -> LTL a -> LTL a
or (LTL f) g = LTL $ \el -> case f el of
  Success -> Success
  Abort e -> Abort (LeftFailed e)
  Failure e1 -> case step g el of
    Failure e2 -> Failure (BothFailed e1 e2)
    g' -> g'
  Continue f' -> case step g el of
    Success -> Success
    Abort e -> Abort (RightFailed e)
    Failure _ -> Continue f'
    Continue g' -> Continue $! f' `or` g'
{-# INLINEABLE or #-}

orNext :: LTL a -> LTL a -> LTL a
orNext (LTL f) g = LTL $ \el -> case f el of
  Success -> Success
  Abort e -> Abort (LeftFailed e)
  Failure _ -> Continue g
  Continue f' -> Continue $! f' `or` g
{-# INLINEABLE orNext #-}

stop :: Answer a -> LTL a
stop x = LTL $ \_ -> case x of
  Failed r -> Failure r
  Succeeded -> Success
{-# INLINE stop #-}

-- | Given an input element, provide a formula to determine its truth. These
--   can be nested, making it possible to have conditional formulas. Consider
--   the following:
--
-- @
-- always (examine (\n -> next (eq (succ n))))
-- @
--
--   One way to read this would be: "for every input n, always examine n if its
--   next element is the successor".
examine :: (a -> LTL a) -> LTL a
examine f = LTL $ \el -> case el of
  Nothing -> Failure (HitBottom "examine has no meaning at end of stream")
  Just a -> step (f a) (Just a)
{-# INLINE examine #-}

end :: LTL a
end = LTL $ \el -> case el of
  Nothing -> Success
  Just _ -> Failure (HitBottom "end only matches at end of stream")
{-# INLINE end #-}

-- | The "next" temporal modality, typically written 'X p' or '◯ p'.
next :: LTL a -> LTL a
next f = LTL $ \el -> case el of
  Nothing -> Failure (HitBottom "next has no meaning at end of stream")
  Just _ -> Continue f
{-# INLINEABLE next #-}

weak :: (LTL a -> LTL a) -> LTL a -> LTL a
weak f p = f (end `or` p)
{-# INLINEABLE weak #-}

-- | The "until" temporal modality, typically written 'p U q'.
until :: LTL a -> LTL a -> LTL a
until p = \q -> fix $ or q . andNext p
{-# INLINE until #-}

-- | Release, the dual of 'until'.
release :: LTL a -> LTL a -> LTL a
release p = \q -> fix $ and q . orNext p
{-# INLINEABLE release #-}

-- | Strong release.
strongRelease :: LTL a -> LTL a -> LTL a
strongRelease p = \q -> (p `release` q) `and` eventually p
{-# INLINE strongRelease #-}

-- | Logical implication: p → q
implies :: LTL a -> LTL a -> LTL a
implies = or . neg
{-# INLINE implies #-}

-- | Eventually the formula will hold, typically written F p or ◇ p.
eventually :: LTL a -> LTL a
eventually = until top
{-# INLINE eventually #-}

-- | Always the formula must hold, typically written G p or □ p.
always :: LTL a -> LTL a
-- Technically this is the definition of always, but is only applicable to
-- infinite streams and thus can never constructively succeed.
-- always = release (bottom "always")
always = release end . or end
{-# INLINE always #-}

-- | True if the given Haskell boolean is true.
truth :: Bool -> LTL a
truth True = top
truth False = bottom "truth"
{-# INLINE truth #-}

-- | True if the given predicate on the input is true.
is :: (a -> Bool) -> LTL a
is = examine . (truth .)
{-# INLINE is #-}

-- | Another name for 'is'.
test :: (a -> Bool) -> LTL a
test = is
{-# INLINE test #-}

-- | Check for equality with the input.
eq :: Eq a => a -> LTL a
eq = is . (==)
{-# INLINE eq #-}
