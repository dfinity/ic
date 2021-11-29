{-# LANGUAGE RankNTypes #-}

{-
What is Consensus?

Consensus fairly distributes work to a pool of compensated participants
who agree upon the results of that result;

data BlockProposal = BlockProposal {
   parent :: Finalized BlockProposal
}
-}

module Meaning where

import Data.Foldable (maximumBy)
import Data.Function (on)
import Data.Maybe (fromMaybe)

type Time = Peano

type Duration = Peano

type Count = Peano

type Node = Peano

data Peano = Zero | Suc Peano
  deriving (Eq, Ord)

type Nat = Peano

toNum :: Peano -> Integer
toNum Zero = 0
toNum (Suc n) = succ (toNum n)

instance Num Peano where
  Zero + j = j
  Suc i + j = Suc (i + j)

  Zero * _ = Zero
  Suc i * j = j + i * j

  fromInteger 0 = Zero
  fromInteger n = 1 + fromInteger (pred n)

  abs x = x

  negate _ = error "Peano numbers cannot be negative"

  signum Zero = 0
  signum _ = 1

newtype Bag a = Bag {getBag :: a -> Count}

instance Ord a => Semigroup (Bag a) where
  Bag f <> Bag g = Bag (\i -> f i + g i)

instance Ord a => Monoid (Bag a) where
  mempty = Bag (\_ -> Zero)
  mappend = (<>)

maximumOn :: Ord b => (a -> b) -> [a] -> a
maximumOn f = maximumBy (compare `on` f)

type Stream a = Nat -> a

type Computer' i o = Stream i -> Stream o

{------------------------------------------------------------------------}

{- Where m is an instance of the Distribution monad -}
type Function i o = i -> o

-- Operationally, a network is lazy distributed speculative execution. But we
-- don't need to think in these terms because we know that Bags support
-- commutative addition, meaning they can arrive in any order (commutativity)
-- and any time (associativity).
type Machine i o = i -> o

type Network i o = (Node -> Machine i o) -> i -> Bag o

-- convolution :: (Monoid m, Semiring s) => (m -> s) -> (m -> s) -> m -> s
-- convolution f g = \m -> foldl' (+) 0 [f x * g y | (x, y) <- split m]

recognizer ::
  Monoid m =>
  (m -> [(m, m)]) ->
  (m -> Bool) ->
  (m -> Bool) ->
  m ->
  Bool
recognizer split f g = \m -> any id [f x && g y | (x, y) <- split m]

-- for language, summation is or and multiplication is conjunction
consensus :: (Bounded o, Enum o) => Bag o -> Maybe o
consensus (Bag bag) =
  let answers = [(i, bag i) | i <- [minBound .. maxBound]]
      sz = sum (Prelude.map snd answers) -- network size
      (o, c) = maximumOn snd answers
   in if c * 2 > sz * 3
        then Just o
        else Nothing

type Computer i o = Network i o -> Maybe o

denote ::
  (Bounded o, Enum o) =>
  (Node -> Machine i o) ->
  Network i o ->
  Function i o
denote ps n = \i -> fromMaybe undefined (consensus (n ps i))

{------------------------------------------------------------------------}

-- Note that as time advances, members can only be added to the Bag

{-
-- The Probability here is a chance that:

-- 1. The node produced the wrong answer
-- 2. The answer was not received within the time bound

Cheating the system is prohibitively expensive;

Agreed upon results are authoritatively published in the form of
a unidirectionally growing and non-mutable "blockchain".

meaning_of_consensus =
  1. progress random beacon

  2. [proposals]
       -> choose proposal
       -> notarize chosen proposal (if network agrees)
       -> finalize chosen proposal (if network agrees)
-}

type Hash = ()

type Signed a = a

-- A blockchain is a list that forgets the parentage of each cons, while
-- retaining a "fingerprint" of what that parent data used to be. So in effect
-- it optimizes eliding the entirety of the list in a secure manner. And since
-- this is purely an optimization -- of not having to always represent all
-- known information -- we leave it as a refinement of the denotation.
--
-- Another way to describe this is that it allows for an incremental
-- description of information, based on what two participants have agreed upon
-- about the past.
data Blockchain a
  = Genesis
  | Block
      { parent :: Hash,
        value :: a
      }

-- Signatures are used to reward block proposers and verify authenticity.
data SignBlockchain a = Blockchain (Signed (Hash, a), a)

type UntrustedNetwork i o = Network (Signed i) (Signed o)
