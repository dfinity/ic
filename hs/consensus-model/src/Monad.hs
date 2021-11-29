{-# LANGUAGE ImplicitParams #-}

module Monad where

import Consensus
import Control.Monad
import Control.Monad.Trans.Class
import Control.Monad.Trans.State
import Data.Function
import Data.Functor.Identity
import Data.List.Safe as Safe
import Genesis
import Lib
import Test.Tasty.HUnit hiding (assert)
import Types
import Utils
import Prelude hiding (round)

------------------------------------------------------------------------------
-- CONSENSUS MONAD
------------------------------------------------------------------------------

data Context = Context
  { ctx_config :: Config,
    ctx_pool :: ConsensusPool,
    ctx_time :: Time
  }

type Consensus m = StateT Context m

runConsensus ::
  (Monad m, ?topo :: Topology) =>
  Config ->
  Time ->
  Consensus m a ->
  m a
runConsensus cfg@(this, _) t action =
  evalStateT action (Context cfg (initial_pool this t) t)

-- The function of 'changes' is two-fold:
--
-- 1. Declaratively check that 'on_state_change' applied to the current pool
--    (which is kept within the state of the Consensus monad) implies the
--    given list of changes exactly.
--
-- 2. If the list of changes indeed checks out (and it is a testing error if
--    not), commit those changes to the pool by "executing" them, and advance
--    time forward.
--
-- Thus, 'changes' is both a confirmation of the expectation state of affairs
-- with regard to the current pool, and it also applies those changes and
-- advances the clock.
changes :: (?topo :: Topology) => [ChangeAction] -> Consensus IO ()
changes xs = do
  Context cfg p t <- get
  lift $ on_state_change cfg p t @?= xs
  void commit
  tick

apply :: Monad m => (?topo :: Topology) => [ChangeAction] -> Consensus m ()
apply change_actions = modify $ \ctx ->
  ctx
    { ctx_pool =
        foldl'
          (apply_change (ctx_time ctx))
          (ctx_pool ctx)
          change_actions
    }

commit :: Monad m => (?topo :: Topology) => Consensus m [ChangeAction]
commit = do
  Context cfg p t <- get
  let change_actions = on_state_change cfg p t
  apply change_actions
  pure change_actions

post :: Monad m => ConsensusMessage -> Consensus m ()
post msg = modify $ \ctx ->
  ctx {ctx_pool = add_to_unvalidated_pool (ctx_time ctx) (ctx_pool ctx) msg}

tick :: Monad m => Consensus m ()
tick = do
  t <- get_time
  set_time (t ^+ 3)

get_time :: Monad m => Consensus m Time
get_time = gets ctx_time

set_time :: Monad m => Time -> Consensus m ()
set_time t = modify $ \ctx -> ctx {ctx_time = t}

get_pool :: Monad m => (?topo :: Topology) => Consensus m ConsensusPool
get_pool = gets ctx_pool

modifyBlocks :: Monad m => (Block -> Block) -> Consensus m ()
modifyBlocks f =
  modify $ \(Context cfg p t) ->
    Context
      cfg
      ( runIdentity
          ( blocks
              ( \b ->
                  Identity (f b)
              )
              p
          )
      )
      t

modifyRandomBeacons ::
  Monad m =>
  (RandomBeacon -> RandomBeacon) ->
  Consensus m ()
modifyRandomBeacons f =
  modify $ \(Context cfg p t) ->
    Context
      cfg
      ( runIdentity
          ( randomBeacons
              ( \b ->
                  Identity (f b)
              )
              p
          )
      )
      t
