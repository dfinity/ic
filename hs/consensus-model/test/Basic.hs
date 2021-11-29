{-# LANGUAGE ImplicitParams #-}
{-# LANGUAGE OverloadedStrings #-}

module Basic where

import Codec.Candid
import Consensus
import Control.Monad
import Control.Monad.Trans.Class
import qualified Crypto.Sign.Ed25519 as Ed25519
import Data.Function
import Data.List.Safe as Safe
import qualified Data.Map as M
import Genesis
import Lib
import Monad
import Test.Tasty.HUnit hiding (assert)
import Types
import Utils
import Prelude hiding (round)

test_initial_pool :: Assertion
test_initial_pool = do
  this <- register_node (Principal "node")
  let (topo, _cfg) =
        create_topology $
          M.insert (Principal "subnet") [this] M.empty
  let ?topo = topo
  let pool = initial_pool this 0

  -- Make sure the basics work
  let msg = Ed25519.sign (replica_sk this) "Hello world"
  Ed25519.verify (replica_pk this) msg @?= True

  assertEqual
    "random_beacon_height"
    (random_beacon_height (validated pool))
    (Just 0)
  assertEqual
    "notarized_height"
    (notarized_height (validated pool))
    (Just 0)
  assertEqual
    "finalized_height"
    (finalized_height (validated pool))
    (Just 0)
  assertEqual
    "current_round"
    (current_round (validated pool))
    (Just 1)
  assertEqual
    "round_start_time"
    (round_start_time (validated pool) 1)
    (Just 0)

  let [(initial_beacon, _)] = all_validated_beacons (validated pool)
      [(initial_block, _)] = all_validated_blocks (validated pool)
      block' = Block 1 (hash_block initial_block) 0 (Payload "")
      proposal = create_block_proposal this block'

  on_state_change (this, (Principal "")) (initial_pool this 0) (0 ^+ 3)
    @?= [ AddToValidated
            ( RandomBeaconShareMsg
                (create_random_beacon_share this initial_beacon)
            ),
          AddToValidated
            ( BlockProposalMsg
                proposal
            )
        ]

-- This test confirms that the essential behaviors of on_state_change are
-- working as expected over several rounds. It does not check for nodes
-- signing other blocks than the one proposed by the current node, but only
-- checks the "happy path" of a network that advances in constant mutual
-- agreement based on a single proposer.
test_on_state_change :: Assertion
test_on_state_change = do
  -- Create the topology for this test of consensus
  these <-
    register_nodes
      [ Principal "node1",
        Principal "node2",
        Principal "node3",
        Principal "node4"
      ]
  let (topo, cfg@(this, _)) =
        create_topology $
          M.insert (Principal "subnet") these M.empty
  let ?topo = topo

  runConsensus cfg 0 $ do
    pool' <- get_pool

    let [(initial_block, _)] = all_validated_blocks (validated pool')
        [(initial_beacon, _)] = all_validated_beacons (validated pool')

        reg_version :: RegistryVersion
        reg_version = "0.1.0"

    (\f -> foldM_ f (initial_beacon, initial_block) [1 .. 10]) $
      \(beacon, block) height -> do
        pool'' <- get_pool
        let Just rnd = current_round (validated pool'')
        lift $ assertEqual "at correct height" height rnd

        let beacon_hash = hash_random_beacon beacon
            next_block = Block height (hash_block block) 0 (Payload "")
            proposal = create_block_proposal this next_block
            next_block_hash = hash_block next_block

        ------------------------------------------------------------------------
        -- Block Proposal
        --
        -- As a round begins, the first two things our node will do is:
        --
        -- 1. Offer a signature share for the next random beacon -- which is
        --    needed so that new block proposals can be made once the current
        --    round has been notarized;
        --
        -- 2. Offer a block proposal using the current random beacon and some
        --    subset of the ingress messages waiting in the inbound queue.
        ------------------------------------------------------------------------

        -- The 'changes' function could more accurately have been named:
        --   confirmChangesAndIfTheyMatchCommitToThePoolAndAdvanceTime
        changes
          [ -- Every node will attempt to sign the next random beacon, if it
            -- has not already.
            AddToValidated
              ( RandomBeaconShareMsg
                  (create_random_beacon_share this beacon)
              ),
            -- Every node will also attempt to propose a block, although it
            -- may be the case that those very low in rank might only do so
            -- part of the time, (2020-11-16): but that's not how the
            -- consensus algorithm is specified at the moment.
            AddToValidated (BlockProposalMsg proposal)
          ]

        ------------------------------------------------------------------------
        -- Notarization
        --
        -- Whenever a proposal exists in the pool that we have not yet
        -- notarized -- including our own -- then if we are a member of the
        -- notirization committee for this round, offer a notarization share
        -- containing our signature applied to this block. NOTE: For the sake
        -- of testing, we are always part of the committee.
        --
        -- We then expect more notarization shares to come in from other
        -- nodes, possibly for other block proposals, and whenever the number
        -- of shares is above the committee threshold, we aggregate the shares
        -- and gossip the resulting notarization.
        --
        -- Once a block has been notarized, and the next random beacon has
        -- been agreed upon, proposals may be created for the next round. This
        -- means we may have several notarized blocks in the validated pool
        -- before we begin seeing finalizations for them; and some may never
        -- reach finalization.
        ------------------------------------------------------------------------

        let nota_share i =
              NotarizationShare
                { ns_replicaId = i,
                  ns_height = height,
                  ns_block = next_block_hash,
                  ns_notarizationShareSignature =
                    sign_notarization_share i reg_version height next_block_hash
                }

        -- Advance time forward and commit those changes, then check that the
        -- resulting pool implies a new set of changes.
        changes
          [ AddToValidated (NotarizationShareMsg (nota_share this))
          ]

        changes []

        -- Just confirming here that without further input from the network
        -- neighborhood, this node would get "stuck" waiting for new
        -- information from the gossip network.
        changes []
        changes []
        changes []
        changes []
        changes []

        forM_ (Prelude.tail replicas) $ \i ->
          -- Calling 'post' here is equivalent to receiving artifact messages
          -- from the network neighborhood via gossip.
          post $ NotarizationShareMsg (nota_share i)

        -- This call to 'commit' moves all the unvalidated messages that were
        -- just posted into the validated pol, provided their signature checks
        -- match.
        void commit

        let signers =
              Prelude.tail replicas
                ++ [Prelude.head replicas]
            nota =
              Notarization
                { n_replicaIds = signers,
                  n_height = height,
                  n_block = next_block_hash,
                  n_notarizationSignature =
                    sign_notarization signers reg_version height next_block_hash
                }

        changes
          [ AddToValidated (NotarizationMsg nota)
          ]

        ------------------------------------------------------------------------
        -- Finalization
        --
        -- Analogous to notarization, whenever we have a notarization in hand
        -- for a given block proposal, we offer a signature share toward
        -- finalization of that block. If we have multiple notarizations in
        -- the same round, we offer to finalize the "best" notarized block.
        --
        -- Once we received enough finalization shares from the rest of the
        -- network, beyond the committee threshold, we aggregate the shares to
        -- create a finalization signature and gossip this to the network.
        ------------------------------------------------------------------------

        let fin_share i =
              FinalizationShare
                { fs_replicaId = i,
                  fs_height = height,
                  fs_block = next_block_hash,
                  fs_finalizationShareSignature =
                    sign_finalization_share i reg_version height next_block_hash
                }

        changes
          [ AddToValidated (FinalizationShareMsg (fin_share this))
          ]

        changes []

        forM_ (Prelude.tail replicas) $ \i ->
          post $ FinalizationShareMsg (fin_share i)
        void commit

        let fina =
              Finalization
                { f_replicaIds = signers,
                  f_height = height,
                  f_block = next_block_hash,
                  f_finalizationSignature =
                    sign_finalization signers reg_version height next_block_hash
                }

        changes
          [ AddToValidated (FinalizationMsg fina)
          ]

        -- There is no new block proposal here! because we never saw the
        -- shares needed to advance the random beacon, and thus don't have the
        -- necessary bits to create the TLS share for the next block.
        changes []

        ------------------------------------------------------------------------
        -- Random Beacon
        --
        -- Similar to how notarizations and finalizations are constructed by
        -- aggregating signature shares received from the network, we also
        -- construct the next random beacon using a similar scheme, except
        -- this is constructed by the random beacon committee rather than the
        -- notarization committee. NOTE: For the sake of testing, all nodes
        -- are also part of the random beacon committee.
        --
        -- Once the random beacon is known at height H, we will create block
        -- proposals -- if we have not done so already -- once we have at
        -- least one notarized block for that height as well. It doesn't
        -- happen below, but on the next round once the new random beacon has
        -- been committed to the pool.
        ------------------------------------------------------------------------

        let rb_share i =
              RandomBeaconShare
                { rbs_replicaId = i,
                  rbs_height = height,
                  rbs_parent = beacon_hash,
                  rbs_randomBeaconShareSignature =
                    sign_random_beacon_share i 0 {- DkgId -} height beacon_hash
                }

        forM_ (Prelude.tail replicas) $ \i ->
          post $ RandomBeaconShareMsg (rb_share i)
        void commit

        let next_beacon =
              RandomBeacon
                { rb_height = height,
                  rb_parent = beacon_hash,
                  rb_randomBeaconSignature =
                    sign_random_beacon signers 0 height beacon_hash
                }

        changes
          [ AddToValidated (RandomBeaconMsg next_beacon)
          ]

        pure (next_beacon, next_block)
