{-# LANGUAGE ImplicitParams #-}
{-# LANGUAGE OverloadedStrings #-}

module Genesis where

import Lib
import Types
import Utils
import Prelude hiding (round)

------------------------------------------------------------------------------
-- COMPLIANCE TEST SETUP
------------------------------------------------------------------------------

initial_pool :: (?topo :: Topology) => ReplicaId -> Time -> ConsensusPool
initial_pool this time =
  ( -- Manu: One “initial state” is to start off with a validated pool
    -- containing one height 0 block, one notarization on that block (so
    -- block_hash matches the hash of the block), and one finalization on that
    -- block, and a a height 0 random beacon). That should be enough to get
    -- started
    [ ( BlockProposalMsg
          ( BlockProposal
              this
              (hash_block initial_block)
              initial_block
              initial_block_sig
          ),
        time
      ),
      (NotarizationMsg (create_notarization initial_block), time),
      (FinalizationMsg (create_finalization initial_block), time),
      (RandomBeaconMsg initial_beacon, time)
    ],
    []
  )
  where
    reg_version :: RegistryVersion
    reg_version = "0.1.0"
    initial_block =
      Block
        0 -- Height
        (HashOfBlock (Hash "<genesis>"))
        0 -- slot
        (Payload "")
    initial_block_sig = sign_block this reg_version initial_block
    initial_beacon =
      RandomBeacon
        0 -- Height
        (HashOfRandomBeacon (Hash "<genesis>"))
        ( everyone_sign_random_beacon
            0 -- DkgId
            0 -- Height
            (HashOfRandomBeacon (Hash "<genesis>"))
        )
