module IC.Certificate where

import IC.HashTree

data Certificate = Certificate
  { cert_tree :: HashTree,
    cert_sig :: Blob,
    cert_delegation :: Maybe Delegation
  }
  deriving (Show)

data Delegation = Delegation
  { del_subnet_id :: Blob,
    del_certificate :: Blob
  }
  deriving (Show)
