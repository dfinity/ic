{-# LANGUAGE OverloadedStrings #-}

module IC.Certificate.Validate (validateCertificate) where

import Control.Monad.Error.Class
import qualified Data.ByteString.Lazy as BS
import qualified Data.Text as T
import IC.Certificate
import IC.Certificate.CBOR
import IC.Crypto.DER_BLS
import IC.HashTree hiding (Blob)
import IC.Types
import qualified Text.Hex as H

validateCertificate :: Blob -> Certificate -> Either T.Text ()
validateCertificate = validate' "certificate"

validate' :: T.Text -> Blob -> Certificate -> Either T.Text ()
validate' what root_key cert = do
  pk <- validateDelegation root_key (cert_delegation cert)
  verboseVerify what "ic-state-root" pk (reconstruct (cert_tree cert)) (cert_sig cert)

validateDelegation :: Blob -> Maybe Delegation -> Either T.Text Blob
validateDelegation root_key Nothing = return root_key
validateDelegation root_key (Just del) = do
  cert <- decodeCert (del_certificate del)
  case wellFormed (cert_tree cert) of
    Left err -> throwError $ "Hash tree not well formed: " <> T.pack err
    Right () -> return ()
  validate' "certificate delegation" root_key cert

  case lookupPath (cert_tree cert) ["subnet", del_subnet_id del, "public_key"] of
    Found b -> return b
    x ->
      throwError $
        "Expected to find subnet public key in certificate, "
          <> "but got "
          <> T.pack (show x)

verboseVerify :: T.Text -> Blob -> Blob -> Blob -> Blob -> Either T.Text ()
verboseVerify what domain_sep pk msg sig =
  case verify domain_sep pk msg sig of
    Left err ->
      throwError $
        T.unlines
          [ "Signature verification failed on " <> what,
            err,
            "Domain separator:   " <> T.pack (prettyBlob domain_sep),
            "Public key (DER):   " <> T.pack (asHex pk),
            "Signature:          " <> T.pack (asHex sig),
            "Checked message:    " <> T.pack (prettyBlob msg)
          ]
    Right () -> return ()

asHex :: Blob -> String
asHex = T.unpack . H.encodeHex . BS.toStrict
