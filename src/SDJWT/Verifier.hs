{-# LANGUAGE OverloadedStrings #-}
-- | Convenience module for SD-JWT verifiers.
--
-- This module provides everything needed to verify SD-JWT presentations
-- and extract claims. It exports a focused API for the verifier role,
-- excluding modules that verifiers don't need (like Issuance and Presentation).
--
-- == Usage
--
-- For verifiers, import this module:
--
-- @
-- import SDJWT.Verifier
-- @
--
-- This gives you access to:
--
-- * Core data types (HashAlgorithm, SDJWTPresentation, ProcessedSDJWTPayload, etc.)
-- * Serialization functions ('deserializePresentation')
-- * Verification functions ('verifySDJWT')
--
-- == Verifying SD-JWTs
--
-- The main function for verifying SD-JWT presentations is 'verifySDJWT':
--
-- @
-- -- Verify SD-JWT presentation (includes signature, disclosures, and key binding verification)
-- result <- verifySDJWT issuerPublicKey presentation Nothing
-- case result of
--   Right processedPayload -> do
--     let claims = processedClaims processedPayload
--     -- Use verified claims...
--     -- If key binding was present, access the holder's public key:
--     case keyBindingInfo processedPayload of
--       Just kbInfo -> 
--         let holderPublicKey = kbPublicKey kbInfo
--         -- Use holder's public key for subsequent operations...
--       Nothing -> -- No key binding present
--   Left err -> -- Handle error
-- @
--
-- For advanced use cases (e.g., verifying key binding separately or parsing payloads),
-- import 'SDJWT.Internal.Verification' to access additional low-level functions.
--
-- == Example
--
-- >>> :set -XOverloadedStrings
-- >>> import SDJWT.Verifier
-- >>> import qualified Data.Text as T
-- >>> -- Deserialize presentation received from holder
-- >>> -- let presentationText = "eyJhbGciOiJSUzI1NiJ9..."
-- >>> -- case deserializePresentation (T.pack presentationText) of
-- >>> --   Right presentation -> do
-- >>> --     issuerPublicKeyJWK <- loadPublicKeyJWK
-- >>> --     verifySDJWT issuerPublicKeyJWK presentation Nothing
-- >>> --   Left err -> Left err
-- >>> -- Extract claims (includes both regular claims and disclosed claims)
-- >>> -- let claims = processedClaims processedPayload
module SDJWT.Verifier
  ( -- * Core Types
    module SDJWT.Internal.Types
    -- * Serialization
  , module SDJWT.Internal.Serialization
    -- * Verification
    -- | Functions for verifying SD-JWT presentations.
  , verifySDJWT
  ) where

import SDJWT.Internal.Types
import SDJWT.Internal.Serialization
import SDJWT.Internal.Verification
  ( verifySDJWT
  )

