{-# LANGUAGE OverloadedStrings #-}
-- | Convenience module for SD-JWT verifiers.
--
-- This module re-exports everything needed to verify SD-JWT presentations
-- and extract claims. It provides a focused API for the verifier role,
-- excluding modules that verifiers don't need (like Issuance and Presentation).
--
-- == Usage
--
-- For verifiers, import this module instead of the main 'SDJWT' module:
--
-- @
-- import SDJWT.Verifier
-- @
--
-- This gives you access to:
--
-- * 'SDJWT.Internal.Types' - Core data types
-- * 'SDJWT.Internal.Serialization' - Deserialize presentations
-- * 'SDJWT.Internal.Verification' - Verify SD-JWTs and extract claims
-- * 'SDJWT.Internal.KeyBinding' - Verify key binding (SD-JWT+KB)
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
  ( module SDJWT.Internal.Types
  , module SDJWT.Internal.Serialization
  , module SDJWT.Internal.Verification
  , module SDJWT.Internal.KeyBinding
  ) where

import SDJWT.Internal.Types
import SDJWT.Internal.Serialization
import SDJWT.Internal.Verification
import SDJWT.Internal.KeyBinding

