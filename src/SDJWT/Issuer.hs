{-# LANGUAGE OverloadedStrings #-}
-- | Convenience module for SD-JWT issuers.
--
-- This module provides everything needed to create and issue SD-JWTs.
-- It exports a focused API for the issuer role, excluding modules
-- that issuers don't need (like Presentation and Verification).
--
-- == Security Warning: EC Signing Timing Attack
--
-- ⚠️ When using Elliptic Curve (EC) keys (ES256 algorithm), be aware that the
-- underlying @jose@ library's EC signing implementation may be vulnerable to
-- timing attacks. This affects /signing only/, not verification.
--
-- For applications where timing attacks are a concern, consider using RSA-PSS (PS256)
-- or Ed25519 (EdDSA) keys instead, which do not have this limitation.
--
-- Note: RS256 (RSA-PKCS#1 v1.5) is deprecated per draft-ietf-jose-deprecate-none-rsa15
-- due to padding oracle attack vulnerabilities. PS256 (RSA-PSS) is the recommended
-- RSA algorithm and is used by default for RSA keys.
--
-- == Usage
--
-- For issuers, import this module:
--
-- @
-- import SDJWT.Issuer
-- @
--
-- This gives you access to:
--
-- * Core data types (HashAlgorithm, SDJWT, SDJWTPayload, etc.)
-- * Serialization functions ('serializeSDJWT', 'deserializeSDJWT')
-- * Issuance functions ('createSDJWT', 'createSDJWTWithDecoys')
--
-- == Creating SD-JWTs
--
-- The main function for creating SD-JWTs is 'createSDJWT':
--
-- @
-- -- Create SD-JWT without typ header
-- result <- createSDJWT Nothing SHA256 issuerKey ["given_name", "family_name"] claims
--
-- -- Create SD-JWT with typ header (recommended)
-- result <- createSDJWT (Just "sd-jwt") SHA256 issuerKey ["given_name", "family_name"] claims
-- @
--
-- == Decoy Digests
--
-- To add decoy digests (to obscure the number of selectively disclosable claims),
-- use 'createSDJWTWithDecoys':
--
-- @
-- -- Create SD-JWT with 5 decoy digests, no typ header
-- result <- createSDJWTWithDecoys Nothing SHA256 issuerKey ["given_name", "email"] claims 5
--
-- -- Create SD-JWT with 5 decoy digests and typ header
-- result <- createSDJWTWithDecoys (Just "sd-jwt") SHA256 issuerKey ["given_name", "email"] claims 5
-- @
--
-- For advanced use cases (e.g., adding decoys to nested @_sd@ arrays or custom
-- placement logic), import 'SDJWT.Internal.Issuance' to access 'buildSDJWTPayload'
-- and other low-level functions.
--
-- == Example
--
-- >>> :set -XOverloadedStrings
-- >>> import SDJWT.Issuer
-- >>> import qualified Data.Map.Strict as Map
-- >>> import qualified Data.Aeson as Aeson
-- >>> import qualified Data.Text as T
-- >>> let claims = Map.fromList [("sub", Aeson.String "user_123"), ("given_name", Aeson.String "John"), ("family_name", Aeson.String "Doe")]
-- >>> -- Note: In real usage, you would load your private key here
-- >>> -- issuerPrivateKeyJWK <- loadPrivateKeyJWK
-- >>> -- result <- createSDJWT Nothing SHA256 issuerPrivateKeyJWK ["given_name", "family_name"] claims
-- >>> -- case result of Right sdjwt -> serializeSDJWT sdjwt; Left err -> T.pack $ show err
module SDJWT.Issuer
  ( -- * Core Types
    module SDJWT.Internal.Types
    -- * Serialization
  , module SDJWT.Internal.Serialization
    -- * Creating SD-JWTs
    -- | Functions for creating SD-JWTs from claims sets.
  , createSDJWT
  , createSDJWTWithDecoys
  ) where

import SDJWT.Internal.Types
import SDJWT.Internal.Serialization
import SDJWT.Internal.Issuance
  ( createSDJWT
  , createSDJWTWithDecoys
  )

