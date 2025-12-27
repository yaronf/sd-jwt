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
-- * Helper functions ('addHolderKeyToClaims')
--
-- == Creating SD-JWTs
--
-- The main function for creating SD-JWTs is 'createSDJWT':
--
-- @
-- -- Create SD-JWT without typ or kid headers
-- result <- createSDJWT Nothing Nothing SHA256 issuerKey ["given_name", "family_name"] claims
--
-- -- Create SD-JWT with typ header (recommended)
-- result <- createSDJWT (Just "sd-jwt") Nothing SHA256 issuerKey ["given_name", "family_name"] claims
--
-- -- Create SD-JWT with typ and kid headers
-- result <- createSDJWT (Just "sd-jwt") (Just "key-1") SHA256 issuerKey ["given_name"] claims
-- @
--
-- == Standard JWT Claims
--
-- Standard JWT claims (RFC 7519) can be included in the @claims@ map and will be preserved
-- in the issuer-signed JWT payload. During verification, standard claims like @exp@ (expiration time)
-- and @nbf@ (not before) are automatically validated if present. See RFC 9901 Section 4.1.
--
-- @
-- -- Create SD-JWT with expiration time
-- let expirationTime = currentTime + 3600  -- 1 hour from now
-- let claimsWithExp = Map.insert "exp" (Aeson.Number (fromIntegral expirationTime)) claims
-- result <- createSDJWT (Just "sd-jwt") Nothing SHA256 issuerKey ["given_name"] claimsWithExp
-- @
--
-- == JWT Headers
--
-- Both @typ@ and @kid@ headers are supported natively through jose's API:
--
-- * @typ@: Recommended by RFC 9901 Section 9.11 for explicit typing (e.g., "sd-jwt")
-- * @kid@: Key ID for key management (useful when rotating keys)
--
-- == Decoy Digests
--
-- To add decoy digests (to obscure the number of selectively disclosable claims),
-- use 'createSDJWTWithDecoys':
--
-- @
-- -- Create SD-JWT with 5 decoy digests, no typ or kid headers
-- result <- createSDJWTWithDecoys Nothing Nothing SHA256 issuerKey ["given_name", "email"] claims 5
--
-- -- Create SD-JWT with 5 decoy digests and typ header
-- result <- createSDJWTWithDecoys (Just "sd-jwt") Nothing SHA256 issuerKey ["given_name", "email"] claims 5
--
-- -- Create SD-JWT with 5 decoy digests, typ and kid headers
-- result <- createSDJWTWithDecoys (Just "sd-jwt") (Just "key-1") SHA256 issuerKey ["given_name"] claims 5
-- @
--
-- For advanced use cases (e.g., adding decoys to nested @_sd@ arrays or custom
-- placement logic), import 'SDJWT.Internal.Issuance' to access 'buildSDJWTPayload'
-- and other low-level functions.
--
-- == Key Binding Support
--
-- To include the holder's public key in the SD-JWT (for key binding), use
-- 'addHolderKeyToClaims' to add the @cnf@ claim:
--
-- @
-- let holderPublicKeyJWK = "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"...\",\"y\":\"...\"}"
-- let claimsWithCnf = addHolderKeyToClaims holderPublicKeyJWK claims
-- result <- createSDJWT (Just "sd-jwt") SHA256 issuerKey ["given_name"] claimsWithCnf
-- @
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
    -- * Helper Functions
    -- | Convenience functions for common operations.
  , addHolderKeyToClaims
  ) where

import SDJWT.Internal.Types
import SDJWT.Internal.Serialization
import SDJWT.Internal.Issuance
  ( createSDJWT
  , createSDJWTWithDecoys
  , addHolderKeyToClaims
  )

