{-# LANGUAGE OverloadedStrings #-}
-- | Convenience module for SD-JWT holders.
--
-- This module provides everything needed to receive SD-JWTs and create
-- presentations. It exports a focused API for the holder role, excluding
-- modules that holders don't need (like Issuance and Verification).
--
-- == Usage
--
-- For holders, import this module:
--
-- @
-- import SDJWT.Holder
-- @
--
-- This gives you access to:
--
-- * Core data types (HashAlgorithm, SDJWT, SDJWTPresentation, etc.)
-- * Serialization functions ('deserializeSDJWT', 'serializePresentation')
-- * Presentation functions ('selectDisclosuresByNames')
-- * Key binding functions ('addKeyBindingToPresentation')
--
-- == Creating Presentations
--
-- The main workflow for holders is:
--
-- @
-- -- 1. Deserialize SD-JWT received from issuer
-- case deserializeSDJWT sdjwtText of
--   Right sdjwt -> do
--     -- 2. Select which disclosures to include
--     case selectDisclosuresByNames sdjwt ["given_name", "email"] of
--       Right presentation -> do
--         -- 3. Optionally add key binding for proof of possession
--         holderPrivateKeyJWK <- loadPrivateKeyJWK
--         let audience = "verifier.example.com"
--         let nonce = "random-nonce-12345"
--         let issuedAt = 1683000000 :: Int64
--         -- Optional: Add standard JWT claims like exp (expiration time) to KB-JWT
--         -- These claims will be automatically validated during verification if present
--         let expirationTime = issuedAt + 3600  -- 1 hour from issued time
--         let optionalClaims = Aeson.object [("exp", Aeson.Number (fromIntegral expirationTime))]
--         kbResult <- addKeyBindingToPresentation SHA256 holderPrivateKeyJWK audience nonce issuedAt presentation optionalClaims
--         case kbResult of
--           Right presentationWithKB -> do
--             -- 4. Serialize presentation to send to verifier
--             let serialized = serializePresentation presentationWithKB
--             -- Send serialized presentation...
--           Left err -> -- Handle error
--       Left err -> -- Handle error
--   Left err -> -- Handle error
-- @
--
-- == Optional Claims in KB-JWT
--
-- The @optionalClaims@ parameter allows adding standard JWT claims (RFC 7519) to the KB-JWT,
-- such as @exp@ (expiration time) or @nbf@ (not before). These claims will be automatically
-- validated during verification if present. Pass @Aeson.object []@ for no additional claims.
-- Note: RFC 9901 Section 4.3 states that additional claims SHOULD be avoided unless there is
-- a compelling reason, as they may harm interoperability.
--
-- For advanced use cases (e.g., creating presentations manually or computing
-- SD hash separately), import 'SDJWT.Internal.Presentation' or
-- 'SDJWT.Internal.KeyBinding' to access additional low-level functions.
module SDJWT.Holder
  ( -- * Core Types
    module SDJWT.Internal.Types
    -- * Serialization
  , deserializeSDJWT
  , serializePresentation
    -- * Presentation
    -- | Functions for creating SD-JWT presentations with selected disclosures.
  , selectDisclosuresByNames
    -- * Key Binding
    -- | Functions for adding key binding to presentations (SD-JWT+KB).
  , addKeyBindingToPresentation
  ) where

import SDJWT.Internal.Types
import SDJWT.Internal.Serialization
  ( deserializeSDJWT
  , serializePresentation
  )
import SDJWT.Internal.Presentation
  ( selectDisclosuresByNames
  )
import SDJWT.Internal.KeyBinding
  ( addKeyBindingToPresentation
  )

