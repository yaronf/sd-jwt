{-# LANGUAGE OverloadedStrings #-}
-- | Convenience module for SD-JWT issuers.
--
-- This module re-exports everything needed to create and issue SD-JWTs.
-- It provides a focused API for the issuer role, excluding modules
-- that issuers don't need (like Presentation and Verification).
--
-- == Security Warning: EC Signing Timing Attack
--
-- ⚠️ When using Elliptic Curve (EC) keys (ES256 algorithm), be aware that the
-- underlying @jose@ library's EC signing implementation may be vulnerable to
-- timing attacks. This affects /signing only/, not verification.
--
-- For applications where timing attacks are a concern, consider using RSA (RS256)
-- or Ed25519 (EdDSA) keys instead, which do not have this limitation.
--
-- == Usage
--
-- For issuers, import this module instead of the main 'SDJWT' module:
--
-- @
-- import SDJWT.Issuer
-- @
--
-- This gives you access to:
-- * 'SDJWT.Internal.Types' - Core data types
-- * 'SDJWT.Internal.Serialization' - Serialize SD-JWTs for transmission
-- * 'SDJWT.Internal.Issuance' - Create SD-JWTs from claims
--
-- == Example
--
-- @
-- import SDJWT.Issuer
-- import qualified Data.Map.Strict as Map
-- import qualified Data.Aeson as Aeson
--
-- main = do
--   let claims = Map.fromList
--         [ ("sub", Aeson.String "user_123")
--         , ("given_name", Aeson.String "John")
--         , ("family_name", Aeson.String "Doe")
--         ]
--   keyPair <- generateTestRSAKeyPair  -- From TestKeys module
--   result <- createSDJWT SHA256 (privateKeyJWK keyPair) ["given_name", "family_name"] claims
--   case result of
--     Right sdjwt -> do
--       let serialized = serializeSDJWT sdjwt
--       putStrLn $ "SD-JWT: " ++ T.unpack serialized
--     Left err -> putStrLn $ "Error: " ++ show err
-- @
module SDJWT.Issuer
  ( module SDJWT.Internal.Types
  , module SDJWT.Internal.Serialization
  , module SDJWT.Internal.Issuance
  ) where

import SDJWT.Internal.Types
import SDJWT.Internal.Serialization
import SDJWT.Internal.Issuance

