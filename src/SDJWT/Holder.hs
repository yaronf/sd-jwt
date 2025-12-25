{-# LANGUAGE OverloadedStrings #-}
-- | Convenience module for SD-JWT holders.
--
-- This module re-exports everything needed to receive SD-JWTs and create
-- presentations. It provides a focused API for the holder role, excluding
-- modules that holders don't need (like Issuance and Verification).
--
-- == Usage
--
-- For holders, import this module instead of the main 'SDJWT' module:
--
-- @
-- import SDJWT.Holder
-- @
--
-- This gives you access to:
--
-- * 'SDJWT.Internal.Types' - Core data types
-- * 'SDJWT.Internal.Serialization' - Deserialize SD-JWTs and serialize presentations
-- * 'SDJWT.Internal.Presentation' - Select disclosures and create presentations
-- * 'SDJWT.Internal.KeyBinding' - Add key binding to presentations (SD-JWT+KB)
--
-- == Example
--
-- @
-- import SDJWT.Holder
-- import qualified Data.Text as T
--
-- main = do
--   -- Deserialize SD-JWT received from issuer
--   let sdjwtText = "eyJhbGciOiJSUzI1NiJ9.eyJfc2QiOlsidGVzdCJdLCJfc2RfYWxnIjoic2hhLTI1NiJ9.~WyJ0ZXN0Il0~"
--   case deserializeSDJWT (T.pack sdjwtText) of
--     Right sdjwt -> do
--       -- Select which disclosures to include in the presentation
--       -- The holder chooses which claims to reveal (e.g., only "given_name", not "family_name")
--       case selectDisclosuresByNames sdjwt ["given_name"] of
--         Right presentation -> do
--           -- The presentation contains:
--           -- - presentationJWT: The issuer-signed JWT (with digests)
--           -- - selectedDisclosures: Only the disclosures for selected claims
--           -- Optionally add key binding for proof of possession
--           keyPair <- generateTestEd25519KeyPair
--           result <- addKeyBinding SHA256 (privateKeyJWK keyPair) "verifier.example.com" "nonce123" 1234567890 presentation
--           case result of
--             Right presentationWithKB -> do
--               -- Serialize: JWT~disclosure1~disclosure2~...~KB-JWT
--               -- This includes both the issuer-signed JWT and the selected disclosures
--               let serialized = serializePresentation presentationWithKB
--               putStrLn $ "Presentation: " ++ T.unpack serialized
--             Left err -> putStrLn $ "Error: " ++ show err
--         Left err -> putStrLn $ "Error: " ++ show err
--     Left err -> putStrLn $ "Error: " ++ show err
-- @
module SDJWT.Holder
  ( module SDJWT.Internal.Types
  , module SDJWT.Internal.Serialization
  , module SDJWT.Internal.Presentation
  , module SDJWT.Internal.KeyBinding
  ) where

import SDJWT.Internal.Types
import SDJWT.Internal.Serialization
import SDJWT.Internal.Presentation
import SDJWT.Internal.KeyBinding

