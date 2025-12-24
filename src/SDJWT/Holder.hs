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
--       -- Select only specific disclosures
--       case selectDisclosuresByNames sdjwt ["given_name"] of
--         Right presentation -> do
--           -- Optionally add key binding
--           keyPair <- generateTestEd25519KeyPair
--           result <- addKeyBinding presentation (privateKeyJWK keyPair) "verifier.example.com" "nonce123" 1234567890
--           case result of
--             Right presentationWithKB -> do
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

