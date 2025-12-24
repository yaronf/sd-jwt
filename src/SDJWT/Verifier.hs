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
-- * 'SDJWT.Internal.Types' - Core data types
-- * 'SDJWT.Internal.Serialization' - Deserialize presentations
-- * 'SDJWT.Internal.Verification' - Verify SD-JWTs and extract claims
-- * 'SDJWT.Internal.KeyBinding' - Verify key binding (SD-JWT+KB)
--
-- == Example
--
-- @
-- import SDJWT.Verifier
-- import qualified Data.Text as T
--
-- main = do
--   -- Deserialize presentation received from holder
--   let presentationText = "eyJhbGciOiJSUzI1NiJ9.eyJfc2QiOlsidGVzdCJdLCJfc2RfYWxnIjoic2hhLTI1NiJ9.~WyJ0ZXN0Il0~"
--   case deserializePresentation (T.pack presentationText) of
--     Right presentation -> do
--       -- Verify the SD-JWT
--       issuerPublicKey <- loadIssuerPublicKey  -- Your function to load issuer's public key
--       result <- verifySDJWT issuerPublicKey presentation
--       case result of
--         Right processedPayload -> do
--           -- Extract claims
--           let claims = processedClaims processedPayload
--           putStrLn $ "Verified claims: " ++ show claims
--         Left err -> putStrLn $ "Verification failed: " ++ show err
--     Left err -> putStrLn $ "Error: " ++ show err
-- @
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

