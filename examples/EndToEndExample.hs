#!/usr/bin/env stack
-- stack --resolver lts-22.0 runghc --package sd-jwt --package aeson --package text --package bytestring
{-# LANGUAGE OverloadedStrings #-}
-- | Complete end-to-end SD-JWT example demonstrating the full flow:
--   Issuer → Holder → Verifier
--
-- This example shows:
-- 1. Issuer creates an SD-JWT with selective disclosure
-- 2. Holder receives SD-JWT, selects which claims to disclose, and creates a presentation
-- 3. Verifier verifies the presentation and extracts the disclosed claims
--
-- Run with: stack runghc examples/EndToEndExample.hs
-- Or: stack exec -- sd-jwt-example

module Main where

import SDJWT.Issuer
import SDJWT.Holder
import SDJWT.Verifier
import qualified Data.Map.Strict as Map
import qualified Data.Aeson as Aeson
import qualified Data.Text as T
import qualified Data.Text.IO as TIO
import qualified Data.Text.Encoding as TE
import qualified Data.Aeson.Key as Key
import qualified Data.Aeson.KeyMap as KeyMap
import Data.Int (Int64)
import System.IO (hPutStrLn, stderr)

-- For this example, we'll use test keys
-- In production, load keys from secure storage
import qualified Data.ByteString.Lazy as BSL
import System.Directory (doesFileExist)

-- Load test keys (simplified version for example)
-- In production, use proper key management
-- Tries multiple paths to find test-keys.json relative to common execution locations
loadTestKeys :: IO Aeson.Value
loadTestKeys = do
  -- Try multiple possible paths (relative to current working directory)
  let possiblePaths = 
        [ "test/test-keys.json"           -- From project root
        , "../test/test-keys.json"        -- From examples/ directory
        , "../../test/test-keys.json"      -- From deeper nested location
        ]
  
  -- Find the first path that exists
  existingPath <- findExistingPath possiblePaths
  case existingPath of
    Just path -> do
      contents <- BSL.readFile path
      case Aeson.eitherDecode contents of
        Left err -> error $ "Failed to load test keys from " ++ path ++ ": " ++ err
        Right val -> return val
    Nothing -> error $ "Could not find test/test-keys.json. Tried:\n" ++ 
                       unlines (map ("  - " ++) possiblePaths) ++
                       "\nMake sure you're running from the project root or that test/test-keys.json exists."

-- Helper to find the first existing path
findExistingPath :: [FilePath] -> IO (Maybe FilePath)
findExistingPath [] = return Nothing
findExistingPath (path:paths) = do
  exists <- doesFileExist path
  if exists
    then return (Just path)
    else findExistingPath paths

getKey :: Aeson.Value -> T.Text -> T.Text -> T.Text
getKey keys keyType keyKind =
  case keys of
    Aeson.Object obj -> case KeyMap.lookup (Key.fromText keyType) obj of
      Just (Aeson.Object keyObj) -> case KeyMap.lookup (Key.fromText keyKind) keyObj of
        Just (Aeson.String keyText) -> keyText
        _ -> error $ "Missing " ++ T.unpack keyKind ++ " key for " ++ T.unpack keyType
      _ -> error $ "Missing " ++ T.unpack keyType ++ " key section"
    _ -> error "test-keys.json is not an object"

main :: IO ()
main = do
  putStrLn "============================================"
  putStrLn "SD-JWT End-to-End Example"
  putStrLn "============================================"
  putStrLn ""
  
  -- Load test keys
  testKeys <- loadTestKeys
  let issuerPrivateKey = getKey testKeys "rsa" "private"
  let issuerPublicKey = getKey testKeys "rsa" "public"
  let holderPrivateKey = getKey testKeys "ed25519" "private"
  let holderPublicKeyJWK = getKey testKeys "ed25519" "public"
  
  putStrLn "STEP 1: ISSUER CREATES SD-JWT"
  putStrLn "--------------------------------------------"
  
  -- Parse holder's public key JWK as JSON for cnf claim
  -- The cnf (confirmation) claim contains the holder's public key
  -- This is required for key binding (SD-JWT+KB)
  let holderPublicKeyJSON = case Aeson.eitherDecodeStrict (TE.encodeUtf8 holderPublicKeyJWK) of
        Right jwk -> jwk
        Left _ -> Aeson.Object KeyMap.empty  -- Fallback (shouldn't happen)
  let cnfValue = Aeson.Object $ KeyMap.fromList [(Key.fromText "jwk", holderPublicKeyJSON)]
  
  -- Issuer prepares claims
  -- Note: The cnf claim contains the holder's public key for key binding
  let issuerClaims = Map.fromList
        [ ("sub", Aeson.String "user_123")
        , ("given_name", Aeson.String "John")
        , ("family_name", Aeson.String "Doe")
        , ("email", Aeson.String "john.doe@example.com")
        , ("phone", Aeson.String "+1-555-1234")
        , ("age", Aeson.Number 30)
        , ("cnf", cnfValue)  -- Confirmation claim with holder's public key
        ]
  
  putStrLn "Issuer claims:"
  mapM_ (\(k, v) -> 
    if k == "cnf"
      then putStrLn $ "  - " ++ T.unpack k ++ ": {jwk: <holder's public key>}"
      else putStrLn $ "  - " ++ T.unpack k ++ ": " ++ show v
    ) (Map.toList issuerClaims)
  putStrLn ""
  
  -- Issuer marks some claims as selectively disclosable
  -- Only "given_name", "family_name", and "email" can be selectively disclosed
  -- "sub", "phone", "age", and "cnf" remain visible to all (regular claims)
  putStrLn "Selectively disclosable claims: given_name, family_name, email"
  putStrLn "Regular claims (always visible): sub, phone, age, cnf"
  putStrLn "  (cnf contains holder's public key for key binding)"
  putStrLn ""
  
  -- Issuer creates SD-JWT
  issuerResult <- createSDJWT SHA256 issuerPrivateKey 
                                ["given_name", "family_name", "email"] 
                                issuerClaims
  
  case issuerResult of
    Left err -> do
      hPutStrLn stderr $ "ERROR: Failed to create SD-JWT: " ++ show err
      return ()
    Right sdjwt -> do
      -- Serialize SD-JWT for transmission
      let serializedSDJWT = serializeSDJWT sdjwt
      putStrLn "✓ SD-JWT created successfully"
      putStrLn $ "  Serialized length: " ++ show (T.length serializedSDJWT) ++ " characters"
      putStrLn ""
      
      putStrLn "============================================"
      putStrLn "STEP 2: HOLDER RECEIVES AND CREATES PRESENTATION"
      putStrLn "--------------------------------------------"
      
      -- Holder receives the SD-JWT and deserializes it
      case deserializeSDJWT serializedSDJWT of
        Left err -> do
          hPutStrLn stderr $ "ERROR: Failed to deserialize SD-JWT: " ++ show err
          return ()
        Right receivedSDJWT -> do
          putStrLn "✓ SD-JWT deserialized successfully"
          putStrLn ""
          
          -- Holder decides which claims to reveal
          -- In this example, holder chooses to reveal only "given_name" and "email"
          -- This demonstrates selective disclosure: "family_name" remains private
          putStrLn "Holder chooses to disclose: given_name, email"
          putStrLn "Holder keeps private: family_name"
          putStrLn ""
          
          case selectDisclosuresByNames receivedSDJWT ["given_name", "email"] of
            Left err -> do
              hPutStrLn stderr $ "ERROR: Failed to select disclosures: " ++ show err
              return ()
            Right presentation -> do
              putStrLn "✓ Presentation created with selected disclosures"
              
              -- Holder optionally adds key binding for proof of possession
              putStrLn ""
              putStrLn "Adding Key Binding (SD-JWT+KB) for proof of possession..."
              let audience = "verifier.example.com"
              let nonce = "random-nonce-from-verifier-12345"
              let issuedAt = 1683000000 :: Int64
              
              kbResult <- addKeyBindingToPresentation SHA256 holderPrivateKey 
                                                       audience nonce issuedAt 
                                                       presentation
              case kbResult of
                Left err -> do
                  hPutStrLn stderr $ "ERROR: Failed to add key binding: " ++ show err
                  return ()
                Right presentationWithKB -> do
                  putStrLn "✓ Key binding added successfully"
                  
                  -- Serialize presentation
                  let serializedPresentation = serializePresentation presentationWithKB
                  putStrLn $ "  Serialized presentation length: " ++ show (T.length serializedPresentation) ++ " characters"
                  putStrLn ""
                  
                  putStrLn "============================================"
                  putStrLn "STEP 3: VERIFIER VERIFIES AND EXTRACTS CLAIMS"
                  putStrLn "--------------------------------------------"
                  
                  -- Verifier receives the presentation and deserializes it
                  case deserializePresentation serializedPresentation of
                    Left err -> do
                      hPutStrLn stderr $ "ERROR: Failed to deserialize presentation: " ++ show err
                      return ()
                    Right receivedPresentation -> do
                      putStrLn "✓ Presentation deserialized successfully"
                      putStrLn ""
                      
                      -- Verifier verifies the SD-JWT
                      putStrLn "Verifying SD-JWT signature and disclosures..."
                      verifyResult <- verifySDJWT issuerPublicKey receivedPresentation Nothing
                      
                      case verifyResult of
                        Left err -> do
                          hPutStrLn stderr $ "ERROR: Verification failed: " ++ show err
                          return ()
                        Right processedPayload -> do
                          putStrLn "✓ SD-JWT verified successfully"
                          putStrLn ""
                          
                          -- Extract verified claims
                          let verifiedClaims = processedClaims processedPayload
                          
                          putStrLn "Verified claims received by verifier:"
                          putStrLn "--------------------------------------------"
                          
                          -- Display all verified claims
                          mapM_ (\(k, v) -> putStrLn $ "  ✓ " ++ T.unpack k ++ ": " ++ show v) 
                                (Map.toList verifiedClaims)
                          putStrLn ""
                          
                          -- Show what was NOT disclosed
                          putStrLn "Claims NOT disclosed (kept private by holder):"
                          putStrLn "--------------------------------------------"
                          if Map.member "family_name" verifiedClaims
                            then putStrLn "  (none - all selectively disclosable claims were disclosed)"
                            else putStrLn "  ✓ family_name (holder chose not to disclose)"
                          putStrLn ""
                          
                          -- Summary
                          putStrLn "============================================"
                          putStrLn "SUMMARY"
                          putStrLn "============================================"
                          putStrLn ""
                          putStrLn "✓ Issuer created SD-JWT with selective disclosure"
                          putStrLn "✓ Holder selected which claims to disclose (given_name, email)"
                          putStrLn "✓ Holder added key binding for proof of possession"
                          putStrLn "✓ Verifier verified signature and extracted claims"
                          putStrLn ""
                          putStrLn "Key Points:"
                          putStrLn "  • Regular claims (sub, phone, age) are always visible"
                          putStrLn "  • Selectively disclosable claims (given_name, email) were disclosed"
                          putStrLn "  • Selectively disclosable claims (family_name) was kept private"
                          putStrLn "  • Verifier only sees what the holder chose to disclose"
                          putStrLn ""
                          putStrLn "This demonstrates the core value of SD-JWT:"
                          putStrLn "  Selective disclosure allows holders to control what"
                          putStrLn "  information they share with verifiers."

