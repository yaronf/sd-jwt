{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# OPTIONS_GHC -Wno-name-shadowing #-}
module IssuanceSpec (spec) where

import Test.Hspec
import Test.QuickCheck
import Test.QuickCheck.Property ((==>))
import TestHelpers
import TestKeys
import SDJWT.Internal.Types
import SDJWT.Internal.Utils
import SDJWT.Internal.Digest
import SDJWT.Internal.Disclosure
import SDJWT.Internal.Serialization
import SDJWT.Internal.Issuance
import SDJWT.Internal.Presentation
import SDJWT.Internal.Verification (verifySDJWT, verifySDJWTSignature, verifySDJWTWithoutSignature, verifyKeyBinding, verifyDisclosures, extractHashAlgorithm, parsePayloadFromJWT)
import SDJWT.Internal.KeyBinding
import SDJWT.Internal.JWT
import qualified Data.Vector as V
import qualified Data.Aeson as Aeson
import qualified Data.Aeson.Key as Key
import qualified Data.Aeson.KeyMap as KeyMap
import qualified Data.Text as T
import Data.Text.Encoding (encodeUtf8, decodeUtf8')
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BSL
import qualified Data.Map.Strict as Map
import Data.Int (Int64)
import Data.Maybe (isJust, mapMaybe)
import Data.List (find, nub)
import Control.Monad (replicateM)

spec :: Spec
spec = describe "SDJWT.Issuance" $ do
  describe "buildSDJWTPayload" $ do
    it "creates SD-JWT payload correctly" $ do
      let claims = KeyMap.fromList

            [  (Key.fromText "sub", Aeson.String "user_42")
            ,  (Key.fromText "given_name", Aeson.String "John")
            ,  (Key.fromText "family_name", Aeson.String "Doe")
            ]
      let selectiveClaims = ["given_name", "family_name"]
      result <- buildSDJWTPayload SHA256 selectiveClaims claims
      case result of
        Right (payload, payloadDisclosures) -> do
          sdAlg payload `shouldBe` Just SHA256
          length payloadDisclosures `shouldBe` 2
          -- Verify it works the same as buildSDJWTPayload
          case payloadValue payload of
            Aeson.Object obj -> do
              KeyMap.lookup "_sd" obj `shouldSatisfy` isJust
              KeyMap.lookup "_sd_alg" obj `shouldSatisfy` isJust
              KeyMap.lookup "sub" obj `shouldSatisfy` isJust
              KeyMap.lookup "given_name" obj `shouldBe` Nothing
              KeyMap.lookup "family_name" obj `shouldBe` Nothing
            _ -> expectationFailure "Payload should be an object"
        Left err -> expectationFailure $ "Failed to create SD-JWT from claims: " ++ show err
  
  describe "buildSDJWTPayload" $ do
    it "creates SD-JWT payload with selective disclosures" $ do
      let claims = KeyMap.fromList

            [  (Key.fromText "sub", Aeson.String "user_42")
            ,  (Key.fromText "given_name", Aeson.String "John")
            ,  (Key.fromText "family_name", Aeson.String "Doe")
            ]
      let selectiveClaims = ["given_name", "family_name"]
      result <- buildSDJWTPayload SHA256 selectiveClaims claims
      case result of
        Right (payload, payloadDisclosures) -> do
          sdAlg payload `shouldBe` Just SHA256
          length payloadDisclosures `shouldBe` 2
          -- Check that _sd array exists in payload
          case payloadValue payload of
            Aeson.Object obj -> do
              KeyMap.lookup "_sd" obj `shouldSatisfy` isJust
              KeyMap.lookup "_sd_alg" obj `shouldSatisfy` isJust
              KeyMap.lookup "sub" obj `shouldSatisfy` isJust  -- Regular claim preserved
              KeyMap.lookup "given_name" obj `shouldBe` Nothing  -- Selective claim removed
              KeyMap.lookup "family_name" obj `shouldBe` Nothing  -- Selective claim removed
            _ -> expectationFailure "Payload should be an object"
        Left err -> expectationFailure $ "Failed to build payload: " ++ show err
    
  -- NOTE: markSelectivelyDisclosable is now internal-only. This test needs to be rewritten
  -- to use buildSDJWTPayload or createSDJWT with JSON Pointer paths instead.
  -- describe "markSelectivelyDisclosable" $ do
  --   it "creates disclosure and digest for a claim" $ do
  --     result <- markSelectivelyDisclosable SHA256 "test_claim" (Aeson.String "test_value")
  --     case result of
  --       Right (digest, disclosure) -> do
  --         unDigest digest `shouldSatisfy` (not . T.null)
  --         unEncodedDisclosure disclosure `shouldSatisfy` (not . T.null)
  --       Left err -> expectationFailure $ "Failed to mark claim: " ++ show err
    
  describe "Array element disclosure via JSON Pointer" $ do
    it "creates disclosure and digest for an array element using JSON Pointer path" $ do
      let claims = KeyMap.fromList [ (Key.fromText "nationalities", Aeson.Array $ V.fromList [Aeson.String "FR"])]
      result <- buildSDJWTPayload SHA256 ["nationalities/0"] claims
      case result of
        Right (payload, disclosures) -> do
          length disclosures `shouldBe` 1
          -- Check that payload has array with ellipsis object
          case payloadValue payload of
            Aeson.Object obj -> do
              case KeyMap.lookup (Key.fromText "nationalities") obj of
                Just (Aeson.Array arr) -> do
                  V.length arr `shouldBe` 1
                  case arr V.!? 0 of
                    Just (Aeson.Object ellipsisObj) -> do
                      KeyMap.lookup (Key.fromText "...") ellipsisObj `shouldSatisfy` isJust
                    _ -> expectationFailure "Array element should be replaced with ellipsis object"
                _ -> expectationFailure "nationalities should be an array"
            _ -> expectationFailure "Payload should be an object"
        Left err -> expectationFailure $ "Failed to build SD-JWT payload: " ++ show err
    
    it "processes array and marks specific elements as selectively disclosable" $ do
      let claims = KeyMap.fromList [ (Key.fromText "nationalities", Aeson.Array $ V.fromList [Aeson.String "DE", Aeson.String "FR", Aeson.String "US"])]
      result <- buildSDJWTPayload SHA256 ["nationalities/1"] claims  -- Mark second element (index 1)
      case result of
        Right (payload, disclosures) -> do
          length disclosures `shouldBe` 1
          -- Check that second element is replaced with {"...": "<digest>"}
          case payloadValue payload of
            Aeson.Object obj -> do
              case KeyMap.lookup (Key.fromText "nationalities") obj of
                Just (Aeson.Array arr) -> do
                  V.length arr `shouldBe` 3
                  case arr V.!? 1 of
                    Just (Aeson.Object ellipsisObj) -> do
                      KeyMap.lookup (Key.fromText "...") ellipsisObj `shouldSatisfy` isJust
                    _ -> expectationFailure "Second element should be replaced with ellipsis object"
                  -- First and third elements should remain unchanged
                  case arr V.!? 0 of
                    Just (Aeson.String "DE") -> return ()
                    _ -> expectationFailure "First element should remain unchanged"
                  case arr V.!? 2 of
                    Just (Aeson.String "US") -> return ()
                    _ -> expectationFailure "Third element should remain unchanged"
                _ -> expectationFailure "nationalities should be an array"
            _ -> expectationFailure "Payload should be an object"
        Left err -> expectationFailure $ "Failed to process array: " ++ show err
  
  describe "addDecoyDigest" $ do
      it "generates a decoy digest with SHA256" $ do
        decoy <- addDecoyDigest SHA256
        unDigest decoy `shouldSatisfy` (not . T.null)
        -- Decoy digest should be a valid base64url string
        unDigest decoy `shouldSatisfy` (\s -> T.length s > 0)
      
      it "generates different decoy digests each time" $ do
        decoy1 <- addDecoyDigest SHA256
        decoy2 <- addDecoyDigest SHA256
        -- Very unlikely to be the same (cryptographically random)
        unDigest decoy1 `shouldNotBe` unDigest decoy2
      
      it "generates decoy digest with SHA384" $ do
        decoy <- addDecoyDigest SHA384
        unDigest decoy `shouldSatisfy` (not . T.null)
        unDigest decoy `shouldSatisfy` (\s -> T.length s > 0)
      
      it "generates decoy digest with SHA512" $ do
        decoy <- addDecoyDigest SHA512
        unDigest decoy `shouldSatisfy` (not . T.null)
        unDigest decoy `shouldSatisfy` (\s -> T.length s > 0)
      
      it "generates different digests for different algorithms" $ do
        decoy256 <- addDecoyDigest SHA256
        decoy384 <- addDecoyDigest SHA384
        decoy512 <- addDecoyDigest SHA512
        -- All should be different (different hash algorithms produce different digests)
        unDigest decoy256 `shouldNotBe` unDigest decoy384
        unDigest decoy256 `shouldNotBe` unDigest decoy512
        unDigest decoy384 `shouldNotBe` unDigest decoy512

  describe "createSDJWTWithDecoys" $ do
    it "creates SD-JWT with specified number of decoy digests" $ do
      issuerKeyPair <- generateTestRSAKeyPair
      let claims = KeyMap.fromList

            [  (Key.fromText "sub", Aeson.String "user_42")
            ,  (Key.fromText "given_name", Aeson.String "John")
            ,  (Key.fromText "family_name", Aeson.String "Doe")
            ]
      let selectiveClaims = ["given_name"]
      
      -- Create SD-JWT with 3 decoy digests
      result <- createSDJWTWithDecoys Nothing Nothing SHA256 (privateKeyJWK issuerKeyPair) selectiveClaims claims 3
      case result of
        Right sdjwt -> do
          -- Verify it was created successfully
          issuerSignedJWT sdjwt `shouldSatisfy` (not . T.null)
          length (disclosures sdjwt) `shouldBe` 1  -- Only one real disclosure
          
          -- Parse the JWT payload to verify decoy digests were added
          case parsePayloadFromJWT (issuerSignedJWT sdjwt) of
            Right payload -> do
              case payloadValue payload of
                Aeson.Object obj -> do
                  case KeyMap.lookup (Key.fromText "_sd") obj of
                    Just (Aeson.Array sdArray) -> do
                      -- Should have 1 real digest + 3 decoy digests = 4 total
                      V.length sdArray `shouldBe` 4
                    _ -> expectationFailure "Payload should contain _sd array"
                _ -> expectationFailure "Payload should be an object"
            Left err -> expectationFailure $ "Failed to parse JWT: " ++ show err
        Left err -> expectationFailure $ "Failed to create SD-JWT with decoys: " ++ show err
    
    it "creates SD-JWT with 0 decoy digests (same as createSDJWT)" $ do
      issuerKeyPair <- generateTestRSAKeyPair
      let claims = KeyMap.fromList

            [  (Key.fromText "sub", Aeson.String "user_42")
            ,  (Key.fromText "given_name", Aeson.String "John")
            ]
      let selectiveClaims = ["given_name"]
      
      -- Create SD-JWT with 0 decoy digests
      result1 <- createSDJWTWithDecoys Nothing Nothing SHA256 (privateKeyJWK issuerKeyPair) selectiveClaims claims 0
      result2 <- createSDJWT Nothing Nothing SHA256 (privateKeyJWK issuerKeyPair) selectiveClaims claims
      
      case (result1, result2) of
        (Right sdjwt1, Right sdjwt2) -> do
          -- Both should have the same number of disclosures
          length (disclosures sdjwt1) `shouldBe` length (disclosures sdjwt2)
        _ -> expectationFailure "Both should succeed"
    
    it "rejects negative decoy count" $ do
      issuerKeyPair <- generateTestRSAKeyPair
      let claims = KeyMap.fromList [ (Key.fromText "given_name", Aeson.String "John")]
      
      result <- createSDJWTWithDecoys Nothing Nothing SHA256 (privateKeyJWK issuerKeyPair) ["given_name"] claims (-1)
      case result of
        Left (InvalidDisclosureFormat msg) ->
          T.isInfixOf "decoyCount must be >= 0" msg `shouldBe` True
        Left err -> expectationFailure $ "Expected InvalidDisclosureFormat, got: " ++ show err
        Right _ -> expectationFailure "Should reject negative decoy count"

  describe "Decoy Digests in SD-JWT" $ do
    describe "creating SD-JWT with decoy digests" $ do
      it "can manually add decoy digests to _sd array" $ do
        let claims = KeyMap.fromList

              [  (Key.fromText "sub", Aeson.String "user_42")
              ,  (Key.fromText "given_name", Aeson.String "John")
              ,  (Key.fromText "family_name", Aeson.String "Doe")
              ]
        let selectiveClaims = ["given_name"]
        
        -- Build the SD-JWT payload
        result <- buildSDJWTPayload SHA256 selectiveClaims claims
        case result of
          Right (sdPayload, sdDisclosures) -> do
            -- Generate decoy digests
            decoy1 <- addDecoyDigest SHA256
            decoy2 <- addDecoyDigest SHA256
            
            -- Manually add decoy digests to the _sd array
            case payloadValue sdPayload of
              Aeson.Object payloadObj -> do
                case KeyMap.lookup (Key.fromText "_sd") payloadObj of
                  Just (Aeson.Array sdArray) -> do
                    -- Verify original array has 1 digest (for given_name)
                    V.length sdArray `shouldBe` 1
                    
                    -- Add decoy digests to the array
                    let decoyDigests = [Aeson.String (unDigest decoy1), Aeson.String (unDigest decoy2)]
                    let updatedSDArray = sdArray <> V.fromList decoyDigests
                    
                    -- Verify the updated array has 3 digests (1 real + 2 decoys)
                    V.length updatedSDArray `shouldBe` 3
                    
                    -- Verify all digests are strings
                    V.all (\v -> case v of Aeson.String _ -> True; _ -> False) updatedSDArray `shouldBe` True
                  _ -> expectationFailure "payload should contain _sd array"
              _ -> expectationFailure "payload should be an object"
            
            -- Verify we still have only 1 disclosure (decoy digests don't create disclosures)
            length sdDisclosures `shouldBe` 1
          Left err -> expectationFailure $ "Failed to build SD-JWT payload: " ++ show err
      
      it "decoy digests don't interfere with real disclosures" $ do
        let claims = KeyMap.fromList

              [  (Key.fromText "sub", Aeson.String "user_42")
              ,  (Key.fromText "given_name", Aeson.String "John")
              ,  (Key.fromText "family_name", Aeson.String "Doe")
              ,  (Key.fromText "email", Aeson.String "john@example.com")
              ]
        let selectiveClaims = ["given_name", "family_name"]
        
        -- Build the SD-JWT payload
        result <- buildSDJWTPayload SHA256 selectiveClaims claims
        case result of
          Right (sdPayload, sdDisclosures) -> do
            -- Generate multiple decoy digests
            decoys <- replicateM 5 (addDecoyDigest SHA256)
            
            -- Extract the real digest from the first disclosure
            let realDigest1 = unDigest $ computeDigest SHA256 (head sdDisclosures)
            let realDigest2 = unDigest $ computeDigest SHA256 (sdDisclosures !! 1)
            
            -- Manually add decoy digests to the _sd array
            case payloadValue sdPayload of
              Aeson.Object payloadObj -> do
                case KeyMap.lookup (Key.fromText "_sd") payloadObj of
                  Just (Aeson.Array sdArray) -> do
                    -- Verify original array has 2 digests
                    V.length sdArray `shouldBe` 2
                    
                    -- Verify both real digests are present
                    let sdDigests = mapMaybe (\v -> case v of Aeson.String s -> Just s; _ -> Nothing) (V.toList sdArray)
                    realDigest1 `elem` sdDigests `shouldBe` True
                    realDigest2 `elem` sdDigests `shouldBe` True
                    
                    -- Add decoy digests
                    let decoyDigests = map (Aeson.String . unDigest) decoys
                    let updatedSDArray = sdArray <> V.fromList decoyDigests
                    
                    -- Verify the updated array has 7 digests (2 real + 5 decoys)
                    V.length updatedSDArray `shouldBe` 7
                    
                    -- Verify real digests are still present
                    let updatedSDDigests = mapMaybe (\v -> case v of Aeson.String s -> Just s; _ -> Nothing) (V.toList updatedSDArray)
                    realDigest1 `elem` updatedSDDigests `shouldBe` True
                    realDigest2 `elem` updatedSDDigests `shouldBe` True
                  _ -> expectationFailure "payload should contain _sd array"
              _ -> expectationFailure "payload should be an object"
            
            -- Verify we still have only 2 disclosures
            length sdDisclosures `shouldBe` 2
          Left err -> expectationFailure $ "Failed to build SD-JWT payload: " ++ show err

  describe "SDJWT.Issuance (Nested Structures)" $ do
    describe "RFC Section 6.2 - Structured SD-JWT with nested address claims" $ do
      it "creates SD-JWT payload with nested _sd array in address object" $ do
        let claims = KeyMap.fromList

              [  (Key.fromText "iss", Aeson.String "https://issuer.example.com")
              ,  (Key.fromText "iat", Aeson.Number 1683000000)
              ,  (Key.fromText "exp", Aeson.Number 1883000000)
              ,  (Key.fromText "sub", Aeson.String "6c5c0a49-b589-431d-bae7-219122a9ec2c")
              ,  (Key.fromText "address", Aeson.Object $ KeyMap.fromList
                  [  (Key.fromText "street_address", Aeson.String "Schulstr. 12")
                  ,  (Key.fromText "locality", Aeson.String "Schulpforta")
                  ,  (Key.fromText "region", Aeson.String "Sachsen-Anhalt")
                  ,  (Key.fromText "country", Aeson.String "DE")
                  ])
              ]
        
        -- Mark nested address sub-claims as selectively disclosable (using JSON Pointer syntax)
        result <- buildSDJWTPayload SHA256 ["address/street_address", "address/locality", "address/region", "address/country"] claims
        
        case result of
          Right (sdPayload, sdDisclosures) -> do
            -- Verify payload structure
            case payloadValue sdPayload of
              Aeson.Object payloadObj -> do
                -- Verify address object exists and contains _sd array
                case KeyMap.lookup (Key.fromText "address") payloadObj of
                  Just (Aeson.Object addressObj) -> do
                    -- Verify _sd array exists in address object
                    case KeyMap.lookup (Key.fromText "_sd") addressObj of
                      Just (Aeson.Array sdArray) -> do
                        -- Should have 4 digests (one for each sub-claim)
                        V.length sdArray `shouldBe` 4
                        -- Verify all digests are strings
                        V.all (\v -> case v of Aeson.String _ -> True; _ -> False) sdArray `shouldBe` True
                      _ -> expectationFailure "address object should contain _sd array"
                    -- Verify address object doesn't contain the original sub-claims
                    KeyMap.lookup (Key.fromText "street_address") addressObj `shouldBe` Nothing
                    KeyMap.lookup (Key.fromText "locality") addressObj `shouldBe` Nothing
                    KeyMap.lookup (Key.fromText "region") addressObj `shouldBe` Nothing
                    KeyMap.lookup (Key.fromText "country") addressObj `shouldBe` Nothing
                  _ -> expectationFailure "address object should exist in payload"
                -- Verify top-level claims are preserved
                KeyMap.lookup (Key.fromText "iss") payloadObj `shouldSatisfy` isJust
                KeyMap.lookup (Key.fromText "sub") payloadObj `shouldSatisfy` isJust
                -- Verify _sd_alg is present
                KeyMap.lookup (Key.fromText "_sd_alg") payloadObj `shouldSatisfy` isJust
              _ -> expectationFailure "payload should be an object"
            
            -- Verify 4 disclosures were created (one for each sub-claim)
            length sdDisclosures `shouldBe` 4
            
            -- Verify each disclosure can be decoded and contains correct claim name
            let decodedDisclosures = decodeDisclosures sdDisclosures
            
            length decodedDisclosures `shouldBe` 4
            
            -- Verify claim names in disclosures
            let claimNames = mapMaybe getDisclosureClaimName decodedDisclosures
            claimNames `shouldContain` ["street_address"]
            claimNames `shouldContain` ["locality"]
            claimNames `shouldContain` ["region"]
            claimNames `shouldContain` ["country"]
            
          Left err -> expectationFailure $ "Failed to build payload: " ++ show err
      
      it "creates SD-JWT with some nested claims disclosed and some hidden" $ do
        let claims = KeyMap.fromList

              [  (Key.fromText "iss", Aeson.String "https://issuer.example.com")
              ,  (Key.fromText "sub", Aeson.String "user_123")
              ,  (Key.fromText "address", Aeson.Object $ KeyMap.fromList
                  [  (Key.fromText "street_address", Aeson.String "123 Main St")
                  ,  (Key.fromText "locality", Aeson.String "City")
                  ,  (Key.fromText "country", Aeson.String "US")
                  ])
              ]
        
        -- Mark only street_address and locality as selectively disclosable
        -- country should remain visible (using JSON Pointer syntax)
        result <- buildSDJWTPayload SHA256 ["address/street_address", "address/locality"] claims
        
        case result of
          Right (sdPayload, sdDisclosures) -> do
            case payloadValue sdPayload of
              Aeson.Object payloadObj -> do
                case KeyMap.lookup (Key.fromText "address") payloadObj of
                  Just (Aeson.Object addressObj) -> do
                    -- Verify _sd array exists with 2 digests
                    case KeyMap.lookup (Key.fromText "_sd") addressObj of
                      Just (Aeson.Array sdArray) -> do
                        V.length sdArray `shouldBe` 2
                      _ -> expectationFailure "address object should contain _sd array"
                    -- Verify country is still visible (not selectively disclosable)
                    case KeyMap.lookup (Key.fromText "country") addressObj of
                      Just (Aeson.String "US") -> return ()
                      _ -> expectationFailure "country should be visible in address object"
                    -- Verify street_address and locality are hidden
                    KeyMap.lookup (Key.fromText "street_address") addressObj `shouldBe` Nothing
                    KeyMap.lookup (Key.fromText "locality") addressObj `shouldBe` Nothing
                  _ -> expectationFailure "address object should exist"
              _ -> expectationFailure "payload should be an object"
            
            -- Should have 2 disclosures
            length sdDisclosures `shouldBe` 2
          Left err -> expectationFailure $ "Failed to build payload: " ++ show err
      
      it "verifies nested structure disclosures can be verified" $ do
        let claims = KeyMap.fromList

              [  (Key.fromText "iss", Aeson.String "https://issuer.example.com")
              ,  (Key.fromText "sub", Aeson.String "user_123")
              ,  (Key.fromText "address", Aeson.Object $ KeyMap.fromList
                  [  (Key.fromText "street_address", Aeson.String "123 Main St")
                  ,  (Key.fromText "locality", Aeson.String "City")
                  ])
              ]
        
        -- Get test keys for signing
        keyPair <- generateTestRSAKeyPair
        
        -- Create SD-JWT with nested structures and sign it (using JSON Pointer syntax)
        result <- createSDJWT Nothing Nothing SHA256 (privateKeyJWK keyPair) ["address/street_address", "address/locality"] claims
        
        case result of
          Right sdjwt -> do
            -- Create presentation with all disclosures
            case selectDisclosuresByNames sdjwt ["address/street_address", "address/locality"] of
              Right presentation -> do
                -- Verify presentation (without issuer key for now - signature verification skipped)
                verificationResult <- verifySDJWTWithoutSignature presentation
                
                case verificationResult of
                  Right processedPayload -> do
                    -- Verify address object is reconstructed correctly
                    case KeyMap.lookup (Key.fromText "address") (processedClaims processedPayload) of
                      Just (Aeson.Object addressObj) -> do
                        -- Verify street_address and locality are present
                        KeyMap.lookup (Key.fromText "street_address") addressObj `shouldSatisfy` isJust
                        KeyMap.lookup (Key.fromText "locality") addressObj `shouldSatisfy` isJust
                      _ -> expectationFailure "address object should be reconstructed"
                  Left err -> expectationFailure $ "Verification failed: " ++ show err
              Left err -> expectationFailure $ "Failed to create presentation: " ++ show err
          Left err -> expectationFailure $ "Failed to create SD-JWT: " ++ show err
  
    describe "RFC Section 6.3 - Recursive Disclosures" $ do
      it "creates SD-JWT with recursive disclosures (parent and sub-claims both selectively disclosable)" $ do
        let claims = KeyMap.fromList

              [  (Key.fromText "iss", Aeson.String "https://issuer.example.com")
              ,  (Key.fromText "iat", Aeson.Number 1683000000)
              ,  (Key.fromText "exp", Aeson.Number 1883000000)
              ,  (Key.fromText "sub", Aeson.String "6c5c0a49-b589-431d-bae7-219122a9ec2c")
              ,  (Key.fromText "address", Aeson.Object $ KeyMap.fromList
                  [  (Key.fromText "street_address", Aeson.String "Schulstr. 12")
                  ,  (Key.fromText "locality", Aeson.String "Schulpforta")
                  ,  (Key.fromText "region", Aeson.String "Sachsen-Anhalt")
                  ,  (Key.fromText "country", Aeson.String "DE")
                  ])
              ]
        
        -- Mark both parent "address" and its sub-claims as selectively disclosable (Section 6.3)
        -- Using JSON Pointer syntax: "/" separates path segments
        result <- buildSDJWTPayload SHA256 ["address", "address/street_address", "address/locality", "address/region", "address/country"] claims
        
        case result of
          Right (sdPayload, sdDisclosures) -> do
            -- Verify payload structure - address should NOT be in payload (it's selectively disclosable)
            case payloadValue sdPayload of
              Aeson.Object payloadObj -> do
                -- Address should not be in payload (it's in top-level _sd)
                KeyMap.lookup (Key.fromText "address") payloadObj `shouldBe` Nothing
                -- Top-level _sd array should exist with address digest
                case KeyMap.lookup (Key.fromText "_sd") payloadObj of
                  Just (Aeson.Array sdArray) -> do
                    V.length sdArray `shouldBe` 1  -- Only address digest in top-level _sd
                  _ -> expectationFailure "Top-level _sd array should exist"
                -- Regular claims should be preserved
                KeyMap.lookup (Key.fromText "iss") payloadObj `shouldSatisfy` isJust
                KeyMap.lookup (Key.fromText "sub") payloadObj `shouldSatisfy` isJust
              _ -> expectationFailure "payload should be an object"
            
            -- Should have 5 disclosures: 1 parent (address) + 4 children
            length sdDisclosures `shouldBe` 5
            
            -- Verify parent disclosure contains _sd array with child digests
            let decodedDisclosures = decodeDisclosures sdDisclosures
            
            -- Find the address disclosure
            let addressDisclosure = find (\dec -> getDisclosureClaimName dec == Just "address") decodedDisclosures
            
            case addressDisclosure of
              Just addrDisc -> do
                -- Address disclosure value should be an object with _sd array
                case getDisclosureValue addrDisc of
                  Aeson.Object addrObj -> do
                    case KeyMap.lookup (Key.fromText "_sd") addrObj of
                      Just (Aeson.Array childSDArray) -> do
                        -- Should have 4 digests (one for each sub-claim)
                        V.length childSDArray `shouldBe` 4
                        -- All should be strings (digests)
                        V.all (\v -> case v of Aeson.String _ -> True; _ -> False) childSDArray `shouldBe` True
                      _ -> expectationFailure "Address disclosure should contain _sd array"
                  _ -> expectationFailure "Address disclosure value should be an object"
              Nothing -> expectationFailure "Address disclosure should exist"
            
            -- Verify child disclosures exist
            let childClaimNames = mapMaybe getDisclosureClaimName decodedDisclosures
            childClaimNames `shouldContain` ["street_address"]
            childClaimNames `shouldContain` ["locality"]
            childClaimNames `shouldContain` ["region"]
            childClaimNames `shouldContain` ["country"]
            
          Left err -> expectationFailure $ "Failed to build payload: " ++ show err
      
      it "verifies recursive disclosures can be verified correctly" $ do
        let claims = KeyMap.fromList

              [  (Key.fromText "iss", Aeson.String "https://issuer.example.com")
              ,  (Key.fromText "sub", Aeson.String "user_123")
              ,  (Key.fromText "address", Aeson.Object $ KeyMap.fromList
                  [  (Key.fromText "street_address", Aeson.String "123 Main St")
                  ,  (Key.fromText "locality", Aeson.String "City")
                  ])
              ]
        
        -- Get test keys for signing
        keyPair <- generateTestRSAKeyPair
        
        -- Create SD-JWT with recursive disclosures (parent + children)
        -- Using JSON Pointer syntax: "/" separates path segments
        result <- createSDJWT Nothing Nothing SHA256 (privateKeyJWK keyPair) ["address", "address/street_address", "address/locality"] claims
        
        case result of
          Right sdjwt -> do
            -- Create presentation with all disclosures
            case selectDisclosuresByNames sdjwt ["address", "address/street_address", "address/locality"] of
              Right presentation -> do
                -- Verify presentation (without issuer key for now - signature verification skipped)
                verificationResult <- verifySDJWTWithoutSignature presentation
                
                case verificationResult of
                  Right processedPayload -> do
                    -- Verify address object is reconstructed correctly
                    case KeyMap.lookup (Key.fromText "address") (processedClaims processedPayload) of
                      Just (Aeson.Object addressObj) -> do
                        -- Verify street_address and locality are present
                        KeyMap.lookup (Key.fromText "street_address") addressObj `shouldSatisfy` isJust
                        KeyMap.lookup (Key.fromText "locality") addressObj `shouldSatisfy` isJust
                      _ -> expectationFailure "address object should be reconstructed"
                  Left err -> expectationFailure $ "Verification failed: " ++ show err
              Left err -> expectationFailure $ "Failed to create presentation: " ++ show err
          Left err -> expectationFailure $ "Failed to create SD-JWT: " ++ show err
  
    describe "JSON Pointer Parsing (partitionNestedPaths)" $ do
      it "handles simple nested paths" $ do
        let claims = KeyMap.fromList

              [  (Key.fromText "address", Aeson.Object $ KeyMap.fromList
                  [  (Key.fromText "street_address", Aeson.String "123 Main St")
                  ,  (Key.fromText "locality", Aeson.String "City")
                  ])
              ]
        result <- buildSDJWTPayload SHA256 ["address/street_address"] claims
        case result of
          Right (payload, _) -> do
            -- Should create structured nested structure (Section 6.2)
            case payloadValue payload of
              Aeson.Object obj -> do
                -- Address should remain with _sd array
                case KeyMap.lookup (Key.fromText "address") obj of
                  Just (Aeson.Object addrObj) -> do
                    KeyMap.lookup (Key.fromText "_sd") addrObj `shouldSatisfy` isJust
                  _ -> expectationFailure "address should be an object with _sd"
              _ -> expectationFailure "Payload should be an object"
          Left err -> expectationFailure $ "Failed: " ++ show err
      
      it "handles deeply nested paths" $ do
        let claims = KeyMap.fromList

              [  (Key.fromText "user", Aeson.Object $ KeyMap.fromList
                  [  (Key.fromText "profile", Aeson.Object $ KeyMap.fromList
                      [  (Key.fromText "name", Aeson.String "John")
                      ])
                  ])
              ]
        result <- buildSDJWTPayload SHA256 ["user/profile/name"] claims
        case result of
          Right _ -> return ()  -- Should succeed
          Left err -> expectationFailure $ "Failed: " ++ show err
      
      it "handles multiple nested paths with same parent" $ do
        let claims = KeyMap.fromList

              [  (Key.fromText "address", Aeson.Object $ KeyMap.fromList
                  [  (Key.fromText "street_address", Aeson.String "123 Main St")
                  ,  (Key.fromText "locality", Aeson.String "City")
                  ,  (Key.fromText "country", Aeson.String "US")
                  ])
              ]
        result <- buildSDJWTPayload SHA256 ["address/street_address", "address/locality", "address/country"] claims
        case result of
          Right (_, sdDisclosures) -> do
            length sdDisclosures `shouldBe` 3
            -- All three should be selectively disclosable
          Left err -> expectationFailure $ "Failed: " ++ show err
    
    describe "JSON Pointer Escaping" $ do
      it "handles keys containing forward slashes using ~1 escape" $ do
        -- Test that a key literally named "contact/email" is treated as top-level, not nested
        -- Note: The Map key is the actual JSON key (unescaped), but we pass the escaped form to buildSDJWTPayload
        let claims = KeyMap.fromList

              [  (Key.fromText "contact/email", Aeson.String "test@example.com")  -- Literal key "contact/email" (unescaped in Map)
              ,  (Key.fromText "address", Aeson.Object $ KeyMap.fromList
                  [  (Key.fromText "street", Aeson.String "123 Main St")
                  ])
              ]
        
        -- Mark the literal "contact/email" key as selectively disclosable (using escaped form in path)
        -- Since "contact~1email" doesn't contain "/", it's treated as top-level and matched to "contact/email"
        result <- buildSDJWTPayload SHA256 ["contact~1email"] claims
        
        case result of
          Right (sdPayload, sdDisclosures) -> do
            -- Should have 1 disclosure
            length sdDisclosures `shouldBe` 1
            -- The literal key should be in top-level _sd, not nested
            case payloadValue sdPayload of
              Aeson.Object payloadObj -> do
                case KeyMap.lookup (Key.fromText "_sd") payloadObj of
                  Just (Aeson.Array sdArray) -> do
                    V.length sdArray `shouldBe` 1  -- One digest for "contact/email"
                  _ -> expectationFailure "Top-level _sd array should exist"
                -- The literal key should not be in payload (it's selectively disclosable)
                KeyMap.lookup (Key.fromText "contact/email") payloadObj `shouldBe` Nothing
              _ -> expectationFailure "payload should be an object"
          Left err -> expectationFailure $ "Failed to build payload: " ++ show err
      
      it "handles keys containing tildes using ~0 escape" $ do
        -- Test that a key literally named "user~name" is treated as top-level, not nested
        -- Note: The Map key is the actual JSON key (unescaped), but we pass the escaped form to buildSDJWTPayload
        let claims = KeyMap.fromList

              [  (Key.fromText "user~name", Aeson.String "testuser")  -- Literal key "user~name" (unescaped in Map)
              ,  (Key.fromText "address", Aeson.Object $ KeyMap.fromList
                  [  (Key.fromText "street", Aeson.String "123 Main St")
                  ])
              ]
        
        -- Mark the literal "user~name" key as selectively disclosable (using escaped form in path)
        -- Since "user~0name" doesn't contain "/", it's treated as top-level and matched to "user~name"
        result <- buildSDJWTPayload SHA256 ["user~0name"] claims
        
        case result of
          Right (_, disclosures) -> do
            -- Should have 1 disclosure
            length disclosures `shouldBe` 1
            -- Verify the disclosure contains the correct claim name
            let decodedDisclosures = decodeDisclosures disclosures
            case decodedDisclosures of
              [decoded] -> do
                getDisclosureClaimName decoded `shouldBe` Just "user~name"  -- Unescaped
              _ -> expectationFailure "Should have exactly one disclosure"
          Left err -> expectationFailure $ "Failed to build payload: " ++ show err
      
      it "correctly distinguishes nested paths from escaped keys" $ do
        -- Test that escaped keys (contact~1email) are treated as top-level,
        -- while nested paths (address/email) are treated as nested
        -- Note: Map keys are unescaped (actual JSON keys)
        let claims = KeyMap.fromList

              [  (Key.fromText "contact/email", Aeson.String "test@example.com")  -- Literal key "contact/email" (unescaped in Map)
              ,  (Key.fromText "address", Aeson.Object $ KeyMap.fromList
                  [  (Key.fromText "street", Aeson.String "123 Main St")
                  ,  (Key.fromText "email", Aeson.String "address@example.com")
                  ])
              ]
        
        -- Mark literal "contact/email" as top-level (using escaped form) AND nested "address/email" as nested
        result <- buildSDJWTPayload SHA256 ["contact~1email", "address/email"] claims
        
        case result of
          Right (sdPayload, sdDisclosures) -> do
            -- Should have 2 disclosures: 1 top-level + 1 nested
            length sdDisclosures `shouldBe` 2
            
            -- Verify nested structure: address should contain _sd array
            case payloadValue sdPayload of
              Aeson.Object payloadObj -> do
                case KeyMap.lookup (Key.fromText "address") payloadObj of
                  Just (Aeson.Object addressObj) -> do
                    -- Should have _sd array with email digest
                    case KeyMap.lookup (Key.fromText "_sd") addressObj of
                      Just (Aeson.Array sdArray) -> do
                        V.length sdArray `shouldBe` 1  -- One digest for "email"
                      _ -> expectationFailure "address should contain _sd array"
                  _ -> expectationFailure "address object should exist"
                
                -- Top-level _sd should contain digest for literal "contact/email"
                case KeyMap.lookup (Key.fromText "_sd") payloadObj of
                  Just (Aeson.Array topSDArray) -> do
                    V.length topSDArray `shouldBe` 1  -- One digest for "contact/email"
                  _ -> expectationFailure "Top-level _sd array should exist"
              _ -> expectationFailure "payload should be an object"
          Left err -> expectationFailure $ "Failed to build payload: " ++ show err
      
      it "handles paths with escaped sequences in nested paths" $ do
        -- Test that ~1 and ~0 work correctly within nested paths
        let claims = KeyMap.fromList

              [  (Key.fromText "parent", Aeson.Object $ KeyMap.fromList
                  [  (Key.fromText "key/with/slash", Aeson.String "value1")  -- Literal key with slashes
                  ,  (Key.fromText "key~with~tilde", Aeson.String "value2")  -- Literal key with tildes
                  ,  (Key.fromText "normal", Aeson.String "value3")
                  ])
              ]
        
        -- Test nested paths with escaped sequences
        -- parent/key~1with~1slash → parent object, child key "key/with/slash"
        -- parent/key~0with~0tilde → parent object, child key "key~with~tilde"
        result <- buildSDJWTPayload SHA256 ["parent/key~1with~1slash", "parent/key~0with~0tilde"] claims
        
        case result of
          Right (sdPayload, sdDisclosures) -> do
            -- Should have 2 disclosures for the nested children
            length sdDisclosures `shouldBe` 2
            -- Parent should contain _sd array with 2 digests
            case payloadValue sdPayload of
              Aeson.Object payloadObj -> do
                case KeyMap.lookup (Key.fromText "parent") payloadObj of
                  Just (Aeson.Object parentObj) -> do
                    case KeyMap.lookup (Key.fromText "_sd") parentObj of
                      Just (Aeson.Array sdArray) -> do
                        V.length sdArray `shouldBe` 2  -- Two digests
                      _ -> expectationFailure "parent should contain _sd array"
                  _ -> expectationFailure "parent object should exist"
              _ -> expectationFailure "payload should be an object"
          Left err -> expectationFailure $ "Failed to build payload: " ++ show err
      
      it "handles nested paths with multiple escaped sequences" $ do
        -- Test that multiple escape sequences work correctly in nested paths
        let claims = KeyMap.fromList

              [  (Key.fromText "parent", Aeson.Object $ KeyMap.fromList
                  [  (Key.fromText "key/with/slashes", Aeson.String "value1")
                  ,  (Key.fromText "key~with~tildes", Aeson.String "value2")
                  ])
              ]
        
        -- Test nested paths with escaped sequences
        -- parent/key~1with~1slashes → parent="parent", child="key/with/slashes"
        -- parent/key~0with~0tildes → parent="parent", child="key~with~tildes"
        result <- buildSDJWTPayload SHA256 ["parent/key~1with~1slashes", "parent/key~0with~0tildes"] claims
        
        case result of
          Right (_, sdDisclosures) -> do
            length sdDisclosures `shouldBe` 2
            -- Verify disclosures are for the correct nested children
            let decodedDisclosures = decodeDisclosures sdDisclosures
            let claimNames = mapMaybe getDisclosureClaimName decodedDisclosures
            claimNames `shouldContain` ["key/with/slashes"]
            claimNames `shouldContain` ["key~with~tildes"]
          Left err -> expectationFailure $ "Failed: " ++ show err
      
      it "handles parent key ending with tilde" $ do
        -- Test case where parent key literally ends with tilde
        -- This exercises the T.isSuffixOf "~" current branch
        let claims = KeyMap.fromList

              [  (Key.fromText "parent~", Aeson.Object $ KeyMap.fromList  -- Parent key ends with tilde
                  [  (Key.fromText "child", Aeson.String "value")
                  ])
              ]
        
        -- Path "parent~0/child" should be parsed as parent="parent~", child="child"
        -- The ~0 escapes to ~, so we get "parent~" as parent
        -- This tests the branch where current ends with "~" when we encounter "/"
        result <- buildSDJWTPayload SHA256 ["parent~0/child"] claims
        
        case result of
          Right (_, sdDisclosures) -> do
            length sdDisclosures `shouldBe` 1
            -- Verify the disclosure is for child "child" within parent "parent~"
            let decodedDisclosures = decodeDisclosures sdDisclosures
            case decodedDisclosures of
              [decoded] -> do
                getDisclosureClaimName decoded `shouldBe` Just "child"
              _ -> expectationFailure "Should have exactly one disclosure"
          Left err -> expectationFailure $ "Failed: " ++ show err

  -- RFC Example Tests (Section 5.1 - Issuance)
  -- NOTE: These tests verify that RFC example disclosures produce expected digests.
  describe "SDJWT.Issuance (RFC Examples)" $ do
    describe "RFC Section 5.1 - given_name disclosure" $ do
      it "verifies RFC example disclosure produces expected digest" $ do
        -- RFC 9901 Section 5.1 example:
        -- Disclosure: WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgImdpdmVuX25hbWUiLCAiSm9obiJd
        -- Contents: ["2GLC42sKQveCfGfryNRN9w", "given_name", "John"]
        -- Expected SHA-256 Hash: jsu9yVulwQQlhFlM_3JlzMaSFzglhQG0DpfayQwLUK4
        
        -- Verify that the RFC example disclosure produces the expected digest
        let rfcDisclosure = EncodedDisclosure "WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgImdpdmVuX25hbWUiLCAiSm9obiJd"
        let rfcDigest = computeDigest SHA256 rfcDisclosure
        unDigest rfcDigest `shouldBe` "jsu9yVulwQQlhFlM_3JlzMaSFzglhQG0DpfayQwLUK4"
        
        -- Verify we can decode the RFC disclosure correctly
        case decodeDisclosure rfcDisclosure of
          Left err -> expectationFailure $ "Failed to decode RFC disclosure: " ++ show err
          Right decoded -> do
            getDisclosureClaimName decoded `shouldBe` Just "given_name"
            getDisclosureValue decoded `shouldBe` Aeson.String "John"
    
    describe "RFC Section 5.1 - family_name disclosure" $ do
      it "creates disclosure matching RFC example digest" $ do
        -- RFC 9901 Section 5.1 example:
        -- Disclosure: WyJlbHVWNU9nM2dTTklJOEVZbnN4QV9BIiwgImZhbWlseV9uYW1lIiwgIkRvZSJd
        -- Contents: ["eluV5Og3gSNII8EYnsxA_A", "family_name", "Doe"]
        -- Expected SHA-256 Hash: TGf4oLbgwd5JQaHyKVQZU9UdGE0w5rtDsrZzfUaomLo
        
        -- Verify that the RFC example disclosure produces the expected digest
        let rfcDisclosure = EncodedDisclosure "WyJlbHVWNU9nM2dTTklJOEVZbnN4QV9BIiwgImZhbWlseV9uYW1lIiwgIkRvZSJd"
        let rfcDigest = computeDigest SHA256 rfcDisclosure
        unDigest rfcDigest `shouldBe` "TGf4oLbgwd5JQaHyKVQZU9UdGE0w5rtDsrZzfUaomLo"
        
        -- Verify we can decode it correctly
        case decodeDisclosure rfcDisclosure of
          Left err -> expectationFailure $ "Failed to decode RFC disclosure: " ++ show err
          Right decoded -> do
            getDisclosureClaimName decoded `shouldBe` Just "family_name"
            getDisclosureValue decoded `shouldBe` Aeson.String "Doe"
    
    describe "RFC Section 5.1 - array element disclosure" $ do
      it "creates array disclosure matching RFC example digest" $ do
        -- RFC 9901 Section 5.1 example:
        -- Disclosure: WyJsa2x4RjVqTVlsR1RQVW92TU5JdkNBIiwgIlVTIl0
        -- Contents: ["lklxF5jMYlGTPUovMNIvCA", "US"]
        -- Expected SHA-256 Hash: pFndjkZ_VCzmyTa6UjlZo3dh-ko8aIKQc9DlGzhaVYo
        
        -- Verify that the RFC example disclosure produces the expected digest
        let rfcDisclosure = EncodedDisclosure "WyJsa2x4RjVqTVlsR1RQVW92TU5JdkNBIiwgIlVTIl0"
        let rfcDigest = computeDigest SHA256 rfcDisclosure
        unDigest rfcDigest `shouldBe` "pFndjkZ_VCzmyTa6UjlZo3dh-ko8aIKQc9DlGzhaVYo"
        
        -- Verify we can decode it correctly
        case decodeDisclosure rfcDisclosure of
          Left err -> expectationFailure $ "Failed to decode RFC disclosure: " ++ show err
          Right decoded -> do
            getDisclosureClaimName decoded `shouldBe` Nothing  -- Array disclosures don't have claim names
            getDisclosureValue decoded `shouldBe` Aeson.String "US"
    
      it "creates SD-JWT with Ed25519 key signing" $ do
        -- Generate test Ed25519 key pair
        issuerKeyPair <- generateTestEd25519KeyPair
        
        -- Create claims with selective disclosure
        let claims = KeyMap.fromList

              [  (Key.fromText "sub", Aeson.String "user_42")
              ,  (Key.fromText "given_name", Aeson.String "John")
              ,  (Key.fromText "family_name", Aeson.String "Doe")
              ]
        let selectiveClaimNames = ["given_name", "family_name"]
        
        -- Create SD-JWT with Ed25519 key signing
        result <- createSDJWT Nothing Nothing SHA256 (privateKeyJWK issuerKeyPair) selectiveClaimNames claims
        case result of
          Left err -> expectationFailure $ "Failed to create SD-JWT with Ed25519 key: " ++ show err
          Right sdJWT -> do
            -- Verify SD-JWT is created (non-empty)
            issuerSignedJWT sdJWT `shouldSatisfy` (not . T.null)
            -- Verify it contains dots (JWT format: header.payload.signature)
            T.splitOn "." (issuerSignedJWT sdJWT) `shouldSatisfy` ((>= 3) . length)
            -- Verify disclosures are created
            disclosures sdJWT `shouldSatisfy` (not . null)
            
            -- Verify we can verify the signature with Ed25519 public key
            let presentation = SDJWTPresentation (issuerSignedJWT sdJWT) (disclosures sdJWT) Nothing
            verifyResult <- verifySDJWTSignature (publicKeyJWK issuerKeyPair) presentation Nothing
            case verifyResult of
              Right () -> return ()  -- Success
              Left err -> expectationFailure $ "Ed25519 signature verification failed: " ++ show err
      
      it "creates SD-JWT with EC P-256 key signing (ES256)" $ do
        -- Generate test EC key pair
        issuerKeyPair <- generateTestECKeyPair
        
        -- Create claims with selective disclosure
        let claims = KeyMap.fromList

              [  (Key.fromText "sub", Aeson.String "user_42")
              ,  (Key.fromText "given_name", Aeson.String "John")
              ,  (Key.fromText "family_name", Aeson.String "Doe")
              ]
        let selectiveClaimNames = ["given_name", "family_name"]
        
        -- Create SD-JWT with EC P-256 key signing (ES256)
        result <- createSDJWT Nothing Nothing SHA256 (privateKeyJWK issuerKeyPair) selectiveClaimNames claims
        case result of
          Left err -> expectationFailure $ "Failed to create SD-JWT with EC key: " ++ show err
          Right sdJWT -> do
            -- Verify SD-JWT is created (non-empty)
            issuerSignedJWT sdJWT `shouldSatisfy` (not . T.null)
            -- Verify it contains dots (JWT format: header.payload.signature)
            T.splitOn "." (issuerSignedJWT sdJWT) `shouldSatisfy` ((>= 3) . length)
            -- Verify disclosures are created
            disclosures sdJWT `shouldSatisfy` (not . null)
            
            -- Verify we can verify the signature with EC public key
            let presentation = SDJWTPresentation (issuerSignedJWT sdJWT) (disclosures sdJWT) Nothing
            verifyResult <- verifySDJWTSignature (publicKeyJWK issuerKeyPair) presentation Nothing
            case verifyResult of
              Right () -> return ()  -- Success
              Left err -> expectationFailure $ "EC signature verification failed: " ++ show err

  describe "SDJWT.Issuance (Error Paths and Edge Cases)" $ do
    describe "buildSDJWTPayload error handling" $ do
      it "handles empty claims map" $ do
        result <- buildSDJWTPayload SHA256 [] KeyMap.empty
        case result of
          Right (sdPayload, sdDisclosures) -> do
            length sdDisclosures `shouldBe` 0
            -- Payload should be empty or contain only _sd_alg
            sdAlg sdPayload `shouldBe` Just SHA256
          Left err -> expectationFailure $ "Should succeed with empty claims: " ++ show err
      
      it "handles claims map with no selective claims" $ do
        let claims = KeyMap.fromList

              [  (Key.fromText "sub", Aeson.String "user_42")
              ,  (Key.fromText "iss", Aeson.String "https://issuer.example.com")
              ]
        result <- buildSDJWTPayload SHA256 [] claims
        case result of
          Right (sdPayload, sdDisclosures) -> do
            length sdDisclosures `shouldBe` 0
            -- All claims should remain as regular claims
            case payloadValue sdPayload of
              Aeson.Object obj -> do
                KeyMap.lookup "sub" obj `shouldSatisfy` isJust
                KeyMap.lookup "iss" obj `shouldSatisfy` isJust
              _ -> expectationFailure "Payload should be an object"
          Left err -> expectationFailure $ "Should succeed: " ++ show err
      
      it "handles selective claim that doesn't exist in claims map" $ do
        let claims = KeyMap.fromList

              [  (Key.fromText "sub", Aeson.String "user_42")
              ]
        result <- buildSDJWTPayload SHA256 ["nonexistent_claim"] claims
        case result of
          Right (_, disclosures) -> do
            -- Should succeed but create no disclosure for nonexistent claim
            length disclosures `shouldBe` 0
          Left _ -> return ()  -- Or might return error, both acceptable
      
      it "handles nested path with missing parent" $ do
        let claims = KeyMap.fromList

              [  (Key.fromText "sub", Aeson.String "user_42")
              ]
        result <- buildSDJWTPayload SHA256 ["address/street_address"] claims
        case result of
          Left (InvalidDisclosureFormat msg) -> do
            T.isInfixOf "Parent claim not found" msg `shouldBe` True
          Left _ -> return ()  -- Any error is acceptable
          Right _ -> expectationFailure "Should fail when parent claim doesn't exist"
      
      it "handles nested path where parent is not an object" $ do
        let claims = KeyMap.fromList

              [  (Key.fromText "address", Aeson.String "not-an-object")
              ]
        result <- buildSDJWTPayload SHA256 ["address/street_address"] claims
        case result of
          Left (InvalidDisclosureFormat msg) -> do
            T.isInfixOf "not an object" msg `shouldBe` True
          Left _ -> return ()  -- Any error is acceptable
          Right _ -> expectationFailure "Should fail when parent is not an object"
      
      it "handles nested path where child doesn't exist in parent" $ do
        let claims = KeyMap.fromList

              [  (Key.fromText "address", Aeson.Object $ KeyMap.fromList
                  [  (Key.fromText "locality", Aeson.String "City")
                  ])
              ]
        result <- buildSDJWTPayload SHA256 ["address/street_address"] claims
        case result of
          Right (_, disclosures) -> do
            -- Should succeed but create no disclosure for nonexistent child
            -- The parent object will have an _sd array (possibly empty or with other children)
            length disclosures `shouldBe` 0  -- No disclosure for nonexistent child
          Left _ -> return ()  -- Or might return error, both acceptable
      
      it "handles recursive disclosure with missing parent" $ do
        let claims = KeyMap.fromList

              [  (Key.fromText "sub", Aeson.String "user_42")
              ]
        result <- buildSDJWTPayload SHA256 ["address", "address/street_address"] claims
        case result of
          Left (InvalidDisclosureFormat msg) -> do
            T.isInfixOf "Parent claim not found" msg `shouldBe` True
          Left _ -> return ()  -- Any error is acceptable
          Right _ -> expectationFailure "Should fail when recursive parent doesn't exist"
      
      it "handles recursive disclosure where parent is not an object" $ do
        let claims = KeyMap.fromList

              [  (Key.fromText "address", Aeson.String "not-an-object")
              ]
        result <- buildSDJWTPayload SHA256 ["address", "address/street_address"] claims
        case result of
          Left (InvalidDisclosureFormat msg) -> do
            T.isInfixOf "not an object" msg `shouldBe` True
          Left _ -> return ()  -- Any error is acceptable
          Right _ -> expectationFailure "Should fail when recursive parent is not an object"
    
    describe "Array element disclosure edge cases via JSON Pointer" $ do
      it "handles array element with null value" $ do
        let claims = KeyMap.fromList [ (Key.fromText "test_array", Aeson.Array $ V.fromList [Aeson.Null])]
        result <- buildSDJWTPayload SHA256 ["test_array/0"] claims
        case result of
          Right (_payload, disclosures) -> do
            length disclosures `shouldBe` 1
            unEncodedDisclosure (head disclosures) `shouldSatisfy` (not . T.null)
          Left err -> expectationFailure $ "Should handle null value: " ++ show err
      
      it "handles array element with object value" $ do
        let objValue = Aeson.Object $ KeyMap.fromList [ (Key.fromText "key", Aeson.String "value")]
        let claims = KeyMap.fromList [ (Key.fromText "test_array", Aeson.Array $ V.fromList [objValue])]
        result <- buildSDJWTPayload SHA256 ["test_array/0"] claims
        case result of
          Right (_payload, disclosures) -> do
            length disclosures `shouldBe` 1
            unEncodedDisclosure (head disclosures) `shouldSatisfy` (not . T.null)
          Left err -> expectationFailure $ "Should handle object value: " ++ show err
      
      it "handles array element with nested array value" $ do
        let arrValue = Aeson.Array $ V.fromList [Aeson.String "item1", Aeson.String "item2"]
        let claims = KeyMap.fromList [ (Key.fromText "test_array", Aeson.Array $ V.fromList [arrValue])]
        result <- buildSDJWTPayload SHA256 ["test_array/0"] claims
        case result of
          Right (_payload, disclosures) -> do
            length disclosures `shouldBe` 1
            unEncodedDisclosure (head disclosures) `shouldSatisfy` (not . T.null)
          Left err -> expectationFailure $ "Should handle array value: " ++ show err
  
  describe "addHolderKeyToClaims" $ do
    it "adds cnf claim with valid JWK JSON string" $ do
      let validJWK = "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\",\"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\"}"
      let claims = KeyMap.fromList

            [  (Key.fromText "sub", Aeson.String "user_123")
            ,  (Key.fromText "given_name", Aeson.String "John")
            ]
      let claimsWithCnf = addHolderKeyToClaims validJWK claims
      
      -- Check that cnf claim was added
      KeyMap.lookup (Key.fromText "cnf") claimsWithCnf `shouldSatisfy` isJust
      
      -- Check that cnf has correct structure: {"jwk": <jwk_value>}
      case KeyMap.lookup (Key.fromText "cnf") claimsWithCnf of
        Just (Aeson.Object cnfObj) -> do
          KeyMap.lookup (Key.fromText "jwk") cnfObj `shouldSatisfy` isJust
          -- JWK should be parsed as an object, not a string
          case KeyMap.lookup (Key.fromText "jwk") cnfObj of
            Just (Aeson.Object _) -> return ()  -- Success - JWK parsed as object
            Just (Aeson.String _) -> expectationFailure "JWK should be parsed as object, not string"
            _ -> expectationFailure "JWK should be an object"
        _ -> expectationFailure "cnf claim should be an object"
      
      -- Check that original claims are preserved
      KeyMap.lookup (Key.fromText "sub") claimsWithCnf `shouldBe` Just (Aeson.String "user_123")
      KeyMap.lookup (Key.fromText "given_name") claimsWithCnf `shouldBe` Just (Aeson.String "John")
    
    it "handles invalid JWK JSON string by storing as string" $ do
      let invalidJWK = "not valid json"
      let claims = KeyMap.fromList [ (Key.fromText "sub", Aeson.String "user_123")]
      let claimsWithCnf = addHolderKeyToClaims invalidJWK claims
      
      -- Check that cnf claim was added
      KeyMap.lookup (Key.fromText "cnf") claimsWithCnf `shouldSatisfy` isJust
      
      -- Check that invalid JWK is stored as string
      case KeyMap.lookup (Key.fromText "cnf") claimsWithCnf of
        Just (Aeson.Object cnfObj) -> do
          case KeyMap.lookup (Key.fromText "jwk") cnfObj of
            Just (Aeson.String jwkStr) -> jwkStr `shouldBe` invalidJWK
            _ -> expectationFailure "Invalid JWK should be stored as string"
        _ -> expectationFailure "cnf claim should be an object"
    
    it "overwrites existing cnf claim" $ do
      let validJWK = "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\",\"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\"}"
      let existingCnf = Aeson.Object $ KeyMap.fromList [ (Key.fromText "jwk", Aeson.String "old_key")]
      let claims = KeyMap.fromList

            [  (Key.fromText "sub", Aeson.String "user_123")
            ,  (Key.fromText "cnf", existingCnf)
            ]
      let claimsWithCnf = addHolderKeyToClaims validJWK claims
      
      -- Check that cnf was overwritten
      case KeyMap.lookup (Key.fromText "cnf") claimsWithCnf of
        Just (Aeson.Object cnfObj) -> do
          case KeyMap.lookup (Key.fromText "jwk") cnfObj of
            Just (Aeson.Object newJWK) -> do
              -- New JWK should have kty field
              case KeyMap.lookup (Key.fromText "kty") newJWK of
                Just (Aeson.String "EC") -> return ()  -- Success
                _ -> expectationFailure "New JWK should have kty field"
            _ -> expectationFailure "New cnf should have parsed JWK object"
        _ -> expectationFailure "cnf claim should be an object"
      
      -- Verify old cnf is gone
      case KeyMap.lookup (Key.fromText "cnf") claimsWithCnf of
        Just (Aeson.Object cnfObj) -> do
          case KeyMap.lookup (Key.fromText "jwk") cnfObj of
            Just (Aeson.String "old_key") -> expectationFailure "Old cnf should be overwritten"
            _ -> return ()  -- Success
        _ -> expectationFailure "cnf claim should exist"
    
    it "works with empty claims map" $ do
      let validJWK = "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\",\"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\"}"
      let claims = KeyMap.empty
      let claimsWithCnf = addHolderKeyToClaims validJWK claims
      
      -- Check that cnf claim was added
      KeyMap.lookup (Key.fromText "cnf") claimsWithCnf `shouldSatisfy` isJust
      KeyMap.size claimsWithCnf `shouldBe` 1
  
