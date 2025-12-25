{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
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
import SDJWT.Internal.Verification (verifySDJWT, verifySDJWTSignature, verifySDJWTWithoutSignature, verifyKeyBinding, verifyDisclosures, extractHashAlgorithm)
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
    it "creates SD-JWT payload with selective disclosures" $ do
      let claims = Map.fromList
            [ ("sub", Aeson.String "user_42")
            , ("given_name", Aeson.String "John")
            , ("family_name", Aeson.String "Doe")
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
    
  describe "markSelectivelyDisclosable" $ do
    it "creates disclosure and digest for a claim" $ do
      result <- markSelectivelyDisclosable SHA256 "test_claim" (Aeson.String "test_value")
      case result of
        Right (digest, disclosure) -> do
          unDigest digest `shouldSatisfy` (not . T.null)
          unEncodedDisclosure disclosure `shouldSatisfy` (not . T.null)
        Left err -> expectationFailure $ "Failed to mark claim: " ++ show err
    
  describe "markArrayElementDisclosable" $ do
    it "creates disclosure and digest for an array element" $ do
      result <- markArrayElementDisclosable SHA256 (Aeson.String "FR")
      case result of
        Right (digest, disclosure) -> do
          unDigest digest `shouldSatisfy` (not . T.null)
          unEncodedDisclosure disclosure `shouldSatisfy` (not . T.null)
        Left err -> expectationFailure $ "Failed to mark array element: " ++ show err
    
  describe "processArrayForSelectiveDisclosure" $ do
    it "processes array and marks elements as selectively disclosable" $ do
      let arr = V.fromList [Aeson.String "DE", Aeson.String "FR", Aeson.String "US"]
      result <- processArrayForSelectiveDisclosure SHA256 arr [1]  -- Mark second element
      case result of
        Right (modifiedArr, sdDisclosures) -> do
          V.length modifiedArr `shouldBe` 3
          length sdDisclosures `shouldBe` 1
          -- Check that second element is replaced with {"...": "<digest>"}
          case modifiedArr V.!? 1 of
            Just (Aeson.Object obj) -> do
              KeyMap.lookup (Key.fromText "...") obj `shouldSatisfy` isJust
            _ -> expectationFailure "Second element should be replaced with ellipsis object"
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

  describe "SDJWT.Issuance (Nested Structures)" $ do
    describe "RFC Section 6.2 - Structured SD-JWT with nested address claims" $ do
      it "creates SD-JWT payload with nested _sd array in address object" $ do
        let claims = Map.fromList
              [ ("iss", Aeson.String "https://issuer.example.com")
              , ("iat", Aeson.Number 1683000000)
              , ("exp", Aeson.Number 1883000000)
              , ("sub", Aeson.String "6c5c0a49-b589-431d-bae7-219122a9ec2c")
              , ("address", Aeson.Object $ KeyMap.fromList
                  [ (Key.fromText "street_address", Aeson.String "Schulstr. 12")
                  , (Key.fromText "locality", Aeson.String "Schulpforta")
                  , (Key.fromText "region", Aeson.String "Sachsen-Anhalt")
                  , (Key.fromText "country", Aeson.String "DE")
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
        let claims = Map.fromList
              [ ("iss", Aeson.String "https://issuer.example.com")
              , ("sub", Aeson.String "user_123")
              , ("address", Aeson.Object $ KeyMap.fromList
                  [ (Key.fromText "street_address", Aeson.String "123 Main St")
                  , (Key.fromText "locality", Aeson.String "City")
                  , (Key.fromText "country", Aeson.String "US")
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
        let claims = Map.fromList
              [ ("iss", Aeson.String "https://issuer.example.com")
              , ("sub", Aeson.String "user_123")
              , ("address", Aeson.Object $ KeyMap.fromList
                  [ (Key.fromText "street_address", Aeson.String "123 Main St")
                  , (Key.fromText "locality", Aeson.String "City")
                  ])
              ]
        
        -- Get test keys for signing
        keyPair <- generateTestRSAKeyPair
        
        -- Create SD-JWT with nested structures and sign it (using JSON Pointer syntax)
        result <- createSDJWT SHA256 (privateKeyJWK keyPair) ["address/street_address", "address/locality"] claims
        
        case result of
          Right sdjwt -> do
            -- Create presentation with all disclosures
            case selectDisclosuresByNames sdjwt ["street_address", "locality"] of
              Right presentation -> do
                -- Verify presentation (without issuer key for now - signature verification skipped)
                verificationResult <- verifySDJWTWithoutSignature presentation
                
                case verificationResult of
                  Right processedPayload -> do
                    -- Verify address object is reconstructed correctly
                    case Map.lookup "address" (processedClaims processedPayload) of
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
        let claims = Map.fromList
              [ ("iss", Aeson.String "https://issuer.example.com")
              , ("iat", Aeson.Number 1683000000)
              , ("exp", Aeson.Number 1883000000)
              , ("sub", Aeson.String "6c5c0a49-b589-431d-bae7-219122a9ec2c")
              , ("address", Aeson.Object $ KeyMap.fromList
                  [ (Key.fromText "street_address", Aeson.String "Schulstr. 12")
                  , (Key.fromText "locality", Aeson.String "Schulpforta")
                  , (Key.fromText "region", Aeson.String "Sachsen-Anhalt")
                  , (Key.fromText "country", Aeson.String "DE")
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
        let claims = Map.fromList
              [ ("iss", Aeson.String "https://issuer.example.com")
              , ("sub", Aeson.String "user_123")
              , ("address", Aeson.Object $ KeyMap.fromList
                  [ (Key.fromText "street_address", Aeson.String "123 Main St")
                  , (Key.fromText "locality", Aeson.String "City")
                  ])
              ]
        
        -- Get test keys for signing
        keyPair <- generateTestRSAKeyPair
        
        -- Create SD-JWT with recursive disclosures (parent + children)
        -- Using JSON Pointer syntax: "/" separates path segments
        result <- createSDJWT SHA256 (privateKeyJWK keyPair) ["address", "address/street_address", "address/locality"] claims
        
        case result of
          Right sdjwt -> do
            -- Create presentation with all disclosures
            case selectDisclosuresByNames sdjwt ["address", "street_address", "locality"] of
              Right presentation -> do
                -- Verify presentation (without issuer key for now - signature verification skipped)
                verificationResult <- verifySDJWTWithoutSignature presentation
                
                case verificationResult of
                  Right processedPayload -> do
                    -- Verify address object is reconstructed correctly
                    case Map.lookup "address" (processedClaims processedPayload) of
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
        let claims = Map.fromList
              [ ("address", Aeson.Object $ KeyMap.fromList
                  [ (Key.fromText "street_address", Aeson.String "123 Main St")
                  , (Key.fromText "locality", Aeson.String "City")
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
        let claims = Map.fromList
              [ ("user", Aeson.Object $ KeyMap.fromList
                  [ (Key.fromText "profile", Aeson.Object $ KeyMap.fromList
                      [ (Key.fromText "name", Aeson.String "John")
                      ])
                  ])
              ]
        result <- buildSDJWTPayload SHA256 ["user/profile/name"] claims
        case result of
          Right _ -> return ()  -- Should succeed
          Left err -> expectationFailure $ "Failed: " ++ show err
      
      it "handles multiple nested paths with same parent" $ do
        let claims = Map.fromList
              [ ("address", Aeson.Object $ KeyMap.fromList
                  [ (Key.fromText "street_address", Aeson.String "123 Main St")
                  , (Key.fromText "locality", Aeson.String "City")
                  , (Key.fromText "country", Aeson.String "US")
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
        let claims = Map.fromList
              [ ("contact/email", Aeson.String "test@example.com")  -- Literal key "contact/email" (unescaped in Map)
              , ("address", Aeson.Object $ KeyMap.fromList
                  [ (Key.fromText "street", Aeson.String "123 Main St")
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
        let claims = Map.fromList
              [ ("user~name", Aeson.String "testuser")  -- Literal key "user~name" (unescaped in Map)
              , ("address", Aeson.Object $ KeyMap.fromList
                  [ (Key.fromText "street", Aeson.String "123 Main St")
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
        let claims = Map.fromList
              [ ("contact/email", Aeson.String "test@example.com")  -- Literal key "contact/email" (unescaped in Map)
              , ("address", Aeson.Object $ KeyMap.fromList
                  [ (Key.fromText "street", Aeson.String "123 Main St")
                  , (Key.fromText "email", Aeson.String "address@example.com")
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
        let claims = Map.fromList
              [ ("parent", Aeson.Object $ KeyMap.fromList
                  [ (Key.fromText "key/with/slash", Aeson.String "value1")  -- Literal key with slashes
                  , (Key.fromText "key~with~tilde", Aeson.String "value2")  -- Literal key with tildes
                  , (Key.fromText "normal", Aeson.String "value3")
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
        let claims = Map.fromList
              [ ("parent", Aeson.Object $ KeyMap.fromList
                  [ (Key.fromText "key/with/slashes", Aeson.String "value1")
                  , (Key.fromText "key~with~tildes", Aeson.String "value2")
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
        let claims = Map.fromList
              [ ("parent~", Aeson.Object $ KeyMap.fromList  -- Parent key ends with tilde
                  [ (Key.fromText "child", Aeson.String "value")
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
        let claims = Map.fromList
              [ ("sub", Aeson.String "user_42")
              , ("given_name", Aeson.String "John")
              , ("family_name", Aeson.String "Doe")
              ]
        let selectiveClaimNames = ["given_name", "family_name"]
        
        -- Create SD-JWT with Ed25519 key signing
        result <- createSDJWT SHA256 (privateKeyJWK issuerKeyPair) selectiveClaimNames claims
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
        let claims = Map.fromList
              [ ("sub", Aeson.String "user_42")
              , ("given_name", Aeson.String "John")
              , ("family_name", Aeson.String "Doe")
              ]
        let selectiveClaimNames = ["given_name", "family_name"]
        
        -- Create SD-JWT with EC P-256 key signing (ES256)
        result <- createSDJWT SHA256 (privateKeyJWK issuerKeyPair) selectiveClaimNames claims
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
        result <- buildSDJWTPayload SHA256 [] Map.empty
        case result of
          Right (sdPayload, sdDisclosures) -> do
            length sdDisclosures `shouldBe` 0
            -- Payload should be empty or contain only _sd_alg
            sdAlg sdPayload `shouldBe` Just SHA256
          Left err -> expectationFailure $ "Should succeed with empty claims: " ++ show err
      
      it "handles claims map with no selective claims" $ do
        let claims = Map.fromList
              [ ("sub", Aeson.String "user_42")
              , ("iss", Aeson.String "https://issuer.example.com")
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
        let claims = Map.fromList
              [ ("sub", Aeson.String "user_42")
              ]
        result <- buildSDJWTPayload SHA256 ["nonexistent_claim"] claims
        case result of
          Right (_, disclosures) -> do
            -- Should succeed but create no disclosure for nonexistent claim
            length disclosures `shouldBe` 0
          Left _ -> return ()  -- Or might return error, both acceptable
      
      it "handles nested path with missing parent" $ do
        let claims = Map.fromList
              [ ("sub", Aeson.String "user_42")
              ]
        result <- buildSDJWTPayload SHA256 ["address/street_address"] claims
        case result of
          Left (InvalidDisclosureFormat msg) -> do
            T.isInfixOf "Parent claim not found" msg `shouldBe` True
          Left _ -> return ()  -- Any error is acceptable
          Right _ -> expectationFailure "Should fail when parent claim doesn't exist"
      
      it "handles nested path where parent is not an object" $ do
        let claims = Map.fromList
              [ ("address", Aeson.String "not-an-object")
              ]
        result <- buildSDJWTPayload SHA256 ["address/street_address"] claims
        case result of
          Left (InvalidDisclosureFormat msg) -> do
            T.isInfixOf "not an object" msg `shouldBe` True
          Left _ -> return ()  -- Any error is acceptable
          Right _ -> expectationFailure "Should fail when parent is not an object"
      
      it "handles nested path where child doesn't exist in parent" $ do
        let claims = Map.fromList
              [ ("address", Aeson.Object $ KeyMap.fromList
                  [ (Key.fromText "locality", Aeson.String "City")
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
        let claims = Map.fromList
              [ ("sub", Aeson.String "user_42")
              ]
        result <- buildSDJWTPayload SHA256 ["address", "address/street_address"] claims
        case result of
          Left (InvalidDisclosureFormat msg) -> do
            T.isInfixOf "Parent claim not found" msg `shouldBe` True
          Left _ -> return ()  -- Any error is acceptable
          Right _ -> expectationFailure "Should fail when recursive parent doesn't exist"
      
      it "handles recursive disclosure where parent is not an object" $ do
        let claims = Map.fromList
              [ ("address", Aeson.String "not-an-object")
              ]
        result <- buildSDJWTPayload SHA256 ["address", "address/street_address"] claims
        case result of
          Left (InvalidDisclosureFormat msg) -> do
            T.isInfixOf "not an object" msg `shouldBe` True
          Left _ -> return ()  -- Any error is acceptable
          Right _ -> expectationFailure "Should fail when recursive parent is not an object"
    
    describe "markArrayElementDisclosable edge cases" $ do
      it "handles array element with null value" $ do
        result <- markArrayElementDisclosable SHA256 Aeson.Null
        case result of
          Right (digest, disclosure) -> do
            unDigest digest `shouldSatisfy` (not . T.null)
            unEncodedDisclosure disclosure `shouldSatisfy` (not . T.null)
          Left err -> expectationFailure $ "Should handle null value: " ++ show err
      
      it "handles array element with object value" $ do
        let objValue = Aeson.Object $ KeyMap.fromList [(Key.fromText "key", Aeson.String "value")]
        result <- markArrayElementDisclosable SHA256 objValue
        case result of
          Right (digest, disclosure) -> do
            unDigest digest `shouldSatisfy` (not . T.null)
            unEncodedDisclosure disclosure `shouldSatisfy` (not . T.null)
          Left err -> expectationFailure $ "Should handle object value: " ++ show err
      
      it "handles array element with array value" $ do
        let arrValue = Aeson.Array $ V.fromList [Aeson.String "item1", Aeson.String "item2"]
        result <- markArrayElementDisclosable SHA256 arrValue
        case result of
          Right (digest, disclosure) -> do
            unDigest digest `shouldSatisfy` (not . T.null)
            unEncodedDisclosure disclosure `shouldSatisfy` (not . T.null)
          Left err -> expectationFailure $ "Should handle array value: " ++ show err
  
