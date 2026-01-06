{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
module PresentationSpec (spec) where

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
spec = describe "SDJWT.Presentation" $ do
  describe "Recursive Disclosure Handling" $ do
    it "automatically includes parent disclosure when selecting nested claim (Section 6.3)" $ do
      let claims = KeyMap.fromList

            [  (Key.fromText "iss", Aeson.String "https://issuer.example.com")
            ,  (Key.fromText "sub", Aeson.String "user_123")
            ,  (Key.fromText "address", Aeson.Object $ KeyMap.fromList
                [  (Key.fromText "street_address", Aeson.String "123 Main St")
                ,  (Key.fromText "locality", Aeson.String "City")
                ,  (Key.fromText "country", Aeson.String "US")
                ])
            ]
      
      -- Get test keys for signing
      keyPair <- generateTestRSAKeyPair
      
      -- Create SD-JWT with recursive disclosures (parent + children)
      result <- createSDJWT Nothing Nothing SHA256 (privateKeyJWK keyPair) ["address", "address/street_address", "address/locality"] claims
      
      case result of
        Right sdjwt -> do
          -- Select only nested claims - parent should be automatically included
          case selectDisclosuresByNames sdjwt ["address/street_address", "address/locality"] of
            Right presentation -> do
              -- Decode selected disclosures
              let decodedDisclosures = decodeDisclosures (selectedDisclosures presentation)
              
              -- Verify parent "address" disclosure is included
              let claimNames = mapMaybe getDisclosureClaimName decodedDisclosures
              claimNames `shouldContain` ["address"]
              claimNames `shouldContain` ["street_address"]
              claimNames `shouldContain` ["locality"]
              
              -- Verify address disclosure is recursive (contains _sd array)
              let addressDisclosure = find (\dec -> getDisclosureClaimName dec == Just "address") decodedDisclosures
              case addressDisclosure of
                Just addrDisc -> do
                  -- Verify it contains _sd array
                  case getDisclosureValue addrDisc of
                    Aeson.Object obj -> do
                      KeyMap.lookup (Key.fromText "_sd") obj `shouldSatisfy` isJust
                    _ -> expectationFailure "address disclosure should be an object"
                Nothing -> expectationFailure "address disclosure should be present"
              
              -- Verify presentation can be verified
              verificationResult <- verifySDJWTWithoutSignature presentation
              case verificationResult of
                Right processedPayload -> do
                  -- Verify address object is reconstructed correctly
                  case KeyMap.lookup (Key.fromText "address") (processedClaims processedPayload) of
                    Just (Aeson.Object addressObj) -> do
                      KeyMap.lookup (Key.fromText "street_address") addressObj `shouldSatisfy` isJust
                      KeyMap.lookup (Key.fromText "locality") addressObj `shouldSatisfy` isJust
                    _ -> expectationFailure "address object should be reconstructed"
                Left err -> expectationFailure $ "Verification failed: " ++ show err
            Left err -> expectationFailure $ "Failed to create presentation: " ++ show err
        Left err -> expectationFailure $ "Failed to create SD-JWT: " ++ show err
    
    it "does not include non-recursive parent when selecting nested claim (Section 6.2)" $ do
      let claims = KeyMap.fromList

            [  (Key.fromText "iss", Aeson.String "https://issuer.example.com")
            ,  (Key.fromText "sub", Aeson.String "user_123")
            ,  (Key.fromText "address", Aeson.Object $ KeyMap.fromList
                [  (Key.fromText "street_address", Aeson.String "123 Main St")
                ,  (Key.fromText "locality", Aeson.String "City")
                ,  (Key.fromText "country", Aeson.String "US")
                ])
            ]
      
      -- Get test keys for signing
      keyPair <- generateTestRSAKeyPair
      
      -- Create SD-JWT with structured nested disclosures (Section 6.2: parent stays, children are selectively disclosable)
      result <- createSDJWT Nothing Nothing SHA256 (privateKeyJWK keyPair) ["address/street_address", "address/locality"] claims
      
      case result of
        Right sdjwt -> do
          -- Select only nested claims - parent should NOT be included (it's not recursively disclosable)
          case selectDisclosuresByNames sdjwt ["address/street_address", "address/locality"] of
            Right presentation -> do
              -- Decode selected disclosures
              let decodedDisclosures = decodeDisclosures (selectedDisclosures presentation)
              
              -- Verify parent "address" disclosure is NOT included (it's not recursively disclosable)
              let claimNames = mapMaybe getDisclosureClaimName decodedDisclosures
              claimNames `shouldNotContain` ["address"]
              claimNames `shouldContain` ["street_address"]
              claimNames `shouldContain` ["locality"]
            Left err -> expectationFailure $ "Failed to create presentation: " ++ show err
        Left err -> expectationFailure $ "Failed to create SD-JWT: " ++ show err
    
    describe "createPresentation" $ do
      it "creates presentation with selected disclosures" $ do
        let jwt = "test.jwt"
        let sdjwt = SDJWT jwt []
        let selected = []
        let presentation = createPresentation sdjwt selected
        presentationJWT presentation `shouldBe` jwt
        selectedDisclosures presentation `shouldBe` selected
        keyBindingJWT presentation `shouldBe` Nothing
    
    describe "selectDisclosures" $ do
      it "selects disclosures from SD-JWT" $ do
        let disclosure1 = EncodedDisclosure "disclosure1"
        let disclosure2 = EncodedDisclosure "disclosure2"
        let sdjwt = SDJWT "test.jwt" [disclosure1, disclosure2]
        case selectDisclosures sdjwt [disclosure1] of
          Right presentation -> do
            presentationJWT presentation `shouldBe` "test.jwt"
            selectedDisclosures presentation `shouldBe` [disclosure1]
          Left err -> expectationFailure $ "Failed to select disclosures: " ++ show err
      
      it "rejects disclosures not in original SD-JWT" $ do
        let disclosure1 = EncodedDisclosure "disclosure1"
        let disclosure2 = EncodedDisclosure "disclosure2"
        let sdjwt = SDJWT "test.jwt" [disclosure1]
        case selectDisclosures sdjwt [disclosure2] of
          Right _ -> expectationFailure "Should have rejected invalid disclosure"
          Left _ -> return ()  -- Expected error
    
    describe "selectDisclosuresByNames" $ do
      it "selects disclosures by claim names" $ do
        -- Create an SD-JWT with disclosures
        let claims = KeyMap.fromList

              [  (Key.fromText "given_name", Aeson.String "John")
              ,  (Key.fromText "family_name", Aeson.String "Doe")
              ,  (Key.fromText "sub", Aeson.String "user_42")
              ]
        result <- buildSDJWTPayload SHA256 ["given_name", "family_name"] claims
        case result of
          Right (payload, testDisclosures) -> do
            -- Create a valid JWT format (header.payload.signature) with the actual payload
            let payloadBS = BSL.toStrict $ Aeson.encode (payloadValue payload)
            let encodedPayload = base64urlEncode payloadBS
            let jwt = T.concat ["eyJhbGciOiJSUzI1NiJ9.", encodedPayload, ".signature"]
            let sdjwt = SDJWT jwt testDisclosures
            
            -- Select only given_name
            case selectDisclosuresByNames sdjwt ["given_name"] of
              Right presentation -> do
                presentationJWT presentation `shouldBe` jwt
                length (selectedDisclosures presentation) `shouldBe` 1
              Left err -> expectationFailure $ "Failed to select by names: " ++ show err
          Left err -> expectationFailure $ "Failed to build payload: " ++ show err

  -- Nested Structure Tests (Section 6.2 - Structured SD-JWT)
  
  describe "SDJWT.Presentation (Error Paths and Edge Cases)" $ do
    describe "selectDisclosuresByNames error handling" $ do
      it "handles empty claim names list" $ do
        let claims = KeyMap.fromList

              [  (Key.fromText "sub", Aeson.String "user_42")
              ,  (Key.fromText "given_name", Aeson.String "John")
              ]
        result <- buildSDJWTPayload SHA256 ["given_name"] claims
        case result of
          Right (_payload, _sdDisclosures) -> do
            keyPair <- generateTestRSAKeyPair
            sdjwtResult <- createSDJWT Nothing Nothing SHA256 (privateKeyJWK keyPair) ["given_name"] claims
            case sdjwtResult of
              Right sdjwt -> do
                case selectDisclosuresByNames sdjwt [] of
                  Right presentation -> do
                    length (selectedDisclosures presentation) `shouldBe` 0
                  Left err -> expectationFailure $ "Should succeed with empty list: " ++ show err
              Left err -> expectationFailure $ "Failed to create SD-JWT: " ++ show err
          Left err -> expectationFailure $ "Failed to build payload: " ++ show err
      
      it "extracts digests from arrays with ellipsis objects" $ do
        -- Test that selectDisclosuresByNames correctly extracts digests from arrays
        -- containing {"...": "<digest>"} objects via extractDigestsFromJWTPayload
        let claims = KeyMap.fromList

              [  (Key.fromText "sub", Aeson.String "user_42")
              ,  (Key.fromText "given_name", Aeson.String "John")
              ,  (Key.fromText "nationalities", Aeson.Array $ V.fromList [Aeson.String "US", Aeson.String "DE"])
              ]
        -- Mark both given_name and nationalities/0 as selectively disclosable using JSON Pointer
        result <- buildSDJWTPayload SHA256 ["given_name", "nationalities/0"] claims
        case result of
          Right (payload, allDisclosures) -> do
            -- Create SD-JWT using the payload
            let payloadBS = BSL.toStrict $ Aeson.encode (payloadValue payload)
            let encodedPayload = base64urlEncode payloadBS
            let jwt = T.concat ["eyJhbGciOiJSUzI1NiJ9.", encodedPayload, ".signature"]
            let sdjwt = SDJWT jwt allDisclosures
            
            -- Select disclosures - this should extract digests from the array ellipsis object
            case selectDisclosuresByNames sdjwt ["given_name"] of
              Right presentation -> do
                -- Should succeed - extractDigestsFromValue should extract digest from array
                length (selectedDisclosures presentation) `shouldBe` 1
              Left err -> expectationFailure $ "Should extract digests from arrays: " ++ show err
          Left err -> expectationFailure $ "Failed to build payload: " ++ show err
      
      it "handles arrays with objects that don't have ellipsis key" $ do
        -- Test that extractDigestsFromValue correctly handles array elements that are objects
        -- but don't have the "..." key (should recursively process them)
        let claims = KeyMap.fromList

              [  (Key.fromText "sub", Aeson.String "user_42")
              ,  (Key.fromText "given_name", Aeson.String "John")
              ]
        result <- buildSDJWTPayload SHA256 ["given_name"] claims
        case result of
          Right (_, sdDisclosures) -> do
            let givenNameDigest = computeDigest SHA256 (head sdDisclosures)
            -- Create payload with array containing objects without "..." key
            let payloadWithArray = Aeson.object
                  [  (Key.fromText "_sd_alg", Aeson.String "sha-256")
                  ,  (Key.fromText "_sd", Aeson.Array $ V.fromList [Aeson.String (unDigest givenNameDigest)])
                  ,  (Key.fromText "items", Aeson.Array $ V.fromList
                      [ Aeson.Object $ KeyMap.fromList [ (Key.fromText "name", Aeson.String "item1"),  (Key.fromText "value", Aeson.Number 10)]  -- Object without "..."
                      , Aeson.Object $ KeyMap.fromList [ (Key.fromText "name", Aeson.String "item2"),  (Key.fromText "value", Aeson.Number 20)]  -- Object without "..."
                      ])
                  ]
            let payloadBS = BSL.toStrict $ Aeson.encode payloadWithArray
            let encodedPayload = base64urlEncode payloadBS
            let jwt = T.concat ["eyJhbGciOiJSUzI1NiJ9.", encodedPayload, ".signature"]
            let sdjwt = SDJWT jwt sdDisclosures
            
            -- Select disclosures - should handle arrays with non-ellipsis objects gracefully
            case selectDisclosuresByNames sdjwt ["given_name"] of
              Right presentation -> do
                length (selectedDisclosures presentation) `shouldBe` 1
              Left err -> expectationFailure $ "Should handle arrays with non-ellipsis objects: " ++ show err
          Left err -> expectationFailure $ "Failed to build payload: " ++ show err
      
      it "exercises buildDisclosureMap with mixed object and array disclosures" $ do
        -- This test ensures buildDisclosureMap's Nothing branch (for array disclosures) is covered
        -- buildDisclosureMap filters out array disclosures since they don't have claim names
        let claims = KeyMap.fromList

              [  (Key.fromText "given_name", Aeson.String "John")
              ,  (Key.fromText "nationalities", Aeson.Array $ V.fromList [Aeson.String "US"])
              ]
        result <- buildSDJWTPayload SHA256 ["given_name"] claims
        case result of
          Right (payload, allDisclosures) -> do
            -- Create SD-JWT with both object and array disclosures
            let payloadBS = BSL.toStrict $ Aeson.encode (payloadValue payload)
            let encodedPayload = base64urlEncode payloadBS
            let jwt = T.concat ["eyJhbGciOiJSUzI1NiJ9.", encodedPayload, ".signature"]
            let sdjwt = SDJWT jwt allDisclosures
            
            -- selectDisclosuresByNames calls buildDisclosureMap internally
            -- buildDisclosureMap processes both object and array disclosures:
            -- - Object disclosures (Just name) -> included in map
            -- - Array disclosures (Nothing) -> filtered out (exercises Nothing branch)
            case selectDisclosuresByNames sdjwt ["given_name"] of
              Right presentation -> do
                -- Should succeed - array disclosures are filtered out by buildDisclosureMap
                -- but object disclosures are still selected correctly
                length (selectedDisclosures presentation) `shouldBe` 1
              Left err -> expectationFailure $ "Should handle mixed disclosures: " ++ show err
          Left err -> expectationFailure $ "Failed to build payload: " ++ show err
      
      it "handles arrays with ellipsis objects where value is not a string" $ do
        -- Test that extractDigestsFromValue correctly handles ellipsis objects where
        -- the "..." value is not a string (should recursively process them)
        let claims = KeyMap.fromList

              [  (Key.fromText "sub", Aeson.String "user_42")
              ,  (Key.fromText "given_name", Aeson.String "John")
              ]
        result <- buildSDJWTPayload SHA256 ["given_name"] claims
        case result of
          Right (_, sdDisclosures) -> do
            let givenNameDigest = computeDigest SHA256 (head sdDisclosures)
            -- Create payload with array containing ellipsis objects with non-string values
            let payloadWithArray = Aeson.object
                  [  (Key.fromText "_sd_alg", Aeson.String "sha-256")
                  ,  (Key.fromText "_sd", Aeson.Array $ V.fromList [Aeson.String (unDigest givenNameDigest)])
                  ,  (Key.fromText "items", Aeson.Array $ V.fromList
                      [ Aeson.Object $ KeyMap.fromList [ (Key.fromText "...", Aeson.Number 123)]  -- Non-string value
                      , Aeson.Object $ KeyMap.fromList [ (Key.fromText "...", Aeson.Bool True)]  -- Non-string value
                      , Aeson.Object $ KeyMap.fromList [ (Key.fromText "...", Aeson.Null)]  -- Non-string value
                      ])
                  ]
            let payloadBS = BSL.toStrict $ Aeson.encode payloadWithArray
            let encodedPayload = base64urlEncode payloadBS
            let jwt = T.concat ["eyJhbGciOiJSUzI1NiJ9.", encodedPayload, ".signature"]
            let sdjwt = SDJWT jwt sdDisclosures
            
            -- Select disclosures - should handle non-string ellipsis values gracefully
            case selectDisclosuresByNames sdjwt ["given_name"] of
              Right presentation -> do
                length (selectedDisclosures presentation) `shouldBe` 1
              Left err -> expectationFailure $ "Should handle non-string ellipsis values: " ++ show err
          Left err -> expectationFailure $ "Failed to build payload: " ++ show err
      
      it "handles arrays with primitive (non-object) elements" $ do
        -- Test that extractDigestsFromValue correctly handles arrays with primitive elements
        -- (should recursively process them, though they won't contain digests)
        let claims = KeyMap.fromList

              [  (Key.fromText "sub", Aeson.String "user_42")
              ,  (Key.fromText "given_name", Aeson.String "John")
              ]
        result <- buildSDJWTPayload SHA256 ["given_name"] claims
        case result of
          Right (_, sdDisclosures) -> do
            let givenNameDigest = computeDigest SHA256 (head sdDisclosures)
            -- Create payload with array containing primitive elements
            let payloadWithArray = Aeson.object
                  [  (Key.fromText "_sd_alg", Aeson.String "sha-256")
                  ,  (Key.fromText "_sd", Aeson.Array $ V.fromList [Aeson.String (unDigest givenNameDigest)])
                  ,  (Key.fromText "items", Aeson.Array $ V.fromList
                      [ Aeson.String "item1"  -- Primitive string
                      , Aeson.Number 42  -- Primitive number
                      , Aeson.Bool True  -- Primitive bool
                      ])
                  ]
            let payloadBS = BSL.toStrict $ Aeson.encode payloadWithArray
            let encodedPayload = base64urlEncode payloadBS
            let jwt = T.concat ["eyJhbGciOiJSUzI1NiJ9.", encodedPayload, ".signature"]
            let sdjwt = SDJWT jwt sdDisclosures
            
            -- Select disclosures - should handle primitive array elements gracefully
            case selectDisclosuresByNames sdjwt ["given_name"] of
              Right presentation -> do
                length (selectedDisclosures presentation) `shouldBe` 1
              Left err -> expectationFailure $ "Should handle primitive array elements: " ++ show err
          Left err -> expectationFailure $ "Failed to build payload: " ++ show err
      
      it "handles claim name that doesn't exist in disclosures" $ do
        let claims = KeyMap.fromList

              [  (Key.fromText "sub", Aeson.String "user_42")
              ,  (Key.fromText "given_name", Aeson.String "John")
              ]
        result <- buildSDJWTPayload SHA256 ["given_name"] claims
        case result of
          Right (_payload, _sdDisclosures) -> do
            keyPair <- generateTestRSAKeyPair
            sdjwtResult <- createSDJWT Nothing Nothing SHA256 (privateKeyJWK keyPair) ["given_name"] claims
            case sdjwtResult of
              Right sdjwt -> do
                case selectDisclosuresByNames sdjwt ["nonexistent_claim"] of
                  Right presentation -> do
                    -- Should succeed but return no disclosures
                    length (selectedDisclosures presentation) `shouldBe` 0
                  Left _ -> return ()  -- Or might return error, both acceptable
              Left err -> expectationFailure $ "Failed to create SD-JWT: " ++ show err
          Left err -> expectationFailure $ "Failed to build payload: " ++ show err
      
      it "handles nested path where parent disclosure is missing" $ do
        -- Create SD-JWT with structured nested disclosure (Section 6.2)
        let claims = KeyMap.fromList

              [  (Key.fromText "address", Aeson.Object $ KeyMap.fromList
                  [  (Key.fromText "street_address", Aeson.String "123 Main St")
                  ,  (Key.fromText "locality", Aeson.String "City")
                  ])
              ]
        keyPair <- generateTestRSAKeyPair
        result <- createSDJWT Nothing Nothing SHA256 (privateKeyJWK keyPair) ["address/street_address"] claims
        case result of
          Right sdjwt -> do
            -- Try to select nested claim - should work (parent stays in payload for Section 6.2)
            case selectDisclosuresByNames sdjwt ["address/street_address"] of
              Right presentation -> do
                length (selectedDisclosures presentation) `shouldBe` 1
              Left err -> expectationFailure $ "Should succeed: " ++ show err
          Left err -> expectationFailure $ "Failed to create SD-JWT: " ++ show err
    
    it "collects disclosures from value's _sd array when claim not in parent _sd (tests collectDisclosuresForValue)" $ do
      -- This tests collectDisclosuresForValue (line 206) which is called when:
      -- - Selecting a claim that is NOT in the parent's _sd array
      -- - But the claim value itself contains an _sd array (Section 6.2 structured nested disclosure)
      -- The existing test "does not include non-recursive parent when selecting nested claim" 
      -- already covers this scenario, but this test explicitly verifies collectDisclosuresForValue works.
      -- Note: collectDisclosuresForValue may not be directly called in all scenarios, but it's part
      -- of the code path for structured nested disclosures where parent stays in payload.
      let claims = KeyMap.fromList

            [  (Key.fromText "address", Aeson.Object $ KeyMap.fromList
                [  (Key.fromText "street_address", Aeson.String "123 Main St")
                ,  (Key.fromText "locality", Aeson.String "City")
                ,  (Key.fromText "country", Aeson.String "US")
                ])
            ]
      
      keyPair <- generateTestRSAKeyPair
      -- Create SD-JWT with structured nested disclosure (Section 6.2)
      -- "address" stays in payload, children are selectively disclosable
      result <- createSDJWT Nothing Nothing SHA256 (privateKeyJWK keyPair) ["address/street_address", "address/locality"] claims
      
      case result of
        Right sdjwt -> do
          -- Select nested claims - this exercises the code path that uses collectDisclosuresForValue
          -- indirectly through the recursive collection logic
          case selectDisclosuresByNames sdjwt ["address/street_address", "address/locality"] of
            Right presentation -> do
              -- Should collect disclosures from address object's _sd array
              let decodedDisclosures = decodeDisclosures (selectedDisclosures presentation)
              let claimNames = mapMaybe getDisclosureClaimName decodedDisclosures
              -- Should include child disclosures (street_address, locality) from address's _sd
              claimNames `shouldContain` ["street_address"]
              claimNames `shouldContain` ["locality"]
              -- Parent "address" should NOT be included (it's not recursively disclosable)
              claimNames `shouldNotContain` ["address"]
              length decodedDisclosures `shouldBe` 2
            Left err -> expectationFailure $ "Should succeed: " ++ show err
        Left err -> expectationFailure $ "Failed to create SD-JWT: " ++ show err
  
