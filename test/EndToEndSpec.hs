{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
-- | End-to-end tests for complete SD-JWT flows.
--
-- These tests verify the complete issuer → holder → verifier flow,
-- ensuring all components work together correctly.
module EndToEndSpec (spec) where

import Test.Hspec
import TestKeys
import SDJWT.Internal.Types
import SDJWT.Internal.Serialization
import SDJWT.Internal.Issuance
import SDJWT.Internal.Presentation
import SDJWT.Internal.Verification
import SDJWT.Internal.KeyBinding
import qualified Data.Aeson as Aeson
import qualified Data.Aeson.Key as Key
import qualified Data.Aeson.KeyMap as KeyMap
import qualified Data.Map.Strict as Map
import qualified Data.Text as T
import Data.Text.Encoding (encodeUtf8)
import Data.Int (Int64)

spec :: Spec
spec = describe "End-to-End SD-JWT Flows" $ do
  describe "Complete Flow: Issuer → Holder → Verifier" $ do
    it "works with RSA keys" $ do
      issuerKeyPair <- generateTestRSAKeyPair
      let claims = Map.fromList
            [ ("sub", Aeson.String "user_123")
            , ("given_name", Aeson.String "John")
            , ("family_name", Aeson.String "Doe")
            , ("email", Aeson.String "john.doe@example.com")
            ]
      
      -- Step 1: Issuer creates SD-JWT
      issuanceResult <- createSDJWT Nothing SHA256 (privateKeyJWK issuerKeyPair) 
                                     ["given_name", "family_name", "email"] claims
      case issuanceResult of
        Left err -> expectationFailure $ "Issuance failed: " ++ show err
        Right sdjwt -> do
          -- Step 2: Serialize and deserialize (simulating transmission)
          let serialized = serializeSDJWT sdjwt
          case deserializeSDJWT serialized of
            Left err -> expectationFailure $ "Deserialization failed: " ++ show err
            Right deserializedSdjwt -> do
              -- Step 3: Holder creates presentation with selected disclosures
              case selectDisclosuresByNames deserializedSdjwt ["given_name", "email"] of
                Left err -> expectationFailure $ "Presentation creation failed: " ++ show err
                Right presentation -> do
                  -- Step 4: Serialize and deserialize presentation
                  let presentationText = serializePresentation presentation
                  case deserializePresentation presentationText of
                    Left err -> expectationFailure $ "Presentation deserialization failed: " ++ show err
                    Right deserializedPresentation -> do
                      -- Step 5: Verifier verifies the presentation
                      verifyResult <- verifySDJWT (publicKeyJWK issuerKeyPair) deserializedPresentation Nothing
                      case verifyResult of
                        Left err -> expectationFailure $ "Verification failed: " ++ show err
                        Right processedPayload -> do
                          -- Step 6: Verify claims are correct
                          let extractedClaims = processedClaims processedPayload
                          Map.lookup "sub" extractedClaims `shouldBe` Just (Aeson.String "user_123")
                          Map.lookup "given_name" extractedClaims `shouldBe` Just (Aeson.String "John")
                          Map.lookup "email" extractedClaims `shouldBe` Just (Aeson.String "john.doe@example.com")
                          -- family_name should NOT be present (not selected)
                          Map.lookup "family_name" extractedClaims `shouldBe` Nothing
    
    it "works with EC P-256 keys" $ do
      issuerKeyPair <- generateTestECKeyPair
      let claims = Map.fromList
            [ ("sub", Aeson.String "user_456")
            , ("given_name", Aeson.String "Jane")
            , ("family_name", Aeson.String "Smith")
            ]
      
      -- Complete flow
      issuanceResult <- createSDJWT Nothing SHA256 (privateKeyJWK issuerKeyPair) 
                                     ["given_name", "family_name"] claims
      case issuanceResult of
        Left err -> expectationFailure $ "Issuance failed: " ++ show err
        Right sdjwt -> do
          let serialized = serializeSDJWT sdjwt
          case deserializeSDJWT serialized of
            Left err -> expectationFailure $ "Deserialization failed: " ++ show err
            Right deserializedSdjwt -> do
              case selectDisclosuresByNames deserializedSdjwt ["given_name"] of
                Left err -> expectationFailure $ "Presentation creation failed: " ++ show err
                Right presentation -> do
                  let presentationText = serializePresentation presentation
                  case deserializePresentation presentationText of
                    Left err -> expectationFailure $ "Presentation deserialization failed: " ++ show err
                    Right deserializedPresentation -> do
                      verifyResult <- verifySDJWT (publicKeyJWK issuerKeyPair) deserializedPresentation Nothing
                      case verifyResult of
                        Left err -> expectationFailure $ "Verification failed: " ++ show err
                        Right processedPayload -> do
                          let extractedClaims = processedClaims processedPayload
                          Map.lookup "sub" extractedClaims `shouldBe` Just (Aeson.String "user_456")
                          Map.lookup "given_name" extractedClaims `shouldBe` Just (Aeson.String "Jane")
                          Map.lookup "family_name" extractedClaims `shouldBe` Nothing
    
    it "works with Ed25519 keys" $ do
      issuerKeyPair <- generateTestEd25519KeyPair
      let claims = Map.fromList
            [ ("sub", Aeson.String "user_789")
            , ("given_name", Aeson.String "Bob")
            , ("email", Aeson.String "bob@example.com")
            ]
      
      -- Complete flow
      issuanceResult <- createSDJWT Nothing SHA256 (privateKeyJWK issuerKeyPair) 
                                     ["given_name", "email"] claims
      case issuanceResult of
        Left err -> expectationFailure $ "Issuance failed: " ++ show err
        Right sdjwt -> do
          let serialized = serializeSDJWT sdjwt
          case deserializeSDJWT serialized of
            Left err -> expectationFailure $ "Deserialization failed: " ++ show err
            Right deserializedSdjwt -> do
              case selectDisclosuresByNames deserializedSdjwt ["given_name", "email"] of
                Left err -> expectationFailure $ "Presentation creation failed: " ++ show err
                Right presentation -> do
                  let presentationText = serializePresentation presentation
                  case deserializePresentation presentationText of
                    Left err -> expectationFailure $ "Presentation deserialization failed: " ++ show err
                    Right deserializedPresentation -> do
                      verifyResult <- verifySDJWT (publicKeyJWK issuerKeyPair) deserializedPresentation Nothing
                      case verifyResult of
                        Left err -> expectationFailure $ "Verification failed: " ++ show err
                        Right processedPayload -> do
                          let extractedClaims = processedClaims processedPayload
                          Map.lookup "sub" extractedClaims `shouldBe` Just (Aeson.String "user_789")
                          Map.lookup "given_name" extractedClaims `shouldBe` Just (Aeson.String "Bob")
                          Map.lookup "email" extractedClaims `shouldBe` Just (Aeson.String "bob@example.com")
  
  describe "End-to-End Flow with Key Binding" $ do
    it "works with RSA keys" $ do
      issuerKeyPair <- generateTestRSAKeyPair
      holderKeyPair <- generateTestRSAKeyPair2
      -- Parse holder's public key JWK as JSON for cnf claim
      let holderPublicKeyJWK = publicKeyJWK holderKeyPair
      let holderPublicKeyJSON = case Aeson.eitherDecodeStrict (encodeUtf8 holderPublicKeyJWK) of
            Right jwk -> jwk
            Left _ -> Aeson.Object KeyMap.empty  -- Fallback
      let cnfValue = Aeson.Object $ KeyMap.fromList [(Key.fromText "jwk", holderPublicKeyJSON)]
      let claims = Map.fromList
            [ ("sub", Aeson.String "user_kb_123")
            , ("given_name", Aeson.String "Alice")
            , ("email", Aeson.String "alice@example.com")
            , ("cnf", cnfValue)
            ]
      
      -- Step 1: Issuer creates SD-JWT with cnf claim
      issuanceResult <- createSDJWT Nothing SHA256 (privateKeyJWK issuerKeyPair) 
                                     ["given_name", "email"] claims
      case issuanceResult of
        Left err -> expectationFailure $ "Issuance failed: " ++ show err
        Right sdjwt -> do
          -- Step 2: Holder creates presentation
          case selectDisclosuresByNames sdjwt ["given_name"] of
            Left err -> expectationFailure $ "Presentation creation failed: " ++ show err
            Right presentation -> do
              -- Step 3: Holder adds key binding
              let audience = "verifier.example.com"
              let nonce = "test-nonce-12345"
              let issuedAt = 1683000000 :: Int64
              kbResult <- addKeyBindingToPresentation SHA256 (privateKeyJWK holderKeyPair) 
                                                          audience nonce issuedAt presentation
              case kbResult of
                Left err -> expectationFailure $ "Key binding failed: " ++ show err
                Right kbPresentation -> do
                  -- Step 4: Serialize and deserialize
                  let presentationText = serializePresentation kbPresentation
                  case deserializePresentation presentationText of
                    Left err -> expectationFailure $ "Deserialization failed: " ++ show err
                    Right deserializedPresentation -> do
                      -- Step 5: Verifier verifies with key binding
                      -- Key binding verification is handled internally by verifySDJWT
                      verifyResult <- verifySDJWT (publicKeyJWK issuerKeyPair) deserializedPresentation Nothing
                      case verifyResult of
                        Left err -> expectationFailure $ "Verification failed: " ++ show err
                        Right processedPayload -> do
                          let extractedClaims = processedClaims processedPayload
                          Map.lookup "sub" extractedClaims `shouldBe` Just (Aeson.String "user_kb_123")
                          Map.lookup "given_name" extractedClaims `shouldBe` Just (Aeson.String "Alice")
                          Map.lookup "email" extractedClaims `shouldBe` Nothing
                          -- Verify key binding info is returned
                          case keyBindingInfo processedPayload of
                            Nothing -> expectationFailure "Expected key binding info but got Nothing"
                            Just kbInfo -> do
                              -- Verify the public key matches what was in the cnf claim
                              kbPublicKey kbInfo `shouldBe` holderPublicKeyJWK
    
    it "works with Ed25519 keys" $ do
      issuerKeyPair <- generateTestEd25519KeyPair
      holderKeyPair <- generateTestEd25519KeyPair
      -- Parse holder's public key JWK as JSON for cnf claim
      let holderPublicKeyJWK = publicKeyJWK holderKeyPair
      let holderPublicKeyJSON = case Aeson.eitherDecodeStrict (encodeUtf8 holderPublicKeyJWK) of
            Right jwk -> jwk
            Left _ -> Aeson.Object KeyMap.empty  -- Fallback
      let cnfValue = Aeson.Object $ KeyMap.fromList [(Key.fromText "jwk", holderPublicKeyJSON)]
      let claims = Map.fromList
            [ ("sub", Aeson.String "user_kb_456")
            , ("given_name", Aeson.String "Charlie")
            , ("cnf", cnfValue)
            ]
      
      issuanceResult <- createSDJWT Nothing SHA256 (privateKeyJWK issuerKeyPair) ["given_name"] claims
      case issuanceResult of
        Left err -> expectationFailure $ "Issuance failed: " ++ show err
        Right sdjwt -> do
          case selectDisclosuresByNames sdjwt ["given_name"] of
            Left err -> expectationFailure $ "Presentation creation failed: " ++ show err
            Right presentation -> do
              kbResult <- addKeyBindingToPresentation SHA256 (privateKeyJWK holderKeyPair) 
                                                          "verifier.example.com" "nonce-123" 1683000000 presentation
              case kbResult of
                Left err -> expectationFailure $ "Key binding failed: " ++ show err
                Right kbPresentation -> do
                  let presentationText = serializePresentation kbPresentation
                  case deserializePresentation presentationText of
                    Left err -> expectationFailure $ "Deserialization failed: " ++ show err
                    Right deserializedPresentation -> do
                      verifyResult <- verifySDJWT (publicKeyJWK issuerKeyPair) deserializedPresentation Nothing
                      case verifyResult of
                        Left err -> expectationFailure $ "Verification failed: " ++ show err
                        Right processedPayload -> do
                          let extractedClaims = processedClaims processedPayload
                          Map.lookup "given_name" extractedClaims `shouldBe` Just (Aeson.String "Charlie")
                          -- Verify key binding info is returned
                          case keyBindingInfo processedPayload of
                            Nothing -> expectationFailure "Expected key binding info but got Nothing"
                            Just kbInfo -> do
                              -- Verify the public key matches what was in the cnf claim
                              kbPublicKey kbInfo `shouldBe` holderPublicKeyJWK
  
  describe "Error Paths" $ do
    it "fails when verifier uses wrong issuer key" $ do
      issuerKeyPair <- generateTestRSAKeyPair
      wrongIssuerKeyPair <- generateTestRSAKeyPair2
      let claims = Map.fromList [("sub", Aeson.String "user_123"), ("name", Aeson.String "Test")]
      
      issuanceResult <- createSDJWT Nothing SHA256 (privateKeyJWK issuerKeyPair) ["name"] claims
      case issuanceResult of
        Left err -> expectationFailure $ "Issuance failed: " ++ show err
        Right sdjwt -> do
          case selectDisclosuresByNames sdjwt ["name"] of
            Left err -> expectationFailure $ "Presentation creation failed: " ++ show err
            Right presentation -> do
              -- Verify with wrong issuer key should fail
              verifyResult <- verifySDJWT (publicKeyJWK wrongIssuerKeyPair) presentation Nothing
              case verifyResult of
                Left (InvalidSignature _) -> return ()  -- Expected error
                Left _ -> return ()  -- Any error is acceptable
                Right _ -> expectationFailure "Verification should fail with wrong issuer key"
    
    it "fails when holder selects non-existent disclosure" $ do
      issuerKeyPair <- generateTestRSAKeyPair
      let claims = Map.fromList [("sub", Aeson.String "user_123"), ("name", Aeson.String "Test")]
      
      issuanceResult <- createSDJWT Nothing SHA256 (privateKeyJWK issuerKeyPair) ["name"] claims
      case issuanceResult of
        Left err -> expectationFailure $ "Issuance failed: " ++ show err
        Right sdjwt -> do
          -- Try to select a disclosure that doesn't exist
          case selectDisclosuresByNames sdjwt ["nonexistent_claim"] of
            Left _ -> return ()  -- Expected error - disclosure doesn't exist
            Right presentation -> do
              -- If it succeeds, verify that the nonexistent claim is not in the presentation
              length (selectedDisclosures presentation) `shouldBe` 0
  
  describe "Edge Cases" $ do
    it "works with empty selective disclosure list" $ do
      issuerKeyPair <- generateTestRSAKeyPair
      let claims = Map.fromList [("sub", Aeson.String "user_123")]
      
      -- Create SD-JWT with no selectively disclosable claims
      issuanceResult <- createSDJWT Nothing SHA256 (privateKeyJWK issuerKeyPair) [] claims
      case issuanceResult of
        Left err -> expectationFailure $ "Issuance failed: " ++ show err
        Right sdjwt -> do
          -- Presentation should have no disclosures
          case selectDisclosuresByNames sdjwt [] of
            Left err -> expectationFailure $ "Presentation creation failed: " ++ show err
            Right presentation -> do
              length (selectedDisclosures presentation) `shouldBe` 0
              -- Verification should still work
              verifyResult <- verifySDJWT (publicKeyJWK issuerKeyPair) presentation Nothing
              case verifyResult of
                Left err -> expectationFailure $ "Verification failed: " ++ show err
                Right processedPayload -> do
                  let extractedClaims = processedClaims processedPayload
                  Map.lookup "sub" extractedClaims `shouldBe` Just (Aeson.String "user_123")
    
    it "works when holder selects all disclosures" $ do
      issuerKeyPair <- generateTestRSAKeyPair
      let claims = Map.fromList
            [ ("sub", Aeson.String "user_123")
            , ("given_name", Aeson.String "John")
            , ("family_name", Aeson.String "Doe")
            , ("email", Aeson.String "john@example.com")
            ]
      
      issuanceResult <- createSDJWT Nothing SHA256 (privateKeyJWK issuerKeyPair) 
                                     ["given_name", "family_name", "email"] claims
      case issuanceResult of
        Left err -> expectationFailure $ "Issuance failed: " ++ show err
        Right sdjwt -> do
          -- Select all disclosures
          case selectDisclosuresByNames sdjwt ["given_name", "family_name", "email"] of
            Left err -> expectationFailure $ "Presentation creation failed: " ++ show err
            Right presentation -> do
              length (selectedDisclosures presentation) `shouldBe` 3
              verifyResult <- verifySDJWT (publicKeyJWK issuerKeyPair) presentation Nothing
              case verifyResult of
                Left err -> expectationFailure $ "Verification failed: " ++ show err
                Right processedPayload -> do
                  let extractedClaims = processedClaims processedPayload
                  Map.lookup "given_name" extractedClaims `shouldBe` Just (Aeson.String "John")
                  Map.lookup "family_name" extractedClaims `shouldBe` Just (Aeson.String "Doe")
                  Map.lookup "email" extractedClaims `shouldBe` Just (Aeson.String "john@example.com")

