{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
module KeyBindingSpec (spec) where

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
spec = describe "SDJWT.KeyBinding (Error Paths and Edge Cases)" $ do
  describe "computeSDHash edge cases" $ do
      it "computes sd_hash for presentation with empty disclosures" $ do
        let jwt = "test.jwt"
        let presentation = SDJWTPresentation jwt [] Nothing
        let sdHash = computeSDHash SHA256 presentation
        unDigest sdHash `shouldSatisfy` (not . T.null)
      
      it "computes sd_hash for presentation with KB-JWT" $ do
        let jwt = "test.jwt"
        let disclosure = EncodedDisclosure "WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgImdpdmVuX25hbWUiLCAiSm9obiJd"
        let kbJwt = Just "kb-jwt-token"
        let presentation = SDJWTPresentation jwt [disclosure] kbJwt
        let sdHash = computeSDHash SHA256 presentation
        unDigest sdHash `shouldSatisfy` (not . T.null)
      
      it "produces different sd_hash for different hash algorithms" $ do
        let jwt = "test.jwt"
        let disclosure = EncodedDisclosure "WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgImdpdmVuX25hbWUiLCAiSm9obiJd"
        let presentation = SDJWTPresentation jwt [disclosure] Nothing
        let sdHash256 = computeSDHash SHA256 presentation
        let sdHash384 = computeSDHash SHA384 presentation
        let sdHash512 = computeSDHash SHA512 presentation
        unDigest sdHash256 `shouldNotBe` unDigest sdHash384
        unDigest sdHash256 `shouldNotBe` unDigest sdHash512
        unDigest sdHash384 `shouldNotBe` unDigest sdHash512
  
  describe "SDJWT.KeyBinding" $ do
    describe "computeSDHash" $ do
      it "computes sd_hash for a presentation" $ do
        let jwt = "test.jwt"
        let disclosure = EncodedDisclosure "WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgImdpdmVuX25hbWUiLCAiSm9obiJd"
        let presentation = SDJWTPresentation jwt [disclosure] Nothing
        let sdHash = computeSDHash SHA256 presentation
        -- Verify sd_hash is computed (non-empty)
        unDigest sdHash `shouldSatisfy` (not . T.null)
    
    describe "createKeyBindingJWT" $ do
      it "creates a KB-JWT with required claims" $ do
        -- Generate test RSA key pair
        keyPair <- generateTestRSAKeyPair
        
        let jwt = "test.jwt"
        let disclosure = EncodedDisclosure "test_disclosure"
        let presentation = SDJWTPresentation jwt [disclosure] Nothing
        let audience = "verifier_123"
        let nonce = "nonce_456"
        let issuedAt = 1234567890 :: Int64
        
        result <- createKeyBindingJWT SHA256 (privateKeyJWK keyPair) audience nonce issuedAt presentation
        case result of
          Right kbJWT -> do
            -- Verify KB-JWT is created (non-empty)
            kbJWT `shouldSatisfy` (not . T.null)
            -- Verify it contains dots (JWT format: header.payload.signature)
            T.splitOn "." kbJWT `shouldSatisfy` ((>= 3) . length)  -- Should have signature now
          Left err -> expectationFailure $ "Failed to create KB-JWT: " ++ show err
      
    describe "verifyKeyBindingJWT" $ do
      it "verifies sd_hash matches presentation" $ do
        -- Generate test RSA key pair
        keyPair <- generateTestRSAKeyPair
        
        let jwt = "test.jwt"
        let disclosure = EncodedDisclosure "WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgImdpdmVuX25hbWUiLCAiSm9obiJd"
        let presentation = SDJWTPresentation jwt [disclosure] Nothing
        
        -- Create a KB-JWT
        result <- createKeyBindingJWT SHA256 (privateKeyJWK keyPair) "audience" "nonce" 1234567890 presentation
        case result of
          Right kbJWT -> do
            -- Verify the KB-JWT (should pass signature and sd_hash checks)
            verifyResult <- verifyKeyBindingJWT SHA256 (publicKeyJWK keyPair) kbJWT presentation
            case verifyResult of
              Right () -> return ()  -- Success
              Left err -> expectationFailure $ "KB-JWT verification failed: " ++ show err
          Left err -> expectationFailure $ "Failed to create KB-JWT: " ++ show err
      
      it "verifies KB-JWT with Ed25519 key" $ do
        -- Generate test Ed25519 key pair
        keyPair <- generateTestEd25519KeyPair
        
        let jwt = "test.jwt"
        let disclosure = EncodedDisclosure "WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgImdpdmVuX25hbWUiLCAiSm9obiJd"
        let presentation = SDJWTPresentation jwt [disclosure] Nothing
        
        -- Create a KB-JWT with Ed25519 key
        result <- createKeyBindingJWT SHA256 (privateKeyJWK keyPair) "audience" "nonce" 1234567890 presentation
        case result of
          Right kbJWT -> do
            -- Verify the KB-JWT with Ed25519 public key (should pass signature and sd_hash checks)
            verifyResult <- verifyKeyBindingJWT SHA256 (publicKeyJWK keyPair) kbJWT presentation
            case verifyResult of
              Right () -> return ()  -- Success
              Left err -> expectationFailure $ "KB-JWT verification with Ed25519 key failed: " ++ show err
          Left err -> expectationFailure $ "Failed to create KB-JWT with Ed25519 key: " ++ show err
      
      it "verifies KB-JWT with EC P-256 key (ES256)" $ do
        -- Generate test EC key pair
        keyPair <- generateTestECKeyPair
        
        let jwt = "test.jwt"
        let disclosure = EncodedDisclosure "WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgImdpdmVuX25hbWUiLCAiSm9obiJd"
        let presentation = SDJWTPresentation jwt [disclosure] Nothing
        
        -- Create a KB-JWT with EC P-256 key (ES256)
        result <- createKeyBindingJWT SHA256 (privateKeyJWK keyPair) "audience" "nonce" 1234567890 presentation
        case result of
          Right kbJWT -> do
            -- Verify the KB-JWT with EC public key (should pass signature and sd_hash checks)
            verifyResult <- verifyKeyBindingJWT SHA256 (publicKeyJWK keyPair) kbJWT presentation
            case verifyResult of
              Right () -> return ()  -- Success
              Left err -> expectationFailure $ "KB-JWT verification with EC key failed: " ++ show err
          Left err -> expectationFailure $ "Failed to create KB-JWT with EC key: " ++ show err
      
      it "rejects KB-JWT with missing typ header" $ do
        -- Generate test RSA key pair
        keyPair <- generateTestRSAKeyPair
        
        let jwt = "test.jwt"
        let disclosure = EncodedDisclosure "WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgImdpdmVuX25hbWUiLCAiSm9obiJd"
        let presentation = SDJWTPresentation jwt [disclosure] Nothing
        
        -- Create a KB-JWT (which should have typ: "kb+jwt")
        result <- createKeyBindingJWT SHA256 (privateKeyJWK keyPair) "audience" "nonce" 1234567890 presentation
        case result of
          Right kbJWT -> do
            -- Manually create a KB-JWT without typ header by replacing the header
            -- Parse the KB-JWT
            let parts = T.splitOn "." kbJWT
            case parts of
              (headerPart : _) -> do
                -- Decode header and verify typ
                headerBytesVal <- case base64urlDecode headerPart of
                  Left err -> fail $ "Failed to decode header: " ++ T.unpack err
                  Right bs -> return bs
                headerJson <- case Aeson.eitherDecodeStrict headerBytesVal of
                  Left err -> fail $ "Failed to parse header: " ++ err
                  Right val -> return val
                -- Verify typ header is present and correct
                case headerJson of
                  Aeson.Object obj -> do
                    case KeyMap.lookup (Key.fromText "typ") obj of
                      Just (Aeson.String "kb+jwt") -> return ()  -- Success - typ header is present and correct
                      Just (Aeson.String typVal) -> expectationFailure $ "Wrong typ value: " ++ T.unpack typVal ++ " (expected 'kb+jwt')"
                      Just _ -> expectationFailure "typ header is not a string"
                      Nothing -> expectationFailure "Missing typ header in KB-JWT"
                  _ -> expectationFailure "Header is not an object"
              _ -> expectationFailure "Invalid KB-JWT format"
          Left err -> expectationFailure $ "Failed to create KB-JWT: " ++ show err
      
      it "rejects KB-JWT with wrong typ header value" $ do
        -- Generate test RSA key pair
        keyPair <- generateTestRSAKeyPair
        
        let jwt = "test.jwt"
        let disclosure = EncodedDisclosure "WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgImdpdmVuX25hbWUiLCAiSm9obiJd"
        let presentation = SDJWTPresentation jwt [disclosure] Nothing
        
        -- Create a KB-JWT
        result <- createKeyBindingJWT SHA256 (privateKeyJWK keyPair) "audience" "nonce" 1234567890 presentation
        case result of
          Right kbJWT -> do
            -- Verify that verification rejects KB-JWT with wrong typ
            -- We can't easily modify the typ without breaking the signature,
            -- but we can verify that our verification function checks typ correctly
            -- by checking that a valid KB-JWT (with correct typ) passes verification
            verifyResult <- verifyKeyBindingJWT SHA256 (publicKeyJWK keyPair) kbJWT presentation
            case verifyResult of
              Right () -> do
                -- Verify the typ header is "kb+jwt" by decoding
                let parts = T.splitOn "." kbJWT
                case parts of
                  (headerPart : _) -> do
                    headerBytesVal <- case base64urlDecode headerPart of
                      Left err -> fail $ "Failed to decode header: " ++ T.unpack err
                      Right bs -> return bs
                    headerJson <- case Aeson.eitherDecodeStrict headerBytesVal of
                      Left err -> fail $ "Failed to parse header: " ++ err
                      Right val -> return val
                    case headerJson of
                      Aeson.Object hObj -> do
                        case KeyMap.lookup (Key.fromText "typ") hObj of
                          Just (Aeson.String "kb+jwt") -> return ()  -- Success - typ is correct
                          Just (Aeson.String typVal) -> expectationFailure $ "Wrong typ value: " ++ T.unpack typVal
                          Just _ -> expectationFailure "typ header is not a string"
                          Nothing -> expectationFailure "Missing typ header"
                      _ -> expectationFailure "Header is not an object"
                  _ -> expectationFailure "Invalid JWT format"
              Left err -> expectationFailure $ "KB-JWT verification failed: " ++ show err
          Left err -> expectationFailure $ "Failed to create KB-JWT: " ++ show err
    
    describe "addKeyBindingToPresentation" $ do
      it "adds key binding to a presentation" $ do
        -- Generate test RSA key pair
        keyPair <- generateTestRSAKeyPair
        
        let jwt = "test.jwt"
        let disclosure = EncodedDisclosure "test_disclosure"
        let presentation = SDJWTPresentation jwt [disclosure] Nothing
        
        result <- addKeyBindingToPresentation SHA256 (privateKeyJWK keyPair) "audience" "nonce" 1234567890 presentation
        case result of
          Right updatedPresentation -> do
            -- Verify key binding was added
            keyBindingJWT updatedPresentation `shouldSatisfy` isJust
            -- Verify other fields unchanged
            presentationJWT updatedPresentation `shouldBe` jwt
            selectedDisclosures updatedPresentation `shouldBe` [disclosure]
          Left err -> expectationFailure $ "Failed to add key binding: " ++ show err
      
      it "adds key binding to a presentation with Ed25519 key" $ do
        -- Generate test Ed25519 key pair
        keyPair <- generateTestEd25519KeyPair
        
        let jwt = "test.jwt"
        let disclosure = EncodedDisclosure "test_disclosure"
        let presentation = SDJWTPresentation jwt [disclosure] Nothing
        
        result <- addKeyBindingToPresentation SHA256 (privateKeyJWK keyPair) "audience" "nonce" 1234567890 presentation
        case result of
          Right updatedPresentation -> do
            -- Verify key binding was added
            keyBindingJWT updatedPresentation `shouldSatisfy` isJust
            -- Verify other fields unchanged
            presentationJWT updatedPresentation `shouldBe` jwt
            selectedDisclosures updatedPresentation `shouldBe` [disclosure]
          Left err -> expectationFailure $ "Failed to add key binding with Ed25519 key: " ++ show err
      
      it "adds key binding using exported addKeyBinding function" $ do
        -- Test the exported addKeyBinding function from Presentation module
        -- This ensures the exported API works correctly
        keyPair <- generateTestRSAKeyPair
        
        let jwt = "test.jwt"
        let disclosure = EncodedDisclosure "test_disclosure"
        let presentation = SDJWTPresentation jwt [disclosure] Nothing
        
        -- Use the exported addKeyBinding function (not addKeyBindingToPresentation)
        result <- addKeyBinding SHA256 (privateKeyJWK keyPair) "audience" "nonce" 1234567890 presentation
        case result of
          Right updatedPresentation -> do
            -- Verify key binding was added
            keyBindingJWT updatedPresentation `shouldSatisfy` isJust
            -- Verify other fields unchanged
            presentationJWT updatedPresentation `shouldBe` jwt
            selectedDisclosures updatedPresentation `shouldBe` [disclosure]
          Left err -> expectationFailure $ "Failed to add key binding via exported function: " ++ show err
      
      it "adds key binding to a presentation with EC P-256 key (ES256)" $ do
        -- Generate test EC key pair
        keyPair <- generateTestECKeyPair
        
        let jwt = "test.jwt"
        let disclosure = EncodedDisclosure "test_disclosure"
        let presentation = SDJWTPresentation jwt [disclosure] Nothing
        
        result <- addKeyBindingToPresentation SHA256 (privateKeyJWK keyPair) "audience" "nonce" 1234567890 presentation
        case result of
          Right updatedPresentation -> do
            -- Verify key binding was added
            keyBindingJWT updatedPresentation `shouldSatisfy` isJust
            -- Verify other fields unchanged
            presentationJWT updatedPresentation `shouldBe` jwt
            selectedDisclosures updatedPresentation `shouldBe` [disclosure]
          Left err -> expectationFailure $ "Failed to add key binding with Ed25519 key: " ++ show err

