{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
module JWTSpec (spec) where

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
spec =     describe "SDJWT.JWT.EC" $ do
    describe "signJWT (ES256)" $ do
      it "signs a JWT with EC P-256 key" $ do
        -- Generate test EC key pair
        keyPair <- generateTestECKeyPair
        
        -- Create a test payload
        let payload = Aeson.object [("sub", Aeson.String "user_123"), ("iat", Aeson.Number 1234567890)]
        
        -- Sign the JWT using EC module directly
        result <- signJWT (privateKeyJWK keyPair) payload
        case result of
          Left err -> expectationFailure $ "Failed to sign JWT with EC key: " ++ show err
          Right signedJWT -> do
            -- Verify JWT structure (header.payload.signature)
            let parts = T.splitOn "." signedJWT
            length parts `shouldBe` 3
            
            -- Verify we can decode and verify with jose
            verifyResult <- verifyJWT (publicKeyJWK keyPair) signedJWT Nothing
            case verifyResult of
              Left err -> expectationFailure $ "Failed to verify EC-signed JWT: " ++ show err
              Right decodedPayload -> do
                -- Verify payload matches
                case decodedPayload of
                  Aeson.Object obj -> case KeyMap.lookup (Key.fromText "sub") obj of
                    Just (Aeson.String "user_123") -> return ()
                    _ -> expectationFailure "Payload 'sub' field mismatch"
                  _ -> expectationFailure "Payload is not an object"
      
      it "fails with invalid JWK format" $ do
        let invalidJWK = "not a valid JSON"
        let payload = Aeson.object [("sub", Aeson.String "user_123")]
        
        result <- signJWT invalidJWK payload
        case result of
          Left (InvalidSignature _) -> return ()  -- Expected error
          Left err -> expectationFailure $ "Unexpected error type: " ++ show err
          Right _ -> expectationFailure "Should fail with invalid JWK format"
      
      it "succeeds with RSA key (signJWT supports all key types)" $ do
        -- Use RSA key - signJWT now supports all key types (RSA, Ed25519, EC)
        -- It will automatically detect the key type and use the appropriate algorithm
        -- RSA keys default to PS256 (RSA-PSS) for security
        rsaKeyPair <- generateTestRSAKeyPair
        let payload = Aeson.object [("sub", Aeson.String "user_123")]
        
        result <- signJWT (privateKeyJWK rsaKeyPair) payload
        case result of
          Left err -> expectationFailure $ "signJWT should succeed with RSA key: " ++ show err
          Right signedJWT -> do
            -- Verify it signed successfully with RSA (PS256 is default)
            let parts = T.splitOn "." signedJWT
            length parts `shouldBe` 3
            -- Verify we can verify it (public key will also default to PS256)
            verifyResult <- verifyJWT (publicKeyJWK rsaKeyPair) signedJWT Nothing
            case verifyResult of
              Left err -> expectationFailure $ "Failed to verify RSA-signed JWT: " ++ show err
              Right _ -> return ()  -- Success
      
      it "succeeds with RSA key using RS256 algorithm (explicit)" $ do
        -- Test RS256 (RSA-PKCS#1 v1.5) support via explicit alg field
        -- PS256 is now the default, but RS256 can be explicitly requested
        rsaKeyPair <- generateTestRSAKeyPair
        -- Create a JWK with alg field specifying RS256 (for both private and public keys)
        let addAlgField jwkText = case Aeson.eitherDecodeStrict (encodeUtf8 jwkText) of
              Right (Aeson.Object obj) -> 
                let updatedObj = KeyMap.insert (Key.fromText "alg") (Aeson.String "RS256") obj
                in case decodeUtf8' (BSL.toStrict (Aeson.encode (Aeson.Object updatedObj))) of
                     Right t -> t
                     Left _ -> jwkText  -- Fallback on decode error
              _ -> jwkText  -- Fallback
        let privateKeyJWKWithAlg = addAlgField (privateKeyJWK rsaKeyPair)
        let publicKeyJWKWithAlg = addAlgField (publicKeyJWK rsaKeyPair)
        let payload = Aeson.object [("sub", Aeson.String "user_rs256")]
        
        result <- signJWT privateKeyJWKWithAlg payload
        case result of
          Left err -> expectationFailure $ "signJWT should succeed with RS256: " ++ show err
          Right signedJWT -> do
            -- Verify it signed successfully with RS256
            let parts = T.splitOn "." signedJWT
            length parts `shouldBe` 3
            -- Verify we can verify it with the public key (public key also needs alg field)
            verifyResult <- verifyJWT publicKeyJWKWithAlg signedJWT Nothing
            case verifyResult of
              Left err -> expectationFailure $ "Failed to verify RS256-signed JWT: " ++ show err
              Right _ -> return ()  -- Success
      
      it "fails with unsupported EC curve" $ do
        -- Create JWK with unsupported curve (P-384 instead of P-256)
        let unsupportedCurveJWK = "{\"kty\":\"EC\",\"crv\":\"P-384\",\"d\":\"dGVzdA\",\"x\":\"dGVzdA\",\"y\":\"dGVzdA\"}"
        let payload = Aeson.object [("sub", Aeson.String "user_123")]
        
        result <- signJWT unsupportedCurveJWK payload
        case result of
          Left (InvalidSignature _) -> return ()  -- Expected error
          Left err -> expectationFailure $ "Unexpected error type: " ++ show err
          Right _ -> expectationFailure "Should fail with unsupported curve"
      
      it "fails with missing 'd' field (private key)" $ do
        -- Create JWK without private key scalar
        let missingD = "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"dGVzdA\",\"y\":\"dGVzdA\"}"
        let payload = Aeson.object [("sub", Aeson.String "user_123")]
        
        result <- signJWT missingD payload
        case result of
          Left (InvalidSignature _) -> return ()  -- Expected error
          Left err -> expectationFailure $ "Unexpected error type: " ++ show err
          Right _ -> expectationFailure "Should fail with missing 'd' field"
      
      it "fails with missing 'x' field" $ do
        -- Create JWK without x coordinate
        let missingX = "{\"kty\":\"EC\",\"crv\":\"P-256\",\"d\":\"dGVzdA\",\"y\":\"dGVzdA\"}"
        let payload = Aeson.object [("sub", Aeson.String "user_123")]
        
        result <- signJWT missingX payload
        case result of
          Left (InvalidSignature _) -> return ()  -- Expected error
          Left err -> expectationFailure $ "Unexpected error type: " ++ show err
          Right _ -> expectationFailure "Should fail with missing 'x' field"
      
      it "fails with missing 'y' field" $ do
        -- Create JWK without y coordinate
        let missingY = "{\"kty\":\"EC\",\"crv\":\"P-256\",\"d\":\"dGVzdA\",\"x\":\"dGVzdA\"}"
        let payload = Aeson.object [("sub", Aeson.String "user_123")]
        
        result <- signJWT missingY payload
        case result of
          Left (InvalidSignature _) -> return ()  -- Expected error
          Left err -> expectationFailure $ "Unexpected error type: " ++ show err
          Right _ -> expectationFailure "Should fail with missing 'y' field"
      
      it "fails with invalid base64url in coordinates" $ do
        -- Create JWK with invalid base64url encoding
        let invalidBase64 = "{\"kty\":\"EC\",\"crv\":\"P-256\",\"d\":\"!!!invalid!!!\",\"x\":\"dGVzdA\",\"y\":\"dGVzdA\"}"
        let payload = Aeson.object [("sub", Aeson.String "user_123")]
        
        result <- signJWT invalidBase64 payload
        case result of
          Left (InvalidSignature _) -> return ()  -- Expected error
          Left err -> expectationFailure $ "Unexpected error type: " ++ show err
          Right _ -> expectationFailure "Should fail with invalid base64url"
      
      it "produces different signatures for same payload (non-deterministic)" $ do
        -- ECDSA signatures are non-deterministic, so signing the same payload twice
        -- should produce different signatures (but both should verify)
        keyPair <- generateTestECKeyPair
        let payload = Aeson.object [("sub", Aeson.String "user_123")]
        
        -- Sign twice
        result1 <- signJWT (privateKeyJWK keyPair) payload
        result2 <- signJWT (privateKeyJWK keyPair) payload
        
        case (result1, result2) of
          (Right jwt1, Right jwt2) -> do
            -- Signatures should be different (ECDSA is non-deterministic)
            jwt1 `shouldNotBe` jwt2
            
            -- But both should verify correctly
            verify1 <- verifyJWT (publicKeyJWK keyPair) jwt1 Nothing
            verify2 <- verifyJWT (publicKeyJWK keyPair) jwt2 Nothing
            
            case (verify1, verify2) of
              (Right _, Right _) -> return ()  -- Both verify successfully
              (Left err, _) -> expectationFailure $ "First JWT verification failed: " ++ show err
              (_, Left err) -> expectationFailure $ "Second JWT verification failed: " ++ show err
          (Left err, _) -> expectationFailure $ "First signing failed: " ++ show err
          (_, Left err) -> expectationFailure $ "Second signing failed: " ++ show err

