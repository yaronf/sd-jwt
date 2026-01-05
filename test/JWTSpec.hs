{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}
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
import SDJWT.Internal.JWT (signJWT, signJWTWithOptionalTyp, verifyJWT, JWKLike(..))
import qualified Crypto.JOSE as Jose
import qualified Crypto.JOSE.JWS as JWS
import qualified Crypto.JOSE.JWK as JWK
import qualified Crypto.JOSE.Compact as Compact
import qualified Crypto.JOSE.Error as JoseError
import Control.Lens ((^..))
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
import Data.Time.Clock.POSIX (getPOSIXTime, POSIXTime)
import Data.Scientific (Scientific)

spec :: Spec
spec = describe "SDJWT.JWT" $ do
  describe "EC" $ do
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
        let invalidJWK :: T.Text = "not a valid JSON"
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
        let unsupportedCurveJWK :: T.Text = "{\"kty\":\"EC\",\"crv\":\"P-384\",\"d\":\"dGVzdA\",\"x\":\"dGVzdA\",\"y\":\"dGVzdA\"}"
        let payload = Aeson.object [("sub", Aeson.String "user_123")]
        
        result <- signJWT unsupportedCurveJWK payload
        case result of
          Left (InvalidSignature _) -> return ()  -- Expected error
          Left err -> expectationFailure $ "Unexpected error type: " ++ show err
          Right _ -> expectationFailure "Should fail with unsupported curve"
      
      it "fails with missing 'd' field (private key)" $ do
        -- Create JWK without private key scalar
        let missingD :: T.Text = "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"dGVzdA\",\"y\":\"dGVzdA\"}"
        let payload = Aeson.object [("sub", Aeson.String "user_123")]
        
        result <- signJWT missingD payload
        case result of
          Left (InvalidSignature _) -> return ()  -- Expected error
          Left err -> expectationFailure $ "Unexpected error type: " ++ show err
          Right _ -> expectationFailure "Should fail with missing 'd' field"
      
      it "fails with missing 'x' field" $ do
        -- Create JWK without x coordinate
        let missingX :: T.Text = "{\"kty\":\"EC\",\"crv\":\"P-256\",\"d\":\"dGVzdA\",\"y\":\"dGVzdA\"}"
        let payload = Aeson.object [("sub", Aeson.String "user_123")]
        
        result <- signJWT missingX payload
        case result of
          Left (InvalidSignature _) -> return ()  -- Expected error
          Left err -> expectationFailure $ "Unexpected error type: " ++ show err
          Right _ -> expectationFailure "Should fail with missing 'x' field"
      
      it "fails with missing 'y' field" $ do
        -- Create JWK without y coordinate
        let missingY :: T.Text = "{\"kty\":\"EC\",\"crv\":\"P-256\",\"d\":\"dGVzdA\",\"x\":\"dGVzdA\"}"
        let payload = Aeson.object [("sub", Aeson.String "user_123")]
        
        result <- signJWT missingY payload
        case result of
          Left (InvalidSignature _) -> return ()  -- Expected error
          Left err -> expectationFailure $ "Unexpected error type: " ++ show err
          Right _ -> expectationFailure "Should fail with missing 'y' field"
      
      it "fails with invalid base64url in coordinates" $ do
        -- Create JWK with invalid base64url encoding
        let invalidBase64 :: T.Text = "{\"kty\":\"EC\",\"crv\":\"P-256\",\"d\":\"!!!invalid!!!\",\"x\":\"dGVzdA\",\"y\":\"dGVzdA\"}"
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
  
  describe "verifyJWT security checks (RFC 8725bis)" $ do
    it "rejects JWT with alg: 'none' header (prevented by jose type system)" $ do
      -- Create a JWT with alg: "none" header manually
      -- Note: jose's type system prevents "none" from being a valid JWA.Alg value,
      -- so it will be rejected during decodeCompact before reaching our validation code
      let header = Aeson.object [("alg", Aeson.String "none"), ("typ", Aeson.String "JWT")]
      let payload = Aeson.object [("sub", Aeson.String "user_123")]
      
      -- Base64url encode header and payload
      let headerBS = BSL.toStrict $ Aeson.encode header
      let payloadBS = BSL.toStrict $ Aeson.encode payload
      let encodedHeader = base64urlEncode headerBS
      let encodedPayload = base64urlEncode payloadBS
      
      -- Create unsecured JWT (no signature)
      let unsecuredJWT = T.concat [encodedHeader, ".", encodedPayload, "."]
      
      -- Try to verify with any key - jose will reject it during decodeCompact
      -- because "none" is not a valid JWA.Alg value (type system prevents it)
      rsaKeyPair <- generateTestRSAKeyPair
      result <- verifyJWT (publicKeyJWK rsaKeyPair) unsecuredJWT Nothing
      
      case result of
        Left (InvalidSignature _msg) -> do
          -- jose library rejects "none" algorithm during decodeCompact
          -- This is the correct behavior - unsecured JWTs are prevented by jose's type system
          -- Our code never sees "none" because it's not a valid JWA.Alg value
          return ()  -- Any error is acceptable - jose prevents "none" at decode time
        Left _err -> return ()  -- Any error is acceptable
        Right _ -> expectationFailure "Should reject JWT with alg: 'none' (jose type system prevents it)"
    
    it "rejects JWT with algorithm mismatch (RFC 8725bis - don't trust header)" $ do
      -- Create a JWT signed with RSA key (PS256)
      rsaKeyPair <- generateTestRSAKeyPair
      let payload = Aeson.object [("sub", Aeson.String "user_123")]
      
      -- Sign with RSA key (will use PS256)
      signedResult <- signJWT (privateKeyJWK rsaKeyPair) payload
      case signedResult of
        Left err -> expectationFailure $ "Failed to sign JWT: " ++ show err
        Right signedJWT -> do
          -- Now try to verify with Ed25519 key (EdDSA)
          -- This should fail because header says PS256 but key expects EdDSA
          ed25519KeyPair <- generateTestEd25519KeyPair
          verifyResult <- verifyJWT (publicKeyJWK ed25519KeyPair) signedJWT Nothing
          
          case verifyResult of
            Left (InvalidSignature msg) -> do
              -- Should reject with algorithm mismatch message
              T.isInfixOf "Algorithm mismatch" msg `shouldBe` True
              T.isInfixOf "RFC 8725bis" msg `shouldBe` True
            Left err -> expectationFailure $ "Expected algorithm mismatch error, got: " ++ show err
            Right _ -> expectationFailure "Should reject JWT with algorithm mismatch"
    
    it "rejects JWT signed with Ed25519 when verified with RSA key" $ do
      -- Create a JWT signed with Ed25519 key (EdDSA)
      ed25519KeyPair <- generateTestEd25519KeyPair
      let payload = Aeson.object [("sub", Aeson.String "user_123")]
      
      -- Sign with Ed25519 key (will use EdDSA)
      signedResult <- signJWT (privateKeyJWK ed25519KeyPair) payload
      case signedResult of
        Left err -> expectationFailure $ "Failed to sign JWT: " ++ show err
        Right signedJWT -> do
          -- Now try to verify with RSA key (PS256)
          -- This should fail because header says EdDSA but key expects PS256
          rsaKeyPair <- generateTestRSAKeyPair
          verifyResult <- verifyJWT (publicKeyJWK rsaKeyPair) signedJWT Nothing
          
          case verifyResult of
            Left (InvalidSignature msg) -> do
              -- Should reject with algorithm mismatch message
              T.isInfixOf "Algorithm mismatch" msg `shouldBe` True
              T.isInfixOf "RFC 8725bis" msg `shouldBe` True
            Left err -> expectationFailure $ "Expected algorithm mismatch error, got: " ++ show err
            Right _ -> expectationFailure "Should reject JWT with algorithm mismatch"
    
    it "rejects JWT signed with RSA when verified with EC key" $ do
      -- Create a JWT signed with RSA key (PS256)
      rsaKeyPair <- generateTestRSAKeyPair
      let payload = Aeson.object [("sub", Aeson.String "user_123")]
      
      -- Sign with RSA key
      signedResult <- signJWT (privateKeyJWK rsaKeyPair) payload
      case signedResult of
        Left err -> expectationFailure $ "Failed to sign JWT: " ++ show err
        Right signedJWT -> do
          -- Now try to verify with EC key (ES256)
          -- This should fail because header says PS256 but key expects ES256
          ecKeyPair <- generateTestECKeyPair
          verifyResult <- verifyJWT (publicKeyJWK ecKeyPair) signedJWT Nothing
          
          case verifyResult of
            Left (InvalidSignature msg) -> do
              -- Should reject with algorithm mismatch message
              T.isInfixOf "Algorithm mismatch" msg `shouldBe` True
              T.isInfixOf "RFC 8725bis" msg `shouldBe` True
            Left err -> expectationFailure $ "Expected algorithm mismatch error, got: " ++ show err
            Right _ -> expectationFailure "Should reject JWT with algorithm mismatch"
  
  describe "verifyJWT error paths" $ do
    it "rejects JWT with invalid format (not 3 parts)" $ do
      keyPair <- generateTestRSAKeyPair
      let invalidJWT = "header.payload"  -- Only 2 parts instead of 3
      
      result <- verifyJWT (publicKeyJWK keyPair) invalidJWT Nothing
      case result of
        Left (InvalidSignature msg) -> do
          T.isInfixOf "Failed to decode JWT" msg `shouldBe` True
        Left _ -> return ()  -- Any error is acceptable
        Right _ -> expectationFailure "Should reject JWT with invalid format"
    
    it "rejects JWT with no signatures" $ do
      keyPair <- generateTestRSAKeyPair
      -- Create a JWT-like string but with empty signature part
      let header = Aeson.object [("alg", Aeson.String "PS256"), ("typ", Aeson.String "JWT")]
      let payload = Aeson.object [("sub", Aeson.String "user_123")]
      let headerBS = BSL.toStrict $ Aeson.encode header
      let payloadBS = BSL.toStrict $ Aeson.encode payload
      let headerB64 = base64urlEncode headerBS
      let payloadB64 = base64urlEncode payloadBS
      -- Create JWT with empty signature (invalid)
      let invalidJWT = T.concat [headerB64, ".", payloadB64, "."]
      
      result <- verifyJWT (publicKeyJWK keyPair) invalidJWT Nothing
      case result of
        Left (InvalidSignature msg) -> do
          -- Should fail during decode or verification (jose might catch it earlier)
          (T.isInfixOf "No signatures found" msg || T.isInfixOf "Failed to decode" msg || T.isInfixOf "JWT verification failed" msg) `shouldBe` True
        Left _ -> return ()  -- Any error is acceptable
        Right _ -> expectationFailure "Should reject JWT with no signatures"
    
    it "rejects JWT with missing typ header when required" $ do
      keyPair <- generateTestRSAKeyPair
      let payload = Aeson.object [("sub", Aeson.String "user_123")]
      
      -- Sign JWT without typ header
      signedResult <- signJWT (privateKeyJWK keyPair) payload
      case signedResult of
        Left err -> expectationFailure $ "Failed to sign JWT: " ++ show err
        Right signedJWT -> do
          -- Verify with required typ (should fail since typ is not present)
          verifyResult <- verifyJWT (publicKeyJWK keyPair) signedJWT (Just "sd-jwt")
          case verifyResult of
            Left (InvalidSignature msg) -> do
              T.isInfixOf "Missing typ header" msg `shouldBe` True
            Left _ -> return ()  -- Any error is acceptable
            Right _ -> expectationFailure "Should reject JWT with missing typ header"
    
    it "rejects JWT with invalid typ header value" $ do
      keyPair <- generateTestRSAKeyPair
      let payload = Aeson.object [("sub", Aeson.String "user_123")]
      
      -- Sign JWT with typ header
      signedResult <- signJWTWithOptionalTyp (Just "wrong-typ") (privateKeyJWK keyPair) payload
      case signedResult of
        Left err -> expectationFailure $ "Failed to sign JWT: " ++ show err
        Right signedJWT -> do
          -- Verify with different required typ (should fail)
          verifyResult <- verifyJWT (publicKeyJWK keyPair) signedJWT (Just "sd-jwt")
          case verifyResult of
            Left (InvalidSignature msg) -> do
              T.isInfixOf "Invalid typ header" msg `shouldBe` True
            Left _ -> return ()  -- Any error is acceptable
            Right _ -> expectationFailure "Should reject JWT with invalid typ header"
    
    it "rejects JWT with invalid payload JSON" $ do
      keyPair <- generateTestRSAKeyPair
      -- Create a JWT with invalid JSON in payload (valid base64url but invalid JSON)
      let header = Aeson.object [("alg", Aeson.String "PS256"), ("typ", Aeson.String "JWT")]
      let headerBS = BSL.toStrict $ Aeson.encode header
      let headerB64 = base64urlEncode headerBS
      -- Create invalid JSON payload
      let invalidPayloadB64 = base64urlEncode (encodeUtf8 "not valid json")
      -- Sign with a dummy signature (we'll fail at parsing anyway)
      let signature = "dummy_signature"
      let invalidJWT = T.concat [headerB64, ".", invalidPayloadB64, ".", signature]
      
      result <- verifyJWT (publicKeyJWK keyPair) invalidJWT Nothing
      case result of
        Left _ -> return ()  -- Any error is acceptable (might fail at signature verification or parsing)
        Right _ -> expectationFailure "Should reject JWT with invalid payload JSON"
  
  describe "validateStandardClaims error paths" $ do
    it "rejects JWT with expired exp claim" $ do
      keyPair <- generateTestRSAKeyPair
      currentTime <- round . realToFrac @POSIXTime @Double <$> getPOSIXTime :: IO Int64
      let expiredTime = currentTime - 3600  -- 1 hour ago (expired)
      let payload = Aeson.object [("sub", Aeson.String "user_123"), ("exp", Aeson.Number (fromIntegral expiredTime))]
      
      signedResult <- signJWT (privateKeyJWK keyPair) payload
      case signedResult of
        Left err -> expectationFailure $ "Failed to sign JWT: " ++ show err
        Right signedJWT -> do
          verifyResult <- verifyJWT (publicKeyJWK keyPair) signedJWT Nothing
          case verifyResult of
            Left (InvalidSignature msg) -> do
              T.isInfixOf "JWT has expired" msg `shouldBe` True
            Left err -> expectationFailure $ "Expected expired JWT error, got: " ++ show err
            Right _ -> expectationFailure "Should reject expired JWT"
    
    it "rejects JWT with invalid exp claim format (not a number)" $ do
      keyPair <- generateTestRSAKeyPair
      let payload = Aeson.object [("sub", Aeson.String "user_123"), ("exp", Aeson.String "not a number")]
      
      signedResult <- signJWT (privateKeyJWK keyPair) payload
      case signedResult of
        Left err -> expectationFailure $ "Failed to sign JWT: " ++ show err
        Right signedJWT -> do
          verifyResult <- verifyJWT (publicKeyJWK keyPair) signedJWT Nothing
          case verifyResult of
            Left (InvalidSignature msg) -> do
              T.isInfixOf "Invalid exp claim format" msg `shouldBe` True
            Left err -> expectationFailure $ "Expected invalid exp format error, got: " ++ show err
            Right _ -> expectationFailure "Should reject JWT with invalid exp format"
    
    it "rejects JWT with exp claim value out of range" $ do
      keyPair <- generateTestRSAKeyPair
      -- Use a number that's too large for Int64
      let hugeNumber = 1e20 :: Scientific
      let payload = Aeson.object [("sub", Aeson.String "user_123"), ("exp", Aeson.Number hugeNumber)]
      
      signedResult <- signJWT (privateKeyJWK keyPair) payload
      case signedResult of
        Left err -> expectationFailure $ "Failed to sign JWT: " ++ show err
        Right signedJWT -> do
          verifyResult <- verifyJWT (publicKeyJWK keyPair) signedJWT Nothing
          case verifyResult of
            Left (InvalidSignature msg) -> do
              T.isInfixOf "Invalid exp claim" msg `shouldBe` True
              T.isInfixOf "out of range" msg `shouldBe` True
            Left _ -> return ()  -- Any error is acceptable
            Right _ -> expectationFailure "Should reject JWT with exp out of range"
    
    it "rejects JWT with nbf claim (not yet valid)" $ do
      keyPair <- generateTestRSAKeyPair
      currentTime <- round . realToFrac @POSIXTime @Double <$> getPOSIXTime :: IO Int64
      let futureTime = currentTime + 3600  -- 1 hour in the future (not yet valid)
      let payload = Aeson.object [("sub", Aeson.String "user_123"), ("nbf", Aeson.Number (fromIntegral futureTime))]
      
      signedResult <- signJWT (privateKeyJWK keyPair) payload
      case signedResult of
        Left err -> expectationFailure $ "Failed to sign JWT: " ++ show err
        Right signedJWT -> do
          verifyResult <- verifyJWT (publicKeyJWK keyPair) signedJWT Nothing
          case verifyResult of
            Left (InvalidSignature msg) -> do
              T.isInfixOf "JWT not yet valid" msg `shouldBe` True
            Left err -> expectationFailure $ "Expected nbf error, got: " ++ show err
            Right _ -> expectationFailure "Should reject JWT with nbf claim"
    
    it "rejects JWT with invalid nbf claim format (not a number)" $ do
      keyPair <- generateTestRSAKeyPair
      let payload = Aeson.object [("sub", Aeson.String "user_123"), ("nbf", Aeson.String "not a number")]
      
      signedResult <- signJWT (privateKeyJWK keyPair) payload
      case signedResult of
        Left err -> expectationFailure $ "Failed to sign JWT: " ++ show err
        Right signedJWT -> do
          verifyResult <- verifyJWT (publicKeyJWK keyPair) signedJWT Nothing
          case verifyResult of
            Left (InvalidSignature msg) -> do
              T.isInfixOf "Invalid nbf claim format" msg `shouldBe` True
            Left err -> expectationFailure $ "Expected invalid nbf format error, got: " ++ show err
            Right _ -> expectationFailure "Should reject JWT with invalid nbf format"
    
    it "rejects JWT with nbf claim value out of range" $ do
      keyPair <- generateTestRSAKeyPair
      -- Use a number that's too large for Int64
      let hugeNumber = 1e20 :: Double
      let payload = Aeson.object [("sub", Aeson.String "user_123"), ("nbf", Aeson.Number (realToFrac hugeNumber))]
      
      signedResult <- signJWT (privateKeyJWK keyPair) payload
      case signedResult of
        Left err -> expectationFailure $ "Failed to sign JWT: " ++ show err
        Right signedJWT -> do
          verifyResult <- verifyJWT (publicKeyJWK keyPair) signedJWT Nothing
          case verifyResult of
            Left (InvalidSignature msg) -> do
              T.isInfixOf "Invalid nbf claim" msg `shouldBe` True
              T.isInfixOf "out of range" msg `shouldBe` True
            Left _ -> return ()  -- Any error is acceptable
            Right _ -> expectationFailure "Should reject JWT with nbf out of range"
  describe "detectKeyAlgorithmFromJWK error paths" $ do
    it "rejects JWK with missing kty field" $ do
      let invalidJWK = "{\"alg\":\"PS256\",\"n\":\"dGVzdA\",\"e\":\"AQAB\"}" :: T.Text
      let payload = Aeson.object [("sub", Aeson.String "user_123")]
      
      result <- signJWT invalidJWK payload
      case result of
        Left (InvalidSignature msg) -> do
          -- jose might parse the JWK but our code should catch missing kty
          (T.isInfixOf "Missing 'kty' field" msg || T.isInfixOf "Failed to parse JWK" msg || T.isInfixOf "Failed to create JWK" msg) `shouldBe` True
        Left _ -> return ()  -- Any error is acceptable (jose might catch it first)
        Right _ -> expectationFailure "Should reject JWK with missing kty"
    
    it "rejects JWK with unsupported EC curve" $ do
      let unsupportedCurveJWK = "{\"kty\":\"EC\",\"crv\":\"P-384\",\"d\":\"dGVzdA\",\"x\":\"dGVzdA\",\"y\":\"dGVzdA\"}" :: T.Text
      let payload = Aeson.object [("sub", Aeson.String "user_123")]
      
      result <- signJWT unsupportedCurveJWK payload
      case result of
        Left _ -> return ()  -- Any error is acceptable (jose might catch it before our code)
        Right _ -> expectationFailure "Should reject JWK with unsupported EC curve"
    
    it "rejects JWK with missing crv field for EC" $ do
      let missingCrvJWK = "{\"kty\":\"EC\",\"d\":\"dGVzdA\",\"x\":\"dGVzdA\",\"y\":\"dGVzdA\"}" :: T.Text
      let payload = Aeson.object [("sub", Aeson.String "user_123")]
      
      result <- signJWT missingCrvJWK payload
      case result of
        Left (InvalidSignature msg) -> do
          (T.isInfixOf "Missing 'crv' field" msg || T.isInfixOf "Failed to" msg) `shouldBe` True
        Left _ -> return ()  -- Any error is acceptable
        Right _ -> expectationFailure "Should reject JWK with missing crv for EC"
    
    it "rejects JWK with unsupported OKP curve" $ do
      let unsupportedOKPJWK = "{\"kty\":\"OKP\",\"crv\":\"Ed448\",\"d\":\"dGVzdA\",\"x\":\"dGVzdA\"}" :: T.Text
      let payload = Aeson.object [("sub", Aeson.String "user_123")]
      
      result <- signJWT unsupportedOKPJWK payload
      case result of
        Left _ -> return ()  -- Any error is acceptable (jose might catch it before our code)
        Right _ -> expectationFailure "Should reject JWK with unsupported OKP curve"
    
    it "rejects JWK with missing crv field for OKP" $ do
      let missingCrvOKPJWK = "{\"kty\":\"OKP\",\"d\":\"dGVzdA\",\"x\":\"dGVzdA\"}" :: T.Text
      let payload = Aeson.object [("sub", Aeson.String "user_123")]
      
      result <- signJWT missingCrvOKPJWK payload
      case result of
        Left (InvalidSignature msg) -> do
          (T.isInfixOf "Missing 'crv' field" msg || T.isInfixOf "Failed to" msg) `shouldBe` True
        Left _ -> return ()  -- Any error is acceptable
        Right _ -> expectationFailure "Should reject JWK with missing crv for OKP"
    
    it "rejects JWK with unsupported key type" $ do
      let unsupportedTypeJWK = "{\"kty\":\"oct\",\"k\":\"dGVzdA\"}" :: T.Text
      let payload = Aeson.object [("sub", Aeson.String "user_123")]
      
      result <- signJWT unsupportedTypeJWK payload
      case result of
        Left (InvalidSignature msg) -> do
          T.isInfixOf "Unsupported key type" msg `shouldBe` True
        Left err -> expectationFailure $ "Expected unsupported key type error, got: " ++ show err
        Right _ -> expectationFailure "Should reject JWK with unsupported key type"
    
    it "rejects JWK with invalid format (not an object)" $ do
      let invalidJWK = "\"not an object\"" :: T.Text
      let payload = Aeson.object [("sub", Aeson.String "user_123")]
      
      result <- signJWT invalidJWK payload
      case result of
        Left (InvalidSignature msg) -> do
          -- jose will catch this during parsing, so error message might vary
          (T.isInfixOf "Invalid JWK format" msg || T.isInfixOf "Failed to parse JWK" msg || T.isInfixOf "Failed to create JWK" msg || T.isInfixOf "parse" msg) `shouldBe` True
        Left _ -> return ()  -- Any error is acceptable
        Right _ -> expectationFailure "Should reject JWK with invalid format"

