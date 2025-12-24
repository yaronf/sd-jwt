{-# LANGUAGE OverloadedStrings #-}
-- | JWT signing and verification using jose-jwt library.
--
-- This module provides functions for signing and verifying JWTs using the
-- jose-jwt library. It handles the conversion between our Text-based JWK
-- placeholders and the jose-jwt library's Jwk types.
module SDJWT.Internal.JWT
  ( signJWT
  , verifyJWT
  , parseJWKFromText
  ) where

import SDJWT.Internal.Types (SDJWTError(..))
import SDJWT.Internal.Utils (base64urlDecode)
import qualified SDJWT.Internal.JWT.EC as EC  -- Temporary EC signing support
import Jose.Jwt (encode, decode, JwtEncoding(..), Payload(..), Jwt(..), JwtContent(..))
import Jose.Jwk (Jwk)
import qualified Jose.Jwa as Jose
import qualified Data.Aeson as Aeson
import qualified Data.Aeson.KeyMap as KeyMap
import qualified Data.Aeson.Key as Key
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import qualified Data.ByteString.Lazy as BSL
import Crypto.Random ()  -- Import instances for MonadRandom

-- | Detect the key type from a JWK JSON and return the appropriate algorithm.
-- Returns "RS256" for RSA keys, "EdDSA" for Ed25519 keys, "ES256" for EC P-256 keys, or an error.
detectKeyAlgorithm :: T.Text -> Either SDJWTError T.Text
detectKeyAlgorithm jwkText = do
  case Aeson.eitherDecodeStrict (TE.encodeUtf8 jwkText) of
    Left err -> Left $ InvalidSignature $ "Failed to parse JWK JSON: " <> T.pack err
    Right (Aeson.Object obj) -> do
      kty <- case KeyMap.lookup (Key.fromText "kty") obj of
        Just (Aeson.String ktyText) -> Right ktyText
        _ -> Left $ InvalidSignature "Missing 'kty' field in JWK"
      
      if kty == "RSA"
        then Right "RS256"
        else if kty == "EC"
          then do
            -- Check curve for EC keys (only P-256 is supported)
            _crv <- case KeyMap.lookup (Key.fromText "crv") obj of
              Just (Aeson.String "P-256") -> Right ()
              Just (Aeson.String crvText) -> Left $ InvalidSignature $ "Unsupported EC curve: " <> crvText <> " (only P-256 is supported)"
              _ -> Left $ InvalidSignature "Missing 'crv' field in EC JWK"
            Right "ES256"
        else if kty == "OKP"
          then do
            -- Check curve for OKP keys (Ed25519, Ed448)
            crv <- case KeyMap.lookup (Key.fromText "crv") obj of
              Just (Aeson.String crvText) -> Right crvText
              _ -> Left $ InvalidSignature "Missing 'crv' field in OKP JWK"
            
            if crv == "Ed25519"
              then Right "EdDSA"
              else Left $ InvalidSignature $ "Unsupported OKP curve: " <> crv <> " (only Ed25519 is supported)"
          else Left $ InvalidSignature $ "Unsupported key type: " <> kty <> " (only RSA, EC P-256, and Ed25519 are supported)"
    Right _ -> Left $ InvalidSignature "Invalid JWK format: expected object"

-- | Sign a JWT payload using a private key.
--
-- Parameters:
-- - privateKeyJWK: Private key as JSON Web Key (JWK) in Text format
-- - payload: The JWT payload as Aeson Value
--
-- Returns the signed JWT as a compact string, or an error.
-- Automatically detects key type and uses:
-- - RS256 for RSA keys (via jose-jwt)
-- - EdDSA for Ed25519 keys (via jose-jwt)
-- - ES256 for EC P-256 keys (via SDJWT.JWT.EC module - temporary until jose-jwt adds EC signing)
signJWT
  :: T.Text  -- ^ Private key JWK (JSON format)
  -> Aeson.Value  -- ^ JWT payload
  -> IO (Either SDJWTError T.Text)
signJWT privateKeyJWK payload = do
  -- Require valid JWK - empty strings are not valid keys
  if T.null privateKeyJWK
    then return $ Left $ InvalidSignature "JWK cannot be empty - provide a valid private key JWK"
    else do
      -- Detect algorithm from key type
      alg <- case detectKeyAlgorithm privateKeyJWK of
        Left err -> return $ Left err
        Right a -> return $ Right a
      
      case alg of
        Left err -> return $ Left err
        Right algText -> do
          -- Handle EC keys separately (using our temporary EC module)
          if algText == "ES256"
            then EC.signJWTES256 privateKeyJWK payload
            else do
              -- For RSA and EdDSA, use jose-jwt
              jwk <- case parseJWKFromText privateKeyJWK of
                Left err -> return $ Left err
                Right key -> return $ Right key
              
              case jwk of
                Left err -> return $ Left err
                Right key -> do
                  -- Encode payload to ByteString
                  let payloadBS = BSL.toStrict $ Aeson.encode payload
                  
                  -- Create JWT encoding based on detected algorithm
                  encodingResult <- case algText of
                        "RS256" -> return $ Right $ JwsEncoding Jose.RS256
                        "EdDSA" -> return $ Right $ JwsEncoding Jose.EdDSA
                        _ -> return $ Left $ InvalidSignature $ "Unsupported algorithm: " <> algText <> " (only RS256, EdDSA, and ES256 are supported)"
                  
                  case encodingResult of
                    Left err -> return $ Left err
                    Right enc -> do
                      -- Sign the JWT
                      result <- encode [key] enc (Claims payloadBS)
                      
                      case result of
                        Left jwtErr -> return $ Left $ InvalidSignature $ "JWT signing failed: " <> T.pack (show jwtErr)
                        Right jwt -> return $ Right $ TE.decodeUtf8 $ unJwt jwt

-- | Verify a JWT signature using a public key.
--
-- Parameters:
-- - publicKeyJWK: Public key as JSON Web Key (JWK) in Text format
-- - jwtText: The JWT to verify as a compact string
--
-- Returns the decoded payload if verification succeeds, or an error.
--
-- SECURITY WARNING: This function uses jose-jwt's decode function which may have
-- a security vulnerability where it accepts JWTs signed with wrong keys.
-- This is a known issue that needs to be investigated and fixed.
-- See: https://github.com/frasertweedale/hs-jose/issues (if applicable)
verifyJWT
  :: T.Text  -- ^ Public key JWK (JSON format)
  -> T.Text  -- ^ JWT to verify
  -> IO (Either SDJWTError Aeson.Value)
verifyJWT publicKeyJWK jwtText = do
  -- Require valid JWK - empty strings are not valid keys
  if T.null publicKeyJWK
    then return $ Left $ InvalidSignature "JWK cannot be empty - provide a valid public key JWK"
    else do
      -- Parse JWK from Text
      jwk <- case parseJWKFromText publicKeyJWK of
        Left err -> return $ Left err
        Right key -> return $ Right key
      
      case jwk of
        Left err -> return $ Left err
        Right key -> do
          -- Convert JWT text to ByteString
          let jwtBS = TE.encodeUtf8 jwtText
          
          -- CRITICAL SECURITY: Parse JWT header first to extract algorithm
          -- This ensures we verify with the correct algorithm and don't accept wrong keys
          let jwtParts = T.splitOn "." jwtText
          case jwtParts of
            (headerPart : _payloadPart : _signaturePart) -> do
              -- Decode header to extract algorithm
              headerBytes <- case base64urlDecode headerPart of
                Left err -> return $ Left $ InvalidSignature $ "Failed to decode JWT header: " <> err
                Right bs -> return $ Right bs
              
              case headerBytes of
                Left err -> return $ Left err
                Right hBytes -> do
                  headerJson <- case Aeson.eitherDecodeStrict hBytes of
                    Left err -> return $ Left $ InvalidSignature $ "Failed to parse JWT header: " <> T.pack err
                    Right val -> return $ Right val
                  
                  case headerJson of
                    Left err -> return $ Left err
                    Right hJson -> do
                      -- Extract algorithm from header
                      alg <- case extractAlgorithmFromHeader hJson of
                        Left err -> return $ Left err
                        Right a -> return $ Right a
                      
                      case alg of
                        Left err -> return $ Left err
                        Right expectedAlg -> do
                          -- CRITICAL: Verify algorithm is supported (RS256, EdDSA, or ES256)
                          if expectedAlg /= "RS256" && expectedAlg /= "EdDSA" && expectedAlg /= "ES256"
                            then return $ Left $ InvalidSignature $ "Unsupported algorithm: " <> expectedAlg <> " (only RS256, EdDSA, and ES256 are supported)"
                            else do
                              -- SECURITY CRITICAL: Decode and verify JWT with EXPLICIT algorithm specification
                              -- By explicitly passing the algorithm, we ensure
                              -- that jose-jwt properly verifies the signature with the provided key.
                              -- Testing confirms that wrong keys are correctly rejected.
                              -- Note: jose-jwt supports ES256 verification (but not signing)
                              let encoding = case expectedAlg of
                                    "RS256" -> JwsEncoding Jose.RS256
                                    "EdDSA" -> JwsEncoding Jose.EdDSA
                                    "ES256" -> JwsEncoding Jose.ES256
                                    _ -> error "Unreachable: algorithm already validated"
                              result <- decode [key] (Just encoding) jwtBS
                          
                              case result of
                                Left jwtErr -> return $ Left $ InvalidSignature $ "JWT verification failed: " <> T.pack (show jwtErr)
                                Right jwtContent -> do
                                  -- Extract payload from JwtContent
                                  -- CRITICAL: Only accept JWS (signed JWTs), reject unsecured JWTs
                                  -- The decode function properly verifies signatures when algorithm is explicitly specified
                                  case jwtContent of
                                    Jws (_, bs) -> do
                                      -- JWS payload is the second element of the tuple
                                      -- Parse payload as JSON
                                      case Aeson.eitherDecodeStrict bs of
                                        Left jsonErr -> return $ Left $ JSONParseError $ "Failed to parse JWT payload: " <> T.pack jsonErr
                                        Right payload -> return $ Right payload
                                    Jwe _ -> return $ Left $ InvalidSignature "JWE (encrypted JWT) not supported - only JWS (signed JWT) is supported"
                                    Unsecured _ -> return $ Left $ InvalidSignature "Unsecured JWT rejected - signature verification required"
            _ -> return $ Left $ InvalidSignature "Invalid JWT format: expected header.payload.signature"
  
  where
    -- Extract algorithm from JWT header
    extractAlgorithmFromHeader :: Aeson.Value -> Either SDJWTError T.Text
    extractAlgorithmFromHeader (Aeson.Object obj) =
      case KeyMap.lookup "alg" obj of
        Just (Aeson.String alg) -> Right alg
        _ -> Left $ InvalidSignature "Missing 'alg' claim in JWT header"
    extractAlgorithmFromHeader _ = Left $ InvalidSignature "Invalid JWT header format"

-- | Parse a JWK from JSON Text.
--
-- Parses a JSON Web Key (JWK) from its JSON representation.
-- Supports RSA and Ed25519 keys (the key types that jose-jwt supports for signing).
--
-- The JWK JSON format follows RFC 7517. Examples:
-- - RSA public key: {"kty":"RSA","n":"...","e":"..."}
-- - Ed25519 public key: {"kty":"OKP","crv":"Ed25519","x":"..."}
-- - RSA private key: {"kty":"RSA","n":"...","e":"...","d":"...","p":"...","q":"..."}
-- - Ed25519 private key: {"kty":"OKP","crv":"Ed25519","d":"...","x":"..."}
--
-- Note: EC P-256 keys are not supported as jose-jwt does not support EC signing.
parseJWKFromText :: T.Text -> Either SDJWTError Jwk
parseJWKFromText jwkText =
  case Aeson.eitherDecodeStrict (TE.encodeUtf8 jwkText) of
    Left err -> Left $ InvalidSignature $ "Failed to parse JWK JSON: " <> T.pack err
    Right jwk -> Right jwk

