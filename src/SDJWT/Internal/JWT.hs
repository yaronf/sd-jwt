{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE FlexibleInstances #-}
-- | JWT signing and verification using jose library.
--
-- This module provides functions for signing and verifying JWTs using the
-- jose library. It supports both Text-based JWK strings and jose JWK objects.
module SDJWT.Internal.JWT
  ( signJWT
  , signJWTWithOptionalTyp
  , signJWTWithTyp
  , verifyJWT
  , parseJWKFromText
  , JWKLike(..)
  ) where

import SDJWT.Internal.Types (SDJWTError(..))
import SDJWT.Internal.Utils (base64urlEncode)
import qualified Crypto.JOSE as Jose
import qualified Crypto.JOSE.JWS as JWS
import qualified Crypto.JOSE.JWK as JWK
import qualified Crypto.JOSE.Header as Header
import qualified Crypto.JOSE.JWA.JWS as JWA
import qualified Crypto.JOSE.Compact as Compact
import qualified Crypto.JOSE.Error as JoseError
import qualified Data.Aeson as Aeson
import qualified Data.Aeson.KeyMap as KeyMap
import qualified Data.Aeson.Key as Key
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import qualified Data.ByteString.Lazy as LBS
import qualified Data.ByteString as BS
import Control.Lens ((&), (?~), (^.), (^..))
import Data.Functor.Identity (Identity(..))

-- | Type class for types that can be converted to a jose JWK.
--
-- This allows functions to accept both Text (JWK JSON strings) and jose JWK objects.
-- Users can pass JWK strings directly without importing jose, or pass jose JWK objects
-- if they're already working with the jose library.
class JWKLike a where
  -- | Convert to a jose JWK object.
  toJWK :: a -> Either SDJWTError JWK.JWK

-- | Text instance: parse JWK from JSON string.
instance JWKLike T.Text where
  toJWK = parseJWKFromText

-- | JWK instance: identity conversion (already a JWK).
instance JWKLike JWK.JWK where
  toJWK = Right

-- | Detect the key type from a jose JWK object and return the appropriate algorithm.
-- Returns "PS256" for RSA keys (defaults to PS256 for security, RS256 also supported via "alg" field),
-- "EdDSA" for Ed25519 keys, "ES256" for EC P-256 keys, or an error.
detectKeyAlgorithmFromJWK :: JWK.JWK -> Either SDJWTError T.Text
detectKeyAlgorithmFromJWK jwk = do
  -- Convert JWK to JSON Value to extract fields
  let jwkValue = Aeson.toJSON jwk
  case jwkValue of
    Aeson.Object obj -> do
      kty <- case KeyMap.lookup (Key.fromText "kty") obj of
        Just (Aeson.String ktyText) -> Right ktyText
        _ -> Left $ InvalidSignature "Missing 'kty' field in JWK"
      
      if kty == "RSA"
        then do
          -- Check if JWK specifies algorithm (RFC 7517 allows optional "alg" field)
          -- RS256 is deprecated per draft-ietf-jose-deprecate-none-rsa15 (padding oracle attacks)
          -- Default to PS256 (RSA-PSS) for security; RS256 can be explicitly requested but is deprecated
          case KeyMap.lookup (Key.fromText "alg") obj of
            Just (Aeson.String "RS256") -> Right "RS256"  -- Deprecated but still supported for compatibility
            _ -> Right "PS256"  -- Default to PS256 (RSA-PSS) for security
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
          else Left $ InvalidSignature $ "Unsupported key type: " <> kty <> " (supported: RSA, EC P-256, Ed25519)"
    _ -> Left $ InvalidSignature "Invalid JWK format: expected object"

-- | Detect the key type from a JWK JSON Text and return the appropriate algorithm.
-- Returns "PS256" for RSA keys (defaults to PS256 for security, RS256 also supported via "alg" field),
-- "EdDSA" for Ed25519 keys, "ES256" for EC P-256 keys, or an error.
detectKeyAlgorithm :: T.Text -> Either SDJWTError T.Text
detectKeyAlgorithm jwkText = do
  case Aeson.eitherDecodeStrict (TE.encodeUtf8 jwkText) of
    Left err -> Left $ InvalidSignature $ "Failed to parse JWK JSON: " <> T.pack err
    Right (Aeson.Object obj) -> do
      kty <- case KeyMap.lookup (Key.fromText "kty") obj of
        Just (Aeson.String ktyText) -> Right ktyText
        _ -> Left $ InvalidSignature "Missing 'kty' field in JWK"
      
      if kty == "RSA"
        then do
          -- Check if JWK specifies algorithm (RFC 7517 allows optional "alg" field)
          -- RS256 is deprecated per draft-ietf-jose-deprecate-none-rsa15 (padding oracle attacks)
          -- Default to PS256 (RSA-PSS) for security; RS256 can be explicitly requested but is deprecated
          case KeyMap.lookup (Key.fromText "alg") obj of
            Just (Aeson.String "RS256") -> Right "RS256"  -- Deprecated but still supported for compatibility
            _ -> Right "PS256"  -- Default to PS256 (RSA-PSS) for security
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
          else Left $ InvalidSignature $ "Unsupported key type: " <> kty <> " (supported: RSA, EC P-256, Ed25519)"
    Right _ -> Left $ InvalidSignature "Invalid JWK format: expected object"

-- | Convert algorithm string to JWA.Alg
-- Supports RSA-PSS (PS256, default) and RSA-PKCS#1 v1.5 (RS256, deprecated per draft-ietf-jose-deprecate-none-rsa15).
-- RS256 is deprecated due to padding oracle attack vulnerabilities. PS256 (RSA-PSS) is recommended.
toJwsAlg :: T.Text -> Either SDJWTError JWA.Alg
toJwsAlg "RS256" = Right JWA.RS256  -- Deprecated: Use PS256 instead (draft-ietf-jose-deprecate-none-rsa15)
toJwsAlg "PS256" = Right JWA.PS256
toJwsAlg "EdDSA" = Right JWA.EdDSA
toJwsAlg "ES256" = Right JWA.ES256
toJwsAlg alg = Left $ InvalidSignature $ "Unsupported algorithm: " <> alg <> " (supported: PS256 default, RS256 deprecated, EdDSA, ES256)"

-- | Sign a JWT payload using a private key.
--
-- Parameters:
-- - privateKeyJWK: Private key as JSON Web Key (JWK) - can be Text (JSON string) or jose JWK object
-- - payload: The JWT payload as Aeson Value
--
-- Returns the signed JWT as a compact string, or an error.
-- Automatically detects key type and uses:
-- - PS256 for RSA keys (default, RS256 also supported via JWK "alg" field)
-- - EdDSA for Ed25519 keys
-- - ES256 for EC P-256 keys
signJWT
  :: JWKLike jwk => jwk  -- ^ Private key JWK (Text or jose JWK object)
  -> Aeson.Value  -- ^ JWT payload
  -> IO (Either SDJWTError T.Text)
signJWT privateKeyJWK payload = signJWTWithOptionalTyp Nothing privateKeyJWK payload

-- | Sign a JWT payload with optional typ header parameter.
--
-- This function allows setting a typ header for issuer-signed JWTs (RFC 9901 Section 9.11 recommends
-- explicit typing, e.g., "sd-jwt" or "example+sd-jwt"). Use 'signJWT' for default behavior (no typ header).
--
-- Parameters:
-- - mbTyp: Optional typ header value (RFC 9901 Section 9.11 recommends explicit typing for issuer-signed JWTs)
-- - privateKeyJWK: Private key JWK (JSON format)
-- - payload: The JWT payload as Aeson Value
--
-- Returns the signed JWT as a compact string, or an error.
signJWTWithOptionalTyp
  :: JWKLike jwk => Maybe T.Text  -- ^ Optional typ header value (RFC 9901 Section 9.11 recommends explicit typing)
  -> jwk  -- ^ Private key JWK (Text or jose JWK object)
  -> Aeson.Value  -- ^ JWT payload
  -> IO (Either SDJWTError T.Text)
signJWTWithOptionalTyp mbTyp privateKeyJWK payload = do
  -- Convert to jose JWK
  case toJWK privateKeyJWK of
    Left err -> return $ Left err
    Right jwk -> do
      -- Detect algorithm from key type
      algResult <- case detectKeyAlgorithmFromJWK jwk of
        Left err -> return $ Left err
        Right algText -> return $ Right algText
      
      case algResult of
        Left err -> return $ Left err
        Right algText -> do
          -- Convert to JWA.Alg
          jwsAlgResult <- case toJwsAlg algText of
            Left err -> return $ Left err
            Right alg -> return $ Right alg
          
          case jwsAlgResult of
            Left err -> return $ Left err
            Right jwsAlg -> do
                  -- Create header with algorithm (Protected header)
                  let baseHeader = JWS.newJWSHeader (Header.Protected, jwsAlg)
                  -- Add typ header if specified (native support in jose!)
                  let header = case mbTyp of
                        Just typValue -> baseHeader & Header.typ ?~ Header.HeaderParam Header.Protected typValue
                        Nothing -> baseHeader
                  
                  -- Encode payload to ByteString
                  let payloadBS = LBS.toStrict $ Aeson.encode payload
                  
                  -- Sign the JWT using Identity container to get FlattenedJWS (single signature)
                  -- With native typ support, jose handles everything!
                  result <- Jose.runJOSE $ JWS.signJWS payloadBS (Identity (header, jwk)) :: IO (Either JoseError.Error (JWS.JWS Identity Header.Protection JWS.JWSHeader))
                  
                  case result of
                    Left err -> return $ Left $ InvalidSignature $ "JWT signing failed: " <> T.pack (show err)
                    Right jws -> do
                      -- Extract the three parts needed for compact JWT format
                      -- The payload is already base64url encoded in the JWS structure
                      -- We just need to extract header, payload, and signature and concatenate them
                      let sig = jws ^.. JWS.signatures
                      case sig of
                        [] -> return $ Left $ InvalidSignature "No signatures in JWS"
                        (sigHead:_) -> do
                          -- Get payload using verifyJWSWithPayload (returns raw bytes, need to base64url encode)
                          -- Note: This is inefficient but necessary since JWS constructor isn't exported
                          payloadResult <- Jose.runJOSE $ JWS.verifyJWSWithPayload return JWS.defaultValidationSettings jwk jws :: IO (Either JoseError.Error BS.ByteString)
                          case payloadResult of
                            Left err -> return $ Left $ InvalidSignature $ "Failed to extract payload: " <> T.pack (show err)
                            Right extractedPayloadBS -> do
                              let headerBS = JWS.rawProtectedHeader sigHead
                              let sigBS = sigHead ^. JWS.signature
                              -- Construct compact JWT: base64url(header).base64url(payload).base64url(signature)
                              -- We construct it manually because jose doesn't provide encodeCompact for FlattenedJWS
                              -- Note: rawProtectedHeader returns base64url-encoded header bytes (already encoded)
                              --       signature returns raw binary bytes (needs encoding)
                              let headerB64 = TE.decodeUtf8 headerBS  -- Already base64url encoded
                              let payloadB64 = base64urlEncode extractedPayloadBS
                              let sigB64 = base64urlEncode sigBS  -- Raw binary, needs encoding
                              let compactJWT = headerB64 <> "." <> payloadB64 <> "." <> sigB64
                              return $ Right compactJWT

-- | Sign a JWT payload with a custom typ header parameter.
--
-- This function constructs the JWT header with the specified typ value,
-- then signs the JWT. This is needed for KB-JWT which requires typ: "kb+jwt"
-- (RFC 9901 Section 4.3).
--
-- Supports all algorithms: EC P-256 (ES256), RSA (PS256 default, RS256 also supported), and Ed25519 (EdDSA).
--
-- Parameters:
-- - typ: The typ header value (e.g., "kb+jwt" for KB-JWT)
-- - privateKeyJWK: Private key JWK (JSON format)
-- - payload: The JWT payload as Aeson Value
--
-- Returns the signed JWT as a compact string, or an error.
signJWTWithTyp
  :: JWKLike jwk => T.Text  -- ^ typ header value
  -> jwk  -- ^ Private key JWK (Text or jose JWK object)
  -> Aeson.Value  -- ^ JWT payload
  -> IO (Either SDJWTError T.Text)
signJWTWithTyp typValue privateKeyJWK payload = signJWTWithOptionalTyp (Just typValue) privateKeyJWK payload

-- | Verify a JWT signature using a public key.
--
-- Parameters:
-- - publicKeyJWK: Public key as JSON Web Key (JWK) in Text format
-- - jwtText: The JWT to verify as a compact string
-- - requiredTyp: Required typ header value (Nothing = allow any/none, Just "sd-jwt" = require exactly "sd-jwt")
--
-- Returns the decoded payload if verification succeeds, or an error.
verifyJWT
  :: JWKLike jwk => jwk  -- ^ Public key JWK (Text or jose JWK object)
  -> T.Text  -- ^ JWT to verify
  -> Maybe T.Text  -- ^ Required typ header value (Nothing = allow any/none, Just "sd-jwt" = require exactly "sd-jwt")
  -> IO (Either SDJWTError Aeson.Value)
verifyJWT publicKeyJWK jwtText requiredTyp = do
  -- Convert to jose JWK
  case toJWK publicKeyJWK of
    Left err -> return $ Left err
    Right jwk -> do
      -- Decode compact JWT
      case Compact.decodeCompact (LBS.fromStrict $ TE.encodeUtf8 jwtText) :: Either JoseError.Error (JWS.CompactJWS JWS.JWSHeader) of
        Left err -> return $ Left $ InvalidSignature $ "Failed to decode JWT: " <> T.pack (show err)
        Right jws -> do
          -- Extract header from signature
          let sigs = jws ^.. JWS.signatures
          case sigs of
            [] -> return $ Left $ InvalidSignature "No signatures found in JWT"
            (sig:_) -> do
              let hdr = sig ^. JWS.header
              
              -- SECURITY: RFC 8725bis - Extract and validate algorithm BEFORE verification
              -- We MUST NOT trust the alg value in the header - we must validate it matches the key
              let algParam = hdr ^. Header.alg . Header.param
              let headerAlg = case algParam of
                    JWA.RS256 -> "RS256"
                    JWA.PS256 -> "PS256"
                    JWA.EdDSA -> "EdDSA"
                    JWA.ES256 -> "ES256"
                    _ -> "UNSUPPORTED"
              
              -- Validate algorithm matches key type (RFC 8725bis requirement)
              expectedAlgResult <- case detectKeyAlgorithmFromJWK jwk of
                Left err -> return $ Left err
                Right expectedAlg -> return $ Right expectedAlg
              
              case expectedAlgResult of
                Left err -> return $ Left err
                Right expectedAlg -> do
                  -- Reject "none" algorithm (unsecured JWT attack prevention)
                  if headerAlg == "none"
                    then return $ Left $ InvalidSignature "Unsecured JWT (alg: 'none') rejected per RFC 8725bis"
                    else do
                      -- Validate algorithm matches expected algorithm (RFC 8725bis - don't trust header)
                      if headerAlg /= expectedAlg
                        then return $ Left $ InvalidSignature $ "Algorithm mismatch: header claims '" <> headerAlg <> "', but key type requires '" <> expectedAlg <> "' (RFC 8725bis)"
                        else do
                          -- Validate algorithm is in whitelist
                          case toJwsAlg expectedAlg of
                            Left err -> return $ Left err
                            Right _ -> do
                                  -- Extract typ from header
                                  let mbTypValue = case hdr ^. Header.typ of
                                        Nothing -> Nothing
                                        Just typParam -> Just (typParam ^. Header.param)
                                  
                                  -- Validate typ header if required
                                  typValidation <- case requiredTyp of
                                    Nothing -> return $ Right ()  -- Liberal mode: allow any typ or none
                                    Just requiredTypValue -> do
                                      case mbTypValue of
                                        Nothing -> return $ Left $ InvalidSignature $ "Missing typ header: required '" <> requiredTypValue <> "'"
                                        Just typVal -> do
                                          if typVal == requiredTypValue
                                            then return $ Right ()
                                            else return $ Left $ InvalidSignature $ "Invalid typ header: expected '" <> requiredTypValue <> "', got '" <> typVal <> "'"
                                  
                                  case typValidation of
                                    Left err -> return $ Left err
                                    Right () -> do
                                      -- Verify JWT signature (algorithm already validated above)
                                      result <- Jose.runJOSE $ JWS.verifyJWS' jwk jws :: IO (Either JoseError.Error BS.ByteString)
                                      
                                      case result of
                                        Left err -> return $ Left $ InvalidSignature $ "JWT verification failed: " <> T.pack (show err)
                                        Right payloadBS -> do
                                          -- Parse payload as JSON
                                          case Aeson.eitherDecodeStrict payloadBS of
                                            Left jsonErr -> return $ Left $ JSONParseError $ "Failed to parse JWT payload: " <> T.pack jsonErr
                                            Right payload -> return $ Right payload

-- | Parse a JWK from JSON Text.
--
-- Parses a JSON Web Key (JWK) from its JSON representation.
-- Supports RSA, Ed25519, and EC P-256 keys.
--
-- The JWK JSON format follows RFC 7517. Examples:
-- - RSA public key: {"kty":"RSA","n":"...","e":"..."}
-- - Ed25519 public key: {"kty":"OKP","crv":"Ed25519","x":"..."}
-- - EC P-256 public key: {"kty":"EC","crv":"P-256","x":"...","y":"..."}
-- - RSA private key: {"kty":"RSA","n":"...","e":"...","d":"...","p":"...","q":"..."}
-- - Ed25519 private key: {"kty":"OKP","crv":"Ed25519","d":"...","x":"..."}
-- - EC P-256 private key: {"kty":"EC","crv":"P-256","d":"...","x":"...","y":"..."}
parseJWKFromText :: T.Text -> Either SDJWTError JWK.JWK
parseJWKFromText jwkText =
  case Aeson.eitherDecodeStrict (TE.encodeUtf8 jwkText) of
    Left err -> Left $ InvalidSignature $ "Failed to parse JWK JSON: " <> T.pack err
    Right jwkValue -> case Aeson.fromJSON jwkValue of
      Aeson.Error err -> Left $ InvalidSignature $ "Failed to create JWK: " <> T.pack err
      Aeson.Success jwk -> Right jwk
