{-# LANGUAGE OverloadedStrings #-}
-- | JWT signing and verification using jose library.
--
-- This module provides functions for signing and verifying JWTs using the
-- jose library. It handles the conversion between our Text-based JWK
-- placeholders and the jose library's JWK types.
module SDJWT.Internal.JWT
  ( signJWT
  , signJWTWithOptionalTyp
  , signJWTWithTyp
  , verifyJWT
  , parseJWKFromText
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

-- | Convert algorithm string to JWA.Alg
toJwsAlg :: T.Text -> Either SDJWTError JWA.Alg
toJwsAlg "RS256" = Right JWA.RS256
toJwsAlg "EdDSA" = Right JWA.EdDSA
toJwsAlg "ES256" = Right JWA.ES256
toJwsAlg alg = Left $ InvalidSignature $ "Unsupported algorithm: " <> alg <> " (only RS256, EdDSA, and ES256 are supported)"

-- | Sign a JWT payload using a private key.
--
-- Parameters:
-- - privateKeyJWK: Private key as JSON Web Key (JWK) in Text format
-- - payload: The JWT payload as Aeson Value
--
-- Returns the signed JWT as a compact string, or an error.
-- Automatically detects key type and uses:
-- - RS256 for RSA keys
-- - EdDSA for Ed25519 keys
-- - ES256 for EC P-256 keys
signJWT
  :: T.Text  -- ^ Private key JWK (JSON format)
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
  :: Maybe T.Text  -- ^ Optional typ header value (RFC 9901 Section 9.11 recommends explicit typing)
  -> T.Text  -- ^ Private key JWK (JSON format)
  -> Aeson.Value  -- ^ JWT payload
  -> IO (Either SDJWTError T.Text)
signJWTWithOptionalTyp mbTyp privateKeyJWK payload = do
  -- Require valid JWK - empty strings are not valid keys
  if T.null privateKeyJWK
    then return $ Left $ InvalidSignature "JWK cannot be empty - provide a valid private key JWK"
    else do
      -- Parse JWK from Text
      case parseJWKFromText privateKeyJWK of
        Left err -> return $ Left err
        Right jwk -> do
          -- Detect algorithm from key type
          algResult <- case detectKeyAlgorithm privateKeyJWK of
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
-- Supports all algorithms: EC P-256 (ES256), RSA (RS256), and Ed25519 (EdDSA).
--
-- Parameters:
-- - typ: The typ header value (e.g., "kb+jwt" for KB-JWT)
-- - privateKeyJWK: Private key JWK (JSON format)
-- - payload: The JWT payload as Aeson Value
--
-- Returns the signed JWT as a compact string, or an error.
signJWTWithTyp
  :: T.Text  -- ^ typ header value
  -> T.Text  -- ^ Private key JWK (JSON format)
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
  :: T.Text  -- ^ Public key JWK (JSON format)
  -> T.Text  -- ^ JWT to verify
  -> Maybe T.Text  -- ^ Required typ header value (Nothing = allow any/none, Just "sd-jwt" = require exactly "sd-jwt")
  -> IO (Either SDJWTError Aeson.Value)
verifyJWT publicKeyJWK jwtText requiredTyp = do
  -- Require valid JWK - empty strings are not valid keys
  if T.null publicKeyJWK
    then return $ Left $ InvalidSignature "JWK cannot be empty - provide a valid public key JWK"
    else do
      -- Parse JWK from Text
      case parseJWKFromText publicKeyJWK of
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
                        JWA.EdDSA -> "EdDSA"
                        JWA.ES256 -> "ES256"
                        _ -> "UNSUPPORTED"
                  
                  -- Validate algorithm matches key type (RFC 8725bis requirement)
                  expectedAlgResult <- case detectKeyAlgorithm publicKeyJWK of
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
