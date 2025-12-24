{-# LANGUAGE OverloadedStrings #-}
-- | JWT signing and verification using jose-jwt library.
--
-- This module provides functions for signing and verifying JWTs using the
-- jose-jwt library. It handles the conversion between our Text-based JWK
-- placeholders and the jose-jwt library's Jwk types.
module SDJWT.Internal.JWT
  ( signJWT
  , signJWTWithOptionalTyp
  , signJWTWithTyp
  , verifyJWT
  , parseJWKFromText
  ) where

import SDJWT.Internal.Types (SDJWTError(..))
import SDJWT.Internal.Utils (base64urlDecode, base64urlEncode)
import qualified SDJWT.Internal.JWT.EC as EC  -- Temporary EC signing support
import Jose.Jwt (encode, decode, JwtEncoding(..), Payload(..), Jwt(..), JwtContent(..), JwsHeader(..), defJwsHdr, encodeHeader)
import Jose.Jwk (Jwk(..))
import qualified Jose.Jwa as Jose
import qualified Jose.Jws as JoseJws
import qualified Data.Aeson as Aeson
import qualified Data.Aeson.KeyMap as KeyMap
import qualified Data.Aeson.Key as Key
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import qualified Data.ByteString.Lazy as BSL
import qualified Crypto.Random as RNG
import Crypto.PubKey.ECC.ECDSA (sign)
import qualified Crypto.Hash.Algorithms as HashAlg

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
-- - typ: Optional typ header value (RFC 9901 Section 9.11 recommends explicit typing for issuer-signed JWTs)
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
      -- Detect algorithm from key type
      alg <- case detectKeyAlgorithm privateKeyJWK of
        Left err -> return $ Left err
        Right a -> return $ Right a
      
      case alg of
        Left err -> return $ Left err
        Right algText -> do
          -- If typ is specified, use signJWTWithTyp (which handles custom headers)
          case mbTyp of
            Just typValue -> signJWTWithTyp typValue privateKeyJWK payload
            Nothing -> do
              -- No typ header - use standard signing
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

-- | Sign a JWT payload with a custom typ header parameter.
--
-- This function manually constructs the JWT header with the specified typ value,
-- then signs the JWT. This is needed for KB-JWT which requires typ: "kb+jwt"
-- (RFC 9901 Section 4.3).
--
-- Supports all algorithms: EC P-256 (ES256), RSA (RS256), and Ed25519 (EdDSA).
-- Uses jose-jwt's JwsHeader type with jwsTyp field and low-level signing functions
-- (rsaEncode, ed25519Encode) to support custom headers.
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
signJWTWithTyp typValue privateKeyJWK payload = do
  -- Detect algorithm from key type
  alg <- case detectKeyAlgorithm privateKeyJWK of
    Left err -> return $ Left err
    Right a -> return $ Right a
  
  case alg of
    Left err -> return $ Left err
    Right algText -> do
      -- Handle EC keys: use JwsHeader with encodeHeader (delegate to jose-jwt)
      -- Still need manual signing since jose-jwt doesn't support EC signing
      if algText == "ES256"
        then do
          -- Parse EC private key from JWK
          case EC.parseECPrivateKeyFromJWK privateKeyJWK of
            Left err -> return $ Left err
            Right privKey -> do
              -- Create JwsHeader with custom typ using jose-jwt (delegate header encoding)
              let header = defJwsHdr { jwsAlg = Jose.ES256, jwsTyp = Just typValue }
              
              -- Encode header using jose-jwt's encodeHeader
              let headerBS = encodeHeader header
              let payloadBS = BSL.toStrict $ Aeson.encode payload
              
              let headerB64 = base64urlEncode headerBS
              let payloadB64 = base64urlEncode payloadBS
              
              -- Build message to sign: base64url(header).base64url(payload)
              let messageToSignBS = TE.encodeUtf8 $ headerB64 <> "." <> payloadB64
              
              -- Sign using cryptonite (jose-jwt doesn't support EC signing)
              drg <- RNG.getSystemDRG
              let (signature, _) = RNG.withDRG drg $ sign privKey HashAlg.SHA256 messageToSignBS
              
              -- Convert signature to JWT format (delegate to EC module)
              case EC.signatureToJWTFormat signature of
                Left err -> return $ Left err
                Right sigBS -> do
                  let sigB64 = base64urlEncode sigBS
                  let jwt = headerB64 <> "." <> payloadB64 <> "." <> sigB64
                  return $ Right jwt
        else do
          -- For RSA and EdDSA, use jose-jwt's JwsHeader with encodeHeader
          -- We'll manually construct the JWT with custom typ header
          jwk <- case parseJWKFromText privateKeyJWK of
            Left err -> return $ Left err
            Right key -> return $ Right key
          
          case jwk of
            Left err -> return $ Left err
            Right key -> do
              -- Convert algorithm string to JwsAlg
              jwsAlg <- case algText of
                "RS256" -> return $ Right Jose.RS256
                "EdDSA" -> return $ Right Jose.EdDSA
                _ -> return $ Left $ InvalidSignature $ "Unsupported algorithm: " <> algText <> " (only RS256, EdDSA, and ES256 are supported)"
              
              case jwsAlg of
                Left err -> return $ Left err
                Right alg -> do
                  -- Create JwsHeader with custom typ (RFC 9901 Section 4.3)
                  -- Using jose-jwt's JwsHeader type which supports jwsTyp field
                  let header = defJwsHdr { jwsAlg = alg, jwsTyp = Just typValue }
                  
                  -- Encode header and payload using jose-jwt's encodeHeader
                  let headerBS = encodeHeader header
                  let payloadBS = BSL.toStrict $ Aeson.encode payload
                  
                  let headerB64 = base64urlEncode headerBS
                  let payloadB64 = base64urlEncode payloadBS
                  
                  -- Build message to sign: base64url(header).base64url(payload)
                  let messageToSignBS = TE.encodeUtf8 $ headerB64 <> "." <> payloadB64
                  
                  -- Extract private key from JWK and sign using jose-jwt's low-level functions
                  -- NOTE: rsaEncode and ed25519Encode create their own JWT with their own header,
                  -- so we need to extract the signature and reconstruct the JWT with our custom header
                  case key of
                    Jose.Jwk.RsaPrivateJwk rsaPrivKey _ _ _ -> do
                      -- Use rsaEncode to sign our custom header.payload message
                      result <- JoseJws.rsaEncode alg rsaPrivKey messageToSignBS
                      case result of
                        Left err -> return $ Left $ InvalidSignature $ "RSA signing failed: " <> T.pack (show err)
                        Right jwt -> do
                          -- Extract signature from the JWT that rsaEncode created
                          -- The JWT format is header.payload.signature
                          let jwtText = TE.decodeUtf8 $ unJwt jwt
                          let parts = T.splitOn "." jwtText
                          case parts of
                            (_headerPart : _payloadPart : sigPart : _) -> do
                              -- Reconstruct JWT with our custom header and the extracted signature
                              -- The signature was computed over our custom header.payload, so it's valid
                              let finalJWT = headerB64 <> "." <> payloadB64 <> "." <> sigPart
                              return $ Right finalJWT
                            _ -> return $ Left $ InvalidSignature "Invalid JWT format from rsaEncode"
                    
                    Jose.Jwk.Ed25519PrivateJwk edSecretKey edPublicKey _ -> do
                      -- Use ed25519Encode to sign our custom header.payload message
                      let jwt = JoseJws.ed25519Encode edSecretKey edPublicKey messageToSignBS
                      -- Extract signature from the JWT that ed25519Encode created
                      let jwtText = TE.decodeUtf8 $ unJwt jwt
                      let parts = T.splitOn "." jwtText
                      case parts of
                        (_headerPart : _payloadPart : sigPart : _) -> do
                          -- Reconstruct JWT with our custom header and the extracted signature
                          -- The signature was computed over our custom header.payload, so it's valid
                          let finalJWT = headerB64 <> "." <> payloadB64 <> "." <> sigPart
                          return $ Right finalJWT
                        _ -> return $ Left $ InvalidSignature "Invalid JWT format from ed25519Encode"
                    
                    _ -> return $ Left $ InvalidSignature $ "JWK is not a private key for algorithm " <> algText <> " (expected RSA or Ed25519 private key)"

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
  -> Maybe T.Text  -- ^ Required typ header value (Nothing = allow any/none, Just "sd-jwt" = require exactly "sd-jwt")
  -> IO (Either SDJWTError Aeson.Value)
verifyJWT publicKeyJWK jwtText requiredTyp = verifyJWTWithTypRequirement publicKeyJWK jwtText requiredTyp

-- | Verify a JWT signature with optional typ header requirement.
--
-- This is the internal function that handles typ requirement. Use 'verifyJWT' for the public API.
verifyJWTWithTypRequirement
  :: T.Text  -- ^ Public key JWK (JSON format)
  -> T.Text  -- ^ JWT to verify
  -> Maybe T.Text  -- ^ Required typ header value (Nothing = allow any/none, Just "sd-jwt" = require exactly "sd-jwt")
  -> IO (Either SDJWTError Aeson.Value)
verifyJWTWithTypRequirement publicKeyJWK jwtText requiredTyp = do
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
                      
                      -- Extract typ from header (optional for issuer-signed JWT, RFC 9901 Section 9.11)
                      typ <- case extractTypFromHeader hJson of
                        Left err -> return $ Left err
                        Right t -> return $ Right t
                      
                      case (alg, typ) of
                        (Left err, _) -> return $ Left err
                        (_, Left err) -> return $ Left err
                        (Right expectedAlg, Right mbTypValue) -> do
                          -- CRITICAL SECURITY (RFC 8725bis): Reject "none" algorithm (unsecured JWT)
                          -- This prevents unsecured JWT attacks
                          if expectedAlg == "none"
                            then return $ Left $ InvalidSignature "Unsecured JWT rejected - 'none' algorithm not allowed (RFC 8725bis)"
                          -- CRITICAL: Verify algorithm is supported (RS256, EdDSA, or ES256)
                          else if expectedAlg /= "RS256" && expectedAlg /= "EdDSA" && expectedAlg /= "ES256"
                            then return $ Left $ InvalidSignature $ "Unsupported algorithm: " <> expectedAlg <> " (only RS256, EdDSA, and ES256 are supported)"
                            else do
                              -- RFC 9901 Section 9.11: Validate typ header based on requirement
                              typValidation <- case requiredTyp of
                                Nothing -> do
                                  -- Liberal mode: allow any typ or none
                                  -- Optionally validate format if present (for informational purposes)
                                  case mbTypValue of
                                    Just typVal -> do
                                      -- If typ is present, validate format (but don't fail)
                                      if typVal == "sd-jwt" || T.isSuffixOf "+sd-jwt" typVal
                                        then return $ Right ()  -- Typ is valid format
                                        else return $ Right ()  -- Still allow it (liberal mode)
                                    Nothing -> return $ Right ()  -- No typ is OK in liberal mode
                                Just requiredTypValue -> do
                                  -- Strict mode: require exact typ value
                                  case mbTypValue of
                                    Just typVal -> do
                                      if typVal == requiredTypValue
                                        then return $ Right ()  -- Typ matches requirement
                                        else return $ Left $ InvalidSignature $ "Invalid typ header: expected '" <> requiredTypValue <> "', got '" <> typVal <> "'"
                                    Nothing -> return $ Left $ InvalidSignature $ "Missing typ header: required '" <> requiredTypValue <> "'"
                              
                              case typValidation of
                                Left err -> return $ Left err
                                Right () -> do
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
    
    -- Extract typ from JWT header (optional for issuer-signed JWT, required for KB-JWT)
    extractTypFromHeader :: Aeson.Value -> Either SDJWTError (Maybe T.Text)
    extractTypFromHeader (Aeson.Object obj) =
      case KeyMap.lookup "typ" obj of
        Just (Aeson.String typ) -> Right (Just typ)
        _ -> Right Nothing  -- typ is optional for issuer-signed JWT
    extractTypFromHeader _ = Left $ InvalidSignature "Invalid JWT header format"

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

