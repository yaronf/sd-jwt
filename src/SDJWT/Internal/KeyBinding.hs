{-# LANGUAGE OverloadedStrings #-}
-- | Key Binding JWT support for SD-JWT+KB.
--
-- This module provides functions for creating and verifying Key Binding JWTs
-- (KB-JWT) as specified in RFC 9901 Section 7. Key Binding provides proof
-- of possession of a key by the holder.
module SDJWT.Internal.KeyBinding
  ( createKeyBindingJWT
  , computeSDHash
  , verifyKeyBindingJWT
  , addKeyBindingToPresentation
  ) where

import SDJWT.Internal.Types (HashAlgorithm(..), Digest(..), SDJWTPresentation(..), SDJWTError(..))
import SDJWT.Internal.Utils (hashToBytes, textToByteString, base64urlEncode, constantTimeEq, base64urlDecode)
import SDJWT.Internal.Serialization (serializePresentation)
import SDJWT.Internal.JWT (signJWTWithTyp, verifyJWT)
import qualified Data.Aeson as Aeson
import qualified Data.Aeson.Key as Key
import qualified Data.Aeson.KeyMap as KeyMap
import qualified Data.Text as T
import Data.Int (Int64)

-- | Create a Key Binding JWT.
--
-- Creates a KB-JWT that proves the holder possesses a specific key.
-- The KB-JWT contains:
-- - aud: Audience (verifier identifier)
-- - nonce: Nonce provided by verifier
-- - iat: Issued at timestamp
-- - sd_hash: Hash of the SD-JWT presentation
--
-- Parameters:
-- - holderPrivateKey: Private key for signing (as Text JWK, placeholder for now)
-- - audience: Audience claim
-- - nonce: Nonce from verifier
-- - issuedAt: Issued at timestamp (Unix epoch seconds)
-- - presentation: The SD-JWT presentation to bind
--
-- Returns the signed KB-JWT as a compact JWT string.
createKeyBindingJWT
  :: HashAlgorithm
  -> T.Text  -- ^ Holder private key (JWK as Text, placeholder for now)
  -> T.Text  -- ^ Audience
  -> T.Text  -- ^ Nonce
  -> Int64   -- ^ Issued at (Unix epoch seconds)
  -> SDJWTPresentation
  -> IO (Either SDJWTError T.Text)
createKeyBindingJWT hashAlg holderPrivateKey audience nonce issuedAt presentation = do
  -- Compute sd_hash of the presentation
  let sdHash = computeSDHash hashAlg presentation
  
  -- Build KB-JWT payload
  let kbPayload = Aeson.object
        [ ("aud", Aeson.String audience)
        , ("nonce", Aeson.String nonce)
        , ("iat", Aeson.Number (fromIntegral issuedAt))
        , ("sd_hash", Aeson.String (unDigest sdHash))
        ]
  
  -- Sign the KB-JWT with typ: "kb+jwt" header (RFC 9901 Section 4.3 requirement)
  -- Supports all key types: RSA (PS256 default, RS256 also supported), EC P-256 (ES256), and Ed25519 (EdDSA).
  signJWTWithTyp "kb+jwt" holderPrivateKey kbPayload

-- | Compute sd_hash for key binding.
--
-- The sd_hash is computed as the hash of the serialized SD-JWT presentation
-- (without the KB-JWT part). This hash is included in the KB-JWT to bind
-- it to the specific presentation.
--
-- The hash is computed over the US-ASCII bytes of the presentation string
-- (per RFC 9901). Since the serialized presentation contains only ASCII
-- characters (base64url-encoded strings and tilde separators), UTF-8 encoding
-- produces identical bytes to US-ASCII.
computeSDHash
  :: HashAlgorithm
  -> SDJWTPresentation
  -> Digest
computeSDHash hashAlg presentation =
  -- Serialize presentation (without KB-JWT)
  -- Create a presentation without KB-JWT for serialization
  let presentationWithoutKB = presentation { keyBindingJWT = Nothing }
      presentationText = serializePresentation presentationWithoutKB
      -- Convert to bytes (UTF-8 is equivalent to US-ASCII for ASCII-only strings)
      presentationBytes = textToByteString presentationText
      -- Compute hash
      hashBytes = hashToBytes hashAlg presentationBytes
      -- Base64url encode
      hashText = base64urlEncode hashBytes
  in
    Digest hashText

-- | Verify a Key Binding JWT.
--
-- Verifies that:
-- 1. The KB-JWT signature is valid (using holder's public key)
-- 2. The sd_hash in the KB-JWT matches the computed hash of the presentation
-- 3. The nonce, audience, and iat claims are present and valid
--
-- Parameters:
-- - holderPublicKey: Public key for verification (JWK as Text, placeholder for now)
-- - kbJWT: The Key Binding JWT to verify
-- - presentation: The SD-JWT presentation
--
-- Returns 'Right ()' if verification succeeds, 'Left' with error otherwise.
verifyKeyBindingJWT
  :: HashAlgorithm
  -> T.Text  -- ^ Holder public key (JWK as Text)
  -> T.Text  -- ^ KB-JWT to verify
  -> SDJWTPresentation
  -> IO (Either SDJWTError ())
verifyKeyBindingJWT hashAlg holderPublicKey kbJWT presentation = do
  -- RFC 9901 Section 4.3: Validate KB-JWT header first
  -- typ: REQUIRED. MUST be kb+jwt
  let kbParts = T.splitOn "." kbJWT
  case kbParts of
    (headerPart : _payloadPart : _signaturePart) -> do
      -- Decode and validate header
      headerBytes <- case base64urlDecode headerPart of
        Left err -> return $ Left $ InvalidKeyBinding $ "Failed to decode KB-JWT header: " <> err
        Right bs -> return $ Right bs
      
      case headerBytes of
        Left err -> return $ Left err
        Right hBytes -> do
          headerJson <- case Aeson.eitherDecodeStrict hBytes of
            Left err -> return $ Left $ InvalidKeyBinding $ "Failed to parse KB-JWT header: " <> T.pack err
            Right val -> return $ Right val
          
          case headerJson of
            Left err -> return $ Left err
            Right (Aeson.Object hObj) -> do
              -- RFC 9901 Section 4.3: typ MUST be "kb+jwt"
              case KeyMap.lookup "typ" hObj of
                Just (Aeson.String "kb+jwt") -> do
                  -- typ is correct, continue with signature verification
                  -- Note: For KB-JWT, typ is already validated above, so we pass Nothing (liberal mode)
                  -- (KB-JWT typ validation is handled separately, not through verifyJWT's typ check)
                  verifiedPayloadResult <- verifyJWT holderPublicKey kbJWT Nothing
                  case verifiedPayloadResult of
                    Left err -> return (Left err)
                    Right kbPayload -> do
                      -- Extract claims from verified payload
                      sdHashClaim <- return $ extractClaim "sd_hash" kbPayload
                      nonceClaim <- return $ extractClaim "nonce" kbPayload
                      audClaim <- return $ extractClaim "aud" kbPayload
                      iatClaim <- return $ extractClaim "iat" kbPayload
                      
                      case sdHashClaim of
                        Left err -> return (Left err)
                        Right (Aeson.String hashText) -> do
                          -- Verify sd_hash matches presentation using constant-time comparison
                          -- SECURITY: Constant-time comparison prevents timing attacks
                          let computedHash = computeSDHash hashAlg presentation
                              expectedBytes = textToByteString hashText
                              computedBytes = textToByteString (unDigest computedHash)
                          if constantTimeEq expectedBytes computedBytes
                            then do
                              -- Verify nonce, audience, iat are present (basic validation)
                              case (nonceClaim, audClaim, iatClaim) of
                                (Right (Aeson.String _), Right (Aeson.String _), Right (Aeson.Number _)) -> return (Right ())
                                _ -> return $ Left $ InvalidKeyBinding "Missing required claims (nonce, aud, iat)"
                            else return $ Left $ InvalidKeyBinding "sd_hash mismatch"
                        Right _ -> return $ Left $ InvalidKeyBinding "Invalid sd_hash claim format"
                Just (Aeson.String typValue) -> return $ Left $ InvalidKeyBinding $ "Invalid KB-JWT typ: expected 'kb+jwt', got '" <> typValue <> "' (RFC 9901 Section 4.3)"
                _ -> return $ Left $ InvalidKeyBinding "Missing 'typ' header in KB-JWT (RFC 9901 Section 4.3 requires typ: 'kb+jwt')"
            Right _ -> return $ Left $ InvalidKeyBinding "Invalid KB-JWT header format: expected object"
    _ -> return $ Left $ InvalidKeyBinding "Invalid KB-JWT format: expected header.payload.signature"

-- | Add key binding to a presentation.
--
-- Creates a KB-JWT and adds it to the presentation, converting it to SD-JWT+KB format.
addKeyBindingToPresentation
  :: HashAlgorithm
  -> T.Text  -- ^ Holder private key
  -> T.Text  -- ^ Audience
  -> T.Text  -- ^ Nonce
  -> Int64   -- ^ Issued at
  -> SDJWTPresentation
  -> IO (Either SDJWTError SDJWTPresentation)
addKeyBindingToPresentation hashAlg holderKey audience nonce issuedAt presentation = do
  kbJWT <- createKeyBindingJWT hashAlg holderKey audience nonce issuedAt presentation
  case kbJWT of
    Left err -> return (Left err)
    Right kb -> return $ Right presentation { keyBindingJWT = Just kb }

-- Helper functions

-- | Extract a claim from a JSON object.
extractClaim :: T.Text -> Aeson.Value -> Either SDJWTError Aeson.Value
extractClaim claimName (Aeson.Object obj) =
  case KeyMap.lookup (Key.fromText claimName) obj of
    Just val -> Right val
    Nothing -> Left $ InvalidKeyBinding $ "Missing claim: " <> claimName
extractClaim _ _ = Left $ InvalidKeyBinding "KB-JWT payload is not an object"


