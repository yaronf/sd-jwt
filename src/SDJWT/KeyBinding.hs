{-# LANGUAGE OverloadedStrings #-}
-- | Key Binding JWT support for SD-JWT+KB.
--
-- This module provides functions for creating and verifying Key Binding JWTs
-- (KB-JWT) as specified in RFC 9901 Section 7. Key Binding provides proof
-- of possession of a key by the holder.
module SDJWT.KeyBinding
  ( createKeyBindingJWT
  , computeSDHash
  , verifyKeyBindingJWT
  , addKeyBindingToPresentation
  ) where

import SDJWT.Types
import SDJWT.Utils (hashToBytes, textToByteString, base64urlEncode)
import SDJWT.Serialization
import SDJWT.JWT
import qualified Data.Aeson as Aeson
import qualified Data.Aeson.Key as Key
import qualified Data.Aeson.KeyMap as KeyMap
import qualified Data.Text as T
import qualified Data.ByteString as BS
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
  
  -- Sign the KB-JWT using jose-jwt with holder's private key
  signJWT holderPrivateKey kbPayload

-- | Compute sd_hash for key binding.
--
-- The sd_hash is computed as the hash of the serialized SD-JWT presentation
-- (without the KB-JWT part). This hash is included in the KB-JWT to bind
-- it to the specific presentation.
--
-- The hash is computed over the US-ASCII bytes of the presentation string.
computeSDHash
  :: HashAlgorithm
  -> SDJWTPresentation
  -> Digest
computeSDHash hashAlg presentation =
  -- Serialize presentation (without KB-JWT)
  -- Create a presentation without KB-JWT for serialization
  let presentationWithoutKB = presentation { keyBindingJWT = Nothing }
      presentationText = serializePresentation presentationWithoutKB
      -- Convert to US-ASCII bytes
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
  -- Verify KB-JWT signature using jose-jwt
  verifiedPayloadResult <- verifyJWT holderPublicKey kbJWT
  case verifiedPayloadResult of
    Left err -> return (Left err)
    Right kbPayload -> do
      -- Extract claims from verified payload
      sdHashClaim <- case extractClaim "sd_hash" kbPayload of
        Left err -> return (Left err)
        Right claim -> return (Right claim)
      nonceClaim <- case extractClaim "nonce" kbPayload of
        Left err -> return (Left err)
        Right claim -> return (Right claim)
      audClaim <- case extractClaim "aud" kbPayload of
        Left err -> return (Left err)
        Right claim -> return (Right claim)
      iatClaim <- case extractClaim "iat" kbPayload of
        Left err -> return (Left err)
        Right claim -> return (Right claim)
      
      case sdHashClaim of
        Left err -> return (Left err)
        Right (Aeson.String hashText) -> do
          -- Verify sd_hash matches presentation
          let computedHash = computeSDHash hashAlg presentation
          if hashText == unDigest computedHash
            then do
              -- Verify nonce, audience, iat are present (basic validation)
              case (nonceClaim, audClaim, iatClaim) of
                (Right (Aeson.String _), Right (Aeson.String _), Right (Aeson.Number _)) -> return (Right ())
                _ -> return $ Left $ InvalidKeyBinding "Missing required claims (nonce, aud, iat)"
            else return $ Left $ InvalidKeyBinding "sd_hash mismatch"
        Right _ -> return $ Left $ InvalidKeyBinding "Invalid sd_hash claim format"

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


