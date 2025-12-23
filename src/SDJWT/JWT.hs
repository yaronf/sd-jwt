{-# LANGUAGE OverloadedStrings #-}
-- | JWT signing and verification using jose-jwt library.
--
-- This module provides functions for signing and verifying JWTs using the
-- jose-jwt library. It handles the conversion between our Text-based JWK
-- placeholders and the jose-jwt library's Jwk types.
module SDJWT.JWT
  ( signJWT
  , verifyJWT
  , parseJWKFromText
  ) where

import SDJWT.Types
import Jose.Jwt (encode, decode, JwtEncoding(..), Payload(..), Jwt(..), JwtContent(..))
import Jose.Jwk (Jwk)
import qualified Jose.Jwa as Jose
import qualified Data.Aeson as Aeson
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import qualified Data.ByteString.Lazy as BSL
import qualified Data.ByteString as BS
import Crypto.Random ()  -- Import instances for MonadRandom

-- | Sign a JWT payload using a private key.
--
-- Parameters:
-- - privateKeyJWK: Private key as JSON Web Key (JWK) in Text format
-- - payload: The JWT payload as Aeson Value
-- - algorithm: The signing algorithm (defaults to RS256)
--
-- Returns the signed JWT as a compact string, or an error.
signJWT
  :: T.Text  -- ^ Private key JWK (JSON format)
  -> Aeson.Value  -- ^ JWT payload
  -> IO (Either SDJWTError T.Text)
signJWT privateKeyJWK payload = do
  -- Require valid JWK - empty strings are not valid keys
  if T.null privateKeyJWK
    then return $ Left $ InvalidSignature "JWK cannot be empty - provide a valid private key JWK"
    else do
      -- Parse JWK from Text
      jwk <- case parseJWKFromText privateKeyJWK of
        Left err -> return $ Left err
        Right key -> return $ Right key
      
      case jwk of
        Left err -> return $ Left err
        Right key -> do
          -- Encode payload to ByteString
          let payloadBS = BSL.toStrict $ Aeson.encode payload
          
          -- Create JWT encoding (RS256 signing)
          let encoding = JwsEncoding Jose.RS256
          
          -- Sign the JWT
          result <- encode [key] encoding (Claims payloadBS)
          
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
          
          -- Decode and verify JWT
          result <- decode [key] Nothing jwtBS
          
          case result of
            Left jwtErr -> return $ Left $ InvalidSignature $ "JWT verification failed: " <> T.pack (show jwtErr)
            Right jwtContent -> do
              -- Extract payload from JwtContent
              let payloadBS = case jwtContent of
                    Jws (_, bs) -> bs  -- JWS payload is the second element of the tuple
                    Jwe _ -> BS.empty  -- JWE not supported yet
                    Unsecured bs -> bs  -- Unsecured JWT
              -- Parse payload as JSON
              case Aeson.eitherDecodeStrict payloadBS of
                Left jsonErr -> return $ Left $ JSONParseError $ "Failed to parse JWT payload: " <> T.pack jsonErr
                Right payload -> return $ Right payload

-- | Parse a JWK from JSON Text.
--
-- Parses a JSON Web Key (JWK) from its JSON representation.
-- Supports all key types that jose-jwt supports: RSA, EC, Ed25519, Ed448, and symmetric keys.
--
-- The JWK JSON format follows RFC 7517. Examples:
-- - RSA public key: {"kty":"RSA","n":"...","e":"..."}
-- - EC public key: {"kty":"EC","crv":"P-256","x":"...","y":"..."}
-- - RSA private key: {"kty":"RSA","n":"...","e":"...","d":"...","p":"...","q":"..."}
parseJWKFromText :: T.Text -> Either SDJWTError Jwk
parseJWKFromText jwkText =
  case Aeson.eitherDecodeStrict (TE.encodeUtf8 jwkText) of
    Left err -> Left $ InvalidSignature $ "Failed to parse JWK JSON: " <> T.pack err
    Right jwk -> Right jwk

