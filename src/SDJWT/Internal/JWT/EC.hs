{-# LANGUAGE OverloadedStrings #-}
-- | EC (Elliptic Curve) JWT signing support using cryptonite.
--
-- This module provides EC signing functionality as a temporary workaround
-- until jose-jwt adds native EC signing support. Once jose-jwt supports EC
-- signing, this entire module can be removed.
--
-- NOTE: This module is intentionally kept separate from SDJWT.Internal.JWT to make
-- removal easy once jose-jwt adds EC signing support.
module SDJWT.Internal.JWT.EC
  ( signJWTES256
  ) where

import SDJWT.Internal.Types (SDJWTError(..))
import SDJWT.Internal.Utils (base64urlEncode, base64urlDecode)
import Crypto.PubKey.ECC.ECDSA (PrivateKey(..), Signature(..), sign)
import Crypto.PubKey.ECC.Types (getCurveByName, CurveName(..))
import qualified Crypto.Hash.Algorithms as HashAlg
import qualified Crypto.Number.Serialize as Serialize
import qualified Data.Aeson as Aeson
import qualified Data.Aeson.KeyMap as KeyMap
import qualified Data.Aeson.Key as Key
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BSL
import qualified Crypto.Random as RNG

-- | Sign a JWT payload using an EC P-256 private key (ES256 algorithm).
--
-- This function implements ES256 signing manually since jose-jwt does not
-- support EC signing. Once jose-jwt adds EC signing support, this function
-- and the entire module can be removed.
--
-- Parameters:
-- - privateKeyJWK: EC private key as JSON Web Key (JWK) in Text format
-- - payload: The JWT payload as Aeson Value
--
-- Returns the signed JWT as a compact string, or an error.
--
-- NOTE: This function uses 'IO' because ECDSA signing requires randomness.
-- Each signature must use a unique, cryptographically secure random nonce (k value)
-- for security. Reusing nonces or using predictable nonces can lead to private
-- key recovery attacks. The function obtains randomness from the system's
-- random number generator via 'RNG.getSystemDRG'.
signJWTES256
  :: T.Text  -- ^ Private key JWK (JSON format, must be EC P-256)
  -> Aeson.Value  -- ^ JWT payload
  -> IO (Either SDJWTError T.Text)
signJWTES256 privateKeyJWK payload = do
  -- Parse EC private key from JWK (pure operation, but we're already in IO)
  case parseECPrivateKeyFromJWK privateKeyJWK of
    Left err -> return $ Left err
    Right privKey -> do
      -- Build JWT header
      let header = Aeson.object
            [ "alg" Aeson..= ("ES256" :: T.Text)
            , "typ" Aeson..= ("JWT" :: T.Text)
            ]
      
      -- Encode header and payload
      let headerBS = BSL.toStrict $ Aeson.encode header
      let payloadBS = BSL.toStrict $ Aeson.encode payload
      
      let headerB64 = base64urlEncode headerBS
      let payloadB64 = base64urlEncode payloadBS
      
      -- Build the message to sign: base64url(header).base64url(payload)
      let messageToSign = TE.encodeUtf8 $ headerB64 <> "." <> payloadB64
      
      -- Sign using cryptonite
      -- NOTE: ECDSA signing requires randomness (a random nonce k for each signature).
      -- This is why we need IO: to get a system random number generator.
      -- Each signature must use a unique, unpredictable nonce for security.
      drg <- RNG.getSystemDRG
      let (signature, _) = RNG.withDRG drg $ sign privKey HashAlg.SHA256 messageToSign
      
      -- Convert signature to JWT format: r || s (each 32 bytes for P-256)
      case signatureToJWTFormat signature of
        Left err -> return $ Left err
        Right sigBS -> do
          -- Build final JWT: base64url(header).base64url(payload).base64url(signature)
          let sigB64 = base64urlEncode sigBS
          let jwt = headerB64 <> "." <> payloadB64 <> "." <> sigB64
          return $ Right jwt

-- | Decode a base64url-encoded coordinate from a JWK object.
--
-- Helper function to extract and decode a coordinate field (d, x, y) from an EC JWK.
decodeCoordinate :: T.Text -> KeyMap.KeyMap Aeson.Value -> Either SDJWTError BS.ByteString
decodeCoordinate fieldName obj =
  case KeyMap.lookup (Key.fromText fieldName) obj of
    Just (Aeson.String coordText) -> case base64urlDecode coordText of
      Left err -> Left $ InvalidSignature $ "Failed to decode '" <> fieldName <> "' coordinate: " <> err
      Right bs -> Right bs
    _ -> Left $ InvalidSignature $ "Missing '" <> fieldName <> "' field in EC private key JWK"

-- | Parse an EC private key from JWK JSON format.
--
-- Expected format: {"kty":"EC","crv":"P-256","d":"...","x":"...","y":"..."}
-- where d, x, y are base64url-encoded coordinates.
parseECPrivateKeyFromJWK :: T.Text -> Either SDJWTError PrivateKey
parseECPrivateKeyFromJWK jwkText = do
  case Aeson.eitherDecodeStrict (TE.encodeUtf8 jwkText) of
    Left err -> Left $ InvalidSignature $ "Failed to parse JWK JSON: " <> T.pack err
    Right (Aeson.Object obj) -> do
      -- Verify key type
      _kty <- case KeyMap.lookup (Key.fromText "kty") obj of
        Just (Aeson.String "EC") -> Right ()
        Just (Aeson.String ktyText) -> Left $ InvalidSignature $ "Expected EC key type, got: " <> ktyText
        _ -> Left $ InvalidSignature "Missing or invalid 'kty' field in JWK"
      
      -- Verify curve
      _crv <- case KeyMap.lookup (Key.fromText "crv") obj of
        Just (Aeson.String "P-256") -> Right ()
        Just (Aeson.String crvText) -> Left $ InvalidSignature $ "Unsupported curve: " <> crvText <> " (only P-256 is supported)"
        _ -> Left $ InvalidSignature "Missing or invalid 'crv' field in JWK"
      
      -- Parse private key scalar (d)
      dBS <- decodeCoordinate "d" obj
      
      -- Parse x coordinate (validate it exists, but don't use it for signing)
      _xBS <- decodeCoordinate "x" obj
      
      -- Parse y coordinate (validate it exists, but don't use it for signing)
      _yBS <- decodeCoordinate "y" obj
      
      -- Convert private key scalar to Integer
      let dInt = bsToInteger dBS
      
      -- Get the P-256 curve
      let curve = getCurveByName SEC_p256r1
      
      -- Create the private key
      -- PrivateKey constructor: PrivateKey { private_curve :: Curve, private_d :: PrivateNumber }
      -- PrivateNumber is just an Integer
      -- Note: We don't need to construct the public point for signing,
      -- cryptonite will derive it from the private key if needed
      let privKey = PrivateKey { private_curve = curve, private_d = dInt }
      
      -- Return the private key (cryptonite will validate during signing)
      Right privKey
    Right _ -> Left $ InvalidSignature "Invalid JWK format: expected object"

-- | Convert a cryptonite ECDSA Signature to JWT format.
--
-- JWT format for ES256: r || s (concatenated, each 32 bytes for P-256)
-- cryptonite Signature has direct access to sign_r and sign_s
signatureToJWTFormat :: Signature -> Either SDJWTError BS.ByteString
signatureToJWTFormat sig = do
  -- Extract r and s from signature
  let rInt = sign_r sig
  let sInt = sign_s sig
  
  -- Convert to fixed-length ByteStrings (32 bytes = 256 bits for P-256)
  let rBS = Serialize.i2ospOf_ 32 rInt
  let sBS = Serialize.i2ospOf_ 32 sInt
  
  -- Concatenate: r || s
  Right $ rBS <> sBS

-- | Convert a ByteString to an Integer (big-endian).
bsToInteger :: BS.ByteString -> Integer
bsToInteger = BS.foldl' (\acc byte -> acc * 256 + fromIntegral byte) 0
