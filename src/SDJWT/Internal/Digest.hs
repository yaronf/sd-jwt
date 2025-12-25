{-# LANGUAGE OverloadedStrings #-}
-- | Hash computation and verification for SD-JWT disclosures (low-level).
--
-- This module provides functions for computing digests of disclosures
-- and verifying that digests match disclosures. All three hash algorithms
-- required by RFC 9901 are supported: SHA-256, SHA-384, and SHA-512.
--
-- == Usage
--
-- This module contains low-level hash and digest utilities that are typically
-- used internally by other SD-JWT modules. Most users should use the higher-level
-- APIs in:
--
-- * 'SDJWT.Issuer' - For issuers (handles digest computation internally)
-- * 'SDJWT.Holder' - For holders (handles digest computation internally)
-- * 'SDJWT.Verifier' - For verifiers (handles digest verification internally)
--
-- These utilities may be useful for:
-- * Advanced use cases requiring custom digest computation
-- * Library developers building on top of SD-JWT
-- * Testing and debugging
--
module SDJWT.Internal.Digest
  ( computeDigest
  , verifyDigest
  , parseHashAlgorithm
  , defaultHashAlgorithm
  , hashAlgorithmToText
  , extractDigestsFromValue
  ) where

import SDJWT.Internal.Types (HashAlgorithm(..), Digest(..), EncodedDisclosure(..))
import SDJWT.Internal.Utils (hashToBytes, base64urlEncode, constantTimeEq, textToByteString)
import qualified Data.Aeson as Aeson
import qualified Data.Aeson.Key as Key
import qualified Data.Aeson.KeyMap as KeyMap
import qualified Data.Vector as V
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import Data.Maybe (mapMaybe)

-- | Default hash algorithm (SHA-256 per RFC 9901).
--
-- When the _sd_alg claim is not present in an SD-JWT, SHA-256 is used
-- as the default hash algorithm.
defaultHashAlgorithm :: HashAlgorithm
defaultHashAlgorithm = SHA256

-- | Convert hash algorithm to text identifier.
--
-- Returns the hash algorithm name as specified in RFC 9901:
-- "sha-256", "sha-384", or "sha-512".
hashAlgorithmToText :: HashAlgorithm -> T.Text
hashAlgorithmToText SHA256 = "sha-256"
hashAlgorithmToText SHA384 = "sha-384"
hashAlgorithmToText SHA512 = "sha-512"

-- | Parse hash algorithm from text identifier.
--
-- Parses hash algorithm names from the _sd_alg claim.
-- Returns 'Nothing' if the algorithm is not recognized.
parseHashAlgorithm :: T.Text -> Maybe HashAlgorithm
parseHashAlgorithm "sha-256" = Just SHA256
parseHashAlgorithm "sha-384" = Just SHA384
parseHashAlgorithm "sha-512" = Just SHA512
parseHashAlgorithm _ = Nothing

-- | Compute digest of a disclosure.
--
-- The digest is computed over the US-ASCII bytes of the base64url-encoded
-- disclosure string (per RFC 9901). The bytes of the hash output are then
-- base64url encoded to produce the final digest.
--
-- This follows the convention in JWS (RFC 7515) and JWE (RFC 7516).
--
-- Note: RFC 9901 requires US-ASCII encoding. Since base64url strings contain
-- only ASCII characters (A-Z, a-z, 0-9, -, _), UTF-8 encoding produces
-- identical bytes to US-ASCII for these strings.

computeDigest :: HashAlgorithm -> EncodedDisclosure -> Digest
computeDigest alg (EncodedDisclosure encoded) =
  let
    -- Convert the base64url-encoded disclosure to bytes
    -- UTF-8 encoding is equivalent to US-ASCII for base64url strings (ASCII-only)
    disclosureBytes = TE.encodeUtf8 encoded
    -- Compute hash
    hashBytes = hashToBytes alg disclosureBytes
    -- Base64url encode the hash bytes
    digestText = base64urlEncode hashBytes
  in
    Digest digestText

-- | Verify that a digest matches a disclosure.
--
-- Computes the digest of the disclosure using the specified hash algorithm
-- and compares it to the expected digest using constant-time comparison.
-- Returns 'True' if they match.
--
-- SECURITY: Uses constant-time comparison to prevent timing attacks.
-- This is critical for cryptographic verification operations.
verifyDigest :: HashAlgorithm -> Digest -> EncodedDisclosure -> Bool
verifyDigest alg expectedDigest disclosure =
  let
    computedDigest = computeDigest alg disclosure
    -- Convert digests to ByteString for constant-time comparison
    expectedBytes = textToByteString (unDigest expectedDigest)
    computedBytes = textToByteString (unDigest computedDigest)
  in
    constantTimeEq expectedBytes computedBytes

-- | Recursively extract digests from JSON value (_sd arrays and array ellipsis objects).
--
-- This function extracts all digests from a JSON value by:
-- 1. Looking for _sd arrays in objects and extracting string digests
-- 2. Looking for {"...": "<digest>"} objects in arrays
-- 3. Recursively processing nested structures
--
-- Used for extracting digests from SD-JWT payloads and disclosure values.
extractDigestsFromValue :: Aeson.Value -> [Digest]
extractDigestsFromValue (Aeson.Object obj) =
  let topLevelDigests = case KeyMap.lookup "_sd" obj of
        Just (Aeson.Array arr) ->
          mapMaybe (\v -> case v of
            Aeson.String s -> Just (Digest s)
            _ -> Nothing
          ) (V.toList arr)
        _ -> []
      -- Recursively extract from nested objects
      nestedDigests = concatMap (extractDigestsFromValue . snd) (KeyMap.toList obj)
  in topLevelDigests ++ nestedDigests
extractDigestsFromValue (Aeson.Array arr) =
  -- Check for array ellipsis objects {"...": "<digest>"}
  concatMap (\el -> case el of
    Aeson.Object obj ->
      case KeyMap.lookup (Key.fromText "...") obj of
        Just (Aeson.String digest) -> [Digest digest]
        _ -> extractDigestsFromValue el  -- Recursively check nested structures
    _ -> extractDigestsFromValue el  -- Recursively check nested structures
  ) (V.toList arr)
extractDigestsFromValue _ = []

