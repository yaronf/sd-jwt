{-# LANGUAGE OverloadedStrings #-}
-- | Hash computation and verification for SD-JWT disclosures.
--
-- This module provides functions for computing digests of disclosures
-- and verifying that digests match disclosures. All three hash algorithms
-- required by RFC 9901 are supported: SHA-256, SHA-384, and SHA-512.
module SDJWT.Digest
  ( computeDigest
  , verifyDigest
  , parseHashAlgorithm
  , defaultHashAlgorithm
  , hashAlgorithmToText
  ) where

import SDJWT.Types
import SDJWT.Utils
import qualified Crypto.Hash as Hash
import qualified Data.ByteArray as BA
import qualified Data.ByteString as BS
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE

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
-- disclosure string. The bytes of the hash output are then base64url encoded
-- to produce the final digest.
--
-- This follows the convention in JWS (RFC 7515) and JWE (RFC 7516).
-- Helper to compute hash and convert to ByteString
hashToBytes :: HashAlgorithm -> BS.ByteString -> BS.ByteString
hashToBytes SHA256 bs = BA.convert (Hash.hash bs :: Hash.Digest Hash.SHA256)
hashToBytes SHA384 bs = BA.convert (Hash.hash bs :: Hash.Digest Hash.SHA384)
hashToBytes SHA512 bs = BA.convert (Hash.hash bs :: Hash.Digest Hash.SHA512)

computeDigest :: HashAlgorithm -> EncodedDisclosure -> Digest
computeDigest alg (EncodedDisclosure encoded) =
  let
    -- Convert the base64url-encoded disclosure to US-ASCII bytes
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
-- and compares it to the expected digest. Returns 'True' if they match.
verifyDigest :: HashAlgorithm -> Digest -> EncodedDisclosure -> Bool
verifyDigest alg expectedDigest disclosure =
  let
    computedDigest = computeDigest alg disclosure
  in
    computedDigest == expectedDigest

