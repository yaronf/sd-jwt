{-# LANGUAGE OverloadedStrings #-}
-- | Utility functions for SD-JWT operations.
--
-- This module provides base64url encoding/decoding, salt generation,
-- and text/ByteString conversions used throughout the SD-JWT library.
module SDJWT.Utils
  ( base64urlEncode
  , base64urlDecode
  , generateSalt
  , textToByteString
  , byteStringToText
  , hashToBytes
  , splitJSONPointer
  , unescapeJSONPointer
  ) where

import qualified Data.ByteString.Base64.URL as Base64
import qualified Data.ByteString as BS
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import qualified Crypto.Random as RNG
import qualified Crypto.Hash as Hash
import qualified Data.ByteArray as BA
import Control.Monad.IO.Class (MonadIO, liftIO)
import SDJWT.Types (HashAlgorithm(..))

-- | Base64url encode a ByteString (without padding).
--
-- This function encodes a ByteString using base64url encoding as specified
-- in RFC 4648 Section 5. The result is URL-safe and does not include padding.
--
-- >>> base64urlEncode "Hello, World!"
-- "SGVsbG8sIFdvcmxkIQ"
base64urlEncode :: BS.ByteString -> T.Text
base64urlEncode = TE.decodeUtf8 . Base64.encodeUnpadded

-- | Base64url decode a Text (handles padding).
--
-- This function decodes a base64url-encoded Text back to a ByteString.
-- It handles both padded and unpadded input.
--
-- Returns 'Left' with an error message if decoding fails.
base64urlDecode :: T.Text -> Either T.Text BS.ByteString
base64urlDecode t =
  case Base64.decodeUnpadded (TE.encodeUtf8 t) of
    Left err -> Left $ T.pack $ show err
    Right bs -> Right bs

-- | Generate a cryptographically secure random salt.
--
-- Generates 128 bits (16 bytes) of random data as recommended by RFC 9901.
-- This salt is used when creating disclosures to ensure that digests cannot
-- be guessed or brute-forced.
--
-- The salt is generated using cryptonite's secure random number generator.
generateSalt :: MonadIO m => m BS.ByteString
generateSalt = liftIO $ RNG.getRandomBytes 16

-- | Convert Text to ByteString (UTF-8 encoding).
--
-- This is a convenience function that encodes Text as UTF-8 ByteString.
textToByteString :: T.Text -> BS.ByteString
textToByteString = TE.encodeUtf8

-- | Convert ByteString to Text (UTF-8 decoding).
--
-- This is a convenience function that decodes a UTF-8 ByteString to Text.
-- Note: This will throw an exception if the ByteString is not valid UTF-8.
-- For safe decoding, use 'Data.Text.Encoding.decodeUtf8'' instead.
byteStringToText :: BS.ByteString -> T.Text
byteStringToText = TE.decodeUtf8

-- | Hash bytes using the specified hash algorithm.
--
-- This function computes a cryptographic hash of the input ByteString
-- using the specified hash algorithm (SHA-256, SHA-384, or SHA-512).
-- Returns the hash digest as a ByteString.
hashToBytes :: HashAlgorithm -> BS.ByteString -> BS.ByteString
hashToBytes SHA256 bs = BA.convert (Hash.hash bs :: Hash.Digest Hash.SHA256)
hashToBytes SHA384 bs = BA.convert (Hash.hash bs :: Hash.Digest Hash.SHA384)
hashToBytes SHA512 bs = BA.convert (Hash.hash bs :: Hash.Digest Hash.SHA512)

-- | Split JSON Pointer path by "/", respecting escapes (RFC 6901).
--
-- This function properly handles JSON Pointer escaping:
-- - "~1" represents a literal forward slash "/"
-- - "~0" represents a literal tilde "~"
--
-- Examples:
-- - "a/b" → ["a", "b"]
-- - "a~1b" → ["a/b"] (escaped slash)
-- - "a~0b" → ["a~b"] (escaped tilde)
-- - "a~1/b" → ["a/b", ""] (escaped slash followed by separator)
splitJSONPointer :: T.Text -> [T.Text]
splitJSONPointer path = go path [] ""
  where
    go remaining acc current
      | T.null remaining = reverse (if T.null current then acc else current : acc)
      | T.take 2 remaining == "~1" =
          -- Escaped slash (must check before checking for unescaped "/")
          go (T.drop 2 remaining) acc (current <> "/")
      | T.take 2 remaining == "~0" =
          -- Escaped tilde
          go (T.drop 2 remaining) acc (current <> "~")
      | T.head remaining == '/' =
          -- Found unescaped slash (after checking escape sequences)
          go (T.tail remaining) (if T.null current then acc else current : acc) ""
      | otherwise =
          -- Regular character
          go (T.tail remaining) acc (T.snoc current (T.head remaining))

-- | Unescape JSON Pointer segment (RFC 6901).
--
-- Converts escape sequences back to literal characters:
-- - "~1" → "/"
-- - "~0" → "~"
--
-- Note: Order matters - must replace ~1 before ~0 to avoid double-replacement.
unescapeJSONPointer :: T.Text -> T.Text
unescapeJSONPointer = T.replace "~1" "/" . T.replace "~0" "~"

