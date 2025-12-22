{-# LANGUAGE OverloadedStrings #-}
-- | Disclosure creation, encoding, and decoding.
--
-- Disclosures are base64url-encoded JSON arrays that contain the cleartext
-- values of selectively disclosable claims. This module provides functions
-- to create disclosures for object properties and array elements, and to
-- encode/decode them.
module SDJWT.Disclosure
  ( createObjectDisclosure
  , createArrayDisclosure
  , decodeDisclosure
  , encodeDisclosure
  , getDisclosureSalt
  , getDisclosureClaimName
  , getDisclosureValue
  ) where

import SDJWT.Types
import SDJWT.Utils
import qualified Data.Aeson as Aeson
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BSL
import qualified Data.Text as T
import qualified Data.Vector as V

-- | Create disclosure for object property: [salt, claim_name, claim_value].
--
-- Creates a disclosure for a selectively disclosable object property.
-- The disclosure is a JSON array containing:
-- 1. The salt (base64url-encoded)
-- 2. The claim name
-- 3. The claim value
--
-- The result is base64url-encoded as required by RFC 9901.
createObjectDisclosure :: Salt -> T.Text -> Aeson.Value -> Either SDJWTError EncodedDisclosure
createObjectDisclosure salt name value =
  let
    saltText = base64urlEncode (unSalt salt)
    -- Create JSON array: [salt, claim_name, claim_value]
    jsonArray = Aeson.Array $ V.fromList
      [ Aeson.String saltText
      , Aeson.String name
      , value
      ]
    -- Encode to JSON bytes (lazy) and convert to strict
    jsonBytes = BS.concat $ BSL.toChunks $ Aeson.encode jsonArray
    -- Base64url encode
    encoded = base64urlEncode jsonBytes
  in
    Right $ EncodedDisclosure encoded

-- | Create disclosure for array element: [salt, claim_value].
--
-- Creates a disclosure for a selectively disclosable array element.
-- The disclosure is a JSON array containing:
-- 1. The salt (base64url-encoded)
-- 2. The array element value
--
-- Note: Array element disclosures do not include a claim name.
-- The result is base64url-encoded as required by RFC 9901.
createArrayDisclosure :: Salt -> Aeson.Value -> Either SDJWTError EncodedDisclosure
createArrayDisclosure salt value =
  let
    saltText = base64urlEncode (unSalt salt)
    -- Create JSON array: [salt, claim_value]
    jsonArray = Aeson.Array $ V.fromList
      [ Aeson.String saltText
      , value
      ]
    -- Encode to JSON bytes (lazy) and convert to strict
    jsonBytes = BS.concat $ BSL.toChunks $ Aeson.encode jsonArray
    -- Base64url encode
    encoded = base64urlEncode jsonBytes
  in
    Right $ EncodedDisclosure encoded

-- | Decode disclosure from base64url.
--
-- Decodes a base64url-encoded disclosure string back into a 'Disclosure'
-- value. The disclosure must be a valid JSON array with either 2 elements
-- (for array disclosures) or 3 elements (for object disclosures).
--
-- Returns 'Left' with an error if the disclosure format is invalid.
decodeDisclosure :: EncodedDisclosure -> Either SDJWTError Disclosure
decodeDisclosure (EncodedDisclosure encoded) =
  case base64urlDecode encoded of
    Left err -> Left $ InvalidDisclosureFormat $ "Failed to decode base64url: " <> err
    Right jsonBytes ->
      case Aeson.eitherDecode (BSL.fromStrict jsonBytes) of
        Left err -> Left $ InvalidDisclosureFormat $ "Failed to parse JSON: " <> T.pack err
        Right (Aeson.Array arr) ->
          let
            len = V.length arr
          in
            if len == 2
              then
                -- Array disclosure: [salt, value]
                case ((V.!?) arr 0, (V.!?) arr 1) of
                  (Just (Aeson.String saltText), Just value) ->
                    case base64urlDecode saltText of
                      Left err -> Left $ InvalidDisclosureFormat $ "Invalid salt encoding: " <> err
                      Right saltBytes ->
                        Right $ DisclosureArray $ ArrayDisclosure (Salt saltBytes) value
                  _ -> Left $ InvalidDisclosureFormat "Invalid array disclosure format"
              else if len == 3
                then
                  -- Object disclosure: [salt, name, value]
                  case ((V.!?) arr 0, (V.!?) arr 1, (V.!?) arr 2) of
                    (Just (Aeson.String saltText), Just (Aeson.String name), Just value) ->
                      case base64urlDecode saltText of
                        Left err -> Left $ InvalidDisclosureFormat $ "Invalid salt encoding: " <> err
                        Right saltBytes ->
                          Right $ DisclosureObject $ ObjectDisclosure (Salt saltBytes) name value
                    _ -> Left $ InvalidDisclosureFormat "Invalid object disclosure format"
                else
                  Left $ InvalidDisclosureFormat $ "Disclosure array must have 2 or 3 elements, got " <> T.pack (show len)
        Right _ -> Left $ InvalidDisclosureFormat "Disclosure must be a JSON array"

-- | Encode disclosure to base64url.
--
-- Encodes a 'Disclosure' value to its base64url-encoded string representation.
-- This is the inverse of 'decodeDisclosure'.
encodeDisclosure :: Disclosure -> EncodedDisclosure
encodeDisclosure (DisclosureObject (ObjectDisclosure s n v)) =
  case createObjectDisclosure s n v of
    Left err -> error $ "Failed to encode object disclosure: " ++ show err
    Right encoded -> encoded
encodeDisclosure (DisclosureArray (ArrayDisclosure s v)) =
  case createArrayDisclosure s v of
    Left err -> error $ "Failed to encode array disclosure: " ++ show err
    Right encoded -> encoded

-- | Extract salt from disclosure.
--
-- Returns the salt value used in the disclosure. The salt is the same
-- regardless of whether it's an object or array disclosure.
getDisclosureSalt :: Disclosure -> Salt
getDisclosureSalt (DisclosureObject (ObjectDisclosure s _ _)) = s
getDisclosureSalt (DisclosureArray (ArrayDisclosure s _)) = s

-- | Extract claim name (for object disclosures).
--
-- Returns 'Just' the claim name for object disclosures, or 'Nothing'
-- for array element disclosures (which don't have claim names).
getDisclosureClaimName :: Disclosure -> Maybe T.Text
getDisclosureClaimName (DisclosureObject (ObjectDisclosure _ n _)) = Just n
getDisclosureClaimName (DisclosureArray _) = Nothing

-- | Extract claim value.
--
-- Returns the claim value from the disclosure, regardless of whether
-- it's an object or array disclosure.
getDisclosureValue :: Disclosure -> Aeson.Value
getDisclosureValue (DisclosureObject (ObjectDisclosure _ _ v)) = v
getDisclosureValue (DisclosureArray (ArrayDisclosure _ v)) = v

