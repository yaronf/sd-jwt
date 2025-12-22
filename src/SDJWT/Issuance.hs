{-# LANGUAGE OverloadedStrings #-}
-- | SD-JWT issuance: Creating SD-JWTs from claims sets.
--
-- This module provides functions for creating SD-JWTs on the issuer side.
-- It handles marking claims as selectively disclosable, creating disclosures,
-- computing digests, and building the final signed JWT.
module SDJWT.Issuance
  ( createSDJWT
  , createSDJWTFromClaims
  , markSelectivelyDisclosable
  , markArrayElementDisclosable
  , processArrayForSelectiveDisclosure
  , addDecoyDigest
  , buildSDJWTPayload
  ) where

import SDJWT.Types
import SDJWT.Utils
import SDJWT.Digest
import SDJWT.Disclosure
-- import SDJWT.JWT  -- Will be used when JWK parsing is implemented
import qualified Data.Aeson as Aeson
import qualified Data.Aeson.Key as Key
import qualified Data.Aeson.KeyMap as KeyMap
import qualified Data.Map.Strict as Map
import qualified Data.Text as T
import qualified Data.Vector as V
import qualified Data.ByteString.Lazy as BSL
import qualified Data.ByteString as BS
import qualified Crypto.Hash as Hash
import qualified Data.ByteArray as BA
import Data.List (sortBy)
import Data.Ord (comparing)
import Data.Either (partitionEithers)

-- | Create an SD-JWT from a claims set, marking specified claims as selectively disclosable.
--
-- This is a high-level function that takes:
-- - A list of claim names to mark as selectively disclosable
-- - A hash algorithm (defaults to SHA-256)
-- - A claims set (Map Text Value)
-- - Returns the complete SD-JWT with all disclosures
--
-- Note: This function does not sign the JWT. For signing, use 'createSDJWT'.
createSDJWTFromClaims
  :: HashAlgorithm
  -> [T.Text]  -- ^ Claim names to mark as selectively disclosable
  -> Map.Map T.Text Aeson.Value  -- ^ Original claims set
  -> IO (Either SDJWTError (SDJWTPayload, [EncodedDisclosure]))
createSDJWTFromClaims = buildSDJWTPayload

-- | Mark a claim as selectively disclosable.
--
-- This function:
-- 1. Generates a salt for the claim
-- 2. Creates a disclosure
-- 3. Computes the digest
-- 4. Returns the digest and encoded disclosure
markSelectivelyDisclosable
  :: HashAlgorithm
  -> T.Text  -- ^ Claim name
  -> Aeson.Value  -- ^ Claim value
  -> IO (Either SDJWTError (Digest, EncodedDisclosure))
markSelectivelyDisclosable hashAlg claimName claimValue = do
  saltBytes <- generateSalt
  let salt = Salt saltBytes
  case createObjectDisclosure salt claimName claimValue of
    Left err -> return (Left err)
    Right encodedDisclosure -> do
      let digest = computeDigest hashAlg encodedDisclosure
      return (Right (digest, encodedDisclosure))

-- | Mark an array element as selectively disclosable.
--
-- This function:
-- 1. Generates a salt for the array element
-- 2. Creates an array disclosure (without claim name)
-- 3. Computes the digest
-- 4. Returns the digest and encoded disclosure
--
-- The digest should be embedded in the array as {"...": "<digest>"}
-- at the same position as the original element.
markArrayElementDisclosable
  :: HashAlgorithm
  -> Aeson.Value  -- ^ Array element value
  -> IO (Either SDJWTError (Digest, EncodedDisclosure))
markArrayElementDisclosable hashAlg elementValue = do
  saltBytes <- generateSalt
  let salt = Salt saltBytes
  case createArrayDisclosure salt elementValue of
    Left err -> return (Left err)
    Right encodedDisclosure -> do
      let digest = computeDigest hashAlg encodedDisclosure
      return (Right (digest, encodedDisclosure))

-- | Process an array and mark specific elements as selectively disclosable.
--
-- Takes an array and a list of indices to mark as selectively disclosable.
-- Returns the modified array with digests replacing selected elements,
-- along with all disclosures created.
processArrayForSelectiveDisclosure
  :: HashAlgorithm
  -> V.Vector Aeson.Value  -- ^ Original array
  -> [Int]  -- ^ Indices to mark as selectively disclosable
  -> IO (Either SDJWTError (V.Vector Aeson.Value, [EncodedDisclosure]))
processArrayForSelectiveDisclosure hashAlg arr indices = do
  -- Process each index
  let indexedElements = map (\idx -> (idx, V.unsafeIndex arr idx)) indices
  
  -- Create disclosures for selected elements
  disclosureResults <- mapM (\(idx, val) -> do
    result <- markArrayElementDisclosable hashAlg val
    return $ fmap (\digestDisclosure -> (idx, digestDisclosure)) result
    ) indexedElements
  
  -- Check for errors
  let (errors, successes) = partitionEithers disclosureResults
  case errors of
    (err:_) -> return (Left err)
    [] -> do
      -- Build new array with digests replacing selected elements
      let arrWithDigests = foldl (\acc (idx, (digest, _disclosure)) ->
            let ellipsisObj = Aeson.Object $ KeyMap.fromList
                  [(Key.fromText "...", Aeson.String (unDigest digest))]
            in V.unsafeUpd acc [(idx, ellipsisObj)]
            ) arr successes
      
      let arrayDisclosures = map snd (map snd successes)
      return (Right (arrWithDigests, arrayDisclosures))

-- | Build SD-JWT payload from claims, marking specified claims as selectively disclosable.
--
-- This function:
-- 1. Separates selectively disclosable claims from regular claims
-- 2. Creates disclosures for selectively disclosable claims
-- 3. Computes digests
-- 4. Builds the JSON payload with _sd array containing digests
-- 5. Returns the payload and all disclosures
--
-- Note: This version only handles object properties. For array elements,
-- use the enhanced version with array element specifications.
buildSDJWTPayload
  :: HashAlgorithm
  -> [T.Text]  -- ^ Claim names to mark as selectively disclosable
  -> Map.Map T.Text Aeson.Value  -- ^ Original claims set
  -> IO (Either SDJWTError (SDJWTPayload, [EncodedDisclosure]))
buildSDJWTPayload hashAlg selectiveClaimNames claims = do
  -- Separate selective and regular claims
  let (selectiveClaims, regularClaims) = Map.partitionWithKey
        (\name _ -> name `elem` selectiveClaimNames) claims
  
  -- Create disclosures and digests for selective claims
  disclosureResults <- mapM (uncurry (markSelectivelyDisclosable hashAlg)) (Map.toList selectiveClaims)
  
  -- Check for errors
  let (errors, successes) = partitionEithers disclosureResults
  case errors of
    (err:_) -> return (Left err)
    [] -> do
      let (digests, sdDisclosures) = unzip successes
      
      -- Build the JSON payload
      -- Start with regular claims
      let payloadObj = foldl (\acc (k, v) ->
            KeyMap.insert (Key.fromText k) v acc) KeyMap.empty (Map.toList regularClaims)
      
      -- Add _sd_alg claim
      let payloadWithAlg = KeyMap.insert "_sd_alg" (Aeson.String (hashAlgorithmToText hashAlg)) payloadObj
      
      -- Add _sd array with digests (sorted for determinism)
      let sortedDigests = map (Aeson.String . unDigest) (sortDigests digests)
      let payloadWithSD = KeyMap.insert "_sd" (Aeson.Array (V.fromList sortedDigests)) payloadWithAlg
      
      -- Create SDJWTPayload
      let payload = SDJWTPayload
            { sdAlg = Just hashAlg
            , payloadValue = Aeson.Object payloadWithSD
            }
      
      return (Right (payload, sdDisclosures))

-- | Create a complete SD-JWT (signed).
--
-- This function creates an SD-JWT and signs it using the issuer's key.
-- For now, this is a placeholder that returns the unsigned JWT.
-- Full JWT signing will be implemented when integrating with jose-jwt.
createSDJWT
  :: HashAlgorithm
  -> [T.Text]  -- ^ Claim names to mark as selectively disclosable
  -> Map.Map T.Text Aeson.Value  -- ^ Original claims set
  -> IO (Either SDJWTError SDJWT)
createSDJWT hashAlg selectiveClaimNames claims = do
  result <- buildSDJWTPayload hashAlg selectiveClaimNames claims
  case result of
    Left err -> return (Left err)
    Right (payload, sdDisclosures) -> do
  
      -- TODO: Sign the JWT using jose-jwt
      -- Note: This requires a proper issuer private key JWK.
      -- For now, we create an unsigned placeholder since JWK parsing is not yet implemented.
      -- When JWK parsing is implemented, replace this with:
      --   signedJWT <- signJWT issuerPrivateKeyJWK (payloadValue payload)
      let jwtPayload = Aeson.encode (payloadValue payload)
      let encodedPayload = base64urlEncode (BSL.toStrict jwtPayload)
      
      -- Create a placeholder JWT: header.payload (unsigned for now)
      -- In a real implementation, this would be: header.payload.signature
      let header = "eyJhbGciOiJSUzI1NiJ9"  -- Placeholder header
      let unsignedJWT = T.concat [header, ".", encodedPayload]
      
      return $ Right $ SDJWT
        { issuerSignedJWT = unsignedJWT
        , disclosures = sdDisclosures
        }

-- | Generate a decoy digest.
--
-- Decoy digests are random digests that don't correspond to any disclosure.
-- They are used to obscure the actual number of selectively disclosable claims.
--
-- According to RFC 9901 Section 4.2.5, decoy digests should be created by
-- hashing over a cryptographically secure random number, then base64url encoding.
addDecoyDigest
  :: HashAlgorithm
  -> IO Digest
addDecoyDigest hashAlg = do
  -- Generate random bytes for the decoy digest
  -- According to RFC 9901, we hash over a cryptographically secure random number
  -- The size doesn't matter much since we're hashing it anyway
  randomBytes <- generateSalt
  
  -- Hash the random bytes using the specified algorithm
  let hashBytes = hashToBytes hashAlg randomBytes
  -- Base64url encode to create the digest
  let digestText = base64urlEncode hashBytes
  return $ Digest digestText

-- Helper function to hash bytes (reused from KeyBinding)
hashToBytes :: HashAlgorithm -> BS.ByteString -> BS.ByteString
hashToBytes SHA256 bs = BA.convert (Hash.hash bs :: Hash.Digest Hash.SHA256)
hashToBytes SHA384 bs = BA.convert (Hash.hash bs :: Hash.Digest Hash.SHA384)
hashToBytes SHA512 bs = BA.convert (Hash.hash bs :: Hash.Digest Hash.SHA512)

-- | Sort digests for deterministic ordering in _sd array.
sortDigests :: [Digest] -> [Digest]
sortDigests = sortBy (comparing unDigest)

