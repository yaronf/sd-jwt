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
  , buildSDJWTPayload
  ) where

import SDJWT.Types
import SDJWT.Utils
import SDJWT.Digest
import SDJWT.Disclosure
import qualified Data.Aeson as Aeson
import qualified Data.Aeson.Key as Key
import qualified Data.Aeson.KeyMap as KeyMap
import qualified Data.Map.Strict as Map
import qualified Data.Text as T
import qualified Data.Vector as V
import qualified Data.ByteString.Lazy as BSL
import Control.Monad (foldM)
import Data.Maybe (fromMaybe)
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
createSDJWTFromClaims hashAlg selectiveClaims claims =
  buildSDJWTPayload hashAlg selectiveClaims claims

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

-- | Build SD-JWT payload from claims, marking specified claims as selectively disclosable.
--
-- This function:
-- 1. Separates selectively disclosable claims from regular claims
-- 2. Creates disclosures for selectively disclosable claims
-- 3. Computes digests
-- 4. Builds the JSON payload with _sd array containing digests
-- 5. Returns the payload and all disclosures
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
  disclosureResults <- mapM (\(name, value) ->
    markSelectivelyDisclosable hashAlg name value) (Map.toList selectiveClaims)
  
  -- Check for errors
  let (errors, successes) = partitionEithers disclosureResults
  case errors of
    (err:_) -> return (Left err)
    [] -> do
      let (digests, disclosures) = unzip successes
      
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
      
      return (Right (payload, disclosures))

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
    Right (payload, disclosures) -> do
  
      -- TODO: Sign the JWT using jose-jwt
      -- For now, encode the payload as a JWT (without signing)
      let jwtPayload = Aeson.encode (payloadValue payload)
      let encodedPayload = base64urlEncode (BSL.toStrict jwtPayload)
      
      -- Create a placeholder JWT: header.payload (unsigned for now)
      -- In a real implementation, this would be: header.payload.signature
      let header = "eyJhbGciOiJSUzI1NiJ9"  -- Placeholder header
      let unsignedJWT = T.concat [header, ".", encodedPayload]
      
      return $ Right $ SDJWT
        { issuerSignedJWT = unsignedJWT
        , disclosures = disclosures
        }

-- | Sort digests for deterministic ordering in _sd array.
sortDigests :: [Digest] -> [Digest]
sortDigests = sortBy (comparing unDigest)

