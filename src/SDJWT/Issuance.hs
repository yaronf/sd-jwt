{-# LANGUAGE OverloadedStrings #-}
-- | SD-JWT issuance: Creating SD-JWTs from claims sets.
--
-- This module provides functions for creating SD-JWTs on the issuer side.
-- It handles marking claims as selectively disclosable, creating disclosures,
-- computing digests, and building the final signed JWT.
--
-- == Nested Structures
--
-- This module supports nested structures (RFC 9901 Sections 6.2 and 6.3) using
-- JSON Pointer syntax (RFC 6901) for specifying nested claim paths.
--
-- === JSON Pointer Syntax
--
-- Nested paths use forward slash (@/@) as a separator:
--
-- @
-- ["address\/street_address", "address\/locality"]
-- @
--
-- This marks @street_address@ and @locality@ within the @address@ object as
-- selectively disclosable.
--
-- === Escaping Special Characters
--
-- JSON Pointer provides escaping for keys containing special characters:
--
-- * @~1@ represents a literal forward slash @/@
-- * @~0@ represents a literal tilde @~@
--
-- Examples:
--
-- * @["contact~1email"]@ → marks the literal key @"contact\/email"@ as selectively disclosable
-- * @["user~0name"]@ → marks the literal key @"user~name"@ as selectively disclosable
-- * @["address\/email"]@ → marks @email@ within @address@ object as selectively disclosable
--
-- === Nested Structure Patterns
--
-- The module supports two patterns for nested structures:
--
-- 1. /Structured SD-JWT/ (Section 6.2): Parent object stays in payload with @_sd@ array
--    containing digests for sub-claims.
--
-- 2. /Recursive Disclosures/ (Section 6.3): Parent is selectively disclosable, and its
--    disclosure contains an @_sd@ array with digests for sub-claims.
--
-- The pattern is automatically detected based on whether the parent claim is also
-- in the selective claims list.
--
-- === Examples
--
-- Structured SD-JWT (Section 6.2):
--
-- @
-- buildSDJWTPayload SHA256 ["address\/street_address", "address\/locality"] claims
-- @
--
-- This creates a payload where @address@ object contains an @_sd@ array.
--
-- Recursive Disclosures (Section 6.3):
--
-- @
-- buildSDJWTPayload SHA256 ["address", "address\/street_address", "address\/locality"] claims
-- @
--
-- This creates a payload where @address@ digest is in top-level @_sd@, and the
-- @address@ disclosure contains an @_sd@ array with sub-claim digests.
--
-- See 'partitionNestedPaths' for detailed JSON Pointer parsing implementation.
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
import SDJWT.Utils (generateSalt, hashToBytes, base64urlEncode, splitJSONPointer, unescapeJSONPointer)
import SDJWT.Digest
import SDJWT.Disclosure
import SDJWT.JWT
import qualified Data.Aeson as Aeson
import qualified Data.Aeson.Key as Key
import qualified Data.Aeson.KeyMap as KeyMap
import qualified Data.Map.Strict as Map
import qualified Data.Set as Set
import qualified Data.Text as T
import qualified Data.Vector as V
import qualified Data.ByteString as BS
import Data.List (sortBy, partition)
import Data.Ord (comparing)
import Data.Either (partitionEithers)
import Data.Maybe (mapMaybe)

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
-- Supports nested structures (Section 6.2, 6.3):
-- - Use JSON Pointer syntax for nested paths: ["address/street_address", "address/locality"]
-- - For Section 6.2 (structured): parent object stays, sub-claims get _sd array within parent
-- - For Section 6.3 (recursive): parent is selectively disclosable, disclosure contains _sd array
buildSDJWTPayload
  :: HashAlgorithm
  -> [T.Text]  -- ^ Claim names to mark as selectively disclosable (supports JSON Pointer syntax for nested paths, see 'partitionNestedPaths')
  -> Map.Map T.Text Aeson.Value  -- ^ Original claims set
  -> IO (Either SDJWTError (SDJWTPayload, [EncodedDisclosure]))
buildSDJWTPayload hashAlg selectiveClaimNames claims = do
  -- Group claims by nesting level (top-level vs nested)
  let (topLevelClaims, nestedPaths) = partitionNestedPaths selectiveClaimNames
  
  -- Group nested paths by parent to detect recursive disclosures (Section 6.3)
  let nestedByParent = Map.fromListWith (++) $ map (\(p, c) -> (p, [c])) nestedPaths
  let recursiveParents = Map.keysSet nestedByParent `Set.intersection` Set.fromList topLevelClaims
  
  -- Separate recursive disclosures (Section 6.3) from structured disclosures (Section 6.2)
  let (recursivePaths, structuredPaths) = partition (\(p, _) -> Set.member p recursiveParents) nestedPaths
  
  -- Process structured nested structures first (Section 6.2: structured SD-JWT)
  structuredResults <- processNestedStructures hashAlg structuredPaths claims
  
  -- Check for errors in structured processing
  case structuredResults of
    Left err -> return (Left err)
    Right (structuredPayload, structuredDisclosures, remainingClaimsAfterStructured) -> do
      -- Process recursive disclosures (Section 6.3)
      recursiveResults <- processRecursiveDisclosures hashAlg recursivePaths remainingClaimsAfterStructured
      
      case recursiveResults of
        Left err -> return (Left err)
        Right (recursiveParentInfo, recursiveDisclosures, remainingClaimsAfterRecursive) -> do
          -- Process remaining top-level selectively disclosable claims (excluding recursive parents)
          let topLevelClaimsWithoutRecursive = filter (`Set.notMember` recursiveParents) topLevelClaims
          let (selectiveClaims, regularClaims) = Map.partitionWithKey
                (\name _ -> name `elem` topLevelClaimsWithoutRecursive) remainingClaimsAfterRecursive
          
          -- Create disclosures and digests for top-level selective claims
          disclosureResults <- mapM (uncurry (markSelectivelyDisclosable hashAlg)) (Map.toList selectiveClaims)
          
          -- Check for errors
          let (errors, successes) = partitionEithers disclosureResults
          case errors of
            (err:_) -> return (Left err)
            [] -> do
              let (topLevelDigests, topLevelDisclosures) = unzip successes
              
              -- Extract recursive parent digests
              let recursiveParentDigests = map (\(_, digest, _) -> digest) recursiveParentInfo
              
              -- Combine all disclosures (structured + recursive + top-level)
              let allDisclosures = structuredDisclosures ++ recursiveDisclosures ++ topLevelDisclosures
              
              -- Combine all digests (recursive parents + top-level)
              let allDigests = recursiveParentDigests ++ topLevelDigests
              
              -- Build the JSON payload
              -- Start with regular claims (including processed structured nested structures)
              let payloadObj = foldl (\acc (k, v) ->
                    KeyMap.insert (Key.fromText k) v acc) structuredPayload (Map.toList regularClaims)
              
              -- Add _sd_alg claim
              let payloadWithAlg = KeyMap.insert "_sd_alg" (Aeson.String (hashAlgorithmToText hashAlg)) payloadObj
              
              -- Add _sd array with digests (sorted for determinism) if there are any digests
              let finalPayload = if null allDigests
                    then payloadWithAlg
                    else let sortedDigests = map (Aeson.String . unDigest) (sortDigests allDigests)
                         in KeyMap.insert "_sd" (Aeson.Array (V.fromList sortedDigests)) payloadWithAlg
              
              -- Create SDJWTPayload
              let payload = SDJWTPayload
                    { sdAlg = Just hashAlg
                    , payloadValue = Aeson.Object finalPayload
                    }
              
              return (Right (payload, allDisclosures))

-- | Create a complete SD-JWT (signed).
--
-- This function creates an SD-JWT and signs it using the issuer's key.
-- Creates a complete SD-JWT with signed JWT using jose-jwt.
createSDJWT
  :: HashAlgorithm
  -> T.Text  -- ^ Issuer private key JWK (JSON format)
  -> [T.Text]  -- ^ Claim names to mark as selectively disclosable
  -> Map.Map T.Text Aeson.Value  -- ^ Original claims set
  -> IO (Either SDJWTError SDJWT)
createSDJWT hashAlg issuerPrivateKeyJWK selectiveClaimNames claims = do
  result <- buildSDJWTPayload hashAlg selectiveClaimNames claims
  case result of
    Left err -> return (Left err)
    Right (payload, sdDisclosures) -> do
      -- Sign the JWT using jose-jwt
      signedJWTResult <- signJWT issuerPrivateKeyJWK (payloadValue payload)
      case signedJWTResult of
        Left err -> return (Left err)
        Right signedJWT -> return $ Right $ SDJWT
          { issuerSignedJWT = signedJWT
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

-- | Sort digests for deterministic ordering in _sd array.
sortDigests :: [Digest] -> [Digest]
sortDigests = sortBy (comparing unDigest)

-- | Partition claim names into top-level and nested paths.
--
-- Nested paths use JSON Pointer syntax (RFC 6901) with forward slash as separator.
-- Examples:
--   - "address/street_address" → parent="address", child="street_address"
--   - "user/profile/email" → parent="user/profile", child="email" (only supports 2-level nesting currently)
--
-- Escaping (RFC 6901):
--   - "~1" represents a literal forward slash "/"
--   - "~0" represents a literal tilde "~"
-- Examples:
--   - "contact~1email" → literal key "contact/email" (not a nested path)
--   - "user~0name" → literal key "user~name" (not a nested path)
--
-- Note: Only single-level nesting is currently supported (parent/child).
-- For deeper nesting, use multiple calls or extend the API.
partitionNestedPaths :: [T.Text] -> ([T.Text], [(T.Text, T.Text)])
partitionNestedPaths claimNames =
  let (topLevel, nested) = partition (not . T.isInfixOf "/") claimNames
      nestedPaths = mapMaybe parseJSONPointerPath nested
      -- Unescape top-level claim names (they may contain ~0 or ~1)
      unescapedTopLevel = map unescapeJSONPointer topLevel
  in (unescapedTopLevel, nestedPaths)
  where
    -- Parse a JSON Pointer path, handling escaping
    -- Returns Nothing if invalid, Just (parent, child) if valid nested path
    parseJSONPointerPath :: T.Text -> Maybe (T.Text, T.Text)
    parseJSONPointerPath path = do
      -- Split by "/" but handle escaped slashes
      let segments = splitJSONPointer path
      case segments of
        [parent, child] -> Just (unescapeJSONPointer parent, unescapeJSONPointer child)
        _ -> Nothing  -- Only support 2-level nesting (parent/child) for now

-- | Process nested structures (Section 6.2: structured SD-JWT).
-- Creates _sd arrays within parent objects for sub-claims.
-- Returns: (processed payload object, all disclosures, remaining unprocessed claims)
processNestedStructures
  :: HashAlgorithm
  -> [(T.Text, T.Text)]  -- ^ List of (parent, child) claim paths
  -> Map.Map T.Text Aeson.Value  -- ^ Original claims set
  -> IO (Either SDJWTError (KeyMap.KeyMap Aeson.Value, [EncodedDisclosure], Map.Map T.Text Aeson.Value))
processNestedStructures hashAlg nestedPaths claims = do
  -- Group nested paths by parent
  let groupedByParent = Map.fromListWith (++) $ map (\(p, c) -> (p, [c])) nestedPaths
  
  -- Process each parent object
  results <- mapM (\(parentName, childNames) -> do
    case Map.lookup parentName claims of
      Nothing -> return $ Left $ InvalidDisclosureFormat $ "Parent claim not found: " <> parentName
      Just (Aeson.Object parentObj) -> do
        -- Extract child claims from parent object
        let childClaims = mapMaybe (\childName -> do
              let childKey = Key.fromText childName
              childValue <- KeyMap.lookup childKey parentObj
              return (childName, childValue)
              ) childNames
        
        -- Create disclosures for child claims
        disclosureResults <- mapM (\(childName, childValue) ->
          markSelectivelyDisclosable hashAlg childName childValue) childClaims
        
        -- Check for errors
        let (errors, successes) = partitionEithers disclosureResults
        case errors of
          (err:_) -> return $ Left err
          [] -> do
            let (childDigests, childDisclosures) = unzip successes
            
            -- Build new parent object with _sd array
            -- Keep all keys except the selectively disclosable children
            let childKeysToRemove = map Key.fromText childNames
            let regularChildren = KeyMap.filterWithKey (\k _ -> not (k `elem` childKeysToRemove)) parentObj
            
            -- Add _sd array with sorted digests
            let sortedChildDigests = map (Aeson.String . unDigest) (sortDigests childDigests)
            let parentWithSD = KeyMap.insert "_sd" (Aeson.Array (V.fromList sortedChildDigests)) regularChildren
            
            return $ Right (parentName, Aeson.Object parentWithSD, childDisclosures)
      Just _ -> return $ Left $ InvalidDisclosureFormat $ "Parent claim is not an object: " <> parentName
    ) (Map.toList groupedByParent)
  
  -- Check for errors
  let (errors, successes) = partitionEithers results
  case errors of
    (err:_) -> return (Left err)
    [] -> do
      -- Build processed payload object
      let processedParents = Map.fromList $ map (\(name, obj, _) -> (name, obj)) successes
      let allDisclosures = concatMap (\(_, _, childDisclosures) -> childDisclosures) successes
      
      -- Remove processed parents from remaining claims
      let remainingClaims = Map.filterWithKey (\name _ -> not (Map.member name processedParents)) claims
      
      -- Convert processed parents to KeyMap
      let processedPayload = foldl (\acc (name, obj) ->
            KeyMap.insert (Key.fromText name) obj acc) KeyMap.empty (Map.toList processedParents)
      
      return (Right (processedPayload, allDisclosures, remainingClaims))

-- | Process recursive disclosures (Section 6.3: recursive disclosures).
-- Creates disclosures for parent claims where the disclosure value contains
-- an _sd array with digests for sub-claims.
-- Returns: (parent digests and disclosures with recursive structure, all disclosures including children, remaining unprocessed claims)
processRecursiveDisclosures
  :: HashAlgorithm
  -> [(T.Text, T.Text)]  -- ^ List of (parent, child) claim paths for recursive disclosures
  -> Map.Map T.Text Aeson.Value  -- ^ Original claims set
  -> IO (Either SDJWTError ([(T.Text, Digest, EncodedDisclosure)], [EncodedDisclosure], Map.Map T.Text Aeson.Value))
processRecursiveDisclosures hashAlg recursivePaths claims = do
  -- Group recursive paths by parent
  let groupedByParent = Map.fromListWith (++) $ map (\(p, c) -> (p, [c])) recursivePaths
  
  -- Process each recursive parent
  results <- mapM (\(parentName, childNames) -> do
    case Map.lookup parentName claims of
      Nothing -> return $ Left $ InvalidDisclosureFormat $ "Parent claim not found: " <> parentName
      Just (Aeson.Object parentObj) -> do
        -- Extract child claims from parent object
        let childClaims = mapMaybe (\childName -> do
              let childKey = Key.fromText childName
              childValue <- KeyMap.lookup childKey parentObj
              return (childName, childValue)
              ) childNames
        
        -- Create disclosures for child claims first
        childDisclosureResults <- mapM (\(childName, childValue) ->
          markSelectivelyDisclosable hashAlg childName childValue) childClaims
        
        -- Check for errors
        let (errors, childSuccesses) = partitionEithers childDisclosureResults
        case errors of
          (err:_) -> return $ Left err
          [] -> do
            let (childDigests, childDisclosures) = unzip childSuccesses
            
            -- Build parent disclosure value: object with _sd array containing child digests
            let sortedChildDigests = map (Aeson.String . unDigest) (sortDigests childDigests)
            let parentDisclosureValue = Aeson.Object $ KeyMap.fromList
                  [("_sd", Aeson.Array (V.fromList sortedChildDigests))]
            
            -- Create disclosure for parent claim with recursive structure
            parentResult <- markSelectivelyDisclosable hashAlg parentName parentDisclosureValue
            
            case parentResult of
              Left err -> return $ Left err
              Right (parentDigest, parentDisclosure) -> do
                -- Return parent name, digest, disclosure, and all child disclosures
                return $ Right (parentName, parentDigest, parentDisclosure, childDisclosures)
      Just _ -> return $ Left $ InvalidDisclosureFormat $ "Parent claim is not an object: " <> parentName
    ) (Map.toList groupedByParent)
  
  -- Check for errors
  let (errors, successes) = partitionEithers results
  case errors of
    (err:_) -> return (Left err)
    [] -> do
      -- Extract parent info and all child disclosures
      let parentInfo = map (\(name, digest, disc, _) -> (name, digest, disc)) successes
      let allChildDisclosures = concatMap (\(_, _, _, childDiscs) -> childDiscs) successes
      
      -- Remove recursive parents from remaining claims (they're now in disclosures)
      let recursiveParentNames = Set.fromList $ map (\(name, _, _, _) -> name) successes
      let remainingClaims = Map.filterWithKey (\name _ -> not (Set.member name recursiveParentNames)) claims
      
      -- Combine parent and child disclosures (parents first, then children)
      let parentDisclosures = map (\(_, _, disc) -> disc) parentInfo
      let allDisclosures = parentDisclosures ++ allChildDisclosures
      
      return (Right (parentInfo, allDisclosures, remainingClaims))

