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
-- == Decoy Digests
--
-- Decoy digests are optional random digests added to @_sd@ arrays to obscure
-- the actual number of selectively disclosable claims. This is useful for
-- privacy-preserving applications where you want to hide how many claims are
-- selectively disclosable.
--
-- To use decoy digests:
--
-- 1. Build the SD-JWT payload using 'buildSDJWTPayload'
-- 2. Generate decoy digests using 'addDecoyDigest'
-- 3. Manually add them to the @_sd@ array in the payload
-- 4. Sign the modified payload
--
-- Example:
--
-- @
-- -- Build the initial payload
-- (payload, disclosures) <- buildSDJWTPayload SHA256 ["given_name", "email"] claims
-- 
-- -- Generate decoy digests
-- decoy1 <- addDecoyDigest SHA256
-- decoy2 <- addDecoyDigest SHA256
-- 
-- -- Add decoy digests to the _sd array
-- case payloadValue payload of
--   Aeson.Object obj -> do
--     case KeyMap.lookup "_sd" obj of
--       Just (Aeson.Array sdArray) -> do
--         let decoyDigests = [Aeson.String (unDigest decoy1), Aeson.String (unDigest decoy2)]
--         let updatedSDArray = sdArray <> V.fromList decoyDigests
--         let updatedObj = KeyMap.insert "_sd" (Aeson.Array updatedSDArray) obj
--         -- Sign the updated payload...
--       _ -> -- Handle error
--   _ -> -- Handle error
-- @
--
-- During verification, decoy digests that don't match any disclosure are
-- automatically ignored, so they don't affect verification.
--
-- See 'partitionNestedPaths' for detailed JSON Pointer parsing implementation.
module SDJWT.Internal.Issuance
  ( -- * Public API
    createSDJWT
  , createSDJWTWithDecoys
  , addDecoyDigest
  , buildSDJWTPayload
    -- * Internal/Test-only functions
    -- These functions are exported primarily for testing purposes.
    -- Most users should use 'createSDJWT' or 'buildSDJWTPayload' instead.
  , markSelectivelyDisclosable
  , markArrayElementDisclosable
  , processArrayForSelectiveDisclosure
  ) where

import SDJWT.Internal.Types (HashAlgorithm(..), Salt(..), Digest(..), EncodedDisclosure(..), SDJWTPayload(..), SDJWT(..), SDJWTError(..))
import SDJWT.Internal.Utils (generateSalt, hashToBytes, base64urlEncode, splitJSONPointer, unescapeJSONPointer)
import SDJWT.Internal.Digest (computeDigest, hashAlgorithmToText)
import SDJWT.Internal.Disclosure (createObjectDisclosure, createArrayDisclosure)
import SDJWT.Internal.JWT (signJWTWithOptionalTyp, JWKLike)
import qualified Data.Aeson as Aeson
import qualified Data.Aeson.Key as Key
import qualified Data.Aeson.KeyMap as KeyMap
import qualified Data.Map.Strict as Map
import qualified Data.Set as Set
import qualified Data.Text as T
import qualified Data.Vector as V
import Data.List (sortBy, partition)
import Data.Ord (comparing)
import Data.Either (partitionEithers)
import Data.Maybe (mapMaybe)
import Control.Monad (replicateM)

-- | Mark a claim as selectively disclosable.
--
-- This function:
--
-- 1. Generates a salt for the claim
-- 2. Creates a disclosure
-- 3. Computes the digest
-- 4. Returns the digest and encoded disclosure
-- | Mark a single claim as selectively disclosable (advanced/low-level).
--
-- This is a low-level function that processes a single claim. Most users should
-- use 'buildSDJWTPayload' or 'createSDJWT' instead, which handle multiple claims
-- and the full SD-JWT creation process.
--
-- This function:
--
-- 1. Generates a salt for the claim
-- 2. Creates an object disclosure
-- 3. Computes the digest
-- 4. Returns the digest and encoded disclosure
--
-- == Advanced Use
--
-- Only use this function if you need fine-grained control over individual claim
-- processing, such as custom disclosure creation logic or testing.
--
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
--
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

-- | Process an array and mark specific elements as selectively disclosable (advanced/low-level).
--
-- This is a low-level function for processing arrays. Most users should use
-- 'buildSDJWTPayload' or 'createSDJWT', which handle arrays automatically.
--
-- Takes an array and a list of indices to mark as selectively disclosable.
-- Returns the modified array with digests replacing selected elements,
-- along with all disclosures created.
--
-- == Advanced Use
--
-- Only use this function if you need fine-grained control over array processing,
-- such as custom array handling logic or testing.
--
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
--
-- 1. Separates selectively disclosable claims from regular claims
-- 2. Creates disclosures for selectively disclosable claims
-- 3. Computes digests
-- 4. Builds the JSON payload with _sd array containing digests
-- 5. Returns the payload and all disclosures
--
-- Supports nested structures (Section 6.2, 6.3):
--
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
  -- Create singleton lists for each child, then combine lists for same parent
  let nestedByParent = Map.fromListWith (++) $ map (\(p, c) -> (p, c : [])) nestedPaths
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
-- Creates a complete SD-JWT with signed JWT using jose.
--
-- Parameters:
--
-- - mbTyp: Optional typ header value (RFC 9901 Section 9.11 recommends explicit typing).
--   If @Nothing@, no typ header is added. If @Just "sd-jwt"@ or @Just "example+sd-jwt"@,
--   the typ header is included in the JWT header.
-- - hashAlg: Hash algorithm for digests
-- - issuerPrivateKeyJWK: Issuer private key JWK - can be Text (JSON string) or jose JWK object
-- - selectiveClaimNames: Claim names to mark as selectively disclosable
-- - claims: Original claims set
--
-- Returns the created SD-JWT or an error.
--
-- == Example
--
-- @
-- -- Create SD-JWT without typ header
-- result <- createSDJWT Nothing SHA256 issuerKey ["given_name", "family_name"] claims
--
-- -- Create SD-JWT with typ header
-- result <- createSDJWT (Just "sd-jwt") SHA256 issuerKey ["given_name", "family_name"] claims
-- @
--
createSDJWT
  :: JWKLike jwk => Maybe T.Text  -- ^ Optional typ header value (RFC 9901 Section 9.11 recommends explicit typing)
  -> HashAlgorithm
  -> jwk  -- ^ Issuer private key JWK (Text or jose JWK object)
  -> [T.Text]  -- ^ Claim names to mark as selectively disclosable
  -> Map.Map T.Text Aeson.Value  -- ^ Original claims set
  -> IO (Either SDJWTError SDJWT)
createSDJWT mbTyp hashAlg issuerPrivateKeyJWK selectiveClaimNames claims = do
  result <- buildSDJWTPayload hashAlg selectiveClaimNames claims
  case result of
    Left err -> return (Left err)
    Right (payload, sdDisclosures) -> do
      -- Sign the JWT with optional typ header
      signedJWTResult <- signJWTWithOptionalTyp mbTyp issuerPrivateKeyJWK (payloadValue payload)
      case signedJWTResult of
        Left err -> return (Left err)
        Right signedJWT -> return $ Right $ SDJWT
          { issuerSignedJWT = signedJWT
          , disclosures = sdDisclosures
          }

-- | Create an SD-JWT with optional typ header and decoy digests.
--
-- This function is similar to 'createSDJWT' but automatically adds
-- a specified number of decoy digests to the @_sd@ array to obscure the
-- actual number of selectively disclosable claims.
--
-- Parameters:
--
-- - mbTyp: Optional typ header value (e.g., Just "sd-jwt" or Just "example+sd-jwt").
--   If @Nothing@, no typ header is added.
-- - hashAlg: Hash algorithm for digests
-- - issuerPrivateKeyJWK: Issuer private key JWK - can be Text (JSON string) or jose JWK object
-- - selectiveClaimNames: Claim names to mark as selectively disclosable
-- - claims: Original claims set
-- - decoyCount: Number of decoy digests to add (must be >= 0)
--
-- Returns the created SD-JWT or an error.
--
-- == Example
--
-- @
-- -- Create SD-JWT with 5 decoy digests, no typ header
-- result <- createSDJWTWithDecoys Nothing SHA256 issuerKey ["given_name", "email"] claims 5
--
-- -- Create SD-JWT with 5 decoy digests and typ header
-- result <- createSDJWTWithDecoys (Just "sd-jwt") SHA256 issuerKey ["given_name", "email"] claims 5
-- @
--
createSDJWTWithDecoys
  :: JWKLike jwk => Maybe T.Text  -- ^ Optional typ header value
  -> HashAlgorithm
  -> jwk  -- ^ Issuer private key JWK
  -> [T.Text]  -- ^ Claim names to mark as selectively disclosable
  -> Map.Map T.Text Aeson.Value  -- ^ Original claims set
  -> Int  -- ^ Number of decoy digests to add
  -> IO (Either SDJWTError SDJWT)
createSDJWTWithDecoys mbTyp hashAlg issuerPrivateKeyJWK selectiveClaimNames claims decoyCount
  | decoyCount < 0 = return $ Left $ InvalidDisclosureFormat "decoyCount must be >= 0"
  | decoyCount == 0 = createSDJWT mbTyp hashAlg issuerPrivateKeyJWK selectiveClaimNames claims
  | otherwise = do
      -- Build the initial payload
      result <- buildSDJWTPayload hashAlg selectiveClaimNames claims
      case result of
        Left err -> return (Left err)
        Right (payload, sdDisclosures) -> do
          -- Generate decoy digests
          decoys <- replicateM decoyCount (addDecoyDigest hashAlg)
          
          -- Add decoy digests to the _sd array
          case payloadValue payload of
            Aeson.Object obj -> do
              case KeyMap.lookup (Key.fromText "_sd") obj of
                Just (Aeson.Array sdArray) -> do
                  -- Add decoy digests to the array
                  let decoyDigests = map (Aeson.String . unDigest) decoys
                  let updatedSDArray = sdArray <> V.fromList decoyDigests
                  let updatedObj = KeyMap.insert (Key.fromText "_sd") (Aeson.Array updatedSDArray) obj
                  let updatedPayload = payload { payloadValue = Aeson.Object updatedObj }
                  
                  -- Sign the updated payload
                  signedJWTResult <- signJWTWithOptionalTyp mbTyp issuerPrivateKeyJWK (payloadValue updatedPayload)
                  case signedJWTResult of
                    Left err -> return (Left err)
                    Right signedJWT -> return $ Right $ SDJWT
                      { issuerSignedJWT = signedJWT
                      , disclosures = sdDisclosures
                      }
                _ -> return $ Left $ InvalidDisclosureFormat "Payload does not contain _sd array"
            _ -> return $ Left $ InvalidDisclosureFormat "Payload is not an object"

-- | Generate a decoy digest.
--
-- Decoy digests are random digests that don't correspond to any disclosure.
-- They are used to obscure the actual number of selectively disclosable claims.
--
-- According to RFC 9901 Section 4.2.5, decoy digests should be created by
-- hashing over a cryptographically secure random number, then base64url encoding.
--
-- == Advanced Use
--
-- Decoy digests are an advanced feature used to hide the number of selectively
-- disclosable claims. They are optional and must be manually added to the _sd array
-- if you want to obscure the actual number of selectively disclosable claims.
--
-- To use decoy digests, call this function to generate them and manually add
-- them to the _sd array in your payload. This is useful for privacy-preserving
-- applications where you want to hide how many claims are selectively disclosable.
--
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
      let recursiveParentNames = Set.fromList $ map (\(name, _, _) -> name) parentInfo
      let remainingClaims = Map.filterWithKey (\name _ -> not (Set.member name recursiveParentNames)) claims
      
      -- Combine parent and child disclosures (parents first, then children)
      let parentDisclosures = map (\(_, _, disc) -> disc) parentInfo
      let allDisclosures = parentDisclosures ++ allChildDisclosures
      
      return (Right (parentInfo, allDisclosures, remainingClaims))

