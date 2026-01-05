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
-- Nested paths use forward slash (@/@) as a separator. Paths can refer to both
-- object properties and array elements:
--
-- @
-- -- Object properties
-- ["address\/street_address", "address\/locality"]
-- @
--
-- This marks @street_address@ and @locality@ within the @address@ object as
-- selectively disclosable.
--
-- @
-- -- Array elements
-- ["nationalities\/0", "nationalities\/2"]
-- @
--
-- This marks elements at indices 0 and 2 in the @nationalities@ array as
-- selectively disclosable.
--
-- @
-- -- Mixed object and array paths
-- ["address\/street_address", "nationalities\/1"]
-- @
--
-- === Ambiguity Resolution
--
-- Paths with numeric segments (e.g., @["x\/22"]@) are ambiguous:
-- they could refer to an array element at index 22, or an object property
-- with key @"22"@. The library resolves this ambiguity by checking the actual
-- claim type at runtime:
--
-- * If @x@ is an array → @["x\/22"]@ refers to array element at index 22
-- * If @x@ is an object → @["x\/22"]@ refers to object property @"22"@
--
-- This follows JSON Pointer semantics (RFC 6901) where the path alone doesn't
-- determine the type.
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
-- Array Elements:
--
-- @
-- buildSDJWTPayload SHA256 ["nationalities\/0", "nationalities\/2"] claims
-- @
--
-- This marks array elements at indices 0 and 2 as selectively disclosable.
--
-- Nested Arrays:
--
-- @
-- buildSDJWTPayload SHA256 ["nested_array\/0\/0", "nested_array\/0\/1", "nested_array\/1\/0"] claims
-- @
--
-- This marks nested array elements. The path @["nested_array\/0\/0"]@ refers to
-- element at index 0 of the array at index 0 of @nested_array@.
--
-- Mixed Object and Array Paths:
--
-- @
-- buildSDJWTPayload SHA256 ["address\/street_address", "nationalities\/1"] claims
-- @
--
-- This marks both an object property and an array element as selectively disclosable.
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
  , addHolderKeyToClaims
  ) where

import SDJWT.Internal.Types (HashAlgorithm(..), Salt(..), Digest(..), EncodedDisclosure(..), SDJWTPayload(..), SDJWT(..), SDJWTError(..))
import SDJWT.Internal.Utils (generateSalt, hashToBytes, base64urlEncode, splitJSONPointer, unescapeJSONPointer)
import SDJWT.Internal.Digest (computeDigest, hashAlgorithmToText)
import SDJWT.Internal.Disclosure (createObjectDisclosure, createArrayDisclosure)
import SDJWT.Internal.JWT (signJWTWithHeaders, JWKLike)
import qualified Data.Aeson as Aeson
import qualified Data.Aeson.Key as Key
import qualified Data.Aeson.KeyMap as KeyMap
import qualified Data.Map.Strict as Map
import qualified Data.Set as Set
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import qualified Data.Vector as V
import Data.List (sortBy, partition, find)
import Data.Ord (comparing)
import Text.Read (readMaybe)
import Data.Either (partitionEithers)
import Data.Maybe (mapMaybe)
import Control.Monad (replicateM)

-- | Mark a claim as selectively disclosable (internal use only).
--
-- This function only works for object claims (JSON objects), not for array elements.
-- It's used internally by 'buildSDJWTPayload' and 'processNestedStructures'.
-- External users should use 'buildSDJWTPayload' or 'createSDJWT' with JSON Pointer paths.
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

-- | Mark an array element as selectively disclosable (internal use only).
--
-- This function is used internally by 'processArrayForSelectiveDisclosure'.
-- External users should use 'buildSDJWTPayload' or 'createSDJWT' with JSON Pointer paths
-- like ["nested_array/0/0"] instead.
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

-- | Partition nested paths by actual claim type (array vs object).
--
-- Recursively checks the actual type of each segment in the path to determine
-- if segments refer to array elements (by index) or object properties (by key).
-- 
-- Note: "x/22" is ambiguous - it could be array index 22 or object key "22".
-- This function resolves the ambiguity by checking the actual claim type.
--
-- Returns: (array paths with indices, object paths with segments)
-- Array paths: [(claimName, [indices])] - e.g., [("nested_array", [0, 1])] for "nested_array/0/1"
-- Object paths: [[segments]] - e.g., [["user", "profile", "email"]]
partitionPathsByType
  :: [[T.Text]]  -- ^ Nested paths as segments
  -> Map.Map T.Text Aeson.Value  -- ^ Claims to check types
  -> IO ([(T.Text, [Int])], [[T.Text]])  -- ^ (array paths (claim, indices), object paths (segments))
partitionPathsByType nestedPaths claims = do
  results <- mapM (\segments -> partitionPathByType segments claims) nestedPaths
  let (arrayPaths, objectPaths) = partitionEithers results
  return (arrayPaths, objectPaths)
  where
    -- Recursively check a path and determine if it's an array path or object path
    -- For paths like "nested_array/0/1", we collect consecutive array indices: ("nested_array", [0, 1])
    -- For paths like "user/profile/email", we return the full path: ["user", "profile", "email"]
    partitionPathByType :: [T.Text] -> Map.Map T.Text Aeson.Value -> IO (Either (T.Text, [Int]) [T.Text])
    partitionPathByType [] _ = return $ Right []  -- Empty path (shouldn't happen)
    partitionPathByType [single] _ = return $ Right [single]  -- Single segment (shouldn't happen, but handle gracefully)
    partitionPathByType (claimName:rest) claims = do
      case Map.lookup claimName claims of
        Just (Aeson.Array arr) -> do
          -- First segment is an array - collect consecutive numeric indices
          let (indices, remaining) = collectArrayIndices rest
          if null indices
            then return $ Right (claimName:rest)  -- No numeric indices, treat as object path
            else do
              -- Check if there are remaining segments (deeper nesting)
              case remaining of
                [] -> return $ Left (claimName, indices)  -- Pure array path
                _ -> do
                  -- There are remaining segments - check if the element at the last index is an array
                  let lastIdx = last indices
                  if lastIdx >= 0 && lastIdx < V.length arr
                    then case V.unsafeIndex arr lastIdx of
                           Aeson.Array _ -> do
                             -- Element is an array - recursively process remaining segments
                             let nestedClaims = Map.singleton "temp" (V.unsafeIndex arr lastIdx)
                             nestedResult <- partitionPathByType remaining nestedClaims
                             case nestedResult of
                               Left (_, nestedIndices) -> return $ Left (claimName, indices ++ nestedIndices)
                               Right _ -> return $ Left (claimName, indices)  -- Fallback to current level
                           _ -> return $ Right (claimName:rest)  -- Element is not an array, treat as object path
                    else return $ Right (claimName:rest)  -- Invalid index
        Just (Aeson.Object _) -> do
          -- First segment is an object - continue as object path
          return $ Right (claimName:rest)
        _ -> do
          -- Unknown type or not found - default to object path (will error later if invalid)
          return $ Right (claimName:rest)
    
    -- Collect consecutive numeric segments from the start of a path
    collectArrayIndices :: [T.Text] -> ([Int], [T.Text])
    collectArrayIndices segments = go segments []
      where
        go [] acc = (reverse acc, [])
        go (seg:rest) acc = case readMaybe (T.unpack seg) :: Maybe Int of
          Just idx -> go rest (idx:acc)
          Nothing -> (reverse acc, seg:rest)

-- | Process arrays from JSON Pointer paths.
--
-- Takes array paths (claim name, indices) and processes the specified array elements
-- as selectively disclosable. Only handles paths where the top-level claim is an array.
-- Supports nested arrays (arrays within arrays), e.g., ("nested_array", [0, 1]) for
-- "nested_array/0/1". Paths that traverse through objects are handled separately by
-- 'processNestedStructures'. Groups paths by claim name and processes each array recursively.
processArraysFromPaths
  :: HashAlgorithm
  -> [(T.Text, [Int])]  -- ^ Array paths (claim name, indices) - e.g., ("nested_array", [0, 1])
  -> Map.Map T.Text Aeson.Value  -- ^ Original claims
  -> IO (Either SDJWTError (Map.Map T.Text Aeson.Value, [EncodedDisclosure]))
processArraysFromPaths hashAlg arrayPaths claims = do
  -- Group array paths by claim name
  let groupedByClaim = Map.fromListWith (++) $ map (\(claim, indices) -> (claim, [indices])) arrayPaths
  
  -- Process each array claim
  results <- mapM (\(claimName, indicesList) -> do
    case Map.lookup claimName claims of
      Nothing -> return $ Left $ InvalidDisclosureFormat $ "Array claim not found: " <> claimName
      Just (Aeson.Array arr) -> do
        -- Group paths by their first index to process nested arrays together
        -- For example, [0,0] and [0,1] both start with 0, so process inner array at 0 with [0,1] together
        let groupByFirstIndex :: [[Int]] -> Map.Map Int [[Int]]
            groupByFirstIndex = Map.fromListWith (++) . map (\path -> case path of
              [] -> (error "Empty path", [])
              (first:rest) -> (first, [rest]))
        
        -- Process each group of paths that share the same first index
        let groupedPaths = groupByFirstIndex indicesList
        groupResults <- mapM (\(firstIdx, restPaths) -> do
          if null restPaths || all null restPaths
            then do
              -- Single-level path (e.g., [0]) - process directly
              processArrayForSelectiveDisclosure hashAlg arr [firstIdx]
            else do
              -- Nested paths (e.g., [0,0] and [0,1]) - process inner array first with all inner indices
              case arr V.!? firstIdx of
                Just (Aeson.Array innerArr) -> do
                  -- Collect all inner indices from restPaths
                  let innerIndices = concat restPaths
                  -- Process inner array with all inner indices at once
                  innerResult <- processArrayForSelectiveDisclosure hashAlg innerArr innerIndices
                  case innerResult of
                    Left err -> return $ Left err
                    Right (modifiedInnerArr, innerDisclosures) -> do
                      -- Replace the element at firstIdx with modified inner array
                      let arrWithModifiedInner = arr V.// [(firstIdx, Aeson.Array modifiedInnerArr)]
                      -- Now process the outer array at index firstIdx
                      outerResult <- processArrayForSelectiveDisclosure hashAlg arrWithModifiedInner [firstIdx]
                      case outerResult of
                        Left err -> return $ Left err
                        Right (modifiedOuterArr, outerDisclosures) -> do
                          return $ Right (modifiedOuterArr, innerDisclosures ++ outerDisclosures)
                Just _ -> return $ Left $ InvalidDisclosureFormat $ "Expected array at index " <> T.pack (show firstIdx) <> " but found other type"
                Nothing -> return $ Left $ InvalidDisclosureFormat $ "Index " <> T.pack (show firstIdx) <> " out of bounds"
          ) (Map.toList groupedPaths)
        
        let (errors, successes) = partitionEithers groupResults
        case errors of
          (err:_) -> return $ Left err
          [] -> do
            -- Merge all modified arrays: for each index, if any array has an ellipsis object, use it
            let (modifiedArrays, allDisclosures) = unzip successes
            let mergeArrays :: [V.Vector Aeson.Value] -> V.Vector Aeson.Value
                mergeArrays [] = arr  -- Shouldn't happen, but fallback to original
                mergeArrays [single] = single
                mergeArrays arrays = 
                  -- For each index, check if any array has an ellipsis object
                  V.generate (V.length arr) (\idx ->
                    -- Check if any modified array has an ellipsis object at this index
                    case find (\modArr -> 
                      idx < V.length modArr &&
                      case modArr V.!? idx of
                        Just (Aeson.Object obj) -> KeyMap.member (Key.fromText "...") obj
                        _ -> False) arrays of
                      Just modArr -> modArr V.! idx  -- Use ellipsis object from this array
                      Nothing -> 
                        -- No ellipsis object at this index, use original value
                        arr V.! idx)
            let finalArray = mergeArrays modifiedArrays
            let combinedDisclosures = concat allDisclosures
            return $ Right (claimName, Aeson.Array finalArray, combinedDisclosures)
      Just _ -> return $ Left $ InvalidDisclosureFormat $ "Claim is not an array: " <> claimName
    ) (Map.toList groupedByClaim)
  
  -- Check for errors
  let (errors, successes) = partitionEithers results
  case errors of
    (err:_) -> return (Left err)
    [] -> do
      -- Build map of modified arrays
      let arrayModifications = Map.fromList $ map (\(name, arr, _) -> (name, arr)) successes
      -- Combine all array disclosures
      let allArrayDisclosures = concatMap (\(_, _, disclosures) -> disclosures) successes
      -- Apply modifications to claims
      let modifiedClaims = Map.foldlWithKey (\acc name arr -> Map.insert name arr acc) claims arrayModifications
      return $ Right (modifiedClaims, allArrayDisclosures)
  where
    -- Recursively process an array path like [0, 1] on an array
    -- For "nested_array/0/1", this processes the inner array first, then the outer
    processArrayPathRecursive :: HashAlgorithm -> V.Vector Aeson.Value -> [Int] -> IO (Either SDJWTError (V.Vector Aeson.Value, [EncodedDisclosure]))
    processArrayPathRecursive hashAlg arr [] = return $ Right (arr, [])  -- No indices, return as-is
    processArrayPathRecursive hashAlg arr [idx] = do
      -- Single index - process this array element
      processArrayForSelectiveDisclosure hashAlg arr [idx]
    processArrayPathRecursive hashAlg arr (idx:rest) = do
      -- Multiple indices - process inner array first, then outer
      if idx >= 0 && idx < V.length arr
        then do
          -- Get the element at this index (should be an array for nested paths)
          case arr V.!? idx of
            Just (Aeson.Array innerArr) -> do
              -- Recursively process inner array first
              innerResult <- processArrayPathRecursive hashAlg innerArr rest
              case innerResult of
                Left err -> return $ Left err
                Right (modifiedInnerArr, innerDisclosures) -> do
                  -- Replace the element at idx with modified inner array
                  let arrWithModifiedInner = arr V.// [(idx, Aeson.Array modifiedInnerArr)]
                  -- Now process the outer array at index idx
                  -- But we need to mark the entire inner array as selectively disclosable
                  -- Actually, we've already processed the inner array, so we just need to mark the outer element
                  outerResult <- processArrayForSelectiveDisclosure hashAlg arrWithModifiedInner [idx]
                  case outerResult of
                    Left err -> return $ Left err
                    Right (modifiedOuterArr, outerDisclosures) -> do
                      return $ Right (modifiedOuterArr, innerDisclosures ++ outerDisclosures)
            Just _ -> return $ Left $ InvalidDisclosureFormat $ "Expected array at index " <> T.pack (show idx) <> " but found other type"
            Nothing -> return $ Left $ InvalidDisclosureFormat $ "Index " <> T.pack (show idx) <> " out of bounds"
        else return $ Left $ InvalidDisclosureFormat $ "Array index " <> T.pack (show idx) <> " out of bounds"

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
  
  -- Process all nested paths together - the recursive function handles arrays and objects at each level
  -- Group nested paths by first segment to detect recursive disclosures (Section 6.3)
  -- A path is recursive if its first segment is also in topLevelClaims
  let getFirstSegment [] = ""
      getFirstSegment (seg:_) = seg
  let recursiveParents = Set.fromList (map getFirstSegment nestedPaths) `Set.intersection` Set.fromList topLevelClaims
  
  -- Separate recursive disclosures (Section 6.3) from structured disclosures (Section 6.2)
  let (recursivePaths, structuredPaths) = partition (\path -> case path of
        [] -> False
        (first:_) -> Set.member first recursiveParents) nestedPaths
  
  -- Process structured nested structures (Section 6.2: structured SD-JWT)
  -- This handles both objects and arrays at each level recursively
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
          -- According to RFC 9901, top-level arrays are treated as object properties
          -- (disclosure format: [salt, claim_name, claim_value])
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
-- Returns the created SD-JWT or an error.
--
-- == Standard JWT Claims
--
-- Standard JWT claims (RFC 7519) can be included in the @claims@ map and will be preserved
-- in the issuer-signed JWT payload. During verification, standard claims like @exp@ and @nbf@
-- are automatically validated if present. See RFC 9901 Section 4.1 for details.
--
-- == Example
--
-- @
-- -- Create SD-JWT without typ header
-- result <- createSDJWT Nothing SHA256 issuerKey ["given_name", "family_name"] claims
--
-- -- Create SD-JWT with typ header
-- result <- createSDJWT (Just "sd-jwt") SHA256 issuerKey ["given_name", "family_name"] claims
--
-- -- Create SD-JWT with expiration time
-- let claimsWithExp = Map.insert "exp" (Aeson.Number (fromIntegral expirationTime)) claims
-- result <- createSDJWT (Just "sd-jwt") SHA256 issuerKey ["given_name"] claimsWithExp
-- @
--
createSDJWT
  :: JWKLike jwk => Maybe T.Text  -- ^ Optional typ header value (RFC 9901 Section 9.11 recommends explicit typing). If @Nothing@, no typ header is added. If @Just "sd-jwt"@ or @Just "example+sd-jwt"@, the typ header is included in the JWT header.
  -> Maybe T.Text  -- ^ Optional kid header value (Key ID for key management). If @Nothing@, no kid header is added.
  -> HashAlgorithm  -- ^ Hash algorithm for digests
  -> jwk  -- ^ Issuer private key JWK (Text or jose JWK object)
  -> [T.Text]  -- ^ Claim names to mark as selectively disclosable
  -> Map.Map T.Text Aeson.Value  -- ^ Original claims set. May include standard JWT claims such as @exp@ (expiration time), @nbf@ (not before), @iss@ (issuer), @sub@ (subject), @iat@ (issued at), etc. These standard claims will be validated during verification if present (see 'SDJWT.Internal.Verification.verifySDJWT').
  -> IO (Either SDJWTError SDJWT)
createSDJWT mbTyp mbKid hashAlg issuerPrivateKeyJWK selectiveClaimNames claims = do
  result <- buildSDJWTPayload hashAlg selectiveClaimNames claims
  case result of
    Left err -> return (Left err)
    Right (payload, sdDisclosures) -> do
      -- Sign the JWT with optional typ and kid headers
      signedJWTResult <- signJWTWithHeaders mbTyp mbKid issuerPrivateKeyJWK (payloadValue payload)
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
-- Returns the created SD-JWT or an error.
--
-- == Standard JWT Claims
--
-- Standard JWT claims (RFC 7519) can be included in the @claims@ map and will be preserved
-- in the issuer-signed JWT payload. During verification, standard claims like @exp@ and @nbf@
-- are automatically validated if present. See RFC 9901 Section 4.1 for details.
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
  :: JWKLike jwk => Maybe T.Text  -- ^ Optional typ header value (e.g., Just "sd-jwt" or Just "example+sd-jwt"). If @Nothing@, no typ header is added.
  -> Maybe T.Text  -- ^ Optional kid header value (Key ID for key management). If @Nothing@, no kid header is added.
  -> HashAlgorithm  -- ^ Hash algorithm for digests
  -> jwk  -- ^ Issuer private key JWK (Text or jose JWK object)
  -> [T.Text]  -- ^ Claim names to mark as selectively disclosable
  -> Map.Map T.Text Aeson.Value  -- ^ Original claims set. May include standard JWT claims such as @exp@ (expiration time), @nbf@ (not before), @iss@ (issuer), @sub@ (subject), @iat@ (issued at), etc. These standard claims will be validated during verification if present (see 'SDJWT.Internal.Verification.verifySDJWT').
  -> Int  -- ^ Number of decoy digests to add (must be >= 0)
  -> IO (Either SDJWTError SDJWT)
createSDJWTWithDecoys mbTyp mbKid hashAlg issuerPrivateKeyJWK selectiveClaimNames claims decoyCount
  | decoyCount < 0 = return $ Left $ InvalidDisclosureFormat "decoyCount must be >= 0"
  | decoyCount == 0 = createSDJWT mbTyp mbKid hashAlg issuerPrivateKeyJWK selectiveClaimNames claims
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
                  
                  -- Sign the updated payload with optional typ and kid headers
                  signedJWTResult <- signJWTWithHeaders mbTyp mbKid issuerPrivateKeyJWK (payloadValue updatedPayload)
                  case signedJWTResult of
                    Left err -> return (Left err)
                    Right signedJWT -> return $ Right $ SDJWT
                      { issuerSignedJWT = signedJWT
                      , disclosures = sdDisclosures
                      }
                _ -> return $ Left $ InvalidDisclosureFormat "Payload does not contain _sd array"
            _ -> return $ Left $ InvalidDisclosureFormat "Payload is not an object"

-- | Add holder's public key to claims as a @cnf@ claim (RFC 7800).
--
-- This convenience function adds the holder's public key to the claims map
-- in the format required by RFC 7800 for key confirmation:
--
-- @
-- {
--   "cnf": {
--     "jwk": "<holderPublicKeyJWK>"
--   }
-- }
-- @
--
-- The @cnf@ claim is used during key binding to prove that the holder
-- possesses the corresponding private key.
--
-- == Example
--
-- @
-- let holderPublicKeyJWK = "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"...\",\"y\":\"...\"}"
-- let claimsWithCnf = addHolderKeyToClaims holderPublicKeyJWK claims
-- result <- createSDJWT (Just "sd-jwt") SHA256 issuerKey ["given_name"] claimsWithCnf
-- @
--
-- == See Also
--
-- * RFC 7800: Proof-of-Possession Key Semantics for JSON Web Tokens (JWT)
-- * RFC 9901 Section 4.3: Key Binding
addHolderKeyToClaims
  :: T.Text  -- ^ Holder's public key as a JWK JSON string
  -> Map.Map T.Text Aeson.Value  -- ^ Original claims map
  -> Map.Map T.Text Aeson.Value  -- ^ Claims map with @cnf@ claim added
addHolderKeyToClaims holderPublicKeyJWK claims =
  let
    -- Parse the JWK JSON string to ensure it's valid JSON
    -- We'll store it as a JSON object value
    jwkValue = case Aeson.eitherDecodeStrict (TE.encodeUtf8 holderPublicKeyJWK) :: Either String Aeson.Value of
      Left _ -> Aeson.String holderPublicKeyJWK  -- If parsing fails, store as string (let verification catch errors)
      Right parsedJWK -> parsedJWK  -- Store as parsed JSON value
    cnfValue = Aeson.Object $ KeyMap.fromList [("jwk", jwkValue)]
  in
    Map.insert "cnf" cnfValue claims

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
--   - "address/street_address" → nested path: ["address", "street_address"]
--   - "nationalities/1" → nested path: ["nationalities", "1"] (could be array index OR object key "1")
--   - "user/profile/email" → nested path: ["user", "profile", "email"]
--   - "nested_array/0/1" → nested path: ["nested_array", "0", "1"]
--
-- Note: The path "x/22" is ambiguous - it could refer to:
--   - Array element at index 22 if "x" is an array
--   - Object property "22" if "x" is an object
-- The actual type is determined when processing the claims (see 'buildSDJWTPayload').
--
-- Escaping (RFC 6901):
--   - "~1" represents a literal forward slash "/"
--   - "~0" represents a literal tilde "~"
-- Examples:
--   - "contact~1email" → literal key "contact/email" (not a nested path)
--   - "user~0name" → literal key "user~name" (not a nested path)
--
-- Returns: (top-level claims, nested paths as list of segments)
partitionNestedPaths :: [T.Text] -> ([T.Text], [[T.Text]])
partitionNestedPaths claimNames =
  let (topLevel, nested) = partition (not . T.isInfixOf "/") claimNames
      nestedPaths = mapMaybe parseJSONPointerPath nested
      -- Unescape top-level claim names (they may contain ~0 or ~1)
      unescapedTopLevel = map unescapeJSONPointer topLevel
  in (unescapedTopLevel, nestedPaths)
  where
    -- Parse a JSON Pointer path, handling escaping
    -- Returns Nothing if invalid, Just [segments] if valid nested path
    -- Supports arbitrary depth: ["a"], ["a", "b"], ["a", "b", "c"], etc.
    parseJSONPointerPath :: T.Text -> Maybe [T.Text]
    parseJSONPointerPath path = do
      -- Split by "/" but handle escaped slashes
      let segments = splitJSONPointer path
      case segments of
        [] -> Nothing  -- Empty path is invalid
        [_] -> Nothing  -- Single segment is top-level, not nested
        _ -> Just (map unescapeJSONPointer segments)  -- Two or more segments = nested path

-- | Process nested structures (Section 6.2: structured SD-JWT).
-- Creates _sd arrays within parent objects for sub-claims, or ellipsis objects in arrays.
-- Supports arbitrary depth paths like ["user", "profile", "email"] or ["user", "emails", "0"].
-- Handles both objects and arrays at each level.
-- Returns: (processed payload object, all disclosures, remaining unprocessed claims)
processNestedStructures
  :: HashAlgorithm
  -> [[T.Text]]  -- ^ List of path segments (e.g., [["user", "profile", "email"]])
  -> Map.Map T.Text Aeson.Value  -- ^ Original claims set
  -> IO (Either SDJWTError (KeyMap.KeyMap Aeson.Value, [EncodedDisclosure], Map.Map T.Text Aeson.Value))
processNestedStructures hashAlg nestedPaths claims = do
  -- Group nested paths by first segment (top-level claim)
  let getFirstSegment [] = ""
      getFirstSegment (seg:_) = seg
  let groupedByTopLevel = Map.fromListWith (++) $ map (\path -> (getFirstSegment path, [path])) nestedPaths
  
  -- Process each top-level claim recursively (can be object or array)
  results <- mapM (\(topLevelName, paths) -> do
    case Map.lookup topLevelName claims of
      Nothing -> return $ Left $ InvalidDisclosureFormat $ "Parent claim not found: " <> topLevelName
      Just topLevelValue -> do
        -- Strip the first segment (topLevelName) from each path before processing
        let strippedPaths = map (\path -> case path of
              [] -> []
              (_:rest) -> rest) paths
        -- Process all paths under this top-level claim (handles both objects and arrays)
        processResult <- processPathsRecursively hashAlg strippedPaths topLevelValue
        case processResult of
          Left err -> return $ Left err
          Right (modifiedValue, disclosures) -> return $ Right (topLevelName, modifiedValue, disclosures)
    ) (Map.toList groupedByTopLevel)
  
  -- Check for errors
  let (errors, successes) = partitionEithers results
  case errors of
    (err:_) -> return (Left err)
    [] -> do
      -- Separate objects and arrays
      let (objects, arrays) = partition (\(_, val, _) -> case val of
            Aeson.Object _ -> True
            _ -> False) successes
      let processedObjects = Map.fromList $ map (\(name, Aeson.Object obj, _) -> (name, obj)) objects
      let processedArrays = Map.fromList $ map (\(name, Aeson.Array arr, _) -> (name, arr)) arrays
      let allDisclosures = concatMap (\(_, _, disclosures) -> disclosures) successes
      
      -- Remove processed parents from remaining claims
      let processedParents = Map.fromList $ map (\(name, _, _) -> (name, ())) successes
      let remainingClaims = Map.filterWithKey (\name _ -> not (Map.member name processedParents)) claims
      
      -- Convert processed objects and arrays to KeyMap
      let processedPayload = foldl (\acc (name, obj) ->
            KeyMap.insert (Key.fromText name) (Aeson.Object obj) acc) KeyMap.empty (Map.toList processedObjects)
      -- Add processed arrays to payload
      let processedPayloadWithArrays = Map.foldlWithKey (\acc name arr ->
            KeyMap.insert (Key.fromText name) (Aeson.Array arr) acc) processedPayload processedArrays
      
      return (Right (processedPayloadWithArrays, allDisclosures, remainingClaims))
  
  where
    -- Helper function to recursively process paths, handling both objects and arrays at each level
    -- This unified function checks the type at each level and handles accordingly
    processPathsRecursively :: HashAlgorithm -> [[T.Text]] -> Aeson.Value -> IO (Either SDJWTError (Aeson.Value, [EncodedDisclosure]))
    processPathsRecursively hashAlg paths value = case value of
      Aeson.Object obj -> processObjectPaths hashAlg paths obj
      Aeson.Array arr -> processArrayPaths hashAlg paths arr
      _ -> return $ Left $ InvalidDisclosureFormat "Cannot process paths in primitive value (not an object or array)"
    
    -- Process paths within an object
    processObjectPaths :: HashAlgorithm -> [[T.Text]] -> KeyMap.KeyMap Aeson.Value -> IO (Either SDJWTError (Aeson.Value, [EncodedDisclosure]))
    processObjectPaths hashAlg paths obj = do
      -- Group paths by their first segment
      let groupedByFirst = Map.fromListWith (++) $ map (\path -> case path of
            [] -> ("", [])
            (first:rest) -> (first, [rest])) paths
      
      -- Process each group
      results <- mapM (\(firstSeg, remainingPaths) -> do
        let firstKey = Key.fromText firstSeg
        case KeyMap.lookup firstKey obj of
          Nothing -> return $ Left $ InvalidDisclosureFormat $ "Path segment not found: " <> firstSeg
          Just nestedValue -> do
            -- Filter out empty paths (this segment is the target)
            let (emptyPaths, nonEmptyPaths) = partition null remainingPaths
            -- If there are remaining paths, the nested value must be an object or array
            typeCheckResult <- if not (null nonEmptyPaths)
              then case nestedValue of
                Aeson.Object _ -> return $ Right ()
                Aeson.Array _ -> return $ Right ()
                _ -> return $ Left $ InvalidDisclosureFormat $ "Path segment is not an object: " <> firstSeg
              else return $ Right ()  -- No remaining paths, value type doesn't matter
            
            case typeCheckResult of
              Left err -> return $ Left err
              Right () -> do
                if null nonEmptyPaths
                  then do
                    -- This segment is the target - mark it as selectively disclosable
                    result <- markSelectivelyDisclosable hashAlg firstSeg nestedValue
                    case result of
                      Left err -> return $ Left err
                      Right (digest, disclosure) -> do
                        -- Replace this key with _sd object
                        -- When marking a claim as selectively disclosable, we replace it with {"_sd": ["digest"]}
                        -- at the same level, not nest it under the original key
                        let updatedObj = KeyMap.delete firstKey obj
                        let sdArray = Aeson.Array (V.fromList [Aeson.String (unDigest digest)])
                        let sdObj = KeyMap.insert "_sd" sdArray KeyMap.empty
                        -- Return the _sd object merged with the updated object (without the original key)
                        return $ Right (KeyMap.union sdObj updatedObj, [disclosure])
                  else do
                    -- Recurse into nested value (could be object or array)
                    nestedResult <- processPathsRecursively hashAlg nonEmptyPaths nestedValue
                    case nestedResult of
                      Left err -> return $ Left err
                      Right (modifiedNestedValue, nestedDisclosures) -> do
                        -- Also handle empty paths (marking this level as selectively disclosable)
                        if null emptyPaths
                          then return $ Right (KeyMap.insert firstKey modifiedNestedValue obj, nestedDisclosures)
                          else do
                            -- Mark this level as selectively disclosable too
                            result <- markSelectivelyDisclosable hashAlg firstSeg modifiedNestedValue
                            case result of
                              Left err -> return $ Left err
                              Right (digest, disclosure) -> do
                                let updatedObj = KeyMap.delete firstKey obj
                                let sdArray = Aeson.Array (V.fromList [Aeson.String (unDigest digest)])
                                let sdObj = KeyMap.insert "_sd" sdArray KeyMap.empty
                                -- Return the _sd object merged with the updated object (without the original key)
                                return $ Right (KeyMap.union sdObj updatedObj, disclosure:nestedDisclosures)
        ) (Map.toList groupedByFirst)
      
      -- Combine results
      let (errors, successes) = partitionEithers results
      case errors of
        (err:_) -> return $ Left err
        [] -> do
          -- Merge all modified objects and combine disclosures
          -- Track which keys were deleted (marked as selectively disclosable)
          let (modifiedObjs, disclosuresList) = unzip successes
          let deletedKeys = Set.fromList $ map (\(firstSeg, _) -> Key.fromText firstSeg) (Map.toList groupedByFirst)
          -- Start with original object and apply all modifications
          -- When merging, combine _sd arrays instead of overwriting them
          -- Also remove keys that were marked as selectively disclosable
          let finalObj = foldl (\acc modifiedObj -> 
                -- Merge modifiedObj into acc, combining _sd arrays if both have them
                KeyMap.foldrWithKey (\k v acc2 -> 
                  if k == Key.fromText "_sd"
                    then case (KeyMap.lookup k acc2, v) of
                      (Just (Aeson.Array existingArr), Aeson.Array newArr) ->
                        -- Combine arrays, removing duplicates and sorting
                        let allDigestsList = V.toList existingArr ++ V.toList newArr
                            allDigests = mapMaybe (\el -> case el of
                                Aeson.String s -> Just s
                                _ -> Nothing
                              ) allDigestsList
                            uniqueDigests = Set.toList $ Set.fromList allDigests
                            sortedDigests = map Aeson.String $ sortBy compare uniqueDigests
                        in KeyMap.insert k (Aeson.Array (V.fromList sortedDigests)) acc2
                      _ -> KeyMap.insert k v acc2
                    else KeyMap.insert k v acc2
                  ) acc modifiedObj) obj modifiedObjs
          -- Remove keys that were marked as selectively disclosable
          let finalObjWithoutDeleted = Set.foldr KeyMap.delete finalObj deletedKeys
          return $ Right (Aeson.Object finalObjWithoutDeleted, concat disclosuresList)
    
    -- Process paths within an array
    -- Paths should have numeric segments representing array indices
    processArrayPaths :: HashAlgorithm -> [[T.Text]] -> V.Vector Aeson.Value -> IO (Either SDJWTError (Aeson.Value, [EncodedDisclosure]))
    processArrayPaths hashAlg paths arr = do
      -- Parse first segment of each path to extract array index
      -- Group paths by first index
      let groupedByFirstIndex = Map.fromListWith (++) $ mapMaybe (\path -> case path of
            [] -> Nothing
            (firstSeg:rest) -> case readMaybe (T.unpack firstSeg) :: Maybe Int of
              Just idx -> Just (idx, [rest])
              Nothing -> Nothing  -- Not a numeric segment, skip (shouldn't happen for array paths)
            ) paths
      
      -- Process each group
      results <- mapM (\(firstIdx, remainingPaths) -> do
        if firstIdx < 0 || firstIdx >= V.length arr
          then return $ Left $ InvalidDisclosureFormat $ "Array index " <> T.pack (show firstIdx) <> " out of bounds"
          else do
            let element = arr V.! firstIdx
            -- Filter out empty paths (this element is the target)
            let (emptyPaths, nonEmptyPaths) = partition null remainingPaths
            
            if null nonEmptyPaths
              then do
                -- This element is the target - mark it as selectively disclosable
                result <- markArrayElementDisclosable hashAlg element
                case result of
                  Left err -> return $ Left err
                  Right (digest, disclosure) -> return $ Right (firstIdx, digest, [disclosure])
              else do
                -- Recurse into nested value (could be object or array)
                nestedResult <- processPathsRecursively hashAlg nonEmptyPaths element
                case nestedResult of
                  Left err -> return $ Left err
                  Right (modifiedNestedValue, nestedDisclosures) -> do
                    -- Mark this element as selectively disclosable (contains nested selective disclosure)
                    outerResult <- markArrayElementDisclosable hashAlg modifiedNestedValue
                    case outerResult of
                      Left err -> return $ Left err
                      Right (digest, outerDisclosure) -> return $ Right (firstIdx, digest, outerDisclosure:nestedDisclosures)
        ) (Map.toList groupedByFirstIndex)
      
      let (errors, successes) = partitionEithers results
      case errors of
        (err:_) -> return $ Left err
        [] -> do
          -- Build modified array with ellipsis objects at specified indices
          let (indices, digests, disclosuresList) = unzip3 successes
          let arrWithDigests = foldl (\acc (idx, digest, _) ->
                let ellipsisObj = Aeson.Object $ KeyMap.fromList
                      [(Key.fromText "...", Aeson.String (unDigest digest))]
                in V.unsafeUpd acc [(idx, ellipsisObj)]
                ) arr (zip3 indices digests (repeat []))
          return $ Right (Aeson.Array arrWithDigests, concat disclosuresList)

-- | Process recursive disclosures (Section 6.3: recursive disclosures).
-- Creates disclosures for parent claims where the disclosure value contains
-- an _sd array with digests for sub-claims.
-- Supports arbitrary depth paths like ["user", "profile", "email"].
-- Returns: (parent digests and disclosures with recursive structure, all disclosures including children, remaining unprocessed claims)
processRecursiveDisclosures
  :: HashAlgorithm
  -> [[T.Text]]  -- ^ List of path segments for recursive disclosures (e.g., [["user", "profile", "email"]])
  -> Map.Map T.Text Aeson.Value  -- ^ Original claims set
  -> IO (Either SDJWTError ([(T.Text, Digest, EncodedDisclosure)], [EncodedDisclosure], Map.Map T.Text Aeson.Value))
processRecursiveDisclosures hashAlg recursivePaths claims = do
  -- Group recursive paths by first segment (top-level claim)
  let getFirstSegment [] = ""
      getFirstSegment (seg:_) = seg
  let groupedByTopLevel = Map.fromListWith (++) $ map (\path -> (getFirstSegment path, [path])) recursivePaths
  
  -- Process each top-level claim recursively
  results <- mapM (\(topLevelName, paths) -> do
    case Map.lookup topLevelName claims of
      Nothing -> return $ Left $ InvalidDisclosureFormat $ "Parent claim not found: " <> topLevelName
      Just (Aeson.Object topLevelObj) -> do
        -- Strip the first segment (topLevelName) from each path before processing
        let strippedPaths = map (\path -> case path of
              [] -> []
              (_:rest) -> rest) paths
        -- Process paths recursively - for recursive disclosures, the parent becomes selectively disclosable
        processResult <- processRecursivePaths hashAlg strippedPaths topLevelObj topLevelName
        case processResult of
          Left err -> return $ Left err
          Right (parentDigest, parentDisclosure, childDisclosures) -> 
            return $ Right (topLevelName, parentDigest, parentDisclosure, childDisclosures)
      Just _ -> return $ Left $ InvalidDisclosureFormat $ "Top-level claim is not an object: " <> topLevelName
    ) (Map.toList groupedByTopLevel)
  
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
  
  where
    -- Helper function to recursively process paths for recursive disclosures
    processRecursivePaths :: HashAlgorithm -> [[T.Text]] -> KeyMap.KeyMap Aeson.Value -> T.Text -> IO (Either SDJWTError (Digest, EncodedDisclosure, [EncodedDisclosure]))
    processRecursivePaths hashAlg paths obj parentName = do
      -- Group paths by their first segment
      let groupedByFirst = Map.fromListWith (++) $ map (\path -> case path of
            [] -> ("", [])
            (first:rest) -> (first, [rest])) paths
      
      -- Process each group
      results <- mapM (\(firstSeg, remainingPaths) -> do
        let firstKey = Key.fromText firstSeg
        case KeyMap.lookup firstKey obj of
          Nothing -> return $ Left $ InvalidDisclosureFormat $ "Path segment not found: " <> firstSeg
          Just (Aeson.Object nestedObj) -> do
            -- Filter out empty paths (this segment is the target)
            let (emptyPaths, nonEmptyPaths) = partition null remainingPaths
            if null nonEmptyPaths
              then do
                -- This segment is the target - mark it as selectively disclosable
                -- Return the digest and disclosure (will be combined into parent _sd array)
                result <- markSelectivelyDisclosable hashAlg firstSeg (Aeson.Object nestedObj)
                case result of
                  Left err -> return $ Left err
                  Right (digest, disclosure) -> return $ Right (digest, disclosure, [])
              else do
                -- Recurse into nested object
                nestedResult <- processRecursivePaths hashAlg nonEmptyPaths nestedObj firstSeg
                case nestedResult of
                  Left err -> return $ Left err
                  Right (childDigest, childDisclosure, grandchildDisclosures) -> do
                    -- Return child digest and disclosure (will be combined into parent _sd array)
                    return $ Right (childDigest, childDisclosure, grandchildDisclosures)
          Just leafValue -> do
            -- Leaf value (string, number, bool, etc.) - this is the target
            -- Check if there are remaining paths (shouldn't happen for leaf values)
            let (emptyPaths, nonEmptyPaths) = partition null remainingPaths
            if not (null nonEmptyPaths)
              then return $ Left $ InvalidDisclosureFormat $ "Cannot traverse into leaf value: " <> firstSeg
              else do
                -- Mark this leaf value as selectively disclosable
                result <- markSelectivelyDisclosable hashAlg firstSeg leafValue
                case result of
                  Left err -> return $ Left err
                  Right (digest, disclosure) -> return $ Right (digest, disclosure, [])
        ) (Map.toList groupedByFirst)
      
      -- Combine results - for recursive disclosures, we need to combine all child digests
      -- into one parent _sd array
      let (errors, successes) = partitionEithers results
      case errors of
        (err:_) -> return $ Left err
        [] -> do
          case successes of
            [] -> return $ Left $ InvalidDisclosureFormat "No paths to process"
            _ -> do
              -- Collect all child digests and disclosures
              -- Each success is (digest, disclosure, grandchildDisclosures)
              -- For leaf children, disclosure is the child disclosure itself
              -- For nested children, disclosure is an intermediate parent, and grandchildDisclosures contains the actual children
              let allChildDigests = map (\(digest, _, _) -> digest) successes
              let allChildDisclosures = concatMap (\(_, disclosure, grandchildDiscs) -> disclosure:grandchildDiscs) successes
              
              -- Create parent disclosure with _sd array containing all child digests
              let sdArray = Aeson.Array (V.fromList $ map (Aeson.String . unDigest) (sortDigests allChildDigests))
              let parentDisclosureValue = Aeson.Object $ KeyMap.fromList [("_sd", sdArray)]
              parentResult <- markSelectivelyDisclosable hashAlg parentName parentDisclosureValue
              case parentResult of
                Left err -> return $ Left err
                Right (parentDigest, parentDisclosure) -> 
                  return $ Right (parentDigest, parentDisclosure, allChildDisclosures)


