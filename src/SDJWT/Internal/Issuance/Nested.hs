{-# LANGUAGE OverloadedStrings #-}
-- | Nested structure processing for SD-JWT issuance.
--
-- This module handles nested structures according to RFC 9901 Sections 6.2 and 6.3:
--
-- * Section 6.2 (Structured SD-JWT): Parent object stays in payload with @_sd@ array
--   containing digests for sub-claims.
--
-- * Section 6.3 (Recursive Disclosures): Parent is selectively disclosable, and its
--   disclosure contains an @_sd@ array with digests for sub-claims.
--
-- This module is used internally by 'SDJWT.Internal.Issuance' and is not part of the
-- public API.
module SDJWT.Internal.Issuance.Nested
  ( processNestedStructures
  , processRecursiveDisclosures
  ) where

import SDJWT.Internal.Types (HashAlgorithm(..), Digest(..), EncodedDisclosure(..), SDJWTError(..), Salt(..), unDigest)
import SDJWT.Internal.Utils (groupPathsByFirstSegment, generateSalt)
import SDJWT.Internal.Digest (computeDigest)
import SDJWT.Internal.Disclosure (createObjectDisclosure, createArrayDisclosure)
import SDJWT.Internal.Monad (SDJWTIO, runSDJWTIO, partitionAndHandle, eitherToExceptT)
import Control.Monad.Except (throwError)
import Control.Monad.IO.Class (liftIO)
import qualified Data.Aeson as Aeson
import qualified Data.Aeson.Key as Key
import qualified Data.Aeson.KeyMap as KeyMap
import qualified Data.Map.Strict as Map
import qualified Data.Set as Set
import qualified Data.Text as T
import qualified Data.Vector as V
import Data.List (partition, sortBy)
import Data.Maybe (mapMaybe)
import Data.Either (partitionEithers)
import Text.Read (readMaybe)
import Data.Ord (comparing)

-- | Process nested structures (Section 6.2: structured SD-JWT).
-- Creates _sd arrays within parent objects for sub-claims, or ellipsis objects in arrays.
-- Supports arbitrary depth paths like ["user", "profile", "email"] or ["user", "emails", "0"].
-- Handles both objects and arrays at each level.
-- Returns: (processed payload object, all disclosures, remaining unprocessed claims)
processNestedStructures
  :: HashAlgorithm
  -> [[T.Text]]  -- ^ List of path segments (e.g., [["user", "profile", "email"]])
  -> Aeson.Object  -- ^ Original claims object
  -> IO (Either SDJWTError (KeyMap.KeyMap Aeson.Value, [EncodedDisclosure], Aeson.Object))
processNestedStructures hashAlg nestedPaths claims =
  runSDJWTIO $ processNestedStructuresExceptT hashAlg nestedPaths claims

-- | Internal ExceptT version of processNestedStructures.
processNestedStructuresExceptT
  :: HashAlgorithm
  -> [[T.Text]]  -- ^ List of path segments (e.g., [["user", "profile", "email"]])
  -> Aeson.Object  -- ^ Original claims object
  -> SDJWTIO (KeyMap.KeyMap Aeson.Value, [EncodedDisclosure], Aeson.Object)
processNestedStructuresExceptT hashAlg nestedPaths claims = do
  -- Group nested paths by first segment (top-level claim)
  let getFirstSegment [] = ""
      getFirstSegment (seg:_) = seg
  -- Convert to format expected by groupPathsByFirstSegment (list of segments)
  let groupedByTopLevel = Map.fromListWith (++) $ map (\path -> (getFirstSegment path, [path])) nestedPaths
  
  -- Process each top-level claim recursively (can be object or array)
  results <- liftIO $ mapM (\(topLevelName, paths) -> do
    case KeyMap.lookup (Key.fromText topLevelName) claims of
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
  
  -- Check for errors using ExceptT helper
  partitionAndHandle results $ \successes -> do
    -- Separate objects and arrays
    let (objects, arrays) = partition (\(_, val, _) -> case val of
          Aeson.Object _ -> True
          _ -> False) successes
    let processedObjects = Map.fromList $ mapMaybe (\(name, val, _) -> case val of
          Aeson.Object obj -> Just (name, obj)
          _ -> Nothing) objects
    let processedArrays = Map.fromList $ mapMaybe (\(name, val, _) -> case val of
          Aeson.Array arr -> Just (name, arr)
          _ -> Nothing) arrays
    let allDisclosures = concatMap (\(_, _, disclosures) -> disclosures) successes
    
    -- Remove processed parents from remaining claims
    let processedParents = Set.fromList $ map (\(name, _, _) -> name) successes
    let remainingClaims = KeyMap.filterWithKey (\k _ -> Key.toText k `Set.notMember` processedParents) claims
    
    -- Convert processed objects and arrays to KeyMap
    let processedPayload = foldl (\acc (name, obj) ->
          KeyMap.insert (Key.fromText name) (Aeson.Object obj) acc) KeyMap.empty (Map.toList processedObjects)
    -- Add processed arrays to payload
    let processedPayloadWithArrays = Map.foldlWithKey (\acc name arr ->
          KeyMap.insert (Key.fromText name) (Aeson.Array arr) acc) processedPayload processedArrays
    
    return (processedPayloadWithArrays, allDisclosures, remainingClaims)
  
  where
    -- Helper function to recursively process paths, handling both objects and arrays at each level
    -- This unified function checks the type at each level and handles accordingly
    processPathsRecursively :: HashAlgorithm -> [[T.Text]] -> Aeson.Value -> IO (Either SDJWTError (Aeson.Value, [EncodedDisclosure]))
    processPathsRecursively hashAlg' paths value = case value of
      Aeson.Object obj -> processObjectPaths hashAlg' paths obj
      Aeson.Array arr -> processArrayPaths hashAlg' paths arr
      _ -> return $ Left $ InvalidDisclosureFormat "Cannot process paths in primitive value (not an object or array)"
    
    -- Validate that nested value is an object or array if there are remaining paths
    validateNestedValueType :: T.Text -> [[T.Text]] -> Aeson.Value -> Either SDJWTError ()
    validateNestedValueType firstSeg nonEmptyPaths nestedValue =
      if null nonEmptyPaths
        then Right ()  -- No remaining paths, value type doesn't matter
        else case nestedValue of
          Aeson.Object _ -> Right ()
          Aeson.Array _ -> Right ()
          _ -> Left $ InvalidDisclosureFormat $ "Path segment is not an object: " <> firstSeg
    
    -- Mark a segment as selectively disclosable and create _sd object
    markSegmentAsSelectivelyDisclosable
      :: HashAlgorithm
      -> T.Text  -- ^ Segment name
      -> Key.Key  -- ^ Segment key
      -> Aeson.Value  -- ^ Value to mark as SD
      -> KeyMap.KeyMap Aeson.Value  -- ^ Original object
      -> IO (Either SDJWTError (KeyMap.KeyMap Aeson.Value, [EncodedDisclosure]))
    markSegmentAsSelectivelyDisclosable hashAlg' firstSeg firstKey nestedValue obj = do
      result <- markSelectivelyDisclosable hashAlg' firstSeg nestedValue
      case result of
        Left err -> return (Left err)
        Right (digest, disclosure) -> do
          -- Replace this key with _sd object
          -- When marking a claim as selectively disclosable, we replace it with {"_sd": ["digest"]}
          -- at the same level, not nest it under the original key
          let updatedObj = KeyMap.delete firstKey obj
          let sdArray = Aeson.Array (V.fromList [Aeson.String (unDigest digest)])
          let sdObj = KeyMap.insert "_sd" sdArray KeyMap.empty
          -- Return the _sd object merged with the updated object (without the original key)
          return (Right (KeyMap.union sdObj updatedObj, [disclosure]))
    
    -- Process a single path segment (handles both target and nested cases)
    processPathSegment
      :: HashAlgorithm
      -> T.Text  -- ^ First segment name
      -> [[T.Text]]  -- ^ Remaining paths
      -> KeyMap.KeyMap Aeson.Value  -- ^ Original object
      -> Aeson.Value  -- ^ Nested value
      -> IO (Either SDJWTError (KeyMap.KeyMap Aeson.Value, [EncodedDisclosure]))
    processPathSegment hashAlg' firstSeg remainingPaths obj nestedValue = do
      -- Filter out empty paths (this segment is the target)
      let (emptyPaths, nonEmptyPaths) = partition null remainingPaths
      
      -- Validate nested value type if there are remaining paths
      case validateNestedValueType firstSeg nonEmptyPaths nestedValue of
        Left err -> return (Left err)
        Right () -> do
          if null nonEmptyPaths
            then do
              -- This segment is the target - mark it as selectively disclosable
              let firstKey = Key.fromText firstSeg
              markSegmentAsSelectivelyDisclosable hashAlg' firstSeg firstKey nestedValue obj
            else do
              -- Recurse into nested value (could be object or array)
              nestedResult <- processPathsRecursively hashAlg' nonEmptyPaths nestedValue
              case nestedResult of
                Left err -> return (Left err)
                Right (modifiedNestedValue, nestedDisclosures) -> do
                  let firstKey = Key.fromText firstSeg
                  if null emptyPaths
                    then return (Right (KeyMap.insert firstKey modifiedNestedValue obj, nestedDisclosures))
                    else do
                      -- Mark this level as selectively disclosable too
                      result <- markSegmentAsSelectivelyDisclosable hashAlg' firstSeg firstKey modifiedNestedValue obj
                      case result of
                        Left err -> return (Left err)
                        Right (sdObj, parentDisclosure) -> 
                          return (Right (sdObj, parentDisclosure ++ nestedDisclosures))
    
    -- Combine results from processing all path segments
    combineObjectPathResults
      :: KeyMap.KeyMap Aeson.Value  -- ^ Original object
      -> Map.Map T.Text [[T.Text]]  -- ^ Grouped paths
      -> [(KeyMap.KeyMap Aeson.Value, [EncodedDisclosure])]  -- ^ Success results
      -> (KeyMap.KeyMap Aeson.Value, [EncodedDisclosure])
    combineObjectPathResults obj groupedByFirst successes = do
      -- Merge all modified objects and combine disclosures
      -- Track which keys were deleted (marked as selectively disclosable)
      let (modifiedObjs, disclosuresList) = unzip successes
      let deletedKeys = Set.fromList $ map (\(firstSeg, _) -> Key.fromText firstSeg) (Map.toList groupedByFirst)
      -- Start with original object and apply all modifications
      -- When merging, combine _sd arrays instead of overwriting them
      -- Also remove keys that were marked as selectively disclosable
      let finalObj = foldl mergeModifiedObject obj modifiedObjs
      -- Remove keys that were marked as selectively disclosable
      let finalObjWithoutDeleted = Set.foldr KeyMap.delete finalObj deletedKeys
      (finalObjWithoutDeleted, concat disclosuresList)
    
    -- Process paths within an object
    processObjectPaths :: HashAlgorithm -> [[T.Text]] -> KeyMap.KeyMap Aeson.Value -> IO (Either SDJWTError (Aeson.Value, [EncodedDisclosure]))
    processObjectPaths hashAlg' paths obj =
      runSDJWTIO $ processObjectPathsExceptT hashAlg' paths obj

    -- Internal ExceptT version of processObjectPaths.
    processObjectPathsExceptT :: HashAlgorithm -> [[T.Text]] -> KeyMap.KeyMap Aeson.Value -> SDJWTIO (Aeson.Value, [EncodedDisclosure])
    processObjectPathsExceptT hashAlg' paths obj = do
      -- Group paths by their first segment
      let groupedByFirst = groupPathsByFirstSegment paths
      
      -- Process each group
      results <- liftIO $ mapM (\(firstSeg, remainingPaths) -> do
        let firstKey = Key.fromText firstSeg
        case KeyMap.lookup firstKey obj of
          Nothing -> return $ Left $ InvalidDisclosureFormat $ "Path segment not found: " <> firstSeg
          Just nestedValue -> processPathSegment hashAlg' firstSeg remainingPaths obj nestedValue
        ) (Map.toList groupedByFirst)
      
      -- Combine results using ExceptT helper
      partitionAndHandle results $ \successes -> do
        let (finalObj, allDisclosures) = combineObjectPathResults obj groupedByFirst successes
        return (Aeson.Object finalObj, allDisclosures)
    
    -- Helper function to merge a modified object into an accumulator, combining _sd arrays
    mergeModifiedObject :: KeyMap.KeyMap Aeson.Value -> KeyMap.KeyMap Aeson.Value -> KeyMap.KeyMap Aeson.Value
    mergeModifiedObject = KeyMap.foldrWithKey insertOrMergeSD
    
    -- Helper function to insert a key-value pair, merging _sd arrays if present
    insertOrMergeSD :: Key.Key -> Aeson.Value -> KeyMap.KeyMap Aeson.Value -> KeyMap.KeyMap Aeson.Value
    insertOrMergeSD k v acc2
      | k == Key.fromText "_sd" = case (KeyMap.lookup k acc2, v) of
          (Just (Aeson.Array existingArr), Aeson.Array newArr) ->
            -- Combine arrays, removing duplicates and sorting
            let allDigestsList = V.toList existingArr ++ V.toList newArr
                allDigests = mapMaybe extractDigestString allDigestsList
                uniqueDigests = Set.toList $ Set.fromList allDigests
                sortedDigests = map Aeson.String $ sortBy compare uniqueDigests
            in KeyMap.insert k (Aeson.Array (V.fromList sortedDigests)) acc2
          _ -> KeyMap.insert k v acc2
      | otherwise = KeyMap.insert k v acc2
    
    -- Helper function to extract digest strings from Aeson values
    extractDigestString :: Aeson.Value -> Maybe T.Text
    extractDigestString (Aeson.String s) = Just s
    extractDigestString _ = Nothing
    
    -- Process paths within an array
    -- Paths should have numeric segments representing array indices
    processArrayPaths :: HashAlgorithm -> [[T.Text]] -> V.Vector Aeson.Value -> IO (Either SDJWTError (Aeson.Value, [EncodedDisclosure]))
    processArrayPaths hashAlg' paths arr =
      runSDJWTIO $ processArrayPathsExceptT hashAlg' paths arr

    -- Internal ExceptT version of processArrayPaths.
    processArrayPathsExceptT :: HashAlgorithm -> [[T.Text]] -> V.Vector Aeson.Value -> SDJWTIO (Aeson.Value, [EncodedDisclosure])
    processArrayPathsExceptT hashAlg' paths arr = do
      -- Parse first segment of each path to extract array index
      -- Group paths by first index
      let groupedByFirstIndex = Map.fromListWith (++) $ mapMaybe (\path -> case path of
            [] -> Nothing
            (firstSeg:rest) -> case readMaybe (T.unpack firstSeg) :: Maybe Int of
              Just idx -> Just (idx, [rest])
              Nothing -> Nothing  -- Not a numeric segment, skip (shouldn't happen for array paths)
            ) paths
      
      -- Process each group
      results <- liftIO $ mapM (\(firstIdx, remainingPaths) -> do
        if firstIdx < 0 || firstIdx >= V.length arr
          then return $ Left $ InvalidDisclosureFormat $ "Array index " <> T.pack (show firstIdx) <> " out of bounds"
          else do
            let element = arr V.! firstIdx
            -- Filter out empty paths (this element is the target)
            let (_emptyPaths, nonEmptyPaths) = partition null remainingPaths
            
            if null nonEmptyPaths
              then do
                -- This element is the target - mark it as selectively disclosable
                result <- markArrayElementDisclosable hashAlg' element
                case result of
                  Left err -> return $ Left err
                  Right (digest, disclosure) -> 
                    let ellipsisObj = Aeson.Object $ KeyMap.fromList [(Key.fromText "...", Aeson.String (unDigest digest))]
                    in return $ Right (firstIdx, ellipsisObj, [disclosure])
              else do
                -- Recurse into nested value (could be object or array)
                nestedResult <- processPathsRecursively hashAlg' nonEmptyPaths element
                case nestedResult of
                  Left err -> return $ Left err
                  Right (modifiedNestedValue, nestedDisclosures) -> do
                    -- If the modified nested value is still an array, preserve the structure
                    -- (don't mark the entire array as SD, just return it with SD elements inside)
                    case modifiedNestedValue of
                      Aeson.Array _ -> 
                        -- Array structure preserved, return it directly without marking as SD
                        return $ Right (firstIdx, modifiedNestedValue, nestedDisclosures)
                      _ -> do
                        -- For objects or other types, mark as selectively disclosable
                        outerResult <- markArrayElementDisclosable hashAlg' modifiedNestedValue
                        case outerResult of
                          Left err -> return $ Left err
                          Right (digest, outerDisclosure) -> 
                            let ellipsisObj = Aeson.Object $ KeyMap.fromList [(Key.fromText "...", Aeson.String (unDigest digest))]
                            in return $ Right (firstIdx, ellipsisObj, outerDisclosure:nestedDisclosures)
        ) (Map.toList groupedByFirstIndex)
      
      partitionAndHandle results $ \successes -> do
        -- Build modified array with ellipsis objects or modified arrays at specified indices
        let arrWithDigests = foldl (\acc (idx, value, _) ->
              -- value can be either an ellipsis object (from markArrayElementDisclosable) or a modified array
              V.unsafeUpd acc [(idx, value)]
              ) arr successes
        let allDisclosures = concatMap (\(_, _, disclosures) -> disclosures) successes
        return (Aeson.Array arrWithDigests, allDisclosures)
    
    -- Helper function to mark a claim as selectively disclosable
    markSelectivelyDisclosable :: HashAlgorithm -> T.Text -> Aeson.Value -> IO (Either SDJWTError (Digest, EncodedDisclosure))
    markSelectivelyDisclosable hashAlg' claimName claimValue =
      fmap (\saltBytes ->
        let salt = Salt saltBytes
        in case createObjectDisclosure salt claimName claimValue of
             Left err -> Left err
             Right encodedDisclosure ->
               let digest = computeDigest hashAlg' encodedDisclosure
               in Right (digest, encodedDisclosure)
      ) generateSalt
    
    -- Helper function to mark an array element as selectively disclosable
    markArrayElementDisclosable :: HashAlgorithm -> Aeson.Value -> IO (Either SDJWTError (Digest, EncodedDisclosure))
    markArrayElementDisclosable hashAlg' elementValue =
      fmap (\saltBytes ->
        let salt = Salt saltBytes
        in case createArrayDisclosure salt elementValue of
             Left err -> Left err
             Right encodedDisclosure ->
               let digest = computeDigest hashAlg' encodedDisclosure
               in Right (digest, encodedDisclosure)
      ) generateSalt

-- | Process recursive disclosures (Section 6.3: recursive disclosures).
-- Creates disclosures for parent claims where the disclosure value contains
-- an _sd array with digests for sub-claims.
-- Supports arbitrary depth paths like ["user", "profile", "email"].
-- Returns: (parent digests and disclosures with recursive structure, all disclosures including children, remaining unprocessed claims)
processRecursiveDisclosures
  :: HashAlgorithm
  -> [[T.Text]]  -- ^ List of path segments for recursive disclosures (e.g., [["user", "profile", "email"]])
  -> Aeson.Object  -- ^ Original claims object
  -> IO (Either SDJWTError ([(T.Text, Digest, EncodedDisclosure)], [EncodedDisclosure], Aeson.Object))
processRecursiveDisclosures hashAlg recursivePaths claims =
  runSDJWTIO $ processRecursiveDisclosuresExceptT hashAlg recursivePaths claims

-- | Internal ExceptT version of processRecursiveDisclosures.
processRecursiveDisclosuresExceptT
  :: HashAlgorithm
  -> [[T.Text]]  -- ^ List of path segments for recursive disclosures (e.g., [["user", "profile", "email"]])
  -> Aeson.Object  -- ^ Original claims object
  -> SDJWTIO ([(T.Text, Digest, EncodedDisclosure)], [EncodedDisclosure], Aeson.Object)
processRecursiveDisclosuresExceptT hashAlg recursivePaths claims = do
  -- Group recursive paths by first segment (top-level claim)
  let getFirstSegment [] = ""
      getFirstSegment (seg:_) = seg
  let groupedByTopLevel = Map.fromListWith (++) $ map (\path -> (getFirstSegment path, [path])) recursivePaths
  
  -- Process each top-level claim recursively
  results <- liftIO $ mapM (\(topLevelName, paths) -> do
    case KeyMap.lookup (Key.fromText topLevelName) claims of
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
  
  -- Check for errors using ExceptT helper
  partitionAndHandle results $ \successes -> do
    -- Extract parent info and all child disclosures
    let parentInfo = map (\(name, digest, disc, _) -> (name, digest, disc)) successes
    let allChildDisclosures = concatMap (\(_, _, _, childDiscs) -> childDiscs) successes
    
    -- Remove recursive parents from remaining claims (they're now in disclosures)
    let recursiveParentNames = Set.fromList $ map (\(name, _, _) -> name) parentInfo
    let remainingClaims = KeyMap.filterWithKey (\k _ -> Key.toText k `Set.notMember` recursiveParentNames) claims
    
    -- Combine parent and child disclosures (parents first, then children)
    let parentDisclosures = map (\(_, _, disc) -> disc) parentInfo
    let allDisclosures = parentDisclosures ++ allChildDisclosures
    
    return (parentInfo, allDisclosures, remainingClaims)
  
  where
    -- Helper function to recursively process paths for recursive disclosures
    processRecursivePaths :: HashAlgorithm -> [[T.Text]] -> KeyMap.KeyMap Aeson.Value -> T.Text -> IO (Either SDJWTError (Digest, EncodedDisclosure, [EncodedDisclosure]))
    processRecursivePaths hashAlg' paths obj parentName =
      runSDJWTIO $ processRecursivePathsExceptT hashAlg' paths obj parentName

    -- Internal ExceptT version of processRecursivePaths.
    processRecursivePathsExceptT :: HashAlgorithm -> [[T.Text]] -> KeyMap.KeyMap Aeson.Value -> T.Text -> SDJWTIO (Digest, EncodedDisclosure, [EncodedDisclosure])
    processRecursivePathsExceptT hashAlg' paths obj parentName = do
      -- Group paths by their first segment
      let groupedByFirst = groupPathsByFirstSegment paths
      
      -- Process each group
      results <- liftIO $ mapM (\(firstSeg, remainingPaths) -> do
        let firstKey = Key.fromText firstSeg
        case KeyMap.lookup firstKey obj of
          Nothing -> return $ Left $ InvalidDisclosureFormat $ "Path segment not found: " <> firstSeg
          Just (Aeson.Object nestedObj) -> do
            -- Filter out empty paths (this segment is the target)
            let (_emptyPaths, nonEmptyPaths) = partition null remainingPaths
            if null nonEmptyPaths
              then do
                -- This segment is the target - mark it as selectively disclosable
                -- Return the digest and disclosure (will be combined into parent _sd array)
                result <- markSelectivelyDisclosable hashAlg' firstSeg (Aeson.Object nestedObj)
                case result of
                  Left err -> return $ Left err
                  Right (digest, disclosure) -> return $ Right (digest, disclosure, [])
              else do
                -- Recurse into nested object
                nestedResult <- processRecursivePaths hashAlg' nonEmptyPaths nestedObj firstSeg
                case nestedResult of
                  Left err -> return $ Left err
                  Right (childDigest, childDisclosure, grandchildDisclosures) -> do
                    -- Return child digest and disclosure (will be combined into parent _sd array)
                    return $ Right (childDigest, childDisclosure, grandchildDisclosures)
          Just leafValue -> do
            -- Leaf value (string, number, bool, etc.) - this is the target
            -- Check if there are remaining paths (shouldn't happen for leaf values)
            let (_emptyPaths, nonEmptyPaths) = partition null remainingPaths
            if not (null nonEmptyPaths)
              then return $ Left $ InvalidDisclosureFormat $ "Cannot traverse into leaf value: " <> firstSeg
              else do
                -- Mark this leaf value as selectively disclosable
                result <- markSelectivelyDisclosable hashAlg' firstSeg leafValue
                case result of
                  Left err -> return $ Left err
                  Right (digest, disclosure) -> return $ Right (digest, disclosure, [])
        ) (Map.toList groupedByFirst)
      
      -- Combine results - for recursive disclosures, we need to combine all child digests
      -- into one parent _sd array
      partitionAndHandle results $ \successes -> do
        case successes of
          [] -> throwError $ InvalidDisclosureFormat "No paths to process"
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
            (parentDigest, parentDisclosure) <- liftIO (markSelectivelyDisclosable hashAlg' parentName parentDisclosureValue) >>= eitherToExceptT
            return (parentDigest, parentDisclosure, allChildDisclosures)
    
    -- Helper function to mark a claim as selectively disclosable
    markSelectivelyDisclosable :: HashAlgorithm -> T.Text -> Aeson.Value -> IO (Either SDJWTError (Digest, EncodedDisclosure))
    markSelectivelyDisclosable hashAlg' claimName claimValue =
      fmap (\saltBytes ->
        let salt = Salt saltBytes
        in case createObjectDisclosure salt claimName claimValue of
             Left err -> Left err
             Right encodedDisclosure ->
               let digest = computeDigest hashAlg' encodedDisclosure
               in Right (digest, encodedDisclosure)
      ) generateSalt
    
    -- Helper function to sort digests
    sortDigests :: [Digest] -> [Digest]
    sortDigests = sortBy (comparing unDigest)

