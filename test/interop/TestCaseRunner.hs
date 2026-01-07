{-# LANGUAGE OverloadedStrings #-}

-- | Helper functions for running interoperability test cases.
--
-- This module provides functions to convert test case formats to the public API format.
module TestCaseRunner
  ( extractDisclosurePaths
  , convertClaimsToObject
  , identifySelectivelyDisclosableClaims
  , compareClaims
  ) where

import qualified Data.Aeson as Aeson
import qualified Data.Aeson.Key as Key
import qualified Data.Aeson.KeyMap as KeyMap
import qualified Data.Map.Strict as Map
import qualified Data.Text as T
import qualified Data.Vector as V
import Data.Maybe (mapMaybe)
import Data.List (nub)

-- | Convert holder_disclosed_claims (boolean format) to JSON Pointer paths.
--
-- Examples:
--   {"given_name": true} → ["given_name"]
--   {"data_types": [True, False, True]} → ["data_types/0", "data_types/2"]
--   {"nested_array": [[True, False], [False, True]]} → ["nested_array/0/0", "nested_array/1/1"]
extractDisclosurePaths :: Map.Map T.Text Aeson.Value -> [T.Text]
extractDisclosurePaths holderDisclosed = concatMap (\(name, value) -> extractPathsForClaim name value) (Map.toList holderDisclosed)
  where
    extractPathsForClaim :: T.Text -> Aeson.Value -> [T.Text]
    extractPathsForClaim claimName (Aeson.Bool True) = [claimName]
    extractPathsForClaim _ (Aeson.Bool False) = []
    extractPathsForClaim claimName (Aeson.Array arr) = 
      concatMap (\(idx, val) -> extractPathsForArrayElement claimName idx val) (zip [0..] (V.toList arr))
    extractPathsForClaim claimName (Aeson.Object obj) =
      -- For objects, if the value is true-like, include the claim itself
      -- Otherwise, recurse into nested structure
      if KeyMap.null obj then []
      else concatMap (\(k, v) -> extractPathsForClaim (claimName <> "/" <> Key.toText k) v) (KeyMap.toList obj)
    extractPathsForClaim _ _ = []
    
    extractPathsForArrayElement :: T.Text -> Int -> Aeson.Value -> [T.Text]
    extractPathsForArrayElement claimName idx (Aeson.Bool True) = [claimName <> "/" <> T.pack (show idx)]
    extractPathsForArrayElement _ _ (Aeson.Bool False) = []
    extractPathsForArrayElement claimName idx (Aeson.Array arr) =
      concatMap (\(innerIdx, val) -> extractPathsForArrayElement (claimName <> "/" <> T.pack (show idx)) innerIdx val) (zip [0 :: Int ..] (V.toList arr))
    extractPathsForArrayElement claimName idx (Aeson.Object obj) =
      -- Nested object in array
      concatMap (\(k, v) -> extractPathsForClaim (claimName <> "/" <> T.pack (show idx) <> "/" <> Key.toText k) v) (KeyMap.toList obj)
    extractPathsForArrayElement _ _ _ = []

-- | Convert Map Text Value to Aeson.Object.
convertClaimsToObject :: Map.Map T.Text Aeson.Value -> Aeson.Object
convertClaimsToObject claims = KeyMap.fromList $ map (\(k, v) -> (Key.fromText k, v)) (Map.toList claims)

-- | Compare verified claims with expected claims.
--
-- This function does a deep comparison, checking that the expected claims match
-- the verified claims. It handles nested objects and arrays correctly.
-- Only checks that expected claims are present and match - extra claims in verified are ignored.
compareClaims :: Aeson.Object -> Aeson.Object -> Either String ()
compareClaims verified expected = 
  -- Check that all expected keys are present and match
  let expectedKeys = KeyMap.keys expected
      missingKeys = filter (\k -> not (KeyMap.member k verified)) expectedKeys
  in case missingKeys of
    (_:_) -> Left $ "Missing expected keys: " ++ show (map Key.toText missingKeys)
    [] -> 
      -- Check each expected key matches
      let mismatches = mapMaybe (\k -> 
            case (KeyMap.lookup k verified, KeyMap.lookup k expected) of
              (Just vVal, Just eVal) -> 
                if compareValues vVal eVal then Nothing else Just (Key.toText k, vVal, eVal)
              _ -> Just (Key.toText k, Aeson.Null, Aeson.Null)
            ) expectedKeys
      in case mismatches of
        [] -> Right ()
        ((keyName, vVal, eVal):_) -> Left $ "Mismatch at key " ++ T.unpack keyName ++ ": expected " ++ show eVal ++ ", got " ++ show vVal
  where
    compareValues :: Aeson.Value -> Aeson.Value -> Bool
    compareValues (Aeson.Object vObj) (Aeson.Object eObj) = 
      case compareClaims vObj eObj of
        Right () -> True
        Left _ -> False
    compareValues (Aeson.Array vArr) (Aeson.Array eArr) =
      -- For arrays, we need to compare element by element
      -- But arrays might have different ordering, so we compare lengths and elements
      V.length vArr == V.length eArr && 
      all (uncurry compareValues) (zip (V.toList vArr) (V.toList eArr))
    compareValues v e = v == e

-- | Identify which claims are selectively disclosable.
--
-- Strategy:
-- 1. If holder_disclosed_claims is not empty, use it to identify selectively disclosable claims
--    (claims that appear in holder_disclosed_claims were marked with !sd)
-- 2. If holder_disclosed_claims is empty, infer from comparing user_claims with expect_verified_user_claims
--    (claims that appear in user_claims but not in expect_verified_user_claims were selectively disclosable)
--
-- Examples:
--   {"given_name": true} → ["given_name"]
--   {"nationalities": [False, True]} → ["nationalities/0", "nationalities/1"] (both were !sd, only 1 is disclosed)
identifySelectivelyDisclosableClaims :: Map.Map T.Text Aeson.Value -> Map.Map T.Text Aeson.Value -> Map.Map T.Text Aeson.Value -> [T.Text]
identifySelectivelyDisclosableClaims userClaims holderDisclosed expectedVerified = 
  if Map.null holderDisclosed
    then inferFromComparison userClaims expectedVerified
    else extractAllPaths holderDisclosed
  where
    extractAllPaths :: Map.Map T.Text Aeson.Value -> [T.Text]
    extractAllPaths m = concatMap (\(name, value) -> extractPaths name value) (Map.toList m)
    
    extractPaths :: T.Text -> Aeson.Value -> [T.Text]
    extractPaths claimName (Aeson.Bool _) = [claimName]  -- Both True and False mean !sd was present
    extractPaths claimName (Aeson.Array arr) = 
      concatMap (\(idx, val) -> extractArrayPaths claimName idx val) (zip [0..] (V.toList arr))
    extractPaths claimName (Aeson.Object obj) =
      concatMap (\(k, v) -> extractPaths (claimName <> "/" <> Key.toText k) v) (KeyMap.toList obj)
    extractPaths _ _ = []
    
    extractArrayPaths :: T.Text -> Int -> Aeson.Value -> [T.Text]
    extractArrayPaths claimName idx (Aeson.Bool _) = [claimName <> "/" <> T.pack (show idx)]
    extractArrayPaths claimName idx (Aeson.Array arr) =
      concatMap (\(innerIdx, val) -> extractArrayPaths (claimName <> "/" <> T.pack (show idx)) innerIdx val) (zip [0..] (V.toList arr))
    extractArrayPaths claimName idx (Aeson.Object obj) =
      concatMap (\(k, v) -> extractPaths (claimName <> "/" <> T.pack (show idx) <> "/" <> Key.toText k) v) (KeyMap.toList obj)
    extractArrayPaths _ _ _ = []
    
    -- Infer selectively disclosable claims by comparing user_claims with expect_verified_user_claims
    inferFromComparison :: Map.Map T.Text Aeson.Value -> Map.Map T.Text Aeson.Value -> [T.Text]
    inferFromComparison user expected = 
      -- Compare each top-level claim
      concatMap (\(name, userVal) ->
        case Map.lookup name expected of
          Just expectedVal -> inferPathsForValue name userVal expectedVal
          Nothing -> [name]  -- Claim not in expected, so it's selectively disclosable
        ) (Map.toList user)
    
    -- Infer selectively disclosable paths by comparing two values
    inferPathsForValue :: T.Text -> Aeson.Value -> Aeson.Value -> [T.Text]
    inferPathsForValue claimName (Aeson.Array userArr) (Aeson.Array expectedArr) =
      -- Compare arrays element by element
      let userList = V.toList userArr
          expectedList = V.toList expectedArr
          userLen = length userList
          expectedLen = length expectedList
          -- If arrays have different lengths, mark extra indices as selectively disclosable
          -- Also mark indices where values differ
          selectiveIndices = 
            -- Indices beyond expected length are selectively disclosable (if user is longer)
            (if userLen > expectedLen then [expectedLen .. userLen - 1] else []) ++
            -- Indices where values differ (up to expected length)
            mapMaybe (\(idx, uVal, eVal) ->
              if idx < expectedLen && not (compareValuesForInference uVal eVal)
                then Just idx
                else Nothing
              ) (zip3 [0..] userList expectedList)
          -- For each selectively disclosable index, recursively check its contents
          basePaths = map (\idx -> claimName <> "/" <> T.pack (show idx)) (nub selectiveIndices)
          -- Recursively infer paths for selectively disclosable elements
          recursivePaths = concatMap (\(idx, uVal) ->
            if idx `elem` selectiveIndices
              then case (uVal, if idx < expectedLen then Just (expectedList !! idx) else Nothing) of
                (Aeson.Array _, Just (Aeson.Array eArr)) ->
                  -- Recursively check nested array
                  inferPathsForValue (claimName <> "/" <> T.pack (show idx)) uVal (Aeson.Array eArr)
                (Aeson.Object _, Just (Aeson.Object eObj)) ->
                  -- Recursively check nested object
                  inferPathsForValue (claimName <> "/" <> T.pack (show idx)) uVal (Aeson.Object eObj)
                (Aeson.Object _, Just (Aeson.Array _)) ->
                  -- Object element was replaced with empty array, recursively mark all its contents as selectively disclosable
                  extractAllPathsFromValue (claimName <> "/" <> T.pack (show idx)) uVal
                (Aeson.Array _, Nothing) ->
                  -- Array element was removed, recursively mark all its contents as selectively disclosable
                  extractAllPathsFromValue (claimName <> "/" <> T.pack (show idx)) uVal
                (Aeson.Object _, Nothing) ->
                  -- Object element was removed, recursively mark all its contents as selectively disclosable
                  extractAllPathsFromValue (claimName <> "/" <> T.pack (show idx)) uVal
                _ -> []
              else []
            ) (zip [0..] userList)
      in basePaths ++ recursivePaths
    inferPathsForValue claimName (Aeson.Object userObj) (Aeson.Object expectedObj) =
      -- Compare objects property by property
      let userKeys = KeyMap.keys userObj
          selectiveKeys = filter (\k ->
            case (KeyMap.lookup k userObj, KeyMap.lookup k expectedObj) of
              (Just uVal, Just eVal) -> not (compareValuesForInference uVal eVal)
              (Just _, Nothing) -> True  -- In user but not expected
              _ -> False
            ) userKeys
          basePaths = map (\k -> claimName <> "/" <> Key.toText k) selectiveKeys
          -- Recursively infer paths for selectively disclosable properties
          recursivePaths = concatMap (\k ->
            case (KeyMap.lookup k userObj, KeyMap.lookup k expectedObj) of
              (Just uVal, Just eVal) ->
                if k `elem` selectiveKeys
                  then inferPathsForValue (claimName <> "/" <> Key.toText k) uVal eVal
                  else []
              (Just uVal, Nothing) ->
                -- Property was removed, recursively mark all its contents
                extractAllPathsFromValue (claimName <> "/" <> Key.toText k) uVal
              _ -> []
            ) userKeys
      in basePaths ++ recursivePaths
    inferPathsForValue claimName userVal expectedVal =
      -- Primitive values: if different, the claim is selectively disclosable
      if userVal == expectedVal then [] else [claimName]
    
    -- Compare values for inference (simplified comparison)
    compareValuesForInference :: Aeson.Value -> Aeson.Value -> Bool
    compareValuesForInference (Aeson.Array uArr) (Aeson.Array eArr) =
      V.length uArr == V.length eArr
    compareValuesForInference (Aeson.Object uObj) (Aeson.Object eObj) =
      KeyMap.size uObj == KeyMap.size eObj
    compareValuesForInference u e = u == e
    
    -- Extract all paths from a value (for when an element is completely removed)
    extractAllPathsFromValue :: T.Text -> Aeson.Value -> [T.Text]
    extractAllPathsFromValue basePath (Aeson.Array arr) =
      -- Mark the array itself and all its elements
      basePath : concatMap (\(idx, val) ->
        extractAllPathsFromValue (basePath <> "/" <> T.pack (show (idx :: Int))) val
        ) (zip [0..] (V.toList arr))
    extractAllPathsFromValue basePath (Aeson.Object obj) =
      -- Mark the object itself and all its properties
      basePath : concatMap (\(k, val) ->
        extractAllPathsFromValue (basePath <> "/" <> Key.toText k) val
        ) (KeyMap.toList obj)
    extractAllPathsFromValue basePath _ = [basePath]  -- Primitive value

