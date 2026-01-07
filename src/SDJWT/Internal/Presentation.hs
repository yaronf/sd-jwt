{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TupleSections #-}
-- | SD-JWT presentation: Creating presentations with selected disclosures.
--
-- This module provides functions for creating SD-JWT presentations on the holder side.
-- The holder selects which disclosures to include when presenting to a verifier.
module SDJWT.Internal.Presentation
  ( createPresentation
  , selectDisclosures
  , selectDisclosuresByNames
  , addKeyBinding
  ) where

import SDJWT.Internal.Types (HashAlgorithm(..), Digest(..), SDJWT(..), SDJWTPayload(..), SDJWTPresentation(..), SDJWTError(..), EncodedDisclosure(..), Disclosure(..))
import SDJWT.Internal.Disclosure (decodeDisclosure, getDisclosureClaimName, getDisclosureValue)
import SDJWT.Internal.Digest (extractDigestsFromValue, computeDigest, computeDigestText, extractDigestStringsFromSDArray, defaultHashAlgorithm)
import SDJWT.Internal.Utils (splitJSONPointer, unescapeJSONPointer)
import SDJWT.Internal.KeyBinding (addKeyBindingToPresentation)
import SDJWT.Internal.JWT (JWKLike)
import SDJWT.Internal.Verification (parsePayloadFromJWT, extractDigestsFromPayload)
import qualified Data.Text as T
import qualified Data.Set as Set
import qualified Data.Map.Strict as Map
import qualified Data.Aeson as Aeson
import qualified Data.Aeson.KeyMap as KeyMap
import qualified Data.Aeson.Key as Key
import qualified Data.Vector as V
import Data.Int (Int64)
import Data.Maybe (mapMaybe, fromMaybe)
import Data.List (partition, find, nubBy)
import Data.Either (partitionEithers)
import Text.Read (readMaybe)

-- | Create a presentation with selected disclosures.
--
-- This is a simple function that creates an SDJWTPresentation from an SDJWT
-- and a list of selected disclosures. The selected disclosures must be a subset
-- of the disclosures in the original SDJWT.
createPresentation
  :: SDJWT
  -> [EncodedDisclosure]  -- ^ Selected disclosures to include
  -> SDJWTPresentation
createPresentation (SDJWT jwt _) selectedDisclos =
  SDJWTPresentation
    { presentationJWT = jwt
    , selectedDisclosures = selectedDisclos
    , keyBindingJWT = Nothing
    }

-- | Select disclosures from an SD-JWT based on claim names.
--
-- This function:
--
-- 1. Decodes all disclosures from the SD-JWT
-- 2. Filters disclosures to include only those matching the provided claim names
-- 3. Handles recursive disclosures (Section 6.3): when selecting nested claims,
--    automatically includes parent disclosures if they are recursively disclosable
-- 4. Validates disclosure dependencies (ensures all required parent disclosures are present)
-- 5. Returns a presentation with the selected disclosures
--
-- Note: This function validates that the selected disclosures exist in the SD-JWT.
-- Supports JSON Pointer syntax for nested paths:
--
-- * Object properties: @["address\/street_address", "address\/locality"]@
-- * Array elements: @["nationalities\/0", "nationalities\/2"]@
-- * Mixed paths: @["address\/street_address", "nationalities\/1"]@
-- * Nested arrays: @["nested_array\/0\/0", "nested_array\/1\/1"]@
--
-- Paths with numeric segments (e.g., @["x\/22"]@) are resolved by checking the
-- actual claim type: if @x@ is an array, it refers to index 22; if @x@ is an
-- object, it refers to property @"22"@.
selectDisclosuresByNames
  :: SDJWT
  -> [T.Text]  -- ^ Claim names to include in presentation (supports JSON Pointer syntax for nested paths, including array indices)
  -> Either SDJWTError SDJWTPresentation
selectDisclosuresByNames sdjwt@(SDJWT issuerJWT allDisclosures) claimNames = do
  -- Extract hash algorithm from JWT payload (RFC 9901 Section 7.2 requires this for validation)
  hashAlg <- extractHashAlgorithmFromJWT issuerJWT
  
  -- Decode all disclosures to check their claim names and detect recursive disclosures
  decodedDisclosures <- mapM decodeDisclosure allDisclosures
  
  -- Parse claim names to separate top-level and nested paths
  let (topLevelNames, nestedPaths) = partitionNestedPaths claimNames
  
  -- Parse JWT payload
  sdPayload <- parsePayloadFromJWT issuerJWT
  let payloadValueObj = payloadValue sdPayload
  
  -- Recursively collect disclosures for all paths (handles both objects and arrays at each level)
  -- Pass decoded disclosures for efficient claim name lookup
  selectedDisclos <- collectDisclosuresRecursively hashAlg topLevelNames nestedPaths payloadValueObj allDisclosures decodedDisclosures
  
  -- For top-level array claims, also collect array element disclosures
  -- When selecting "foo" where foo is an array with ellipsis objects, we need to include
  -- the disclosures for those ellipsis objects
  -- When nestedPaths is empty (holder_disclosed_claims is empty), don't recursively collect nested disclosures
  let shouldRecurse = not (null nestedPaths)
  arrayElementDisclos <- collectArrayElementDisclosures hashAlg topLevelNames issuerJWT allDisclosures decodedDisclosures shouldRecurse
  
  -- Combine all selected disclosures and deduplicate by digest
  let allSelectedDisclosRaw = selectedDisclos ++ arrayElementDisclos
      -- Deduplicate by computing digest for each disclosure
      allSelectedDisclos = nubBy (\enc1 enc2 -> computeDigest hashAlg enc1 == computeDigest hashAlg enc2) allSelectedDisclosRaw
  
  -- Validate disclosure dependencies per RFC 9901 Section 7.2, step 2b:
  -- Verify that each selected Disclosure satisfies one of:
  -- a. The hash is contained in the Issuer-signed JWT claims
  -- b. The hash is contained in the claim value of another selected Disclosure
  validateDisclosureDependencies hashAlg allSelectedDisclos issuerJWT
  
  -- Create presentation
  return $ createPresentation sdjwt allSelectedDisclos

-- | Recursively collect disclosures for paths, handling both objects and arrays at each level.
collectDisclosuresRecursively
  :: HashAlgorithm
  -> [T.Text]  -- ^ Top-level claim names
  -> [[T.Text]]  -- ^ Nested paths as segments
  -> Aeson.Value  -- ^ Current value (object or array)
  -> [EncodedDisclosure]  -- ^ All available disclosures
  -> [Disclosure]  -- ^ Decoded disclosures (for claim name lookup)
  -> Either SDJWTError [EncodedDisclosure]
collectDisclosuresRecursively hashAlg topLevelNames nestedPaths value allDisclosures decodedDisclosures = do
  case value of
    Aeson.Object obj -> collectFromObject hashAlg topLevelNames nestedPaths obj allDisclosures decodedDisclosures
    Aeson.Array arr -> collectFromArray hashAlg topLevelNames nestedPaths arr allDisclosures decodedDisclosures
    _ -> return []  -- Primitive value, no disclosures

-- | Collect disclosures from an object.
collectFromObject
  :: HashAlgorithm
  -> [T.Text]  -- ^ Top-level claim names
  -> [[T.Text]]  -- ^ Nested paths as segments
  -> KeyMap.KeyMap Aeson.Value  -- ^ Current object
  -> [EncodedDisclosure]  -- ^ All available disclosures
  -> [Disclosure]  -- ^ Decoded disclosures (for claim name lookup)
  -> Either SDJWTError [EncodedDisclosure]
collectFromObject hashAlg topLevelNames nestedPaths obj allDisclosures decodedDisclosures = do
  -- Process top-level names
  -- For top-level selectively disclosable claims (including arrays), the claim is removed
  -- from payload and its digest is in the root _sd array (RFC 9901 treats top-level arrays
  -- as object properties, not array elements).
  topLevelDisclos <- if null topLevelNames
    then return []
    else do
      -- Extract digests from root _sd array
      let rootDigests = extractDigestStringsFromSDArray obj
      if null rootDigests
        then return []  -- No root _sd array
        else do
          -- Find disclosures matching these digests AND matching the claim names
          let matchingDisclos = mapMaybe (\(encDisclosure, decoded) ->
                let digestText = computeDigestText hashAlg encDisclosure
                in do
                  -- Check if digest is in root _sd array AND claim name matches
                  claimName <- getDisclosureClaimName decoded
                  if digestText `elem` rootDigests && claimName `elem` topLevelNames
                    then Just encDisclosure
                    else Nothing
                ) $ zip allDisclosures decodedDisclosures
          return matchingDisclos
  
  -- Group nested paths by first segment
  let groupedByFirst = Map.fromListWith (++) $ map (\path -> case path of
        [] -> ("", [])
        (first:rest) -> (first, [rest])) nestedPaths
  
  -- Process each group recursively
  nestedDisclos <- mapM (\(firstSeg, remainingPaths) ->
      -- Check if the key exists in the object, or if it's in an _sd array
      let -- Check if there's an _sd array that might contain this claim
          sdArrayDigests = extractDigestStringsFromSDArray obj
          -- Find disclosure for this claim name in the _sd array
          claimDisclosure = find (\(encDisclosure, decoded) ->
                let digestText = computeDigestText hashAlg encDisclosure
                    claimName = getDisclosureClaimName decoded
                in digestText `elem` sdArrayDigests && claimName == Just firstSeg
              ) $ zip allDisclosures decodedDisclosures
          nestedValue = case claimDisclosure of
            Just (_, decoded) ->
              -- Claim is in _sd array, reconstruct the value from disclosure
              getDisclosureValue decoded
            Nothing ->
              -- Claim might be a regular key or not exist
              fromMaybe Aeson.Null $ KeyMap.lookup (Key.fromText firstSeg) obj
      in do
        -- Filter out empty paths (this segment is the target)
        let (emptyPaths, nonEmptyPaths) = partition null remainingPaths
        -- Collect disclosure for this level if it's a target
        thisLevelDisclos <- if null emptyPaths
          then return []
          else case claimDisclosure of
            Just (encDisclosure, _) -> return [encDisclosure]
            Nothing -> collectDisclosuresForValue hashAlg firstSeg nestedValue allDisclosures
        -- Recurse into nested value
        deeperDisclos <- if null nonEmptyPaths
          then return []
          else do
            -- Collect disclosures for nested paths
            nestedDisclos2 <- collectDisclosuresRecursively hashAlg [] nonEmptyPaths nestedValue allDisclosures decodedDisclosures
            -- If we found nested disclosures, check if the parent itself is selectively disclosable
            -- (Section 6.3 recursive disclosure). The parent is selectively disclosable if its digest
            -- is in a parent _sd array. For top-level claims, check if the claim name is in topLevelNames.
            -- For nested claims, check if the parent object's digest is in the current object's _sd array.
            parentDisclos <- if not (null nestedDisclos2) && isRecursiveValue nestedValue
              then do
                -- Check if this parent claim itself has a disclosure (is selectively disclosable)
                -- For nested claims, we check if the parent's digest is in the current object's _sd array
                case claimDisclosure of
                  Just (encDisclosure, _) -> return [encDisclosure]  -- Parent is selectively disclosable
                  Nothing -> return []  -- Parent is not selectively disclosable (Section 6.2)
              else return []
            return (parentDisclos ++ nestedDisclos2)
        return (thisLevelDisclos ++ deeperDisclos)
    ) (Map.toList groupedByFirst)
  
  return $ topLevelDisclos ++ concat nestedDisclos

-- | Collect disclosures from an array.
collectFromArray
  :: HashAlgorithm
  -> [T.Text]  -- ^ Top-level claim names (should be empty for arrays)
  -> [[T.Text]]  -- ^ Nested paths as segments
  -> V.Vector Aeson.Value  -- ^ Current array
  -> [EncodedDisclosure]  -- ^ All available disclosures
  -> [Disclosure]  -- ^ Decoded disclosures (for claim name lookup)
  -> Either SDJWTError [EncodedDisclosure]
collectFromArray hashAlg _topLevelNames nestedPaths arr allDisclosures decodedDisclosures = do
  -- Parse first segment of each path to extract array index
  -- Group paths by first index
  let groupedByFirstIndex = Map.fromListWith (++) $ mapMaybe (\path -> case path of
        [] -> Nothing
        (firstSeg:rest) -> case readMaybe (T.unpack firstSeg) :: Maybe Int of
          Just idx -> Just (idx, [rest])
          Nothing -> Nothing  -- Not a numeric segment, skip
        ) nestedPaths
  
  -- Process each group
  results <- mapM (\(firstIdx, remainingPaths) ->
      if firstIdx < 0 || firstIdx >= V.length arr
        then return []
        else do
          let element = arr V.! firstIdx
          -- Filter out empty paths (this element is the target)
          let (emptyPaths, nonEmptyPaths) = partition null remainingPaths
          -- Collect disclosure for this element if it's a target
          thisLevelDisclos <- if null emptyPaths
            then return []
            else collectDisclosuresForArrayElement hashAlg element allDisclosures
          -- Recurse into nested value
          deeperDisclos <- if null nonEmptyPaths
            then return []
            else do
              -- If the element is an ellipsis object, we need to get the actual value from the disclosure
              -- and include the parent element disclosure
              case element of
                Aeson.Object ellipsisObj ->
                  case KeyMap.lookup (Key.fromText "...") ellipsisObj of
                    Just (Aeson.String digest) ->
                      -- Find the disclosure for this digest
                      case find (\encDisclosure ->
                            computeDigestText hashAlg encDisclosure == digest
                          ) allDisclosures of
                        Just encDisclosure -> do
                          -- Decode to get the actual value
                          decoded <- decodeDisclosure encDisclosure
                          let actualValue = getDisclosureValue decoded
                          -- Recurse into the actual value (not the ellipsis object)
                          nestedDisclos <- collectDisclosuresRecursively hashAlg [] nonEmptyPaths actualValue allDisclosures decodedDisclosures
                          -- Always include parent element disclosure when recursing into ellipsis object
                          return ([encDisclosure] ++ nestedDisclos)
                        Nothing -> return []  -- No disclosure found
                    _ -> do
                      -- Not an ellipsis object, recurse normally
                      nestedDisclos <- collectDisclosuresRecursively hashAlg [] nonEmptyPaths element allDisclosures decodedDisclosures
                      return nestedDisclos
                _ -> do
                  -- Not an ellipsis object, recurse normally
                  nestedDisclos <- collectDisclosuresRecursively hashAlg [] nonEmptyPaths element allDisclosures decodedDisclosures
                  return nestedDisclos
          return (thisLevelDisclos ++ deeperDisclos)
    ) (Map.toList groupedByFirstIndex)
  
  return $ concat results

-- | Collect disclosures for a value (object or array element).
collectDisclosuresForValue
  :: HashAlgorithm
  -> T.Text  -- ^ Claim name
  -> Aeson.Value  -- ^ Value (object or array element)
  -> [EncodedDisclosure]  -- ^ All available disclosures
  -> Either SDJWTError [EncodedDisclosure]
collectDisclosuresForValue hashAlg _claimName value allDisclosures = do
  case value of
    Aeson.Object obj -> do
      -- Extract digests from _sd array
      let digests = extractDigestStringsFromSDArray obj
      if null digests
        then return []  -- No _sd array, no disclosures
        else do
          -- Find disclosures matching these digests
          let matchingDisclos = mapMaybe (\encDisclosure ->
                let digestText = computeDigestText hashAlg encDisclosure
                in if digestText `elem` digests
                  then Just encDisclosure
                  else Nothing
                ) allDisclosures
          return matchingDisclos
    _ -> return []  -- Not an object, no disclosures

-- | Collect disclosures for an array element.
collectDisclosuresForArrayElement
  :: HashAlgorithm
  -> Aeson.Value  -- ^ Array element value
  -> [EncodedDisclosure]  -- ^ All available disclosures
  -> Either SDJWTError [EncodedDisclosure]
collectDisclosuresForArrayElement hashAlg value allDisclosures = do
  case value of
    Aeson.Object ellipsisObj -> do
      -- Extract digest from ellipsis object
      case KeyMap.lookup (Key.fromText "...") ellipsisObj of
        Just (Aeson.String digestText) -> do
          -- Find disclosure matching this digest
          let matchingDisclos = mapMaybe (\encDisclosure ->
                let digestText2 = computeDigestText hashAlg encDisclosure
                in if digestText2 == digestText
                  then Just encDisclosure
                  else Nothing
                ) allDisclosures
          return matchingDisclos
        _ -> return []  -- No ellipsis object, no disclosures
    _ -> return []  -- Not an ellipsis object, no disclosures

-- | Check if a value is a recursive disclosure (contains _sd array).
isRecursiveValue :: Aeson.Value -> Bool
isRecursiveValue value = case value of
  Aeson.Object obj ->
    case KeyMap.lookup (Key.fromText "_sd") obj of
      Just (Aeson.Array _) -> True
      _ -> False
  _ -> False

-- | Select disclosures from an SD-JWT (more flexible version).
--
-- This function allows selecting disclosures directly by providing the disclosure
-- objects themselves. Useful when you already know which disclosures to include.
selectDisclosures
  :: SDJWT
  -> [EncodedDisclosure]  -- ^ Disclosures to include
  -> Either SDJWTError SDJWTPresentation
selectDisclosures sdjwt@(SDJWT _ allDisclosures) selectedDisclos = do
  -- Validate that all selected disclosures are in the original SD-JWT
  let allDisclosuresSet = Set.fromList (map unEncodedDisclosure allDisclosures)
  let selectedSet = Set.fromList (map unEncodedDisclosure selectedDisclos)
  
  -- Check if all selected disclosures are in the original set
  if selectedSet `Set.isSubsetOf` allDisclosuresSet
    then return $ createPresentation sdjwt selectedDisclos
    else Left $ InvalidDisclosureFormat "Selected disclosures must be a subset of original disclosures"

-- | Add key binding to a presentation.
--
-- Creates a Key Binding JWT and adds it to the presentation, converting it
-- to SD-JWT+KB format. The KB-JWT proves that the holder possesses a specific key.
--
-- Returns the presentation with key binding added, or an error if KB-JWT creation fails.
addKeyBinding
  :: JWKLike jwk => HashAlgorithm  -- ^ Hash algorithm to use for sd_hash computation
  -> jwk  -- ^ Holder private key (Text or jose JWK object)
  -> T.Text  -- ^ Audience claim (verifier identifier)
  -> T.Text  -- ^ Nonce provided by verifier
  -> Int64   -- ^ Issued at timestamp (Unix epoch seconds)
  -> SDJWTPresentation  -- ^ The SD-JWT presentation to add key binding to
  -> Aeson.Object  -- ^ Optional additional claims (e.g., exp, nbf). Default: empty object
  -> IO (Either SDJWTError SDJWTPresentation)
addKeyBinding hashAlg holderKey audience nonce issuedAt presentation optionalClaims = 
  addKeyBindingToPresentation hashAlg holderKey audience nonce issuedAt presentation optionalClaims

-- | Partition claim names into top-level and nested paths (using JSON Pointer syntax).
--
-- Supports JSON Pointer escaping (RFC 6901):
--
-- - "~1" represents a literal forward slash "/"
-- - "~0" represents a literal tilde "~"
--
-- Note: The path "x/22" is ambiguous - it could refer to:
--   - Array element at index 22 if "x" is an array
--   - Object property "22" if "x" is an object
-- The actual type is determined when processing (see 'selectDisclosuresByNames').
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

-- | Extract hash algorithm from JWT payload.
--
-- Helper function to extract _sd_alg from JWT payload, defaulting to SHA-256.
extractHashAlgorithmFromJWT :: T.Text -> Either SDJWTError HashAlgorithm
extractHashAlgorithmFromJWT jwt =
  fmap (fromMaybe defaultHashAlgorithm . sdAlg) (parsePayloadFromJWT jwt)

-- | Validate disclosure dependencies per RFC 9901 Section 7.2, step 2.
--
-- Verifies that each selected Disclosure satisfies one of:
-- a. The hash of the Disclosure is contained in the Issuer-signed JWT claims
-- b. The hash of the Disclosure is contained in the claim value of another selected Disclosure
--
-- This implements the Holder's validation requirement before presenting to Verifier.
validateDisclosureDependencies
  :: HashAlgorithm
  -> [EncodedDisclosure]
  -> T.Text  -- ^ Issuer-signed JWT
  -> Either SDJWTError ()
validateDisclosureDependencies hashAlg selectedDisclos issuerJWT = do
  -- Extract digests from issuer-signed JWT payload (condition a)
  issuerDigests <- extractDigestsFromJWTPayload issuerJWT
  
  -- Compute digests for all selected disclosures (as Text for comparison)
  let selectedDigests = Set.fromList $ map (computeDigestText hashAlg) selectedDisclos
  
  -- Build set of all valid digests (from JWT payload + recursive disclosures)
  -- This is used to verify condition (a): disclosure digest is in issuer-signed JWT
  let allValidDigests = Set.union issuerDigests selectedDigests
  
  -- RFC 9901 Section 7.2, step 2: Verify each selected Disclosure satisfies one of:
  -- a. The hash is contained in the Issuer-signed JWT claims
  -- b. The hash is contained in the claim value of another selected Disclosure
  
  -- First, verify condition (a): each selected disclosure's digest must be in issuer JWT or another disclosure
  mapM_ (\encDisclosure -> do
    let disclosureDigestText = computeDigestText hashAlg encDisclosure
    if disclosureDigestText `Set.member` allValidDigests
      then return ()  -- Condition (a) or (b) satisfied ✓
      else Left $ MissingDisclosure $ "Disclosure digest not found in issuer-signed JWT or other selected disclosures: " <> disclosureDigestText
    ) selectedDisclos
  
  -- Second, verify condition (b) for recursive disclosures: 
  -- If a recursive disclosure is selected, child digests that are selected must be valid.
  -- Note: Child digests that are NOT selected are simply not disclosed, which is valid.
  decodedSelected <- mapM decodeDisclosure selectedDisclos
  
  -- Check each selected disclosure for recursive structure (condition b)
  mapM_ (\disclosure -> do
    case getDisclosureValue disclosure of
      Aeson.Object obj -> do
        -- This is a recursive disclosure - extract child digests
        let childDigests = extractDigestStringsFromSDArray obj
        if null childDigests
          then return ()  -- Not a recursive disclosure
          else do
            -- RFC 9901 Section 7.2, step 2b: For each child digest that IS selected,
            -- verify it's valid (in issuer JWT or another selected disclosure).
            -- Child digests that are NOT selected are simply not disclosed, which is fine.
            mapM_ (\childDigestText -> do
              if childDigestText `Set.member` selectedDigests
                then return ()  -- Child digest is selected and matches a selected disclosure ✓
                else if childDigestText `Set.member` issuerDigests
                  then return ()  -- Child digest is in issuer JWT (valid but not selected) ✓
                  else return ()  -- Child digest is not selected (holder chose not to disclose it) ✓
              ) childDigests
      _ -> return ()  -- Not an object disclosure
    ) decodedSelected

-- | Extract digests from JWT payload (_sd arrays and array ellipsis objects).
--
-- Helper function to extract all digests from the issuer-signed JWT payload.
extractDigestsFromJWTPayload :: T.Text -> Either SDJWTError (Set.Set T.Text)
extractDigestsFromJWTPayload jwt =
  parsePayloadFromJWT jwt >>= \sdPayload ->
    fmap (Set.fromList . map unDigest) (extractDigestsFromPayload sdPayload)

-- | Collect array element disclosures for selected array claims.
--
-- When an array claim is selected, we need to include array element disclosures
-- that are referenced by digests in that array. For nested arrays, we recursively
-- process array disclosure values to find nested array element disclosures.
collectArrayElementDisclosures
  :: HashAlgorithm
  -> [T.Text]  -- ^ Selected top-level claim names (may include array claims)
  -> T.Text  -- ^ Issuer-signed JWT
  -> [EncodedDisclosure]  -- ^ All available disclosures
  -> [Disclosure]  -- ^ Decoded disclosures (for claim name lookup)
  -> Bool  -- ^ Whether to recursively collect nested array element disclosures
  -> Either SDJWTError [EncodedDisclosure]
collectArrayElementDisclosures hashAlg claimNames issuerJWT allDisclosures decodedDisclosures shouldRecurse = do
  -- Early return if no claim names (no disclosures should be selected)
  if null claimNames
    then return []
    else do
      -- Parse JWT payload
      sdPayload <- parsePayloadFromJWT issuerJWT
      let payloadValueObj = payloadValue sdPayload
      
      -- Extract digests from selected array claims
      -- Check both payload (for Section 6.2 structured disclosure) and disclosure values (for top-level selective disclosure)
      case payloadValueObj of
        Aeson.Object obj -> do
          -- For each selected claim name, check if it's an array in payload or in disclosure value
          arrayDigests <- mapM (\claimName -> do
            -- First check payload
            payloadDigests <- case KeyMap.lookup (Key.fromText claimName) obj of
              Just (Aeson.Array arr) -> do
                -- Extract digests from ellipsis objects in this array
                digests <- extractDigestsFromValue (Aeson.Array arr)
                return digests
              _ -> return []
            -- Also check if this claim is selectively disclosable (in root _sd array)
            let rootDigests = extractDigestStringsFromSDArray obj
            disclosureDigests <- if null rootDigests
              then return []
              else do
                -- Find disclosure for this claim name
                case find (\(encDisclosure, decoded) ->
                      let digestText = computeDigestText hashAlg encDisclosure
                          claimNameFromDisclosure = getDisclosureClaimName decoded
                      in digestText `elem` rootDigests && claimNameFromDisclosure == Just claimName
                      ) $ zip allDisclosures decodedDisclosures of
                  Just (_, decoded) -> do
                    -- Get the disclosure value and check if it's an array with ellipsis objects
                    let value = getDisclosureValue decoded
                    case value of
                      Aeson.Array arr -> extractDigestsFromValue (Aeson.Array arr)
                      _ -> return []
                  Nothing -> return []
            return (claimName, payloadDigests ++ disclosureDigests)
            ) claimNames
          
          -- Find array element disclosures matching digests from selected arrays
          -- When shouldRecurse is False (holder_disclosed_claims is empty), don't include element disclosures
          -- They will be processed as empty arrays instead
          let selectedArrayElementDisclos = if shouldRecurse
                then mapMaybe (\encDisclosure ->
                      let digestText = computeDigestText hashAlg encDisclosure
                      in if any (\(_, digests) -> any ((== digestText) . unDigest) digests) arrayDigests
                        then Just encDisclosure
                        else Nothing
                      ) allDisclosures
                else []  -- Don't include element disclosures when shouldRecurse is False
          
          -- Recursively collect nested array element disclosures
          -- For each selected array element disclosure, check if its value is an array
          -- and extract digests from it. This needs to be recursive to handle multiple levels.
          let collectNestedRecursive :: [EncodedDisclosure] -> [EncodedDisclosure] -> Either SDJWTError [EncodedDisclosure]
              collectNestedRecursive currentDisclos alreadyCollected = do
                -- For each current disclosure, check if its value is an array
                nestedDisclos <- mapM (\encDisclosure -> do
                    decoded <- decodeDisclosure encDisclosure
                    let value = getDisclosureValue decoded
                    case value of
                      Aeson.Array nestedArr -> do
                        -- Extract digests from nested array
                        nestedDigests <- extractDigestsFromValue (Aeson.Array nestedArr)
                        -- Find disclosures matching these digests that we haven't already collected
                        let matchingDisclos = mapMaybe (\encDisclosure2 ->
                              let digestText2 = computeDigestText hashAlg encDisclosure2
                              in if any ((== digestText2) . unDigest) nestedDigests &&
                                    not (encDisclosure2 `elem` alreadyCollected) &&
                                    not (encDisclosure2 `elem` currentDisclos)
                                then Just encDisclosure2
                                else Nothing
                              ) allDisclosures
                        return matchingDisclos
                      _ -> return []
                    ) currentDisclos
                
                let newDisclos = concat nestedDisclos
                if null newDisclos
                  then return []  -- No more nested disclosures to collect
                  else do
                    -- Recursively collect from the newly found disclosures
                    deeperDisclos <- collectNestedRecursive newDisclos (alreadyCollected ++ currentDisclos ++ newDisclos)
                    return (newDisclos ++ deeperDisclos)
          
          nestedDisclos <- if shouldRecurse
            then collectNestedRecursive selectedArrayElementDisclos selectedArrayElementDisclos
            else return []
          
          -- Combine all array element disclosures (including nested ones if shouldRecurse is True)
          return $ selectedArrayElementDisclos ++ nestedDisclos
        _ -> return []  -- Payload is not an object, no arrays to process
