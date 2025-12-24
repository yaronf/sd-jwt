{-# LANGUAGE OverloadedStrings #-}
-- | SD-JWT presentation: Creating presentations with selected disclosures.
--
-- This module provides functions for creating SD-JWT presentations on the holder side.
-- The holder selects which disclosures to include when presenting to a verifier.
module SDJWT.Presentation
  ( createPresentation
  , selectDisclosures
  , selectDisclosuresByNames
  , addKeyBinding
  ) where

import SDJWT.Types (HashAlgorithm(..), Digest(..), SDJWT(..), SDJWTPayload(..), SDJWTPresentation(..), SDJWTError(..), EncodedDisclosure(..), Disclosure(..))
import SDJWT.Disclosure (decodeDisclosure, getDisclosureClaimName, getDisclosureValue)
import SDJWT.Digest (extractDigestsFromValue, computeDigest, defaultHashAlgorithm)
import SDJWT.Utils (splitJSONPointer, unescapeJSONPointer)
import SDJWT.KeyBinding (addKeyBindingToPresentation)
import SDJWT.Verification (parsePayloadFromJWT)
import qualified Data.Text as T
import qualified Data.Set as Set
import qualified Data.Map.Strict as Map
import qualified Data.Aeson as Aeson
import qualified Data.Aeson.KeyMap as KeyMap
import qualified Data.Aeson.Key as Key
import qualified Data.Vector as V
import Data.Int (Int64)
import Data.Maybe (mapMaybe)
import Data.List (partition)

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
-- 1. Decodes all disclosures from the SD-JWT
-- 2. Filters disclosures to include only those matching the provided claim names
-- 3. Handles recursive disclosures (Section 6.3): when selecting nested claims,
--    automatically includes parent disclosures if they are recursively disclosable
-- 4. Validates disclosure dependencies (ensures all required parent disclosures are present)
-- 5. Returns a presentation with the selected disclosures
--
-- Note: This function validates that the selected disclosures exist in the SD-JWT.
-- Supports JSON Pointer syntax for nested paths (e.g., "address/street_address").
selectDisclosuresByNames
  :: SDJWT
  -> [T.Text]  -- ^ Claim names to include in presentation (supports JSON Pointer syntax for nested paths)
  -> Either SDJWTError SDJWTPresentation
selectDisclosuresByNames sdjwt@(SDJWT issuerJWT allDisclosures) claimNames = do
  -- Extract hash algorithm from JWT payload (RFC 9901 Section 7.2 requires this for validation)
  hashAlg <- extractHashAlgorithmFromJWT issuerJWT
  
  -- Decode all disclosures to check their claim names and detect recursive disclosures
  decodedDisclosures <- mapM decodeDisclosure allDisclosures
  
  -- Build a map of claim name -> disclosure for efficient lookup
  let disclosureMap = buildDisclosureMap decodedDisclosures allDisclosures
  
  -- Parse claim names to separate top-level and nested paths
  let (topLevelNames, nestedPaths) = partitionNestedPaths claimNames
  
  -- Collect all claim names that need to be included (including parent dependencies)
  let requiredClaimNames = collectRequiredClaims topLevelNames nestedPaths disclosureMap
  
  -- Filter disclosures that match the required claim names
  let selectedDisclos = filterDisclosuresByNames decodedDisclosures allDisclosures requiredClaimNames
  
  -- Validate disclosure dependencies per RFC 9901 Section 7.2, step 2b:
  -- Verify that each selected Disclosure satisfies one of:
  -- a. The hash is contained in the Issuer-signed JWT claims
  -- b. The hash is contained in the claim value of another selected Disclosure
  validateDisclosureDependencies hashAlg selectedDisclos issuerJWT
  
  -- Create presentation
  return $ createPresentation sdjwt selectedDisclos

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
-- Parameters:
-- - presentation: The SD-JWT presentation to add key binding to
-- - hashAlg: Hash algorithm to use for sd_hash computation
-- - holderPrivateKey: Private key for signing the KB-JWT (JWK as Text)
-- - audience: Audience claim (verifier identifier)
-- - nonce: Nonce provided by verifier
-- - issuedAt: Issued at timestamp (Unix epoch seconds)
--
-- Returns the presentation with key binding added, or an error if KB-JWT creation fails.
addKeyBinding
  :: HashAlgorithm
  -> T.Text  -- ^ Holder private key (JWK as Text)
  -> T.Text  -- ^ Audience
  -> T.Text  -- ^ Nonce
  -> Int64   -- ^ Issued at (Unix epoch seconds)
  -> SDJWTPresentation
  -> IO (Either SDJWTError SDJWTPresentation)
addKeyBinding = addKeyBindingToPresentation

-- | Build a map of claim name -> (decoded disclosure, encoded disclosure).
-- Also identifies recursive disclosures (disclosures containing _sd arrays).
buildDisclosureMap
  :: [Disclosure]
  -> [EncodedDisclosure]
  -> Map.Map T.Text (Disclosure, EncodedDisclosure)
buildDisclosureMap decoded encoded =
  let pairs = zip decoded encoded
      mappings = mapMaybe (\(dec, enc) ->
        case getDisclosureClaimName dec of
          Just name -> Just (name, (dec, enc))
          Nothing -> Nothing  -- Array disclosures don't have claim names
        ) pairs
  in Map.fromList mappings

-- | Partition claim names into top-level and nested paths (using JSON Pointer syntax).
--
-- Supports JSON Pointer escaping (RFC 6901):
-- - "~1" represents a literal forward slash "/"
-- - "~0" represents a literal tilde "~"
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

-- | Collect all required claim names, including parent dependencies for recursive disclosures.
collectRequiredClaims
  :: [T.Text]  -- ^ Top-level claim names
  -> [(T.Text, T.Text)]  -- ^ Nested paths (parent, child)
  -> Map.Map T.Text (Disclosure, EncodedDisclosure)  -- ^ All available disclosures
  -> Set.Set T.Text  -- ^ Set of all required claim names (including parents)
collectRequiredClaims topLevelNames nestedPaths disclosureMap =
  let topLevelSet = Set.fromList topLevelNames
      -- Collect child claim names from nested paths
      childNames = Set.fromList $ map snd nestedPaths
      -- Collect parent claim names from nested paths
      parentNames = Set.fromList $ map fst nestedPaths
      -- Check which parents are recursive disclosures (contain _sd arrays)
      recursiveParents = Set.filter (\parentName ->
        case Map.lookup parentName disclosureMap of
          Just (disclosure, _) -> isRecursiveDisclosure disclosure
          Nothing -> False
        ) parentNames
      -- All required names: top-level + children + recursive parents
      allRequired = topLevelSet `Set.union` childNames `Set.union` recursiveParents
  in allRequired

-- | Check if a disclosure is recursive (contains an _sd array in its value).
isRecursiveDisclosure :: Disclosure -> Bool
isRecursiveDisclosure disclosure =
  case getDisclosureValue disclosure of
    Aeson.Object obj ->
      case KeyMap.lookup (Key.fromText "_sd") obj of
        Just (Aeson.Array _) -> True
        _ -> False
    _ -> False

-- | Filter disclosures that match the required claim names.
filterDisclosuresByNames
  :: [Disclosure]
  -> [EncodedDisclosure]
  -> Set.Set T.Text
  -> [EncodedDisclosure]
filterDisclosuresByNames decoded encoded requiredNames =
  let matches = zip decoded encoded
      filtered = filter (\(disclosure, _) ->
        case getDisclosureClaimName disclosure of
          Just name -> name `Set.member` requiredNames
          Nothing -> False  -- Array disclosures don't have claim names, skip for now
        ) matches
  in map snd filtered

-- | Extract hash algorithm from JWT payload.
--
-- Helper function to extract _sd_alg from JWT payload, defaulting to SHA-256.
extractHashAlgorithmFromJWT :: T.Text -> Either SDJWTError HashAlgorithm
extractHashAlgorithmFromJWT jwt = do
  sdPayload <- parsePayloadFromJWT jwt
  return $ case sdAlg sdPayload of
    Just alg -> alg
    Nothing -> defaultHashAlgorithm

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
  let selectedDigests = Set.fromList $ map (unDigest . computeDigest hashAlg) selectedDisclos
  
  -- Build set of all valid digests (from JWT payload + recursive disclosures)
  -- This is used to verify condition (a): disclosure digest is in issuer-signed JWT
  let allValidDigests = Set.union issuerDigests selectedDigests
  
  -- RFC 9901 Section 7.2, step 2: Verify each selected Disclosure satisfies one of:
  -- a. The hash is contained in the Issuer-signed JWT claims
  -- b. The hash is contained in the claim value of another selected Disclosure
  
  -- First, verify condition (a): each selected disclosure's digest must be in issuer JWT or another disclosure
  mapM_ (\encDisclosure -> do
    let disclosureDigestText = unDigest $ computeDigest hashAlg encDisclosure
    if disclosureDigestText `Set.member` allValidDigests
      then return ()  -- Condition (a) or (b) satisfied ✓
      else Left $ MissingDisclosure $ "Disclosure digest not found in issuer-signed JWT or other selected disclosures: " <> disclosureDigestText
    ) selectedDisclos
  
  -- Second, verify condition (b) for recursive disclosures: child digests must be in selected disclosures
  decodedSelected <- mapM decodeDisclosure selectedDisclos
  
  -- Check each selected disclosure for recursive structure (condition b)
  mapM_ (\disclosure -> do
    case getDisclosureValue disclosure of
      Aeson.Object obj ->
        case KeyMap.lookup (Key.fromText "_sd") obj of
          Just (Aeson.Array sdArray) -> do
            -- This is a recursive disclosure - extract child digests
            let childDigests = mapMaybe (\v -> case v of
                  Aeson.String s -> Just s  -- Keep as Text for comparison
                  _ -> Nothing
                  ) (V.toList sdArray)
            
            -- RFC 9901 Section 7.2, step 2b: Verify each child digest is in another selected disclosure
            mapM_ (\childDigestText -> do
              if childDigestText `Set.member` selectedDigests
                then return ()  -- Child digest matches a selected disclosure ✓
                else Left $ MissingDisclosure $ "Child digest from recursive disclosure not found in selected disclosures: " <> childDigestText
              ) childDigests
          _ -> return ()  -- Not a recursive disclosure
      _ -> return ()  -- Not an object disclosure
    ) decodedSelected
  
  return ()

-- | Extract digests from JWT payload (_sd arrays and array ellipsis objects).
--
-- Helper function to extract all digests from the issuer-signed JWT payload.
extractDigestsFromJWTPayload :: T.Text -> Either SDJWTError (Set.Set T.Text)
extractDigestsFromJWTPayload jwt = do
  sdPayload <- parsePayloadFromJWT jwt
  let digests = extractDigestsFromValue (payloadValue sdPayload)
  return $ Set.fromList $ map unDigest digests

