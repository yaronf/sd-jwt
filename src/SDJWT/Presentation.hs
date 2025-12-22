{-# LANGUAGE OverloadedStrings #-}
-- | SD-JWT presentation: Creating presentations with selected disclosures.
--
-- This module provides functions for creating SD-JWT presentations on the holder side.
-- The holder selects which disclosures to include when presenting to a verifier.
module SDJWT.Presentation
  ( createPresentation
  , selectDisclosures
  , selectDisclosuresByNames
  ) where

import SDJWT.Types
import SDJWT.Disclosure
import qualified Data.Text as T
import qualified Data.Set as Set

-- | Create a presentation with selected disclosures.
--
-- This is a simple function that creates an SDJWTPresentation from an SDJWT
-- and a list of selected disclosures. The selected disclosures must be a subset
-- of the disclosures in the original SDJWT.
createPresentation
  :: SDJWT
  -> [EncodedDisclosure]  -- ^ Selected disclosures to include
  -> SDJWTPresentation
createPresentation (SDJWT jwt _) selectedDisclosures =
  SDJWTPresentation
    { presentationJWT = jwt
    , selectedDisclosures = selectedDisclosures
    , keyBindingJWT = Nothing
    }

-- | Select disclosures from an SD-JWT based on claim names.
--
-- This function:
-- 1. Decodes all disclosures from the SD-JWT
-- 2. Filters disclosures to include only those matching the provided claim names
-- 3. Returns a presentation with the selected disclosures
--
-- Note: This function validates that the selected disclosures exist in the SD-JWT.
selectDisclosuresByNames
  :: SDJWT
  -> [T.Text]  -- ^ Claim names to include in presentation
  -> Either SDJWTError SDJWTPresentation
selectDisclosuresByNames sdjwt@(SDJWT _ allDisclosures) claimNames = do
  -- Decode all disclosures to check their claim names
  decodedDisclosures <- mapM decodeDisclosure allDisclosures
  
  -- Create a set of requested claim names for efficient lookup
  let requestedNames = Set.fromList claimNames
  
  -- Filter disclosures that match the requested claim names
  let selectedDisclosures = filterMatches decodedDisclosures allDisclosures requestedNames
  
  -- Create presentation
  return $ createPresentation sdjwt selectedDisclosures

-- | Select disclosures from an SD-JWT (more flexible version).
--
-- This function allows selecting disclosures directly by providing the disclosure
-- objects themselves. Useful when you already know which disclosures to include.
selectDisclosures
  :: SDJWT
  -> [EncodedDisclosure]  -- ^ Disclosures to include
  -> Either SDJWTError SDJWTPresentation
selectDisclosures sdjwt@(SDJWT _ allDisclosures) selectedDisclosures = do
  -- Validate that all selected disclosures are in the original SD-JWT
  let allDisclosuresSet = Set.fromList (map unEncodedDisclosure allDisclosures)
  let selectedSet = Set.fromList (map unEncodedDisclosure selectedDisclosures)
  
  -- Check if all selected disclosures are in the original set
  if selectedSet `Set.isSubsetOf` allDisclosuresSet
    then return $ createPresentation sdjwt selectedDisclosures
    else Left $ InvalidDisclosureFormat "Selected disclosures must be a subset of original disclosures"

-- | Filter disclosures that match the requested claim names.
--
-- This helper function filters disclosures based on their claim names.
filterMatches
  :: [Disclosure]
  -> [EncodedDisclosure]
  -> Set.Set T.Text
  -> [EncodedDisclosure]
filterMatches decoded encoded requestedNames =
  let matches = zip decoded encoded
      filtered = filter (\(disclosure, _) ->
        case getDisclosureClaimName disclosure of
          Just name -> name `Set.member` requestedNames
          Nothing -> False  -- Array disclosures don't have claim names, skip for now
        ) matches
  in map snd filtered

