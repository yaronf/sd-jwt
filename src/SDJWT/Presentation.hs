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

import SDJWT.Types
import SDJWT.Disclosure
import SDJWT.KeyBinding
import qualified Data.Text as T
import qualified Data.Set as Set
import Data.Int (Int64)

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
  let selectedDisclos = filterMatches decodedDisclosures allDisclosures requestedNames
  
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

