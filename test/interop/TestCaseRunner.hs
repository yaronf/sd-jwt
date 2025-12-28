{-# LANGUAGE OverloadedStrings #-}
-- | Test case runner for Python SD-JWT test cases.
--
-- This module provides functions to run Python test cases and compare results.
module TestCaseRunner
  ( runTestCase
  , identifySelectivelyDisclosableClaims
  , extractDisclosedClaimNames
  , compareClaims
  ) where

import TestCaseParser (TestCase(..))
import SDJWT.Internal.Types (HashAlgorithm(..), ProcessedSDJWTPayload(..))
import SDJWT.Internal.Issuance (createSDJWT)
import SDJWT.Internal.Presentation (selectDisclosuresByNames)
import SDJWT.Internal.Verification (verifySDJWTWithoutSignature)
import qualified Data.Aeson as Aeson
import qualified Data.Aeson.KeyMap as KeyMap
import qualified Data.Map.Strict as Map
import qualified Data.Text as T
import qualified Data.Vector as V

-- | Run a test case and compare results with expected output.
--
-- This function:
-- 1. Identifies selectively disclosable claims from the test case
-- 2. Creates an SD-JWT with those claims
-- 3. Creates a presentation with disclosed claims
-- 4. Verifies the presentation
-- 5. Compares verified claims with expected claims
runTestCase
  :: T.Text  -- ^ Issuer private key JWK
  -> HashAlgorithm  -- ^ Hash algorithm to use
  -> TestCase  -- ^ Test case to run
  -> IO (Either String ())  -- ^ Right () if test passes, Left error message if it fails
runTestCase issuerPrivateKeyJWK hashAlg testCase = do
  -- Skip JSON serialization test cases
  case tcSerializationFormat testCase of
    Just "json" -> return $ Left "Skipping JSON serialization test case (not yet supported)"
    _ -> do
      -- Identify which claims are selectively disclosable
      let selectiveClaimNames = identifySelectivelyDisclosableClaims
            (tcUserClaims testCase)
            (tcHolderDisclosedClaims testCase)
      
      -- Extract which claims should be disclosed in the presentation
      let disclosedClaimNames = extractDisclosedClaimNames
            (tcUserClaims testCase)
            (tcHolderDisclosedClaims testCase)
      
      -- Create SD-JWT
      sdjwtResult <- createSDJWT Nothing Nothing hashAlg issuerPrivateKeyJWK selectiveClaimNames (tcUserClaims testCase)
      case sdjwtResult of
        Left err -> return $ Left $ "Failed to create SD-JWT: " ++ show err
        Right sdjwt -> do
          -- Create presentation with disclosed claims
          case selectDisclosuresByNames sdjwt disclosedClaimNames of
            Left err -> return $ Left $ "Failed to create presentation: " ++ show err
            Right presentation -> do
              -- Verify presentation (without signature for now, since we're testing our own creation)
              verifyResult <- verifySDJWTWithoutSignature presentation
              case verifyResult of
                Left err -> return $ Left $ "Failed to verify presentation: " ++ show err
                Right processedPayload -> do
                  -- Compare verified claims with expected claims
                  let verifiedClaims = processedClaims processedPayload
                  case compareClaims verifiedClaims (tcExpectedVerifiedClaims testCase) of
                    Left err -> return $ Left err
                    Right () -> return $ Right ()

-- | Identify which claims are selectively disclosable by comparing user_claims with holder_disclosed_claims.
--
-- In Python test cases, claims marked with !sd tags are selectively disclosable.
-- Since YAML tags are lost in conversion, we identify them by checking if they appear
-- in holder_disclosed_claims (which uses boolean flags). A claim is selectively disclosable
-- if it appears in holder_disclosed_claims (regardless of the boolean value).
identifySelectivelyDisclosableClaims
  :: Map.Map T.Text Aeson.Value  -- ^ User claims
  -> Map.Map T.Text Aeson.Value  -- ^ Holder disclosed claims (boolean flags)
  -> [T.Text]  -- ^ List of claim names that are selectively disclosable
identifySelectivelyDisclosableClaims userClaims holderDisclosed =
  -- All claims that appear in holder_disclosed_claims are selectively disclosable
  -- (the boolean value indicates whether to disclose, not whether it's selectively disclosable)
  Map.keys $ Map.filterWithKey (\claimName _value -> Map.member claimName userClaims) holderDisclosed

-- | Extract which claims should be disclosed based on holder_disclosed_claims boolean flags.
--
-- For object claims: if the flag is True, include the claim name.
-- For array claims: if the flag is True, include the claim name (arrays are handled differently).
extractDisclosedClaimNames
  :: Map.Map T.Text Aeson.Value  -- ^ User claims
  -> Map.Map T.Text Aeson.Value  -- ^ Holder disclosed claims (boolean flags)
  -> [T.Text]  -- ^ List of claim names to disclose
extractDisclosedClaimNames _userClaims holderDisclosed =
  Map.foldlWithKey (\acc claimName disclosedValue ->
    case disclosedValue of
      Aeson.Bool True -> claimName : acc
      Aeson.Bool False -> acc
      Aeson.Object obj -> 
        -- Nested object - check if any sub-claims are disclosed
        if Map.null (Map.filter (== Aeson.Bool True) (KeyMap.toMapText obj))
          then acc
          else claimName : acc
      Aeson.Array arr ->
        -- Array - check if any elements are disclosed
        if V.any (== Aeson.Bool True) arr
          then claimName : acc
          else acc
      _ -> acc
    ) [] holderDisclosed

-- | Compare verified claims with expected claims.
--
-- Handles minor differences like claim ordering and nested structures.
compareClaims
  :: Map.Map T.Text Aeson.Value  -- ^ Verified claims
  -> Map.Map T.Text Aeson.Value  -- ^ Expected claims
  -> Either String ()  -- ^ Right () if they match, Left error message if they don't
compareClaims verified expected =
  let
    -- Check that all expected claims are present
    missingClaims = Map.foldlWithKey (\acc name _value ->
      if Map.member name verified
        then acc
        else name : acc
      ) [] expected
    
    -- Check that values match
    mismatchedClaims = Map.foldlWithKey (\acc name expectedValue ->
      case Map.lookup name verified of
        Just verifiedValue ->
          if valuesEqual verifiedValue expectedValue
            then acc
            else (name, verifiedValue, expectedValue) : acc
        Nothing -> acc
      ) [] expected
  in
    case (missingClaims, mismatchedClaims) of
      ([], []) -> Right ()
      (missing, []) -> Left $ "Missing claims: " ++ show missing
      ([], mismatched) -> Left $ "Mismatched claims: " ++ show mismatched
      (missing, mismatched) -> Left $ "Missing: " ++ show missing ++ ", Mismatched: " ++ show mismatched

-- | Compare two Aeson values for equality, handling arrays and objects.
valuesEqual :: Aeson.Value -> Aeson.Value -> Bool
valuesEqual (Aeson.Object obj1) (Aeson.Object obj2) =
  KeyMap.toMapText obj1 == KeyMap.toMapText obj2
valuesEqual (Aeson.Array arr1) (Aeson.Array arr2) =
  V.toList arr1 == V.toList arr2
valuesEqual v1 v2 = v1 == v2

