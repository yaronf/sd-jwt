{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- | Interoperability tests with Python SD-JWT implementation.
--
-- These tests are only built when the 'interop-tests' flag is enabled:
--   stack build --flag sd-jwt:interop-tests
--   stack exec sd-jwt-interop-test
--
-- See internal-docs/INTEROPERABILITY_TESTING.md for details.
module Main (main) where

import Test.Hspec
import TestCaseParser
import TestCaseRunner (extractDisclosurePaths, convertClaimsToObject, compareClaims)
import TestCaseParser (extractSelectivelyDisclosablePaths)
import TestKeys
import SDJWT.Issuer
import SDJWT.Holder
import SDJWT.Verifier
import qualified Data.Aeson as Aeson
import qualified Data.Aeson.Key as Key
import qualified Data.Aeson.KeyMap as KeyMap
import qualified Data.Map.Strict as Map
import qualified Data.Text as T
import Data.List (nub)
import System.FilePath
import System.Directory
import Control.Monad
import Control.Exception (catch, SomeException)
import Data.Int (Int64)

main :: IO ()
main = do
  -- Find all test case directories
  vectorsDir <- getCurrentDirectory >>= \dir -> return $ dir </> "test" </> "interop" </> "vectors"
  testCases <- listDirectory vectorsDir `catch` (\(_::SomeException) -> return [])
  
  -- Filter to only directories with specification.yml
  validTestCases <- filterM (\name -> do
    let specFile = vectorsDir </> name </> "specification.yml"
    doesFileExist specFile
    ) testCases
  
  hspec $ describe "Python SD-JWT Interoperability Tests" $ do
    forM_ validTestCases $ \testCaseName -> do
      it ("can run test case: " ++ testCaseName) $ do
        let specFile = vectorsDir </> testCaseName </> "specification.yml"
        result <- loadTestCase specFile
        case result of
          Left err -> expectationFailure $ "Failed to parse test case: " ++ err
          Right testCase -> runTestCase specFile testCase

-- | Run a single test case using only the public API.
runTestCase :: FilePath -> TestCase -> IO ()
runTestCase specFile testCase = do
  -- Skip JSON serialization test cases (not yet supported)
  case tcSerializationFormat testCase of
    Just "json" -> return ()  -- Skip for now
    _ -> do
      -- Generate test keys
      keyPair <- generateTestRSAKeyPair
      
      -- Convert user_claims to Aeson.Object
      let userClaimsObj = convertClaimsToObject (tcUserClaims testCase)
      
      -- Extract selectively disclosable paths from YAML file (preserves !sd tags)
      sdPathsResult <- extractSelectivelyDisclosablePaths specFile
      selectiveClaimNames <- case sdPathsResult of
        Left err -> do
          expectationFailure $ "Failed to extract selectively disclosable paths from YAML: " ++ err
          return []  -- Never reached, but satisfies type checker
        Right paths -> return paths
      
      -- Debug: print selectively disclosable paths for array_recursive_sd and recursions
      when (Map.member "array_with_recursive_sd" (tcUserClaims testCase) || Map.member "animals" (tcUserClaims testCase)) $ do
        let testName = if Map.member "array_with_recursive_sd" (tcUserClaims testCase) then "array_recursive_sd" else "recursions"
        putStrLn $ "\n=== " ++ testName ++ " test case ==="
        putStrLn $ "Selectively disclosable paths (from YAML tags):"
        mapM_ (putStrLn . ("  " ++) . T.unpack) selectiveClaimNames
        putStrLn ""
      
      -- Create SD-JWT
      sdjwtResult <- createSDJWT Nothing Nothing SHA256 (privateKeyJWK keyPair) selectiveClaimNames userClaimsObj
      case sdjwtResult of
        Left err -> expectationFailure $ "Failed to create SD-JWT: " ++ show err
        Right sdjwt -> do
          -- Extract disclosure paths from holder_disclosed_claims
          let disclosurePaths = extractDisclosurePaths (tcHolderDisclosedClaims testCase)
          
          -- Create presentation
          presentationResult <- case selectDisclosuresByNames sdjwt disclosurePaths of
            Left err -> return $ Left $ "Failed to select disclosures: " ++ show err
            Right presentation -> do
              -- Add key binding if required
              if tcKeyBinding testCase
                then do
                  -- Generate holder key pair
                  holderKeyPair <- generateTestEd25519KeyPair
                  -- Add holder key to claims (for cnf claim)
                  let claimsWithCnf = addHolderKeyToClaims (publicKeyJWK holderKeyPair) userClaimsObj
                  -- Recreate SD-JWT with cnf claim
                  sdjwtWithCnfResult <- createSDJWT Nothing Nothing SHA256 (privateKeyJWK keyPair) selectiveClaimNames claimsWithCnf
                  case sdjwtWithCnfResult of
                    Left err -> return $ Left $ "Failed to create SD-JWT with cnf: " ++ show err
                    Right sdjwtWithCnf -> do
                      -- Select disclosures again
                      case selectDisclosuresByNames sdjwtWithCnf disclosurePaths of
                        Left err -> return $ Left $ "Failed to select disclosures: " ++ show err
                        Right pres -> do
                          -- Add key binding
                          let audience = "test-audience"
                          let nonce = "test-nonce"
                          let issuedAt = 1234567890 :: Int64
                          kbResult <- addKeyBindingToPresentation SHA256 (privateKeyJWK holderKeyPair) audience nonce issuedAt pres KeyMap.empty
                          case kbResult of
                            Left err -> return $ Left $ "Failed to add key binding: " ++ show err
                            Right presWithKB -> return $ Right presWithKB
                else return $ Right presentation
          
          case presentationResult of
            Left err -> expectationFailure err
            Right presentation -> do
              -- Verify SD-JWT
              verifyResult <- verifySDJWT (publicKeyJWK keyPair) presentation Nothing
              case verifyResult of
                Left err -> expectationFailure $ "Verification failed: " ++ show err
                Right processedPayload -> do
                  -- Compare with expected claims
                  let verifiedClaims = processedClaims processedPayload
                  let expectedClaimsObj = convertClaimsToObject (tcExpectedVerifiedClaims testCase)
                  
                  -- Compare claims using deep comparison
                  case compareClaims verifiedClaims expectedClaimsObj of
                    Right () -> return ()
                    Left err -> expectationFailure $ "Claims mismatch: " ++ err ++ "\nExpected: " ++ show expectedClaimsObj ++ "\nGot: " ++ show verifiedClaims

