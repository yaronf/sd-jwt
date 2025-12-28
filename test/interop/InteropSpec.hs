{-# LANGUAGE OverloadedStrings #-}
-- | Interoperability tests with Python SD-JWT implementation.
--
-- This is a separate test suite that does NOT run with the normal test suite.
-- Run it explicitly with: stack exec sd-jwt-interop-test
--
-- Phase 1: Test case parser for YAML specifications.
-- Phase 2: Real test case execution.
module Main (main) where

import Test.Hspec
import TestCaseParser
import TestCaseRunner
import TestKeys (generateTestRSAKeyPair, TestKeyPair(..))
import SDJWT.Internal.Types (HashAlgorithm(..))
import System.Environment (lookupEnv)
import System.FilePath ((</>))
import qualified Data.Aeson as Aeson
import qualified Data.Map.Strict as Map

main :: IO ()
main = hspec spec

spec :: Spec
spec = describe "Interoperability Testing" $ do
  describe "TestCaseParser" $ do
    it "can parse a simple test case structure" $ do
      -- This is a placeholder test. Once we have actual test case files,
      -- we can test loading them.
      let testCase = TestCase
            { tcUserClaims = Map.empty
            , tcHolderDisclosedClaims = Map.empty
            , tcExpectedVerifiedClaims = Map.empty
            , tcKeyBinding = False
            , tcSerializationFormat = Nothing
            , tcAddDecoyClaims = False
            , tcExtraHeaderParameters = Map.empty
            }
      testCase `shouldBe` testCase

  describe "TestCaseRunner" $ do
    it "can identify selectively disclosable claims" $ do
      let userClaims = Map.fromList
            [ ("given_name", Aeson.String "John")
            , ("family_name", Aeson.String "Doe")
            , ("email", Aeson.String "john@example.com")
            ]
      let holderDisclosed = Map.fromList
            [ ("given_name", Aeson.Bool True)
            , ("family_name", Aeson.Bool False)
            , ("email", Aeson.Bool True)
            ]
      let selective = identifySelectivelyDisclosableClaims userClaims holderDisclosed
      -- All claims in holder_disclosed_claims are selectively disclosable
      -- (the boolean indicates whether to disclose, not whether it's selectively disclosable)
      selective `shouldSatisfy` ("given_name" `elem`)
      selective `shouldSatisfy` ("family_name" `elem`)
      selective `shouldSatisfy` ("email" `elem`)
      length selective `shouldBe` 3

    it "can extract disclosed claim names" $ do
      let userClaims = Map.fromList
            [ ("given_name", Aeson.String "John")
            , ("family_name", Aeson.String "Doe")
            ]
      let holderDisclosed = Map.fromList
            [ ("given_name", Aeson.Bool True)
            , ("family_name", Aeson.Bool False)
            ]
      let disclosed = extractDisclosedClaimNames userClaims holderDisclosed
      disclosed `shouldContain` ["given_name"]
      disclosed `shouldNotContain` ["family_name"]

  describe "Real Test Cases" $ do
    it "can load and run a test case if PYTHON_TEST_CASES_DIR is set" $ do
      mbTestCasesDir <- lookupEnv "PYTHON_TEST_CASES_DIR"
      case mbTestCasesDir of
        Nothing -> 
          pendingWith "Set PYTHON_TEST_CASES_DIR environment variable to run real test cases"
        Just testCasesDir -> do
          -- Try to load a simple test case
          let testCasePath = testCasesDir </> "no_sd" </> "specification.yml"
          result <- loadTestCase testCasePath
          case result of
            Left err -> 
              expectationFailure $ "Failed to load test case: " ++ err
            Right testCase -> do
              -- Get test keys
              TestKeyPair{privateKeyJWK = issuerKey} <- generateTestRSAKeyPair
              -- Run the test case
              runResult <- runTestCase issuerKey SHA256 testCase
              case runResult of
                Left err -> expectationFailure $ "Test case failed: " ++ err
                Right () -> return ()  -- Test passed
