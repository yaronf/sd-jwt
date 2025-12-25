{-# LANGUAGE OverloadedStrings #-}
-- | Test that the end-to-end example application runs successfully
module ExampleSpec (spec) where

import Test.Hspec
import System.Process (readProcessWithExitCode)
import System.Exit (ExitCode(..))
import System.Directory (doesFileExist)

-- Get stack yaml file to use (prefer stack-ci.yaml if it exists, otherwise default)
getStackYaml :: IO [String]
getStackYaml = do
  ciExists <- doesFileExist "stack-ci.yaml"
  if ciExists
    then return ["--stack-yaml", "stack-ci.yaml"]
    else return []

spec :: Spec
spec = describe "End-to-End Example Application" $ do
  it "runs successfully without crashing" $ do
    -- Get stack yaml args (for CI compatibility)
    stackArgs <- getStackYaml
    -- Run the example executable
    (exitCode, stdout, stderr) <- readProcessWithExitCode "stack" 
      (stackArgs ++ ["exec", "--", "sd-jwt-example"]) ""
    
    case exitCode of
      ExitSuccess -> do
        -- Check that we got some expected output
        stdout `shouldContain` "SD-JWT End-to-End Example"
        stdout `shouldContain` "STEP 1: ISSUER CREATES SD-JWT"
        stdout `shouldContain` "STEP 2: HOLDER RECEIVES AND CREATES PRESENTATION"
        stdout `shouldContain` "STEP 3: VERIFIER VERIFIES AND EXTRACTS CLAIMS"
        stdout `shouldContain` "✓ SD-JWT verified successfully"
        stdout `shouldContain` "SUMMARY"
        -- Should not have any errors
        stderr `shouldNotContain` "ERROR:"
        return ()
      ExitFailure code -> 
        expectationFailure $ 
          "Example application failed with exit code " ++ show code ++ 
          "\nstdout: " ++ stdout ++ 
          "\nstderr: " ++ stderr

