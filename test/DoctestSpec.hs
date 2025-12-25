{-# LANGUAGE CPP #-}
-- | Run doctest on documentation examples
--
-- This test suite runs doctest on:
-- - Haddock examples in persona modules (Issuer, Holder, Verifier)
-- - README.md examples (converted to doctest format)
module DoctestSpec (spec) where

import Test.Hspec
import System.Process (readProcessWithExitCode)
import System.Exit (ExitCode(..))

spec :: Spec
spec = describe "Doctest" $ do
  it "runs doctest on Haddock examples" $ do
    -- Run doctest on persona modules
    (exitCode, stdout, stderr) <- readProcessWithExitCode "stack" 
      ["exec", "--", "doctest", 
       "src/SDJWT/Issuer.hs",
       "src/SDJWT/Holder.hs", 
       "src/SDJWT/Verifier.hs"] ""
    
    case exitCode of
      ExitSuccess -> return ()
      ExitFailure code -> 
        expectationFailure $ 
          "doctest failed with exit code " ++ show code ++ 
          "\nstdout: " ++ stdout ++ 
          "\nstderr: " ++ stderr
  
  it "runs doctest on README.md examples" $ do
    -- First, ensure README examples are converted to doctest format
    (exitCode1, _, _) <- readProcessWithExitCode "bash" 
      ["./scripts/extract-doc-examples.sh"] ""
    
    case exitCode1 of
      ExitSuccess -> return ()
      ExitFailure code -> 
        expectationFailure $ 
          "Failed to extract README examples: exit code " ++ show code
    
    -- Then run doctest on the generated file
    (exitCode2, stdout, stderr) <- readProcessWithExitCode "stack" 
      ["exec", "--", "doctest", "test/ReadmeExamplesDoctest.hs"] ""
    
    case exitCode2 of
      ExitSuccess -> return ()
      ExitFailure code -> 
        expectationFailure $ 
          "doctest failed with exit code " ++ show code ++ 
          "\nstdout: " ++ stdout ++ 
          "\nstderr: " ++ stderr
