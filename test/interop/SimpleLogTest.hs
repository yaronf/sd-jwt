{-# LANGUAGE OverloadedStrings #-}

module SimpleLogTest where

import Test.Hspec
import System.IO
import System.Directory
import Control.Exception

spec :: Spec
spec = describe "Simple File I/O Test" $ do
  it "can test file I/O" $ do
    -- Simple file I/O test
    let testFile = "/tmp/sd-jwt-test-simple.log"
    -- Remove file if it exists
    _ <- (removeFile testFile) `catch` (\(_::SomeException) -> return ())
    -- Write to file
    h <- openFile testFile WriteMode
    hSetBuffering h LineBuffering
    hPutStrLn h "=== FILE I/O TEST ==="
    hPutStrLn h "This is a test message"
    hFlush h
    hClose h
    -- Verify file was created
    fileExists <- doesFileExist testFile
    fileExists `shouldBe` True
    -- Read file contents
    contents <- readFile testFile
    contents `shouldContain` "FILE I/O TEST"
    contents `shouldContain` "test message"

