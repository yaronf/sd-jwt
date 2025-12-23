{-# LANGUAGE OverloadedStrings #-}
-- | Test key generation utilities for SD-JWT tests.
--
-- This module provides functions to load test RSA and EC keys
-- from a JSON file for use in unit tests. Keys are cached
-- to avoid regenerating them on every test run.
module TestKeys
  ( generateTestRSAKeyPair
  , generateTestRSAKeyPair2
  , generateTestECKeyPair
  , TestKeyPair(..)
  ) where

import qualified Data.Aeson as Aeson
import qualified Data.Text as T
import qualified Data.ByteString.Lazy as BSL
import System.IO.Unsafe (unsafePerformIO)
import qualified Data.Aeson.KeyMap as KeyMap
import qualified Data.Aeson.Key as Key

-- | A test key pair containing both private and public keys in JWK JSON format.
data TestKeyPair = TestKeyPair
  { privateKeyJWK :: T.Text  -- ^ Private key JWK (JSON format)
  , publicKeyJWK :: T.Text   -- ^ Public key JWK (JSON format)
  }

-- | Path to the test keys JSON file (relative to test directory)
testKeysPath :: FilePath
testKeysPath = "test/test-keys.json"

-- | Load test keys from JSON file (cached)
loadTestKeys :: IO Aeson.Value
loadTestKeys = do
  contents <- BSL.readFile testKeysPath
  case Aeson.eitherDecode contents of
    Left err -> error $ "Failed to parse test-keys.json: " ++ err ++ "\nRun 'stack runghc generate-test-keys.hs' to generate keys."
    Right val -> return val

-- | Cached test keys (loaded once)
{-# NOINLINE cachedTestKeys #-}
cachedTestKeys :: Aeson.Value
cachedTestKeys = unsafePerformIO loadTestKeys

-- | Extract a key from the cached test keys
extractKey :: T.Text -> T.Text -> T.Text
extractKey keyType keyKind =
  case cachedTestKeys of
    Aeson.Object obj -> case KeyMap.lookup (Key.fromText keyType) obj of
      Just (Aeson.Object keyObj) -> case KeyMap.lookup (Key.fromText keyKind) keyObj of
        Just (Aeson.String keyText) -> keyText
        _ -> error $ "Missing " ++ T.unpack keyKind ++ " key for " ++ T.unpack keyType
      _ -> error $ "Missing " ++ T.unpack keyType ++ " key section"
    _ -> error "test-keys.json is not an object"

-- | Generate a test RSA key pair.
--
-- Returns cached 2048-bit RSA key pair from test-keys.json.
-- This is fast since keys are pre-generated and cached.
-- Keys are generated using 'stack runghc generate-test-keys.hs'.
generateTestRSAKeyPair :: IO TestKeyPair
generateTestRSAKeyPair = return $ TestKeyPair
  { privateKeyJWK = extractKey "rsa" "private"
  , publicKeyJWK = extractKey "rsa" "public"
  }

-- | Generate a second test RSA key pair (for testing signature verification with wrong key).
--
-- Returns cached 2048-bit RSA key pair from test-keys.json.
-- This is a different key pair from generateTestRSAKeyPair, used for testing
-- that signature verification properly rejects JWTs signed with wrong keys.
generateTestRSAKeyPair2 :: IO TestKeyPair
generateTestRSAKeyPair2 = return $ TestKeyPair
  { privateKeyJWK = extractKey "rsa2" "private"
  , publicKeyJWK = extractKey "rsa2" "public"
  }

-- | Generate a test EC key pair (P-256).
--
-- Returns cached EC key pair from test-keys.json.
-- This is fast since keys are pre-generated and cached.
-- Keys are generated using 'stack runghc generate-test-keys.hs'.
generateTestECKeyPair :: IO TestKeyPair
generateTestECKeyPair = return $ TestKeyPair
  { privateKeyJWK = extractKey "ec" "private"
  , publicKeyJWK = extractKey "ec" "public"
  }
