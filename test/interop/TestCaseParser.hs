{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE LambdaCase #-}
-- | Parser for Python SD-JWT test case YAML specifications.
--
-- This module parses the YAML test case files from the Python SD-JWT library
-- and converts them to Haskell test case structures.
module TestCaseParser
  ( TestCase(..)
  , loadTestCase
  , parseUserClaims
  , parseHolderDisclosedClaims
  ) where

import Data.Aeson (Value(..), Object, (.=), (.:), (.:?), (.!=), object)
import qualified Data.Aeson as Aeson
import qualified Data.Aeson.Key as Key
import qualified Data.Aeson.KeyMap as KeyMap
import Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map
import Data.Text (Text)
import qualified Data.Text as T
import Data.Yaml  (Key.fromText "decodeFileEither", prettyPrintParseException, ParseException)
import qualified Data.Yaml as Yaml
import System.FilePath ((</>))

-- | Test case structure matching Python test case format
data TestCase = TestCase
  { tcUserClaims :: Map Text Value
    -- ^ Input claims with selective disclosure markers
  , tcHolderDisclosedClaims :: Map Text Value
    -- ^ Which claims the holder should disclose (boolean flags or claim names)
  , tcExpectedVerifiedClaims :: Map Text Value
    -- ^ Expected verified claims after selective disclosure
  , tcKeyBinding :: Bool
    -- ^ Whether key binding is enabled
  , tcSerializationFormat :: Maybe Text
    -- ^ Serialization format: "compact" or "json"
  , tcAddDecoyClaims :: Bool
    -- ^ Whether to add decoy claims
  , tcExtraHeaderParameters :: Map Text Value
    -- ^ Extra header parameters
  }
  deriving  (Key.fromText "Eq", Show)

-- | Load a test case from a YAML specification file
--
-- The YAML library can decode directly to Aeson.Value, which simplifies parsing.
-- YAML tags like !sd are lost in conversion, but we can identify selectively
-- disclosable claims by comparing with holder_disclosed_claims.
loadTestCase :: FilePath -> IO (Either String TestCase)
loadTestCase filePath = do
  result <- decodeFileEither filePath :: IO (Either ParseException Aeson.Value)
  case result of
    Left err -> return $ Left $ "Failed to parse YAML: " ++ prettyPrintParseException err
    Right aesonValue -> return $ parseTestCase aesonValue

-- | Parse an Aeson Value into a TestCase
parseTestCase :: Aeson.Value -> Either String TestCase
parseTestCase (Object obj) = do
  userClaims <- parseField "user_claims" obj >>= parseUserClaims
  holderDisclosed <- parseField "holder_disclosed_claims" obj >>= parseHolderDisclosedClaims
  expectedVerified <- parseField "expect_verified_user_claims" obj >>= parseUserClaims
  keyBinding <- parseFieldMaybe "key_binding" obj >>= \case
    Just (Bool b) -> Right b
    Just _ -> Left "key_binding must be a boolean"
    Nothing -> Right False
  serializationFormat <- parseFieldMaybe "serialization_format" obj >>= \case
    Just (String s) -> Right $ Just s
    Just _ -> Left "serialization_format must be a string"
    Nothing -> Right Nothing
  addDecoyClaims <- parseFieldMaybe "add_decoy_claims" obj >>= \case
    Just (Bool b) -> Right b
    Just _ -> Left "add_decoy_claims must be a boolean"
    Nothing -> Right False
  extraHeaderParams <- parseFieldMaybe "extra_header_parameters" obj >>= \case
    Just (Object o) -> Right $ KeyMap.toMapText o
    Just _ -> Left "extra_header_parameters must be an object"
    Nothing -> Right Map.empty
  
  return $ TestCase
    { tcUserClaims = userClaims
    , tcHolderDisclosedClaims = holderDisclosed
    , tcExpectedVerifiedClaims = expectedVerified
    , tcKeyBinding = keyBinding
    , tcSerializationFormat = serializationFormat
    , tcAddDecoyClaims = addDecoyClaims
    , tcExtraHeaderParameters = extraHeaderParams
    }
parseTestCase _ = Left "Test case must be a YAML object"

-- | Parse user claims from Aeson Value
--
-- The Python library uses YAML tags like `!sd` to mark selectively disclosable claims.
-- When converted to Aeson, these tags are lost, but we can identify selectively
-- disclosable claims by comparing with holder_disclosed_claims.
parseUserClaims :: Value -> Either String (Map Text Value)
parseUserClaims (Object obj) = Right $ KeyMap.toMapText obj
parseUserClaims _ = Left "user_claims must be an object"

-- | Parse holder disclosed claims from Aeson Value
--
-- The Python format uses boolean flags (True/False) to indicate which claims
-- should be disclosed. For arrays, it's a list of booleans.
parseHolderDisclosedClaims :: Value -> Either String (Map Text Value)
parseHolderDisclosedClaims (Object obj) = Right $ KeyMap.toMapText obj
parseHolderDisclosedClaims _ = Left "holder_disclosed_claims must be an object"


-- | Parse a required field from an Aeson object
parseField :: Text -> Object -> Either String Value
parseField fieldName obj = case KeyMap.lookup (Key.fromText fieldName) obj of
  Just v -> Right v
  Nothing -> Left $ "Missing required field: " ++ T.unpack fieldName

-- | Parse an optional field from an Aeson object
parseFieldMaybe :: Text -> Object -> Either String (Maybe Value)
parseFieldMaybe fieldName obj = Right $ KeyMap.lookup (Key.fromText fieldName) obj

