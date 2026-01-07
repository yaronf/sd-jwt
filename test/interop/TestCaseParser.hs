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
  , extractSelectivelyDisclosablePaths
  ) where

import Data.Aeson (Value(..), Object, (.=), (.:), (.:?), (.!=), object)
import qualified Data.Aeson as Aeson
import qualified Data.Aeson.Key as Key
import qualified Data.Aeson.KeyMap as KeyMap
import Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map
import qualified Data.Vector as V
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import Data.YAML (decodeNode, Node(..), docRoot, Scalar(..), Mapping, Pos)
import System.FilePath ((</>))
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BSL
import Text.Read (readMaybe)

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
  deriving (Eq, Show)

-- | Load a test case from a YAML specification file
--
-- Uses HsYAML which preserves YAML tags. We parse to Node first, then convert
-- to Aeson.Value by walking the structure (ignoring tags for Aeson conversion).
loadTestCase :: FilePath -> IO (Either String TestCase)
loadTestCase filePath = do
  yamlContent <- BS.readFile filePath
  -- Parse to Node, then convert to Aeson.Value
  case decodeNode (BSL.fromStrict yamlContent) of
    Right [doc] -> do
      -- Convert Node to Aeson.Value by walking the structure
      let aesonValue = nodeToAeson (docRoot doc)
      return $ parseTestCase aesonValue
    Right _ -> return $ Left "Expected single YAML document"
    Left (pos, err) -> return $ Left $ "Failed to parse YAML at " ++ show pos ++ ": " ++ err

-- | Convert HsYAML Node to Aeson.Value (ignoring tags)
nodeToAeson :: Node Pos -> Aeson.Value
nodeToAeson node = case node of
  Scalar _ scalar -> scalarToAeson scalar
  Mapping _ _ pairs -> Aeson.Object $ KeyMap.fromList $ map (\(k, v) ->
    (keyToKey k, nodeToAeson v)) (Map.toList pairs)
  Sequence _ _ items -> Aeson.Array $ V.fromList $ map nodeToAeson items
  Anchor _ _ innerNode -> nodeToAeson innerNode

scalarToAeson :: Scalar -> Aeson.Value
scalarToAeson scalar = case scalar of
  SNull -> Aeson.Null
  SBool b -> Aeson.Bool b
  SInt i -> Aeson.Number (fromInteger i)
  SFloat d -> Aeson.Number (realToFrac d)
  SStr s -> Aeson.String s
  SUnknown _ s -> 
    -- Try to parse the string as a number or boolean, otherwise treat as string
    case parseScalarValue s of
      Just (Aeson.Number n) -> Aeson.Number n
      Just (Aeson.Bool b) -> Aeson.Bool b
      Just Aeson.Null -> Aeson.Null
      _ -> Aeson.String s

-- | Try to parse a string as a scalar value (number, boolean, null)
parseScalarValue :: T.Text -> Maybe Aeson.Value
parseScalarValue s
  | s == "null" || s == "Null" || s == "NULL" = Just Aeson.Null
  | s == "true" || s == "True" || s == "TRUE" = Just (Aeson.Bool True)
  | s == "false" || s == "False" || s == "FALSE" = Just (Aeson.Bool False)
  | Just i <- readMaybe (T.unpack s) :: Maybe Integer = Just (Aeson.Number (fromInteger i))
  | Just d <- readMaybe (T.unpack s) :: Maybe Double = Just (Aeson.Number (realToFrac d))
  | otherwise = Nothing

keyToKey :: Node Pos -> Key.Key
keyToKey node = case node of
  Scalar _ (SStr s) -> Key.fromText s
  Scalar _ (SUnknown _ s) -> Key.fromText s  -- Extract value from SUnknown
  Scalar _ (SInt i) -> Key.fromText (T.pack (show i))
  Scalar _ (SFloat d) -> Key.fromText (T.pack (show d))
  Scalar _ (SBool b) -> Key.fromText (T.pack (show b))
  Scalar _ SNull -> Key.fromText "null"
  _ -> Key.fromText (T.pack (show node))

-- | Extract text value from a scalar node (for path extraction)
extractScalarTextFromNode :: Node Pos -> T.Text
extractScalarTextFromNode node = case node of
  Scalar _ (SStr s) -> s
  Scalar _ (SUnknown _ s) -> s
  Scalar _ (SInt i) -> T.pack (show i)
  Scalar _ (SFloat d) -> T.pack (show d)
  Scalar _ (SBool b) -> T.pack (show b)
  Scalar _ SNull -> "null"
  _ -> T.pack (show node)

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

-- | Extract selectively disclosable paths from YAML file.
--
-- Uses HsYAML's Node representation which preserves tags, allowing us to
-- extract paths that have the !sd tag.
-- | Extract selectively disclosable paths from user_claims in YAML file.
--
-- Uses HsYAML's Node representation which preserves tags, allowing us to
-- extract paths that have the !sd tag. Only extracts paths from user_claims.
extractSelectivelyDisclosablePaths :: FilePath -> IO (Either String [T.Text])
extractSelectivelyDisclosablePaths filePath = do
  yamlContent <- BS.readFile filePath
  -- Parse to Node to extract tags
  case decodeNode (BSL.fromStrict yamlContent) of
    Right [doc] -> do
      -- Find user_claims in the document and extract paths from it
      let rootNode = docRoot doc
          userClaimsPaths = extractUserClaimsPaths rootNode []
      return $ Right userClaimsPaths
    Right _ -> return $ Left "Expected single YAML document"
    Left (pos, err) -> return $ Left $ "Failed to parse YAML at " ++ show pos ++ ": " ++ err

-- | Extract paths from user_claims section only
extractUserClaimsPaths :: Node Pos -> [T.Text] -> [T.Text]
extractUserClaimsPaths node currentPath = case node of
  Mapping _ _ pairs ->
    -- Look for "user_claims" key
    concatMap (\(keyNode, valueNode) ->
      case keyNode of
        Scalar _ (SStr "user_claims") ->
          -- Found user_claims, extract paths from its value (which is a mapping)
          case valueNode of
            Mapping _ _ userPairs ->
              -- Extract paths from each top-level claim in user_claims
              concatMap (\(claimKeyNode, claimValueNode) ->
                let claimName = extractScalarText claimKeyNode
                    claimPath = if T.null claimName then [] else [claimName]
                    paths = extractSDPathsFromNode claimValueNode claimPath
                in paths
              ) (Map.toList userPairs)
            _ -> extractSDPathsFromNode valueNode []
        _ -> []
    ) (Map.toList pairs)
  _ -> []

-- | Extract text from a scalar node
extractScalarText :: Node Pos -> T.Text
extractScalarText node = case node of
  Scalar _ (SStr s) -> s
  Scalar _ _ -> T.pack (show node)
  _ -> T.pack (show node)

-- | Extract paths with !sd tags from HsYAML Node.
--
-- We recursively walk through the Node structure and track the current path.
-- When we encounter a node with tag "!sd", we record the current path.
extractSDPathsFromNode :: Node Pos -> [T.Text] -> [T.Text]
extractSDPathsFromNode node currentPath = case node of
  Mapping _ tag pairs -> extractMappingPaths tag pairs currentPath
  Sequence _ tag items -> extractSequencePaths tag items currentPath
  Scalar _ (SUnknown tag _) -> extractScalarSDPath tag currentPath
  Scalar _ _ -> []
  Anchor _ _ innerNode -> extractSDPathsFromNode innerNode currentPath

extractMappingPaths :: (Show a) => a -> Mapping Pos -> [T.Text] -> [T.Text]
extractMappingPaths tag pairs currentPath =
  let isSD = isSDTag tag
      childPaths = concatMap processPair (Map.toList pairs)
      processPair (keyNode, valueNode) =
        let keyPath = extractKeyPath keyNode currentPath
            -- Check if the key itself has !sd tag (use currentPath, extractKeySDPaths adds the key itself)
            keySDPaths = extractKeySDPaths keyNode currentPath
            -- Extract paths from the value (use keyPath which includes the key)
            valuePaths = extractSDPathsFromNode valueNode keyPath
        in keySDPaths ++ valuePaths
  in if isSD && not (null currentPath)
       then T.intercalate "/" currentPath : childPaths
       else childPaths

-- | Extract paths if a key node has !sd tag
extractKeySDPaths :: Node Pos -> [T.Text] -> [T.Text]
extractKeySDPaths keyNode currentPath = case keyNode of
  Scalar _ (SUnknown tag _) | isSDTag tag ->
    -- Key has !sd tag, record the path
    let keyText = extractScalarTextFromNode keyNode
        fullPath = currentPath ++ [keyText]
    in if not (T.null keyText)
         then [T.intercalate "/" fullPath]
         else []
  _ -> []

extractSequencePaths :: (Show a) => a -> [Node Pos] -> [T.Text] -> [T.Text]
extractSequencePaths tag items currentPath =
  let isSD = isSDTag tag
      childPaths = concatMap processItem (zip [0..] items)
      processItem (idx, itemNode) =
        extractSDPathsFromNode itemNode (currentPath ++ [T.pack (show idx)])
  in if isSD && not (null currentPath)
       then T.intercalate "/" currentPath : childPaths
       else childPaths

extractScalarSDPath :: (Show a) => a -> [T.Text] -> [T.Text]
extractScalarSDPath tag currentPath =
  if isSDTag tag && not (null currentPath)
    then [T.intercalate "/" currentPath]
    else []

-- | Extract key path from a mapping key node
extractKeyPath :: Node Pos -> [T.Text] -> [T.Text]
extractKeyPath keyNode currentPath = 
  let keyText = extractScalarTextFromNode keyNode
  in if not (T.null keyText)
       then currentPath ++ [keyText]
       else currentPath

-- | Check if a tag is the !sd tag
-- Tag can be Maybe Tag (for Mapping/Sequence) or Tag (for SUnknown scalars)
isSDTag :: (Show a) => a -> Bool
isSDTag tag = let tagText = T.pack (show tag)
              in tagText == "!sd" || tagText == "Just \"!sd\"" || T.isSuffixOf "!sd" tagText

