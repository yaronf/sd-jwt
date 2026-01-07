{-# LANGUAGE OverloadedStrings #-}
-- | Types and records for Issuance module.
--
-- This module provides record types for functions with many parameters,
-- making the code more maintainable and easier to read.
module SDJWT.Internal.Issuance.Types where

import SDJWT.Internal.Types (HashAlgorithm)
import qualified Data.Aeson as Aeson
import qualified Data.Aeson.KeyMap as KeyMap
import qualified Data.Vector as V
import qualified Data.Text as T

-- | Configuration for processing nested structures.
data ProcessConfig = ProcessConfig
  { processHashAlg :: HashAlgorithm
  , processPaths :: [[T.Text]]
  , processClaims :: Aeson.Object
  }
  deriving (Eq, Show)

-- | Configuration for processing paths recursively.
data PathProcessConfig = PathProcessConfig
  { pathHashAlg :: HashAlgorithm
  , pathSegments :: [[T.Text]]
  , pathValue :: Aeson.Value
  }
  deriving (Eq, Show)

-- | Configuration for processing object paths.
data ObjectPathConfig = ObjectPathConfig
  { objHashAlg :: HashAlgorithm
  , objPaths :: [[T.Text]]
  , objObject :: KeyMap.KeyMap Aeson.Value
  }
  deriving (Eq, Show)

-- | Configuration for processing array paths.
data ArrayPathConfig = ArrayPathConfig
  { arrHashAlg :: HashAlgorithm
  , arrPaths :: [[T.Text]]
  , arrArray :: V.Vector Aeson.Value
  }
  deriving (Eq, Show)

