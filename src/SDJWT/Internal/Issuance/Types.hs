{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE OverloadedStrings #-}
-- | Types and records for Issuance module.
--
-- This module provides record types for functions with many parameters,
-- making the code more maintainable and easier to read.
module SDJWT.Internal.Issuance.Types
  ( ProcessConfig(..)
  , PathProcessConfig(..)
  , ObjectPathConfig(..)
  , ArrayPathConfig(..)
  , TopLevelClaimsConfig(..)
  , TopLevelClaimsResult(..)
  , CreateSDJWTConfig(..)
  , CreateSDJWTWithDecoysConfig(..)
  , BuildSDJWTPayloadConfig(..)
  , BuildSDJWTPayloadResult(..)
  ) where

import SDJWT.Internal.Types (HashAlgorithm, Digest(..), EncodedDisclosure(..))
import qualified Data.Aeson as Aeson
import qualified Data.Aeson.KeyMap as KeyMap
import qualified Data.Vector as V
import qualified Data.Text as T
import qualified Data.Set as Set

-- | Configuration for processing nested structures.
data ProcessConfig = ProcessConfig
  { processHashAlg :: HashAlgorithm
  , processPaths :: [[T.Text]]
  , processClaims :: Aeson.Object
  }
  deriving stock (Eq, Show)

-- | Configuration for processing paths recursively.
data PathProcessConfig = PathProcessConfig
  { pathHashAlg :: HashAlgorithm
  , pathSegments :: [[T.Text]]
  , pathValue :: Aeson.Value
  }
  deriving stock (Eq, Show)

-- | Configuration for processing object paths.
data ObjectPathConfig = ObjectPathConfig
  { objHashAlg :: HashAlgorithm
  , objPaths :: [[T.Text]]
  , objObject :: KeyMap.KeyMap Aeson.Value
  }
  deriving stock (Eq, Show)

-- | Configuration for processing array paths.
data ArrayPathConfig = ArrayPathConfig
  { arrHashAlg :: HashAlgorithm
  , arrPaths :: [[T.Text]]
  , arrArray :: V.Vector Aeson.Value
  }
  deriving stock (Eq, Show)

-- | Configuration for processing top-level selective claims.
data TopLevelClaimsConfig = TopLevelClaimsConfig
  { topLevelHashAlg :: HashAlgorithm
  , topLevelRecursiveParents :: Set.Set T.Text
  , topLevelClaimNames :: [T.Text]
  , topLevelRemainingClaims :: Aeson.Object
  }
  deriving stock (Eq, Show)

-- | Result of processing top-level selective claims.
data TopLevelClaimsResult = TopLevelClaimsResult
  { resultDigests :: [Digest]
  , resultDisclosures :: [EncodedDisclosure]
  , resultRegularClaims :: Aeson.Object
  }
  deriving stock (Eq, Show)

-- | Configuration for creating an SD-JWT.
data CreateSDJWTConfig jwk = CreateSDJWTConfig
  { createTyp :: Maybe T.Text  -- ^ Optional typ header value
  , createKid :: Maybe T.Text  -- ^ Optional kid header value
  , createHashAlg :: HashAlgorithm
  , createIssuerKey :: jwk  -- ^ Issuer private key
  , createSelectiveClaimNames :: [T.Text]  -- ^ Claim names to mark as selectively disclosable
  , createClaims :: Aeson.Object  -- ^ Original claims object
  }
  deriving stock (Eq, Show)

-- | Configuration for creating an SD-JWT with decoys.
data CreateSDJWTWithDecoysConfig jwk = CreateSDJWTWithDecoysConfig
  { createDecoysTyp :: Maybe T.Text
  , createDecoysKid :: Maybe T.Text
  , createDecoysHashAlg :: HashAlgorithm
  , createDecoysIssuerKey :: jwk
  , createDecoysSelectiveClaimNames :: [T.Text]
  , createDecoysClaims :: Aeson.Object
  , createDecoysCount :: Int  -- ^ Number of decoy digests
  }
  deriving stock (Eq, Show)

-- | Configuration for building SD-JWT payload.
data BuildSDJWTPayloadConfig = BuildSDJWTPayloadConfig
  { buildHashAlg :: HashAlgorithm
  , buildSelectiveClaimNames :: [T.Text]
  , buildClaims :: Aeson.Object
  }
  deriving stock (Eq, Show)

-- | Result of building SD-JWT payload.
data BuildSDJWTPayloadResult = BuildSDJWTPayloadResult
  { buildPayload :: Aeson.Value  -- ^ The payload value (Object)
  , buildDisclosures :: [EncodedDisclosure]
  }
  deriving stock (Eq, Show)

