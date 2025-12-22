{-# LANGUAGE DeriveGeneric #-}
-- | Core data types for SD-JWT (Selective Disclosure for JSON Web Tokens).
--
-- This module defines all the data types used throughout the SD-JWT library,
-- including hash algorithms, disclosures, SD-JWT structures, and error types.
-- These types correspond to the structures defined in RFC 9901.
module SDJWT.Types
  ( HashAlgorithm(..)
  , Salt(..)
  , Digest(..)
  , ObjectDisclosure(..)
  , ArrayDisclosure(..)
  , Disclosure(..)
  , EncodedDisclosure(..)
  , SDJWTPayload(..)
  , KeyBindingInfo(..)
  , SDJWT(..)
  , SDJWTPresentation(..)
  , ProcessedSDJWTPayload(..)
  , SDJWTError(..)
  ) where

import Data.Aeson (Value)
import Data.ByteString (ByteString)
import Data.Map.Strict (Map)
import Data.Text (Text)
import GHC.Generics (Generic)

-- | Hash algorithm identifier for computing disclosure digests.
--
-- All three algorithms (SHA-256, SHA-384, SHA-512) must be supported.
-- SHA-256 is the default when _sd_alg is not specified in the SD-JWT.
data HashAlgorithm
  = SHA256  -- ^ SHA-256 (default, required)
  | SHA384  -- ^ SHA-384
  | SHA512  -- ^ SHA-512
  deriving (Eq, Show, Read, Generic)

-- | Salt value (cryptographically secure random).
--
-- Salts are used when creating disclosures to prevent brute-force attacks.
-- RFC 9901 recommends 128 bits (16 bytes) of entropy.
newtype Salt = Salt { unSalt :: ByteString }
  deriving (Eq, Show, Generic)

-- | Digest (base64url-encoded hash).
--
-- A digest is the base64url-encoded hash of a disclosure. Digests replace
-- claim values in the SD-JWT payload to enable selective disclosure.
newtype Digest = Digest { unDigest :: Text }
  deriving (Eq, Show, Generic)

-- | Disclosure for object properties: [salt, claim_name, claim_value]
data ObjectDisclosure = ObjectDisclosure
  { disclosureSalt :: Salt
  , disclosureName :: Text
  , disclosureValue :: Value
  }
  deriving (Eq, Show, Generic)

-- | Disclosure for array elements: [salt, claim_value]
data ArrayDisclosure = ArrayDisclosure
  { arraySalt :: Salt
  , arrayValue :: Value
  }
  deriving (Eq, Show, Generic)

-- | Unified disclosure type
data Disclosure
  = DisclosureObject ObjectDisclosure
  | DisclosureArray ArrayDisclosure
  deriving (Eq, Show, Generic)

-- | Encoded disclosure (base64url string)
newtype EncodedDisclosure = EncodedDisclosure { unEncodedDisclosure :: Text }
  deriving (Eq, Show, Generic)

-- | Key Binding information from cnf claim
data KeyBindingInfo = KeyBindingInfo
  { kbPublicKey :: Text  -- TODO: Use proper JWK type from jose-jwt
  }
  deriving (Eq, Show, Generic)

-- | SD-JWT payload structure
-- Note: This is a simplified representation. The actual payload
-- is a JSON object with _sd arrays and ... objects for arrays.
data SDJWTPayload = SDJWTPayload
  { sdAlg :: Maybe HashAlgorithm  -- ^ _sd_alg claim
  , payloadValue :: Value  -- ^ The actual JSON payload
  }
  deriving (Eq, Show, Generic)

-- | Complete SD-JWT structure (as issued)
data SDJWT = SDJWT
  { issuerSignedJWT :: Text  -- ^ The signed JWT (compact serialization)
  , disclosures :: [EncodedDisclosure]  -- ^ All disclosures
  }
  deriving (Eq, Show, Generic)

-- | SD-JWT presentation (with selected disclosures)
data SDJWTPresentation = SDJWTPresentation
  { presentationJWT :: Text
  , selectedDisclosures :: [EncodedDisclosure]
  , keyBindingJWT :: Maybe Text  -- ^ KB-JWT if present
  }
  deriving (Eq, Show, Generic)

-- | Processed SD-JWT payload (after verification)
data ProcessedSDJWTPayload = ProcessedSDJWTPayload
  { processedClaims :: Map Text Value
  }
  deriving (Eq, Show, Generic)

-- | SD-JWT errors
data SDJWTError
  = InvalidDisclosureFormat Text
  | InvalidDigest Text
  | MissingDisclosure Text
  | DuplicateDisclosure Text
  | InvalidSignature Text
  | InvalidKeyBinding Text
  | InvalidHashAlgorithm Text
  | InvalidClaimName Text
  | SaltGenerationError Text
  | JSONParseError Text
  | SerializationError Text
  | VerificationError Text
  deriving (Eq, Show)

