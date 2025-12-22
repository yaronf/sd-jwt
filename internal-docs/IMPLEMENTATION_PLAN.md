# SD-JWT Implementation Plan for Haskell

## Overview

This document outlines the implementation plan for RFC 9901 (Selective Disclosure for JSON Web Tokens) in Haskell.

## Core Concepts

### SD-JWT Structure
- **SD-JWT**: `<Issuer-signed JWT>~<Disclosure 1>~<Disclosure 2>~...~<Disclosure N>~`
- **SD-JWT+KB**: `<Issuer-signed JWT>~<Disclosure 1>~...~<Disclosure N>~<KB-JWT>`
- Disclosures are base64url-encoded JSON arrays
- Digests replace claim values in the JWT payload

### Key Components
1. **Issuer-signed JWT**: Standard JWT signed by issuer, contains digests instead of selective claims
2. **Disclosures**: Base64url-encoded arrays containing (salt, claim_name?, claim_value)
3. **Key Binding JWT**: Optional proof of possession (KB-JWT)

## Implementation Architecture

### Module Structure

```
SDJWT/
├── Core.hs              -- Core data types and type classes
├── Types.hs             -- Type definitions
├── Disclosure.hs        -- Disclosure creation and parsing
├── Digest.hs            -- Hash computation and verification
├── Issuance.hs          -- SD-JWT creation (issuer side)
├── Presentation.hs      -- SD-JWT presentation (holder side)
├── Verification.hs      -- SD-JWT verification (verifier side)
├── KeyBinding.hs        -- Key Binding JWT support
├── Serialization.hs     -- Serialization/deserialization
└── Utils.hs             -- Utility functions (base64url, JSON, etc.)
```

## Phase 1: Core Data Types and Infrastructure

### 1.1 Core Types (`Types.hs`)

```haskell
-- Hash algorithm identifier
data HashAlgorithm = SHA256 | SHA384 | SHA512
  deriving (Eq, Show, Read)

-- Salt value (cryptographically secure random)
newtype Salt = Salt { unSalt :: ByteString }
  deriving (Eq, Show)

-- Digest (base64url-encoded hash)
newtype Digest = Digest { unDigest :: Text }
  deriving (Eq, Show)

-- Disclosure for object properties: [salt, claim_name, claim_value]
data ObjectDisclosure = ObjectDisclosure
  { disclosureSalt :: Salt
  , disclosureName :: Text
  , disclosureValue :: Value  -- Aeson Value
  }
  deriving (Eq, Show)

-- Disclosure for array elements: [salt, claim_value]
data ArrayDisclosure = ArrayDisclosure
  { arraySalt :: Salt
  , arrayValue :: Value
  }
  deriving (Eq, Show)

-- Unified disclosure type
data Disclosure
  = ObjectDisclosure ObjectDisclosure
  | ArrayDisclosure ArrayDisclosure
  deriving (Eq, Show)

-- Encoded disclosure (base64url string)
newtype EncodedDisclosure = EncodedDisclosure { unEncodedDisclosure :: Text }
  deriving (Eq, Show)

-- SD-JWT payload structure
data SDJWTPayload = SDJWTPayload
  { sdAlg :: Maybe HashAlgorithm  -- _sd_alg claim
  , sdDigests :: Map Text [Digest]  -- _sd arrays by path
  , arrayDigests :: Map Text [Maybe Digest]  -- Array elements with ... digests
  , regularClaims :: Map Text Value  -- Non-selectively disclosable claims
  , keyBinding :: Maybe KeyBindingInfo  -- cnf claim
  }
  deriving (Eq, Show)

-- Key Binding information
data KeyBindingInfo = KeyBindingInfo
  { kbPublicKey :: JWK  -- From cnf.jwk
  }
  deriving (Eq, Show)

-- Complete SD-JWT structure
data SDJWT = SDJWT
  { issuerSignedJWT :: JWT  -- The signed JWT
  , disclosures :: [EncodedDisclosure]  -- All disclosures (for issuance)
  }
  deriving (Eq, Show)

-- SD-JWT presentation (with selected disclosures)
data SDJWTPresentation = SDJWTPresentation
  { presentationJWT :: JWT
  , selectedDisclosures :: [EncodedDisclosure]
  , keyBindingJWT :: Maybe JWT  -- KB-JWT if present
  }
  deriving (Eq, Show)

-- Processed SD-JWT payload (after verification)
data ProcessedSDJWTPayload = ProcessedSDJWTPayload
  { processedClaims :: Map Text Value
  }
  deriving (Eq, Show)
```

### 1.2 Utility Functions (`Utils.hs`)

- Base64url encoding/decoding
- JSON canonicalization helpers (if needed)
- Secure random salt generation
- Text/ByteString conversions

### 1.3 Hash/Digest Functions (`Digest.hs`)

```haskell
-- Compute digest of a disclosure
computeDigest :: HashAlgorithm -> EncodedDisclosure -> Digest

-- Verify digest matches disclosure
verifyDigest :: HashAlgorithm -> Digest -> EncodedDisclosure -> Bool

-- Hash algorithm from claim value
parseHashAlgorithm :: Text -> Maybe HashAlgorithm

-- Default hash algorithm (SHA-256 per RFC 9901)
-- Note: All hash algorithms (SHA-256, SHA-384, SHA-512) must be supported
defaultHashAlgorithm :: HashAlgorithm
```

## Phase 2: Disclosure Handling

### 2.1 Disclosure Creation (`Disclosure.hs`)

```haskell
-- Create disclosure for object property
createObjectDisclosure :: Salt -> Text -> Value -> Either SDJWTError EncodedDisclosure

-- Create disclosure for array element
createArrayDisclosure :: Salt -> Value -> Either SDJWTError EncodedDisclosure

-- Decode disclosure from base64url
decodeDisclosure :: EncodedDisclosure -> Either SDJWTError Disclosure

-- Encode disclosure to base64url
encodeDisclosure :: Disclosure -> EncodedDisclosure

-- Extract salt from disclosure
disclosureSalt :: Disclosure -> Salt

-- Extract claim name (for object disclosures)
disclosureClaimName :: Disclosure -> Maybe Text

-- Extract claim value
disclosureValue :: Disclosure -> Value
```

### 2.2 Disclosure Validation

- Validate disclosure format
- Check salt uniqueness
- Verify claim names don't conflict with reserved names (_sd, ...)

## Phase 3: SD-JWT Issuance

### 3.1 Payload Construction (`Issuance.hs`)

```haskell
-- Mark claim as selectively disclosable
markSelectivelyDisclosable :: Text -> Value -> IssuerState -> Either SDJWTError IssuerState

-- Mark array element as selectively disclosable
markArrayElementDisclosable :: Text -> Int -> Value -> IssuerState -> Either SDJWTError IssuerState

-- Add decoy digest
addDecoyDigest :: Text -> IssuerState -> Either SDJWTError IssuerState

-- Build SD-JWT payload from claims
buildSDJWTPayload :: HashAlgorithm -> Map Text Value -> Either SDJWTError (SDJWTPayload, [EncodedDisclosure])

-- Create complete SD-JWT
createSDJWT :: JWK -> HashAlgorithm -> Map Text Value -> Either SDJWTError SDJWT
```

### 3.2 Issuer State Management

- Track which claims are selectively disclosable
- Generate unique salts
- Build _sd arrays
- Handle nested structures
- Support recursive disclosures

## Phase 4: SD-JWT Presentation

### 4.1 Presentation Creation (`Presentation.hs`)

```haskell
-- Select disclosures for presentation
selectDisclosures :: SDJWT -> [Text] -> Either SDJWTError SDJWTPresentation
  -- Selects disclosures based on claim names/paths

-- Create presentation with selected disclosures
createPresentation :: SDJWT -> [EncodedDisclosure] -> SDJWTPresentation

-- Add key binding to presentation
addKeyBinding :: SDJWTPresentation -> JWK -> Text -> Text -> Int64 -> Either SDJWTError SDJWTPresentation
  -- Parameters: presentation, holder private key, audience, nonce, issued_at

-- Serialize presentation
serializePresentation :: SDJWTPresentation -> Text
```

### 4.2 Disclosure Selection Logic

- Filter disclosures based on claim paths
- Handle recursive disclosures (include parent disclosures)
- Validate disclosure dependencies

## Phase 5: SD-JWT Verification

### 5.1 Verification (`Verification.hs`)

```haskell
-- Verify SD-JWT signature
verifySDJWTSignature :: JWK -> SDJWTPresentation -> Either SDJWTError ()

-- Verify disclosures match digests
verifyDisclosures :: HashAlgorithm -> SDJWTPayload -> [EncodedDisclosure] -> Either SDJWTError ()

-- Verify key binding (if present)
verifyKeyBinding :: SDJWTPresentation -> Either SDJWTError ()

-- Complete verification
verifySDJWT :: JWK -> Maybe (JWK -> Bool) -> SDJWTPresentation -> Either SDJWTError ProcessedSDJWTPayload
  -- Parameters: issuer public key, key binding validator, presentation

-- Process SD-JWT payload (replace digests with values)
processPayload :: HashAlgorithm -> SDJWTPayload -> [EncodedDisclosure] -> Either SDJWTError ProcessedSDJWTPayload
```

### 5.2 Verification Steps

1. Parse SD-JWT structure
2. Verify issuer signature on JWT
3. Extract hash algorithm (_sd_alg or default SHA-256)
   - Must support all three algorithms: SHA-256, SHA-384, SHA-512
4. For each disclosure:
   - Compute digest
   - Verify digest exists in payload
   - Check no duplicate disclosures
5. If KB-JWT present:
   - Verify KB-JWT signature with holder's public key
   - Verify sd_hash matches SD-JWT
   - Verify nonce, audience, iat
6. Reconstruct processed payload

## Phase 6: Key Binding Support

### 6.1 Key Binding (`KeyBinding.hs`)

```haskell
-- Create Key Binding JWT
createKeyBindingJWT :: JWK -> Text -> Text -> Int64 -> SDJWTPresentation -> Either SDJWTError JWT
  -- Parameters: holder private key, audience, nonce, issued_at, SD-JWT presentation

-- Compute sd_hash for key binding
computeSDHash :: HashAlgorithm -> SDJWTPresentation -> Digest

-- Verify Key Binding JWT
verifyKeyBindingJWT :: JWK -> JWT -> SDJWTPresentation -> Either SDJWTError ()
```

## Phase 7: Serialization

### 7.1 Serialization (`Serialization.hs`)

```haskell
-- Serialize SD-JWT
serializeSDJWT :: SDJWT -> Text

-- Deserialize SD-JWT
deserializeSDJWT :: Text -> Either SDJWTError SDJWT

-- Serialize presentation
serializePresentation :: SDJWTPresentation -> Text

-- Deserialize presentation
deserializePresentation :: Text -> Either SDJWTError SDJWTPresentation

-- Parse tilde-separated format
parseTildeSeparated :: Text -> Either SDJWTError (JWT, [EncodedDisclosure], Maybe JWT)
```

## Phase 8: Error Handling

### 8.1 Error Types

```haskell
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
```

## Phase 9: Testing

### 9.1 Test Cases

1. **Unit Tests**
   - Disclosure creation/parsing
   - Digest computation
   - Salt generation
   - Serialization/deserialization

2. **Integration Tests**
   - Complete issuance flow
   - Presentation with selected disclosures
   - Verification with various scenarios
   - Key binding flow

3. **RFC Compliance Tests**
   - Examples from RFC 9901 Section 5
   - Nested structure examples (Section 6)
   - Recursive disclosure examples
   - Edge cases (empty disclosures, no disclosures, etc.)

## Dependencies

### Required Libraries

```yaml
dependencies:
  - base >= 4.14 && < 5
  - aeson >= 2.0
  - bytestring >= 0.11
  - text >= 2.0
  - cryptonite >= 0.30  # For cryptographic operations
  - memory >= 0.18      # For secure random generation
  - jose-jwt >= 0.10   # For JWT handling
  - base64-bytestring >= 1.2  # For base64url encoding
  - unordered-containers >= 0.2  # For Map
  - vector >= 0.13     # For arrays
```

### Optional Libraries

- `quickcheck` - Property-based testing
- `hspec` - Testing framework
- `lens` - Optional for easier data manipulation

## Implementation Order

1. **Week 1**: Core types, utilities, and disclosure handling
2. **Week 2**: Digest computation and hash algorithms
3. **Week 3**: SD-JWT issuance (basic cases)
4. **Week 4**: SD-JWT issuance (nested and recursive)
5. **Week 5**: Presentation and disclosure selection
6. **Week 6**: Verification (basic)
7. **Week 7**: Key Binding support
8. **Week 8**: Serialization and edge cases
9. **Week 9**: Testing and RFC compliance
10. **Week 10**: Documentation and polish

## Security Considerations

1. **Salt Generation**: Use cryptographically secure random (128 bits minimum)
2. **Hash Algorithm**: Support SHA-256, SHA-384, SHA-512 (all are required)
3. **Signature Verification**: Properly verify all signatures
4. **Input Validation**: Validate all inputs (disclosures, digests, etc.)
5. **Constant-Time Operations**: Use constant-time comparisons where applicable
6. **Memory Safety**: Avoid exposing sensitive data unnecessarily

## Future Enhancements

1. JWS JSON Serialization support (Section 8)
2. Performance optimizations
3. Streaming support for large SD-JWTs
4. Additional hash algorithms (beyond SHA-256, SHA-384, SHA-512)
5. Custom claim processors
6. SD-JWT profile support

## Notes

- Follow RFC 9901 specification strictly
- Ensure compatibility with existing JWT libraries
- Provide clear error messages
- Document all public APIs
- Include examples in documentation
- Consider performance for large payloads

