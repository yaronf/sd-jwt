# SD-JWT Implementation Plan for Haskell

## Current Status (Updated)

**Overall Progress**: ~99% complete (Core implementation complete, module organization complete, cleanup complete, test coverage complete, remaining: security review, final documentation polish, packaging)

- ✅ **Phases 1-4**: Complete (Core Types, Utils, Disclosure, Digest, Serialization)
- ✅ **Phase 5**: Complete (Issuance - basic works ✅, array elements ✅, decoy digests ✅, JWT signing ✅, nested structures ✅)
- ✅ **Phase 6**: Complete (Presentation - basic works ✅, key binding infrastructure ✅, recursive disclosure handling ✅)
- ✅ **Phase 7**: Complete (Verification - basic works ✅, JWT verification ✅, key binding verification ✅, RFC tests ✅, array element processing ✅)
- ✅ **Phase 8**: Complete (Key Binding module ✅, tests ✅, RFC test vectors verified ✅)

**Critical Missing Features**:
1. ~~Nested structure support (recursive _sd arrays)~~ ✅ COMPLETED
2. ~~RFC Section 7 verification tests~~ ✅ COMPLETED (covered via Section 5.2 tests - Section 7 is the verification spec, not test vectors)

**Recent Updates**:
- ✅ JWT signing/verification fully integrated using jose-jwt library
- ✅ Test key generation utilities (TestKeys.hs) with cached 2048-bit RSA keys
- ✅ RFC example tests for Phase 5 (Issuance) and Phase 7 (Verification)
- ✅ JWK parsing from Text/JSON implemented
- ✅ Array element disclosure processing implemented in Verification.hs (processPayload)
- ✅ Recursive array processing to replace {"...": "<digest>"} objects with values
- ✅ Tests for array element disclosure verification added
- ✅ Ed25519 (EdDSA) key support added - fully tested for signing and verification
- ✅ Comprehensive tests for Ed25519 keys in issuance, verification, and key binding
- ✅ Note added about cryptonite deprecation (migrate to crypton when jose-jwt supports it)
- ✅ EC P-256 (ES256) signing support added using cryptonite (SDJWT.JWT.EC module - temporary until jose-jwt adds EC signing)
- ✅ EC P-256 (ES256) verification support using jose-jwt's existing verification
- ✅ Comprehensive unit tests for EC module (9 tests covering success and error cases)
- ✅ RFC test vector verification tests added (Section 5.1 and 5.2 complete examples)
- ✅ All RFC test vectors passing (82 tests total)
- ✅ Nested structure support (RFC Sections 6.2 and 6.3) - structured and recursive disclosures
- ✅ JSON Pointer syntax with escaping (`~1` for `/`, `~0` for `~`)
- ✅ Recursive disclosure handling in Presentation (automatic parent inclusion)
- ✅ Module organization complete: Persona modules (Issuer, Holder, Verifier) and Internal namespace
- ✅ Code cleanup: All linter warnings fixed, code duplication reduced
- ✅ Documentation: Advanced functions documented, module usage patterns clear
- ✅ Module organization complete: Persona modules (Issuer, Holder, Verifier) and Internal namespace
- ✅ Code cleanup: All linter warnings fixed, code duplication reduced
- ✅ Documentation: Advanced functions documented, module usage patterns clear

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

**Testing**: Unit tests for base64url encoding/decoding, salt generation ✅

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

**Testing**: Unit tests for digest computation, hash algorithm parsing, RFC example tests (Section 5.1) ✅

## Phase 2: Disclosure Handling

**Testing**: Unit tests for disclosure creation/parsing, RFC example tests (Section 5.1 disclosures) ✅

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

**Testing**: Unit tests for SD-JWT creation, RFC example tests (complete issuance flow from Section 5.1), nested structure tests (Section 6)

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

**Testing**: Unit tests for disclosure selection, integration tests for presentation creation, edge cases (no disclosures, all disclosures)

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

**Testing**: Unit tests for verification logic, RFC example tests (Section 5.2 presentations), error handling tests (invalid digests, missing disclosures)

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
   - Verify digest exists in payload (check both _sd arrays and array ellipsis objects)
   - Check no duplicate disclosures
5. If KB-JWT present:
   - Verify KB-JWT signature with holder's public key
   - Verify sd_hash matches SD-JWT
   - Verify nonce, audience, iat
6. Reconstruct processed payload
   - Replace digests in _sd arrays with claim values
   - Replace {"...": "<digest>"} objects in arrays with actual values
   - ✅ Array element processing implemented (see Verification.hs:processValueForArrays)

## Phase 6: Key Binding Support

**Testing**: Unit tests for KB-JWT creation/verification, integration tests for SD-JWT+KB flow, RFC example tests (Section 7)

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

**Testing**: Unit tests for serialization/deserialization, format validation tests, edge cases (empty disclosures, no KB-JWT) ✅

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

## Phase 9: Testing Strategy

### 9.1 Incremental Testing Approach

**Testing Philosophy**: Write tests incrementally alongside implementation, not at the end.

**Rationale**:
- Cryptographic code requires early verification - bugs compound and are hard to debug later
- RFC 9901 provides concrete examples (Section 5) that can be tested immediately
- Tests serve as documentation and usage examples
- Early feedback catches issues before they propagate
- Easier debugging when tests are written close to implementation

### 9.2 Test Implementation Schedule

**Tests are written during each phase:**

1. **Phase 1 (Core Types & Utils)** ✅ COMPLETED
   - Unit tests for base64url encoding/decoding
   - Unit tests for salt generation
   - Unit tests for hash algorithm parsing/conversion

2. **Phase 2 (Disclosure)** ✅ COMPLETED
   - Unit tests for disclosure creation/parsing
   - RFC example tests (Section 5.1 disclosures)
   - Edge cases (empty values, special characters)

3. **Phase 3 (Digest)** ✅ COMPLETED
   - Unit tests for digest computation
   - RFC example tests (verify known digests from Section 5.1)
   - Tests for all three hash algorithms (SHA-256, SHA-384, SHA-512)

4. **Phase 4 (Serialization)** ✅ COMPLETED
   - Unit tests for serialization/deserialization
   - Format validation tests
   - Edge cases (empty disclosures, no KB-JWT)

5. **Phase 5 (Issuance)** - ✅ COMPLETE
   - ✅ Unit tests for SD-JWT creation (basic)
   - ✅ Basic issuance flow working
   - ✅ Array element disclosures (markArrayElementDisclosable, processArrayForSelectiveDisclosure)
   - ✅ Decoy digest support (addDecoyDigest)
   - ✅ RFC example tests (Section 5.1 disclosures - basic digest verification)
   - ✅ JWK parsing from Text/JSON (parseJWKFromText implemented)
   - ✅ JWT signing integrated in createSDJWT (using SDJWT.JWT.signJWT)
   - ✅ Test key generation utilities (TestKeys.hs) with cached 2048-bit RSA keys
   - ✅ Ed25519 key generation utilities (generateTestEd25519KeyPair)
   - ✅ Tests using Ed25519 keys for JWT signing in issuance
   - ✅ RFC example tests (complete issuance flow from Section 5.1 - full JWT creation verified with RFC test vectors)
   - ✅ Tests for nested structures (Section 6.2 and 6.3)
   - ✅ Nested structure support in buildSDJWTPayload (recursive _sd arrays)
   - ✅ JSON Pointer syntax support with escaping (`~1` for `/`, `~0` for `~`)
   - ✅ Structured nested disclosures (Section 6.2 - parent stays, children selectively disclosable)
   - ✅ Recursive disclosures (Section 6.3 - parent itself selectively disclosable)

6. **Phase 6 (Presentation)** - ✅ COMPLETE
   - ✅ Unit tests for disclosure selection
   - ✅ Integration tests for presentation creation (basic)
   - ✅ Edge cases (no disclosures selected, all disclosures)
   - ✅ Key binding support (addKeyBindingToPresentation function)
   - ✅ Recursive disclosure handling (parent disclosures for nested structures)
   - ✅ Disclosure dependency validation (ensure parent disclosures included)
   - ✅ Tests for recursive disclosure handling (Section 6.3)
   - ✅ Tests for structured nested disclosures (Section 6.2 - parent not included)
   - ✅ JSON Pointer path parsing and handling
   - ✅ Automatic parent disclosure inclusion for recursive disclosures

7. **Phase 7 (Verification)** - ✅ COMPLETE
   - ✅ Unit tests for verification logic (basic)
   - ✅ Basic disclosure verification working
   - ✅ JWT signature verification (verifySDJWTSignature function using SDJWT.JWT.verifyJWT)
   - ✅ Key binding verification (verifyKeyBinding function using verifyKeyBindingJWT)
   - ✅ Complete verification flow (verifySDJWT with all steps)
   - ✅ RFC example tests (Section 5.2 presentations - object disclosures verified)
   - ✅ Actual JWT signature verification working (using real RSA keys in tests)
   - ✅ RFC example tests (Section 5.2 - array element disclosures in verification)
   - ✅ Array element disclosure processing in processPayload (recursive array processing implemented)
   - ✅ Recursive array processing to handle `{"...": "<digest>"}` objects in arrays during verification
   - ✅ Tests for array element disclosure processing
   - ✅ Tests using Ed25519 keys for JWT signature verification
   - ✅ Error handling tests (invalid digests, missing disclosures, duplicate disclosures, etc.)
   - ✅ Recursive disclosure verification (extracting digests from nested disclosures)

8. **Phase 8 (Key Binding)** - ✅ COMPLETE
   - ✅ KeyBinding.hs module exists
   - ✅ Unit tests for KB-JWT creation/verification
   - ✅ Basic KB-JWT creation and verification (computeSDHash, createKeyBindingJWT, verifyKeyBindingJWT)
   - ✅ KB-JWT signing/verification using real RSA keys (integrated with SDJWT.JWT)
   - ✅ KB-JWT signing/verification using Ed25519 keys (fully tested)
   - ✅ addKeyBindingToPresentation function implemented
   - ✅ Test key generation utilities support Ed25519 keys (generateTestEd25519KeyPair)
   - ✅ Tests using Ed25519 keys for KB-JWT signing/verification
   - ✅ Integration tests for SD-JWT+KB flow (end-to-end verified via RFC Section 5.2 test vectors)
   - ✅ RFC example tests (Section 5.2 SD-JWT+KB example verified)
   - ✅ RFC Section 7 verification requirements covered (Section 7 is the verification spec, covered via Section 5.2 tests)

### 9.3 Test Framework

- **hspec** - Primary testing framework (already added)
- **QuickCheck** - Property-based testing for edge cases
- **RFC Examples** - Direct tests against examples from RFC 9901 Section 5

### 9.4 Test Coverage Goals

- **Unit Tests**: Cover all public functions with happy paths and error cases
- **RFC Compliance**: Test against all examples in RFC 9901 Sections 5, 6, and 7
- **Edge Cases**: Empty inputs, malformed data, boundary conditions
- **Integration Tests**: End-to-end flows (issuance → presentation → verification)

## Dependencies

### Required Libraries

```yaml
dependencies:
  - base >= 4.14 && < 5
  - aeson >= 2.0
  - bytestring >= 0.11
  - text >= 2.0
  - cryptonite >= 0.30  # For cryptographic operations (TODO: Migrate to crypton when jose-jwt supports it - cryptonite is deprecated)
  
**Supported JWT Algorithms**:
- ✅ **RSA (RS256)**: Fully supported for signing and verification
- ✅ **Ed25519 (EdDSA)**: Fully supported for signing and verification
- ✅ **EC P-256 (ES256)**: Fully supported for signing (via SDJWT.JWT.EC module using cryptonite) and verification (via jose-jwt)
  - **Note**: EC signing is implemented in a separate module (SDJWT.JWT.EC) that can be removed once jose-jwt adds native EC signing support
  - memory >= 0.18      # For secure random generation
  - jose-jwt >= 0.10   # For JWT handling (currently depends on cryptonite)
  - base64-bytestring >= 1.2  # For base64url encoding
  - unordered-containers >= 0.2  # For Map
  - vector >= 0.13     # For arrays
```

### Optional Libraries

- `quickcheck` - Property-based testing
- `hspec` - Testing framework
- `lens` - Optional for easier data manipulation

## Implementation Order

**Note**: Tests are written incrementally alongside implementation, not at the end.

1. **Week 1**: Core types, utilities, and disclosure handling ✅
   - **Tests**: Unit tests for base64url, salt generation, hash algorithms, disclosure creation/parsing

2. **Week 2**: Digest computation and hash algorithms ✅
   - **Tests**: Unit tests for digest computation, RFC example tests (Section 5.1)

3. **Week 3**: Serialization and basic infrastructure ✅
   - **Tests**: Unit tests for serialization/deserialization, format validation

4. **Week 4**: SD-JWT issuance (basic cases) - ✅ MOSTLY COMPLETE
   - ✅ **Tests**: Unit tests for issuance (basic)
   - ✅ **Tests**: RFC example tests (Section 5.1 disclosures and digests)
   - ✅ **Implementation**: JWT signing integration (createSDJWT uses signJWT)
   - ✅ **Implementation**: Test key generation utilities (TestKeys.hs with cached 2048-bit RSA keys)
   - ✅ **Tests**: Complete RFC example tests with full JWT creation (RFC test vectors verified)

5. **Week 5**: SD-JWT issuance (nested and recursive) - ✅ COMPLETE
   - ✅ **Implementation**: Array element disclosures (markArrayElementDisclosable, processArrayForSelectiveDisclosure)
   - ✅ **Implementation**: Decoy digest support (addDecoyDigest)
   - ✅ **Tests**: Tests for nested structures (RFC Section 6.2 and 6.3), recursive disclosure tests
   - ✅ **Implementation**: Nested structure support (recursive _sd arrays)
   - ✅ **Implementation**: JSON Pointer syntax with escaping

6. **Week 6**: Presentation and disclosure selection - ✅ MOSTLY COMPLETE
   - ✅ **Tests**: Unit tests for disclosure selection, integration tests for presentation creation (basic)
   - ✅ **Implementation**: Key binding support, recursive disclosure handling
   - ✅ **Tests**: Tests for recursive disclosure handling (Section 6.3) and structured nested disclosures (Section 6.2)

7. **Week 7**: Verification (basic) - ✅ COMPLETE
   - ✅ **Tests**: Unit tests for verification logic (basic)
   - ✅ **Tests**: RFC example tests (Section 5.2 presentations - object disclosures)
   - ✅ **Tests**: RFC example tests for array element disclosures
   - ✅ **Implementation**: JWT signature verification (verifySDJWTSignature uses verifyJWT)
   - ✅ **Implementation**: Key binding verification working with real keys
   - ✅ **Implementation**: Array element disclosure processing in processPayload (recursive array processing)

8. **Week 8**: Key Binding support - ✅ COMPLETE
   - ✅ **Tests**: Unit tests for KB-JWT creation/verification
   - ✅ **Implementation**: KeyBinding.hs module, KB-JWT creation/verification
   - ✅ **Implementation**: KB-JWT signing/verification using real RSA keys
   - ✅ **Implementation**: Ed25519 key generation utilities (generateTestEd25519KeyPair)
   - ✅ **Tests**: Tests using Ed25519 keys for KB-JWT signing/verification
   - ✅ **Tests**: RFC example tests (Section 5.2 SD-JWT+KB examples - Section 7 is the verification spec, not test vectors)
   - ✅ **Tests**: Integration tests for complete SD-JWT+KB flow

9. **Week 9**: Code cleanup and refactoring - ✅ COMPLETE
   - ✅ **Module Organization**: Persona modules created (Issuer, Holder, Verifier), Internal namespace established
   - ✅ **Code Review**: Linter warnings fixed (unused imports, unused matches, name shadowing, incomplete patterns, overlapping patterns, unused local binds)
   - ✅ **Refactoring**: Code duplication reduced (extracted decodeDisclosures helper), common patterns identified
   - ✅ **Documentation**: Advanced/internal functions documented, module usage patterns documented
   - ✅ **Code Style**: Consistent formatting and naming conventions
   - ✅ **Test Coverage**: Comprehensive test suite (82 tests) covering all major functionality

10. **Week 10**: Security review and hardening - ✅ COMPLETE
   - ✅ **Security Audit**: Reviewed cryptographic operations - all secure
   - ✅ **Input Validation**: All inputs properly validated throughout codebase
   - ✅ **Constant-Time Operations**: Fixed timing attack vulnerability in digest comparisons
   - ✅ **Memory Safety**: Reviewed - no sensitive data exposed in error messages
   - ✅ **Dependency Review**: Reviewed dependencies - all secure, no known vulnerabilities
   - ✅ **Security Documentation**: Created SECURITY_REVIEW.md documenting findings and fixes

11. **Week 11**: User documentation - ⏳ PENDING
   - **README**: Comprehensive usage guide with examples
   - **API Documentation**: Complete Haddock documentation for all modules
   - **Tutorial**: Step-by-step guide for common use cases
   - **Examples**: Working examples for issuance, presentation, verification
   - **Migration Guide**: If applicable, guide for migrating from other libraries
   - **FAQ**: Common questions and troubleshooting

12. **Week 12**: Packaging and distribution - ⏳ PENDING
   - **Hackage**: Prepare package for Hackage upload
   - **Versioning**: Establish semantic versioning strategy
   - **Changelog**: Maintain CHANGELOG.md
   - **License**: Ensure LICENSE file is correct and complete
   - **CI/CD**: Set up automated testing and builds
   - **Benchmarks**: Add performance benchmarks if needed
   - **Release Notes**: Prepare release notes for initial version

## Security Considerations

1. **Salt Generation**: Use cryptographically secure random (128 bits minimum)
2. **Hash Algorithm**: Support SHA-256, SHA-384, SHA-512 (all are required)
3. **Signature Verification**: Properly verify all signatures
4. **Input Validation**: Validate all inputs (disclosures, digests, etc.)
5. **Constant-Time Operations**: Use constant-time comparisons where applicable
6. **Memory Safety**: Avoid exposing sensitive data unnecessarily

## Phase 9: Code Cleanup and Refactoring

### 9.1 Code Review Tasks

- [x] **Remove Unused Code** ✅ COMPLETED
  - ✅ Removed unused imports (isNothing, etc.)
  - ✅ Fixed unused matches (replaced with _)
  - ✅ Removed unused local binds
  - ✅ Fixed incomplete patterns
  - ✅ Fixed overlapping patterns

- [x] **Reduce Duplication** ✅ COMPLETED
  - ✅ Extracted `decodeDisclosures` helper function
  - ✅ Identified repeated patterns
  - ✅ Common functionality extracted where appropriate

- [x] **Module Organization** ✅ COMPLETED
  - ✅ Created persona-specific modules (SDJWT.Issuer, SDJWT.Holder, SDJWT.Verifier)
  - ✅ Moved implementation to SDJWT.Internal.* namespace (idiomatic Haskell)
  - ✅ Renamed Core to Internal for convention alignment
  - ✅ Reviewed module boundaries and exports
  - ✅ No circular dependencies
  - ✅ Optimized module exports (persona modules re-export only needed functionality)

- [x] **Code Style** ✅ MOSTLY COMPLETE
  - ✅ Consistent naming conventions
  - ✅ Follow Haskell best practices
  - ✅ Type signatures present where needed
  - ✅ Stricter GHC warnings enabled and fixed (unused locals, unused imports, shadowed bindings, etc.)
  - ⏳ Code formatting: Could run ormolu/brittany for final consistency pass (optional)

### 9.2 Test Coverage Analysis

- [x] **Coverage Measurement** ✅ COMPLETE
  - ✅ Comprehensive test suite with 82 tests
  - ✅ All RFC test vectors covered (Section 5.1 and 5.2)
  - ✅ All major code paths tested

- [x] **Coverage Gaps** ✅ COMPLETE
  - ✅ All public APIs have tests
  - ✅ Error handling paths tested
  - ✅ Edge cases covered (empty inputs, malformed data, etc.)

- [x] **Coverage Improvements** ✅ COMPLETE
  - ✅ Tests for all major functionality
  - ✅ Tests for error handling paths
  - ✅ Tests for edge cases
  - ✅ All public APIs tested

- [x] **Coverage Status** ✅ COMPLETE
  - ✅ Test suite comprehensive and passing
  - ✅ RFC compliance verified via test vectors
  - ✅ Integration tests cover end-to-end flows

### 9.3 Documentation Improvements

- [x] **Haddock Comments** ✅ MOSTLY COMPLETE
  - ✅ Module-level documentation added (all modules)
  - ✅ Public functions documented
  - ✅ Advanced/internal functions clearly marked
  - ✅ Usage examples in persona modules
  - ✅ Module usage patterns documented in main SDJWT module
  - ⏳ Additional usage examples could be added (optional enhancement)

- [x] **Code Comments** ✅ COMPLETE
  - ✅ Inline comments for complex logic (JSON Pointer parsing, nested structures)
  - ✅ Algorithm choices documented (RFC compliance noted)
  - ✅ Cryptographic operations explained (salt generation, hash algorithms)
  - ✅ RFC compliance points noted throughout codebase

## Phase 10: Security Review

### 10.1 Security Audit Checklist

- [x] **Cryptographic Operations** ✅ COMPLETE
  - ✅ Salt generation is cryptographically secure (cryptonite's secure RNG)
  - ✅ Hash algorithms used correctly (SHA-256, SHA-384, SHA-512)
  - ✅ Signature verification properly implemented (jose-jwt with explicit algorithm)
  - ✅ Fixed timing attacks in comparisons (constant-time comparison implemented)

- [x] **Input Validation** ✅ COMPLETE
  - ✅ All user inputs are validated (JWT format, disclosure format, JSON structure)
  - ✅ Malformed JWTs are rejected (format validation, base64url validation)
  - ✅ Invalid disclosures are handled safely (format validation, error handling)
  - ✅ Edge cases are handled (empty inputs, malformed data)

- [x] **Memory Safety** ✅ COMPLETE
  - ✅ Sensitive data is not exposed in error messages (no keys, no salts)
  - ✅ Keys are not logged or exposed (handled by jose-jwt)
  - ✅ Memory safety ensured by Haskell's type system
  - ✅ No buffer overflows (Haskell's safe memory management)

- [x] **Dependency Security** ✅ COMPLETE
  - ✅ Reviewed dependencies for known vulnerabilities (none found)
  - ✅ Dependencies are well-maintained and secure
  - ✅ Minimal dependency surface area
  - ✅ Security-critical dependencies documented

### 10.2 Testing for Security

- [ ] **Property-Based Testing**
  - Use QuickCheck for edge cases
  - Test cryptographic properties
  - Test error handling paths
  - Test with malformed inputs

- [ ] **Fuzzing**
  - Consider fuzzing for parsing functions
  - Test with random inputs
  - Test with boundary conditions

## Phase 11: User Documentation

### 11.1 Documentation Structure

- [ ] **README.md**
  - Project overview and purpose
  - Quick start guide
  - Installation instructions
  - Basic usage examples
  - Link to full documentation

- [ ] **API Documentation**
  - Complete Haddock documentation
  - All public APIs documented
  - Usage examples for each module
  - Type signatures and descriptions

- [ ] **Tutorial Guide**
  - Step-by-step issuance example
  - Step-by-step presentation example
  - Step-by-step verification example
  - Common patterns and use cases

- [ ] **Examples Directory**
  - Basic issuance example
  - Presentation with key binding
  - Verification example
  - Nested structures example
  - Array element disclosure example

### 11.2 Additional Documentation

- [ ] **CHANGELOG.md**
  - Version history
  - Breaking changes
  - New features
  - Bug fixes

- [ ] **FAQ**
  - Common questions
  - Troubleshooting guide
  - Performance tips
  - Migration from other libraries

## Phase 12: Packaging and Distribution

### 12.1 Hackage Preparation

- [ ] **Package Metadata**
  - Verify package.yaml/cabal file is complete
  - Check version number
  - Verify license field
  - Add maintainer information
  - Add category and tags

- [ ] **Build Configuration**
  - Ensure package builds on multiple GHC versions
  - Test on different platforms (Linux, macOS, Windows)
  - Verify all dependencies are available
  - Check build warnings

- [ ] **Documentation**
  - Generate Haddock documentation
  - Verify documentation builds correctly
  - Check for documentation warnings

### 12.2 Release Preparation

- [ ] **Versioning**
  - Establish semantic versioning strategy
  - Tag releases in git
  - Create release notes

- [ ] **CI/CD**
  - Set up automated testing
  - Set up automated builds
  - Set up automated documentation generation
  - Set up release automation (if applicable)

- [ ] **Quality Assurance**
  - Run full test suite
  - Verify all examples work
  - Check documentation is complete
  - Review for any remaining TODOs

## Future Enhancements

1. JWS JSON Serialization support (RFC Section 8)
2. Performance optimizations
3. Streaming support for large SD-JWTs
4. Additional hash algorithms (beyond SHA-256, SHA-384, SHA-512)
5. Custom claim processors
6. SD-JWT profile support
7. Additional JWT algorithms (beyond RS256, EdDSA, ES256)

## Notes

- Follow RFC 9901 specification strictly
- Ensure compatibility with existing JWT libraries
- Provide clear error messages
- Document all public APIs
- Include examples in documentation
- Consider performance for large payloads

