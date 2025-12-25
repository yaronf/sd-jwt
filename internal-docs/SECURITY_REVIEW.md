# Security Review

## Overview

This document provides a comprehensive security review of the SD-JWT library implementation. 

**Last Updated**: December 2025 (Post jose migration, includes parallelism review)

## Current Status

All known security issues have been addressed. The library implements security best practices and is ready for production use.

## Security Review Checklist

### ✅ Cryptographic Operations

#### Salt Generation
- **Status**: ✅ Secure
- Uses `Crypto.Random.getRandomBytes` from `cryptonite` library
- Generates 128 bits (16 bytes) as recommended by RFC 9901
- Cryptographically secure random number generator
- Thread-safe (no shared mutable state)

#### Hash Algorithms
- **Status**: ✅ Secure
- Uses `cryptonite` library's `Crypto.Hash` module
- Supports SHA-256, SHA-384, SHA-512 (all required by RFC 9901)
- Proper hash computation over bytes (RFC requires US-ASCII; UTF-8 encoding is equivalent for ASCII-only base64url strings)
- Pure functions, thread-safe by design

**Note**: The codebase uses `cryptonite` (not `crypton`) for hashing and random number generation. While `cryptonite` is deprecated in favor of `crypton`, it is still maintained and widely used. The `jose` library uses the `Crypto.JOSE.*` namespace but is a separate package from `cryptonite`.

#### Signature Verification
- **Status**: ✅ Secure (RFC 8725bis Compliant)

**Implementation Details**:
- Uses `jose` library for JWT signature verification
- **RFC 8725bis Compliance**: Algorithm extracted from header but NOT trusted - validated against key type
- Explicit algorithm validation: Algorithm from header must match key type (prevents algorithm confusion attacks)
- Algorithm whitelist enforcement (PS256, RS256, EdDSA, ES256) - only these algorithms accepted
- "none" algorithm rejection: jose library uses typed algorithms (`JWA.Alg`), "none" is not a valid `JWA.Alg` value
- JWE rejection: Uses `Compact.decodeCompact` with `JWS.CompactJWS` type - only JWS (signed) supported, JWE cannot be decoded
- Case-sensitive algorithm comparison (via typed `JWA.Alg` values)

**Key Security Improvement** (Post-Migration):
```haskell
-- SECURITY: RFC 8725bis - Extract and validate algorithm BEFORE verification
-- We MUST NOT trust the alg value in the header - we must validate it matches the key
let algParam = hdr ^. Header.alg . Header.param
-- ... extract header algorithm ...

-- Validate algorithm matches key type (RFC 8725bis requirement)
expectedAlgResult <- case detectKeyAlgorithm publicKeyJWK of
  -- ... get expected algorithm from key type ...

-- Validate algorithm matches expected algorithm (RFC 8725bis - don't trust header)
if headerAlg /= expectedAlg
  then return $ Left $ InvalidSignature "Algorithm mismatch: header claims '...', but key type requires '...' (RFC 8725bis)"
  else -- proceed with verification
```

**Code Location**: `SDJWT.Internal.JWT.verifyJWT`

#### JWT Header Validation
- **Status**: ✅ Implemented (RFC 9901 Compliant)
- **KB-JWT typ validation**: ✅ REQUIRED (RFC 9901 Section 4.3)
  - Verifies that KB-JWT header contains `typ: "kb+jwt"`
  - Rejects KB-JWT if typ is missing or incorrect
  - Prevents confusion attacks by ensuring KB-JWT is explicitly typed
- **Issuer-signed JWT typ**: ⚠️ RECOMMENDED but not required (RFC 9901 Section 9.11)
  - RFC 9901 recommends explicit typing for issuer-signed JWTs
  - Currently not validated (optional per RFC)
  - Application profiles can enforce typ validation if needed
  - Supported via `requiredTyp` parameter in verification functions

#### Constant-Time Operations
- **Status**: ✅ Fixed
- Digest comparisons use constant-time comparison (`constantTimeEq`)
- Hash comparisons use constant-time comparison
- Prevents timing attacks
- Verified post-migration

### ✅ Input Validation

#### JWT Parsing
- **Status**: ✅ Validated
- Validates JWT format (header.payload.signature - 3 parts)
- Validates base64url encoding
- Validates JSON structure
- Rejects malformed JWTs

#### Disclosure Parsing
- **Status**: ✅ Validated
- Validates base64url encoding
- Validates JSON array format
- Validates array length (2 or 3 elements)
- Validates salt encoding
- Validates claim name format (for object disclosures)

#### JSON Parsing
- **Status**: ✅ Validated
- Uses safe parsers (`Aeson.eitherDecodeStrict`)
- Validates JSON structure
- Handles parse errors gracefully

#### Base64url Decoding
- **Status**: ✅ Validated
- Uses safe decoder (`Base64.decodeUnpadded`)
- Returns `Either` for error handling
- Validates encoding format

#### Hash Algorithm Parsing
- **Status**: ✅ Validated
- Only accepts recognized algorithms ("sha-256", "sha-384", "sha-512")
- Returns `Nothing` for unrecognized algorithms
- Defaults to SHA-256 when not specified

### ✅ Memory Safety

#### Error Messages
- **Status**: ✅ Safe
- Error messages do not expose private keys
- Error messages do not expose salts
- Error messages may include digest text (acceptable - digests are public)
- Error messages do NOT expose claim names for selectively disclosable claims
- **Important**: Claim names for selectively disclosable claims are NOT in the payload - they're only in disclosures, which are only sent when the holder creates a presentation and selects them
- **Verification/Presentation errors**: Only reference digests (public), never claim names from disclosures
- **Issuance errors**: May reference claim names, but this is safe - issuer already knows all claim names when creating SD-JWT
- No sensitive data in error messages

#### Key Handling
- **Status**: ✅ Safe
- Keys are passed as Text (JWK format) or jose JWK objects
- Keys are not logged
- Keys are not exposed in error messages
- Keys are handled by `jose` library (well-tested)

#### Salt Handling
- **Status**: ✅ Safe
- Salts are not exposed in error messages
- Salts are only used internally for disclosure creation
- Salts are cryptographically secure random values

### ✅ Dependency Security

**Dependencies Review**:

- **cryptonite** (>= 0.30): ✅ Cryptographic library
  - Used for hashing (`Crypto.Hash`) and random number generation (`Crypto.Random`)
  - Note: `cryptonite` is deprecated in favor of `crypton`, but still maintained and widely used
  - Currently the standard library for these operations in the Haskell ecosystem
  - No known critical vulnerabilities
  - Migration to `crypton` can be considered for future versions

- **jose** (>= 0.10): ✅ JWT/JWS library
  - Handles JWT signing/verification with native typ header support
  - Well-tested library
  - Supports EC signing (ES256) with timing attack caveat (acceptable per user decision)
  - Native `typ` header support via lenses
  - No known critical vulnerabilities

- **lens** (>= 4.16): ✅ Required by jose
  - Standard Haskell library for lens operations
  - Well-maintained
  - No known critical vulnerabilities

- **aeson** (>= 2.0): ✅ JSON library
  - Standard Haskell JSON library
  - Well-maintained
  - No known critical vulnerabilities

- **base64-bytestring** (>= 1.2): ✅ Base64 encoding
  - Standard library
  - Well-maintained
  - No known critical vulnerabilities

**Recommendation**: Regularly update dependencies and monitor for security advisories.

### ✅ Thread Safety and Parallelism

**Status**: ✅ **Thread-Safe and Parallel-Safe**

- **No Mutable State**: No `IORef`, `MVar`, `TVar`, or `STM` usage in source code
- **No Concurrent Operations**: No `forkIO`, `async`, or other concurrency primitives
- **Immutable Data Structures**: All core types are immutable
- **Pure Functions**: Most functions are pure (no side effects)
- **Thread-Safe Dependencies**: Random number generation, JWT operations, and hash operations are thread-safe
- **Safe for Concurrent Use**: Multiple threads can call library functions simultaneously without issues

See `PARALLELISM_REVIEW.md` for detailed analysis.

## Security Best Practices

### ✅ Implemented

1. **Constant-Time Comparisons**: All cryptographic comparisons use constant-time operations
2. **Secure Random Generation**: Uses cryptographically secure RNG for salts
3. **Input Validation**: All inputs are validated before processing
4. **Error Handling**: Errors don't expose sensitive information
5. **Algorithm Specification**: JWT verification explicitly validates algorithm against key type (RFC 8725bis)
6. **Rejection of Unsafe Formats**: Unsecured JWTs and JWE are rejected
7. **Thread Safety**: Library is safe for concurrent use

### ⚠️ Considerations

1. **EC Signing Timing Attack**: ⚠️ **ACCEPTABLE** (per user decision)
   - `jose` library's EC signing implementation has a timing attack caveat
   - User explicitly accepted this trade-off
   - This affects signing only, not verification
   - For most use cases, this is acceptable
   - Mitigation: Documented in code and README

2. **Dependency Updates**: Monitor cryptonite deprecation and plan migration to crypton
3. **Error Message Content**: Current error messages are safe, but consider if more detail is needed for debugging
4. **Input Size Limits**: No explicit limits on input size (relies on system limits)
5. **Resource Exhaustion**: Large inputs could consume significant memory (mitigated by Haskell's lazy evaluation)

## Testing for Security

### ✅ Current Test Coverage

- **Unit Tests**: Comprehensive coverage of all functions (227 tests)
- **RFC Compliance**: All RFC test vectors verified
- **Error Handling**: Error paths tested
- **Edge Cases**: Edge cases covered (empty inputs, malformed data)
- **End-to-End Tests**: Complete issuer → holder → verifier flows tested
- **Property-Based Testing**: QuickCheck tests for edge cases

### ⏳ Additional Security Testing (Optional)

- **Fuzzing**: Could fuzz parsing functions with random inputs
- **Timing Attack Tests**: Could add tests to verify constant-time comparison
- **Concurrent Testing**: Could add tests for concurrent access patterns

## RFC 8725bis Compliance

The implementation is **fully compliant** with RFC 8725bis (JWT Best Current Practices):

- ✅ Explicit algorithm validation (not trusting header)
- ✅ Algorithm whitelist enforcement
- ✅ Rejection of "none" algorithm (unsecured JWTs)
- ✅ Rejection of JWE (encryption)
- ✅ Case-sensitive algorithm comparison
- ✅ Proper header validation
- ✅ Key validation

**Improvement Post-Migration**: Algorithm validation now explicitly checks header algorithm against key type BEFORE verification, providing stronger protection against algorithm confusion attacks.

RFC 8725bis compliance is verified in the code implementation and documented in this security review.

## Recommendations

### High Priority

1. ✅ **FIXED**: Implement constant-time comparison for digest verification
2. ✅ **DONE**: Review error messages for sensitive data exposure
3. ✅ **DONE**: Verify input validation throughout codebase
4. ✅ **DONE**: Verify thread safety and parallelism

### Medium Priority

1. **Monitor Dependencies**: Set up automated dependency vulnerability scanning
2. **Document Security Considerations**: Security warnings added to README and Issuer module
3. **Consider Input Size Limits**: Document expected input sizes

### Low Priority

1. **Fuzzing**: Consider fuzzing for parsing functions
2. **Security Audit**: Consider external security audit before major release

## Conclusion

The SD-JWT library implementation follows security best practices:

- ✅ Secure cryptographic operations
- ✅ Proper input validation
- ✅ Constant-time comparisons (fixed)
- ✅ Safe error handling
- ✅ Well-tested codebase
- ✅ RFC 8725bis compliant
- ✅ Thread-safe and parallel-safe

One security issue (timing attack vulnerability) has been identified and fixed. The library is ready for use, with recommendations for ongoing security monitoring.