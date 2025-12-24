# Security Review - Post jose Migration

## Overview

This document verifies that all security properties from the original security review (`SECURITY_REVIEW.md`) still hold after migrating from `jose-jwt` to `jose` library.

## Migration Summary

- **Old Library**: `jose-jwt` (>= 0.9)
- **New Library**: `jose` (>= 0.10)
- **Reason**: Native EC signing support, native `typ` header support, cleaner API
- **Trade-off**: EC signing has timing attack caveat (acceptable per user decision)

## Security Properties Verification

### ✅ 1. Timing Attack Vulnerability (STILL FIXED)

**Status**: ✅ **VERIFIED - Still Fixed**

- `constantTimeEq` still used in `SDJWT.Internal.Digest.verifyDigest`
- `constantTimeEq` still used in `SDJWT.Internal.KeyBinding.verifyKeyBindingJWT`
- Implementation unchanged - uses `Data.ByteArray.constEq` from cryptonite

**Verification**: ✅ **PASS**

### ✅ 2. Cryptographic Operations

#### Salt Generation
**Status**: ✅ **VERIFIED - Still Secure**
- Still uses `Crypto.Random.getRandomBytes` from cryptonite
- Still generates 128 bits (16 bytes)
- No changes to salt generation

**Verification**: ✅ **PASS**

#### Hash Algorithms
**Status**: ✅ **VERIFIED - Still Secure**
- Still uses cryptonite's `Crypto.Hash` module
- Still supports SHA-256, SHA-384, SHA-512
- No changes to hash computation

**Verification**: ✅ **PASS**

#### Signature Verification
**Status**: ✅ **VERIFIED - RFC 8725bis Compliant (IMPROVED)**

**Changes**:
- ✅ **Algorithm Validation**: Now explicitly validates algorithm from header matches key type BEFORE verification
- ✅ **RFC 8725bis Compliance**: Algorithm from header is NOT trusted - validated against key type
- ✅ **Algorithm Whitelist**: Still enforced via `toJwsAlg` (RS256, EdDSA, ES256)
- ✅ **"none" Algorithm Rejection**: jose uses typed `JWA.Alg` values - "none" is not a valid algorithm type
- ✅ **JWE Rejection**: `Compact.decodeCompact` with `JWS.CompactJWS` type ensures only JWS can be decoded
- ✅ **Case-Sensitive Comparison**: Enforced via typed `JWA.Alg` values

**Code Location**: `SDJWT.Internal.JWT.verifyJWT` (lines 229-257)

**Key Security Improvement**:
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

**Verification**: ✅ **PASS (IMPROVED)**

#### JWT Header Validation
**Status**: ✅ **VERIFIED - Still Implemented**

- ✅ **KB-JWT typ validation**: Still required and enforced (RFC 9901 Section 4.3)
- ✅ **Issuer-signed JWT typ**: Still optional but supported via `requiredTyp` parameter
- ✅ **Native typ support**: jose library provides native `typ` header support via lenses

**Verification**: ✅ **PASS**

#### Constant-Time Operations
**Status**: ✅ **VERIFIED - Still Fixed**
- Digest comparisons still use `constantTimeEq`
- Hash comparisons still use `constantTimeEq`
- No changes to constant-time operations

**Verification**: ✅ **PASS**

### ✅ 3. Input Validation

**Status**: ✅ **VERIFIED - Still Validated**

All input validation remains unchanged:
- ✅ JWT parsing: Still validates format, base64url encoding, JSON structure
- ✅ Disclosure parsing: Still validates format, encoding, structure
- ✅ JSON parsing: Still uses safe parsers
- ✅ Base64url decoding: Still uses safe decoder
- ✅ Hash algorithm parsing: Still validates against whitelist

**Verification**: ✅ **PASS**

### ✅ 4. Memory Safety

**Status**: ✅ **VERIFIED - Still Safe**

- ✅ Error messages: Still don't expose private keys, salts, or claim names
- ✅ Key handling: Still passed as Text (JWK format), not logged
- ✅ Salt handling: Still not exposed in error messages

**Verification**: ✅ **PASS**

### ✅ 5. Dependency Security

**Status**: ✅ **VERIFIED - Updated**

**Dependencies Review**:

- ✅ **cryptonite** (>= 0.30): Still used (unchanged)
  - Still needed for hashing and random number generation
  - Note: cryptonite is deprecated in favor of crypton, but still maintained

- ✅ **jose** (>= 0.10): ✅ **NEW** - Replaces jose-jwt
  - Handles JWT signing/verification
  - Well-tested library
  - Supports EC signing (ES256) with timing attack caveat (acceptable per user decision)
  - Native `typ` header support
  - No known critical vulnerabilities

- ✅ **lens** (>= 4.16): ✅ **NEW** - Required by jose
  - Standard Haskell library for lens operations
  - Well-maintained
  - No known critical vulnerabilities

- ✅ **aeson** (>= 2.0): Still used (unchanged)
- ✅ **base64-bytestring** (>= 1.2): Still used (unchanged)

**Verification**: ✅ **PASS**

## RFC 8725bis Compliance

**Status**: ✅ **VERIFIED - Still Fully Compliant**

All RFC 8725bis requirements still met:

1. ✅ **Algorithm Verification**: Algorithm from header validated against key type (IMPROVED)
2. ✅ **Rejection of Unsecured JWTs**: "none" algorithm cannot exist in jose's typed system
3. ✅ **Encryption-Signature Confusion Prevention**: Type system prevents JWE decoding as JWS
4. ✅ **Algorithm Whitelist**: Still enforced (RS256, EdDSA, ES256)
5. ✅ **Header Validation**: Still validates header format and extracts algorithm
6. ✅ **Key Validation**: Still validates JWK format and key type

**Verification**: ✅ **PASS (IMPROVED)**

## Security Improvements from Migration

1. **Better Algorithm Validation**: Now explicitly validates algorithm from header matches key type BEFORE verification (RFC 8725bis compliance improved)
2. **Type Safety**: jose's typed algorithms (`JWA.Alg`) provide compile-time safety against invalid algorithms
3. **Native typ Support**: No manual header construction needed - jose handles it natively
4. **Code Simplification**: Removed ~167 lines of complex EC signing code

## Potential Security Considerations

### ⚠️ EC Signing Timing Attack

**Status**: ⚠️ **ACCEPTABLE** (per user decision)

- jose library's EC signing implementation has a timing attack caveat
- User explicitly accepted this trade-off: "if it's only the timing issue, I will take it"
- This affects signing only, not verification
- For most use cases, this is acceptable

**Mitigation**: Documented in code and accepted by user.

## Conclusion

**All security properties from the original security review still hold after migration:**

- ✅ Timing attack vulnerability: Still fixed
- ✅ Cryptographic operations: Still secure (improved algorithm validation)
- ✅ Input validation: Still validated
- ✅ Memory safety: Still safe
- ✅ Dependency security: Updated (jose replaces jose-jwt)
- ✅ RFC 8725bis compliance: Still compliant (improved)

**Status**: ✅ **SECURITY REVIEW PASSED**

The migration to `jose` maintains all security properties and improves RFC 8725bis compliance through explicit algorithm validation.

## Date

Verified: After migration from `jose-jwt` to `jose` (December 2024)

