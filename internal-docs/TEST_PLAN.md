# SD-JWT Test Plan

This document provides a comprehensive overview of test coverage for the SD-JWT implementation, mapped to RFC 9901 sections and requirements.

## Test Suite Overview

**Total Test Count**: 224 examples  
**Test Files**: 11 test modules + 2 helper modules  
**Test Framework**: Hspec + QuickCheck (property-based testing)

### Test Modules

1. **UtilsSpec.hs** - Utility function tests (base64url, salt generation, text conversions)
2. **DigestSpec.hs** - Hash algorithm and digest computation tests
3. **DisclosureSpec.hs** - Disclosure creation, encoding, and decoding tests
4. **SerializationSpec.hs** - SD-JWT serialization/deserialization tests
5. **IssuanceSpec.hs** - SD-JWT issuance and payload construction tests
6. **PresentationSpec.hs** - Presentation creation and disclosure selection tests
7. **VerificationSpec.hs** - SD-JWT verification tests
8. **KeyBindingSpec.hs** - Key Binding JWT (KB-JWT) tests
9. **JWTSpec.hs** - JWT signing and verification tests
10. **RFCSpec.hs** - RFC 9901 test vector verification tests
11. **PropertySpec.hs** - Property-based tests (QuickCheck)
12. **EndToEndSpec.hs** - End-to-end integration tests

## RFC 9901 Coverage by Section

### Section 4: SD-JWT Structure

**Coverage**: ✅ Complete

- **4.1 SD-JWT Format**: Tested in `SerializationSpec.hs`
  - Serialization format: `<JWT>~<Disclosure 1>~...~<Disclosure N>~`
  - Deserialization parsing
  - Edge cases (empty disclosures, single disclosure)

- **4.2 Disclosure Format**: Tested in `DisclosureSpec.hs`
  - Object disclosure format: `[salt, claim_name, claim_value]`
  - Array disclosure format: `[salt, claim_value]`
  - Base64url encoding/decoding
  - RFC example disclosures verified

- **4.3 Key Binding JWT Format**: Tested in `KeyBindingSpec.hs`
  - KB-JWT structure: `<SD-JWT>~<KB-JWT>`
  - KB-JWT header requirements (`typ: "kb+jwt"`)
  - KB-JWT payload claims (aud, nonce, iat, sd_hash)

### Section 5: Examples

**Coverage**: ✅ Complete

- **5.1 Issuer-Signed JWT Example**: Tested in `RFCSpec.hs` and `IssuanceSpec.hs`
  - Complete issuer-signed JWT from RFC (lines 1223-1240)
  - All disclosures from RFC example verified
  - Individual disclosure digests verified:
    - `given_name` disclosure → digest `jsu9yVulwQQlhFlM_3JlzMaSFzglhQG0DpfayQwLUK4`
    - `family_name` disclosure → digest `TGf4oLbgwd5JQaHyKVQZU9UdGE0w5rtDsrZzfUaomLo`
    - Array element disclosure (nationalities) → digest `pFndjkZ_VCzmyTa6UjlZo3dh-ko8aIKQc9DlGzhaVYo`
  - Complete SD-JWT with all disclosures (lines 1244-1272)
  - JWT signature verification with RFC public key

- **5.2 Presentation Example**: Tested in `RFCSpec.hs` and `VerificationSpec.hs`
  - SD-JWT+KB example (lines 1283-1310)
  - Selected disclosures verification
  - KB-JWT verification
  - Complete presentation flow

### Section 6: Nested Structures

**Coverage**: ✅ Complete

- **6.1 JSON Pointer Syntax**: Tested in `IssuanceSpec.hs` and `PresentationSpec.hs`
  - JSON Pointer path parsing (`/` separator)
  - Escaping (`~1` for `/`, `~0` for `~`)
  - Nested path handling

- **6.2 Structured SD-JWT**: Tested in `IssuanceSpec.hs` and `PresentationSpec.hs`
  - Parent object stays in payload
  - Children marked as selectively disclosable
  - `_sd` array created within parent object
  - Presentation selection excludes parent (parent not selectively disclosable)

- **6.3 Recursive Disclosures**: Tested in `IssuanceSpec.hs` and `PresentationSpec.hs`
  - Parent itself is selectively disclosable
  - Parent disclosure contains `_sd` array with child digests
  - Automatic parent inclusion when selecting nested claims
  - Disclosure dependency validation

### Section 7: Verification

**Coverage**: ✅ Complete (Note: Section 7 is the verification specification, not test vectors)

- **7.1 Signature Verification**: Tested in `VerificationSpec.hs`
  - Issuer signature verification
  - Algorithm validation (RFC 8725bis requirement)
  - Typ header validation (liberal and strict modes)
  - Error handling (invalid signatures, wrong keys)

- **7.2 Disclosure Verification**: Tested in `VerificationSpec.hs`
  - Hash algorithm extraction (`_sd_alg` or default SHA-256)
  - Digest computation and matching
  - Duplicate disclosure detection
  - Missing disclosure detection
  - Array element disclosure verification

- **7.3 Key Binding Verification**: Tested in `KeyBindingSpec.hs` and `VerificationSpec.hs`
  - KB-JWT signature verification
  - `sd_hash` computation and verification
  - Nonce, audience, and `iat` validation
  - Holder public key extraction from `cnf` claim

- **7.4 Payload Processing**: Tested in `VerificationSpec.hs`
  - Digest replacement in `_sd` arrays
  - Array element processing (`{"...": "<digest>"}` replacement)
  - Recursive disclosure processing
  - Final payload reconstruction

### Section 8: JWS JSON Serialization

**Coverage**: ❌ Not Implemented

- JWS JSON Serialization format not implemented
- Marked as future enhancement in implementation plan

### Section 9: Security Considerations

**Coverage**: ✅ Addressed

- **9.1 Hash Algorithm**: Tested in `DigestSpec.hs`
  - Support for SHA-256, SHA-384, SHA-512
  - Default algorithm (SHA-256)
  - Algorithm parsing and validation

- **9.2 Salt Generation**: Tested in `UtilsSpec.hs` and `PropertySpec.hs`
  - Cryptographically secure random generation
  - Minimum 128 bits (16 bytes) per RFC requirement
  - Uniqueness verification

- **9.3 Disclosure Uniqueness**: Tested in `VerificationSpec.hs`
  - Duplicate disclosure detection
  - Salt uniqueness enforcement

- **9.4 Key Binding Security**: Tested in `KeyBindingSpec.hs`
  - KB-JWT signature verification
  - `sd_hash` binding verification
  - Constant-time comparison for `sd_hash` (timing attack prevention)

- **9.5 Typ Header**: Tested in `JWTSpec.hs` and `VerificationSpec.hs`
  - Typ header support for issuer-signed JWTs (Section 9.11)
  - Typ header requirement for KB-JWT (`kb+jwt`)
  - Typ header validation modes (liberal/strict)

- **9.6 EC Signing Timing Attack**: Documented in `Issuer.hs` and `README.md`
  - Security warning added to documentation
  - Recommendation to use RSA or Ed25519 for timing-sensitive applications

### Section 10: IANA Considerations

**Coverage**: ✅ Implemented

- Hash algorithm identifiers (`sha-256`, `sha-384`, `sha-512`)
- Typ header values (`sd-jwt`, `kb+jwt`, application-specific)

## Test Coverage by Component

### Core Components

#### Hash Algorithms (`DigestSpec.hs`)
- ✅ SHA-256, SHA-384, SHA-512 support
- ✅ Algorithm parsing (`parseHashAlgorithm`)
- ✅ Algorithm to text conversion (`hashAlgorithmToText`)
- ✅ Default algorithm (SHA-256)
- ✅ Digest computation (`computeDigest`)
- ✅ Digest verification (`verifyDigest`)
- ✅ RFC example digest verification

#### Disclosures (`DisclosureSpec.hs`)
- ✅ Object disclosure creation (`createObjectDisclosure`)
- ✅ Array disclosure creation (`createArrayDisclosure`)
- ✅ Disclosure encoding (`encodeDisclosure`)
- ✅ Disclosure decoding (`decodeDisclosure`)
- ✅ Claim name extraction (`getDisclosureClaimName`)
- ✅ Claim value extraction (`getDisclosureValue`)
- ✅ RFC example disclosure verification
- ✅ Edge cases (empty values, special characters)

#### Serialization (`SerializationSpec.hs`)
- ✅ SD-JWT serialization (`serializeSDJWT`)
- ✅ SD-JWT deserialization (`deserializeSDJWT`)
- ✅ Presentation serialization (`serializePresentation`)
- ✅ Presentation deserialization (`deserializePresentation`)
- ✅ Tilde-separated format parsing (`parseTildeSeparated`)
- ✅ Edge cases (empty disclosures, no KB-JWT)

#### Issuance (`IssuanceSpec.hs`)
- ✅ SD-JWT creation (`createSDJWT`)
- ✅ SD-JWT with typ header (`createSDJWTWithTyp`)
- ✅ Payload construction (`buildSDJWTPayload`)
- ✅ Selective disclosure marking (`markSelectivelyDisclosable`)
- ✅ Array element disclosure (`processArrayForSelectiveDisclosure`)
- ✅ Decoy digest generation (`addDecoyDigest`)
- ✅ Nested structure support (Sections 6.2, 6.3)
- ✅ JSON Pointer syntax handling
- ✅ RFC example tests (Section 5.1)
- ✅ Key type support (RSA defaults to PS256, RS256 available, EC, Ed25519)

#### Presentation (`PresentationSpec.hs`)
- ✅ Disclosure selection (`selectDisclosuresByNames`)
- ✅ Presentation creation (`createPresentation`)
- ✅ Recursive disclosure handling (Section 6.3)
- ✅ Structured disclosure handling (Section 6.2)
- ✅ JSON Pointer path parsing
- ✅ Parent disclosure inclusion
- ✅ Edge cases (all disclosures, no disclosures)

#### Verification (`VerificationSpec.hs`)
- ✅ Complete verification (`verifySDJWT`)
- ✅ Signature verification (`verifySDJWTSignature`)
- ✅ Disclosure verification (`verifyDisclosures`)
- ✅ Key binding verification (`verifyKeyBinding`)
- ✅ Payload processing (`processPayload`)
- ✅ Hash algorithm extraction (`extractHashAlgorithm`)
- ✅ RFC example tests (Section 5.2)
- ✅ Array element processing
- ✅ Error handling (invalid signatures, missing disclosures, duplicates)

#### Key Binding (`KeyBindingSpec.hs`)
- ✅ KB-JWT creation (`createKeyBindingJWT`)
- ✅ SD hash computation (`computeSDHash`)
- ✅ KB-JWT verification (`verifyKeyBindingJWT`)
- ✅ Key binding addition (`addKeyBindingToPresentation`)
- ✅ Typ header validation (`kb+jwt`)
- ✅ Key type support (RSA defaults to PS256, RS256 available, EC, Ed25519)
- ✅ Edge cases (empty presentations, different hash algorithms)

#### JWT Operations (`JWTSpec.hs`)
- ✅ JWT signing (`signJWT`)
- ✅ JWT signing with typ (`signJWTWithTyp`)
- ✅ JWT verification (`verifyJWT`)
- ✅ JWK parsing (`parseJWKFromText`)
- ✅ Algorithm detection (`detectKeyAlgorithm`)
- ✅ Key type support (RSA defaults to PS256, RS256 available via JWK `alg` field, EC P-256 with ES256, Ed25519 with EdDSA)
- ✅ RSA-PSS (PS256) is default for RSA keys (security best practice)
- ✅ RS256 can be explicitly requested via JWK `alg` field (RFC 7517)
- ✅ Typ header support
- ✅ PS256 (default) and RS256 (explicit) signing and verification tests

### Integration Tests

#### End-to-End Tests (`EndToEndSpec.hs`)
- ✅ Complete issuer → holder → verifier flow (RSA)
- ✅ Complete issuer → holder → verifier flow (EC P-256)
- ✅ Complete issuer → holder → verifier flow (Ed25519)
- ✅ Key binding flow (RSA)
- ✅ Key binding flow (Ed25519)
- ✅ Error paths (wrong issuer key, non-existent disclosures)
- ✅ Edge cases (empty disclosures, all disclosures)

#### RFC Test Vectors (`RFCSpec.hs`)
- ✅ RFC Section 5.1 issuer-signed JWT verification
- ✅ RFC Section 5.1 complete SD-JWT verification
- ✅ RFC Section 5.2 SD-JWT+KB verification
- ✅ RFC public key verification
- ✅ RFC disclosure verification

### Property-Based Tests (`PropertySpec.hs`)

- ✅ Base64url encoding/decoding round-trips
- ✅ Digest computation consistency
- ✅ Disclosure encoding/decoding round-trips
- ✅ Hash algorithm parsing round-trips
- ✅ Salt generation uniqueness
- ✅ Text/ByteString conversions
- ✅ Serialization/deserialization round-trips
- ✅ 26 property-based tests total

## Test Coverage Gaps

### Known Gaps

1. **Section 8: JWS JSON Serialization**
   - Not implemented (marked as future enhancement)
   - No tests for JWS JSON format

2. **Additional Hash Algorithms**
   - Only SHA-256, SHA-384, SHA-512 supported (as required by RFC)
   - No tests for unsupported algorithms (expected to fail)

3. **Performance Tests**
   - No benchmarks or performance tests
   - No stress tests for large payloads

4. **Fuzzing**
   - No fuzzing tests for parsing functions
   - No random input testing beyond QuickCheck

### Potential Enhancements

1. **Additional Key Types**
   - Currently supports RSA (PS256 default, RS256 available), EC P-256 (ES256), Ed25519 (EdDSA)
   - Could add EC P-384, EC P-521, PS384, PS512

2. **Error Message Testing**
   - Could add tests verifying error message clarity
   - Could test error message internationalization

3. **Concurrency Tests**
   - No tests for concurrent SD-JWT operations
   - No tests for thread safety

## Test Statistics

- **Total Test Files**: 11 test modules
- **Total Test Examples**: 224
- **Property-Based Tests**: 26
- **RFC Test Vector Tests**: 3
- **End-to-End Tests**: 9
- **Unit Tests**: ~186 (includes PS256 test)

## Test Execution

```bash
# Run all tests
stack test

# Run specific test module
stack test --test-arguments "--match UtilsSpec"

# Run with coverage
stack test --coverage
```

## Test Maintenance

### Adding New Tests

1. **RFC Compliance**: When adding features, add corresponding RFC test vectors
2. **Property Tests**: Add property-based tests for round-trip operations
3. **Edge Cases**: Test boundary conditions and error paths
4. **Integration**: Add end-to-end tests for new flows

### Test Organization

- **Module Tests**: One test file per implementation module
- **RFC Tests**: Centralized in `RFCSpec.hs` for RFC test vectors
- **End-to-End Tests**: Centralized in `EndToEndSpec.hs` for integration tests
- **Property Tests**: Centralized in `PropertySpec.hs` for QuickCheck tests

## Conclusion

The test suite provides comprehensive coverage of RFC 9901 requirements:

- ✅ **All RFC examples covered** (Sections 5.1, 5.2)
- ✅ **All nested structure patterns covered** (Sections 6.2, 6.3)
- ✅ **All verification requirements covered** (Section 7)
- ✅ **All security considerations addressed** (Section 9)
- ✅ **End-to-end flows tested** (issuer → holder → verifier)
- ✅ **Property-based testing** for robustness
- ✅ **Multiple key types** (RSA defaults to PS256, RS256 available, EC P-256, Ed25519)

The test suite ensures RFC 9901 compliance and provides confidence in the implementation's correctness and security.

