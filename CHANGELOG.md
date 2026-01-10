# Changelog for `sd-jwt`

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to the
[Haskell Package Versioning Policy](https://pvp.haskell.org/).

## 0.1.0.1 - 2025-01-10

### Fixed
- Corrected documentation regarding RS256 deprecation status: RS256 (RSA-PKCS#1 v1.5) is deprecated for encryption per draft-ietf-jose-deprecate-none-rsa15, but remains valid for signatures. Previous documentation incorrectly stated RS256 was deprecated for signatures.

### Documentation
- Updated README.md, source code comments, and module documentation to clarify RS256 deprecation status
- PS256 (RSA-PSS) remains the recommended default for RSA keys

## 0.1.0.0 - 2025-01-09

### Added
- Initial release of SD-JWT library implementing RFC 9901
- SD-JWT issuance (issuer side)
- SD-JWT presentation (holder side)
- SD-JWT verification (verifier side)
- Key Binding support (SD-JWT+KB) per RFC 9901 Section 4.3
- Nested and recursive disclosures (RFC 9901 Sections 6.2, 6.3)
- Multiple hash algorithms: SHA-256 (default), SHA-384, SHA-512
- Multiple signing algorithms:
  - PS256 (RSA-PSS) - Default for RSA keys, recommended for security
  - RS256 (RSA-PKCS#1 v1.5) - Supported for signatures (deprecated for encryption per draft-ietf-jose-deprecate-none-rsa15)
  - ES256 (EC P-256) - Elliptic Curve signing
  - EdDSA (Ed25519) - Recommended for high-security applications
- Persona-specific modules: `SDJWT.Issuer`, `SDJWT.Holder`, `SDJWT.Verifier`
- Comprehensive test suite (>300 tests including property-based tests)
- RFC 9901 test vector verification
- End-to-end integration tests
- Property-based testing with QuickCheck
- Interoperability testing against the Python reference implementation
- Complete Haddock documentation

### Security
- PS256 (RSA-PSS) is the default algorithm for RSA keys (security best practice)
- RS256 (RSA-PKCS#1 v1.5) is deprecated for encryption per draft-ietf-jose-deprecate-none-rsa15, but remains valid for signatures
- EC signing timing attack warning documented (affects signing only, not verification)
- RFC 8725bis compliance: algorithm validation, typ header support, "none" algorithm rejection

### Documentation
- Comprehensive README with usage examples
- Internal implementation plan documentation
- Test plan documentation mapping tests to RFC sections
- Security review documentation
- RFC 8725bis compliance review

### Technical Details
- Built on `jose` library (v0.10+) for JWT/JWS operations with native EC signing support
- Uses `cryptonite` for cryptographic operations (hashing, random number generation)
- Full RFC 9901 compliance including all examples from Sections 5.1 and 5.2
- Support for JSON Pointer syntax (RFC 6901) for nested structures
- Proper handling of JSON Pointer escaping (`~1` for `/`, `~0` for `~`)
