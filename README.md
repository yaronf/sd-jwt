# SD-JWT: Selective Disclosure for JSON Web Tokens

Haskell implementation of [RFC 9901](https://www.rfc-editor.org/rfc/rfc9901.html): Selective Disclosure for JSON Web Tokens (SD-JWT).

## Overview

SD-JWT enables selective disclosure of individual elements of a JSON data structure used as the payload of a JSON Web Signature (JWS). The primary use case is the selective disclosure of JSON Web Token (JWT) claims.

## Features

- ✅ SD-JWT issuance (issuer side)
- ✅ SD-JWT presentation (holder side)
- ✅ SD-JWT verification (verifier side)
- ✅ Key Binding support (SD-JWT+KB)
- ✅ Nested and recursive disclosures
- ✅ Multiple hash algorithms (SHA-256, SHA-384, SHA-512)
- ✅ Multiple signing algorithms: PS256 (RSA-PSS, default), RS256 (deprecated), ES256 (EC P-256), EdDSA (Ed25519)

## Status

✅ **Stable** - This implementation is feature-complete and ready for use.

The library implements RFC 9901 with comprehensive test coverage (224 tests). See [internal-docs/IMPLEMENTATION_PLAN.md](internal-docs/IMPLEMENTATION_PLAN.md) for implementation details.

## Installation

```bash
stack build
# or
cabal build
```

## Examples

A complete end-to-end example demonstrating the full SD-JWT flow (issuer → holder → verifier) is available:

```bash
stack exec sd-jwt-example
# or
stack runghc examples/EndToEndExample.hs
```

This example shows:
- Issuer creating an SD-JWT with selective disclosure
- Holder selecting which claims to disclose and creating a presentation
- Verifier verifying the presentation and extracting claims

## Usage

### Recommended: Use Persona-Specific Modules

The library provides three persona-specific modules for different use cases:

#### For Issuers (Creating SD-JWTs)

⚠️ **Security Warning**: When using Elliptic Curve (EC) keys (ES256 algorithm), be aware that the underlying `jose` library's EC signing implementation may be vulnerable to timing attacks. This affects signing only, not verification. For applications where timing attacks are a concern, consider using RSA-PSS (PS256, default for RSA keys) or Ed25519 (EdDSA) keys instead.

**Note**: RS256 (RSA-PKCS#1 v1.5) is deprecated per [draft-ietf-jose-deprecate-none-rsa15](https://datatracker.ietf.org/doc/draft-ietf-jose-deprecate-none-rsa15/) due to padding oracle attack vulnerabilities. PS256 (RSA-PSS) is the recommended RSA algorithm and is used by default for RSA keys.

```haskell
import SDJWT.Issuer
import qualified Data.Map.Strict as Map
import qualified Data.Aeson as Aeson
import qualified Data.Text as T

-- Create claims
let claims = Map.fromList
      [ ("sub", Aeson.String "user_123")
      , ("given_name", Aeson.String "John")
      , ("family_name", Aeson.String "Doe")
      ]

-- Load issuer's private key (can be Text or jose JWK object)
-- Example Text format: "{\"kty\":\"RSA\",\"n\":\"...\",\"e\":\"AQAB\",\"d\":\"...\"}"
issuerPrivateKeyJWK <- loadPrivateKeyJWK  -- Your function to load the key (returns Text or JWK.JWK)

-- Create SD-JWT with selective disclosure
-- PS256 (RSA-PSS) is used by default for RSA keys
result <- createSDJWT SHA256 issuerPrivateKeyJWK ["given_name", "family_name"] claims
case result of
  Right sdjwt -> do
    let serialized = serializeSDJWT sdjwt
    -- Send serialized SD-JWT to holder
  Left err -> putStrLn $ "Error creating SD-JWT: " ++ show err
```

#### For Holders (Creating Presentations)

```haskell
import SDJWT.Holder
import qualified Data.Text as T
import Data.Int (Int64)

-- Deserialize SD-JWT received from issuer
case deserializeSDJWT sdjwtText of
  Right sdjwt -> do
    -- Select which disclosures to include in the presentation
    -- The holder chooses which claims to reveal (e.g., only "given_name", not "family_name")
    case selectDisclosuresByNames sdjwt ["given_name"] of
      Right presentation -> do
        -- The presentation now contains:
        -- - presentationJWT: The issuer-signed JWT (with digests for all claims)
        -- - selectedDisclosures: Only the disclosures for "given_name"
        -- Optionally add key binding (SD-JWT+KB) for proof of possession
        holderPrivateKeyJWK <- loadPrivateKeyJWK  -- Your function to load holder's private key (Text or jose JWK)
        let audience = "verifier.example.com"
        let nonce = "random-nonce-12345"
        let issuedAt = 1683000000 :: Int64
        result <- addKeyBindingToPresentation SHA256 holderPrivateKeyJWK audience nonce issuedAt presentation
        case result of
          Right presentationWithKB -> do
            -- Serialize the presentation: JWT~disclosure1~disclosure2~...~KB-JWT
            -- This includes both the issuer-signed JWT and the selected disclosures
            let serialized = serializePresentation presentationWithKB
            -- Send serialized presentation to verifier
            -- The verifier will verify the signature and reconstruct claims from the selected disclosures
          Left err -> putStrLn $ "Error adding key binding: " ++ show err
      Left err -> putStrLn $ "Error selecting disclosures: " ++ show err
  Left err -> putStrLn $ "Error deserializing SD-JWT: " ++ show err
```

#### For Verifiers (Verifying SD-JWTs)

```haskell
import SDJWT.Verifier
import qualified Data.Text as T

-- Deserialize presentation received from holder
case deserializePresentation presentationText of
  Right presentation -> do
    -- Load issuer's public key (can be Text or jose JWK object)
    issuerPublicKeyJWK <- loadPublicKeyJWK  -- Your function to load issuer's public key (Text or jose JWK)
    
    -- Verify the SD-JWT (optionally require specific typ header)
    -- Pass Nothing to allow any typ, or Just "sd-jwt" to require specific typ
    result <- verifySDJWT issuerPublicKeyJWK presentation Nothing
    case result of
      Right processedPayload -> do
        -- Extract claims
        let claims = processedClaims processedPayload
        -- Use verified claims
      Left err -> putStrLn $ "Verification failed: " ++ show err
  Left err -> putStrLn $ "Error deserializing presentation: " ++ show err
```

### Advanced Usage

For library developers or advanced use cases requiring low-level access,
import specific Internal modules as needed:

```haskell
import SDJWT.Internal.Types
import SDJWT.Internal.Serialization
import SDJWT.Internal.Issuance
-- etc.
```

### Nested Structures

The library supports nested structures using JSON Pointer syntax (RFC 6901):

```haskell
let claims = Map.fromList
      [ ("address", Aeson.Object $ KeyMap.fromList
          [ (Key.fromText "street_address", Aeson.String "123 Main St")
          , (Key.fromText "locality", Aeson.String "City")
          , (Key.fromText "country", Aeson.String "US")
          ])
      ]

-- Structured SD-JWT (Section 6.2): parent stays, sub-claims get _sd array
result <- buildSDJWTPayload SHA256 ["address/street_address", "address/locality"] claims

-- Recursive Disclosures (Section 6.3): parent is selectively disclosable
result <- buildSDJWTPayload SHA256 ["address", "address/street_address", "address/locality"] claims
```

#### JSON Pointer Escaping

Keys containing forward slashes or tildes must be escaped using JSON Pointer syntax (RFC 6901):

- `~1` = literal `/` (forward slash)
- `~0` = literal `~` (tilde)

**Important**: When creating claims Maps, use the actual (unescaped) JSON keys. When passing claim names to `buildSDJWTPayload`, use escaped forms for keys containing special characters.

Examples:
- Map key: `"contact/email"`, path: `["contact~1email"]` → marks literal key `"contact/email"` (not nested)
- Map key: `"user~name"`, path: `["user~0name"]` → marks literal key `"user~name"` (not nested)
- Map key: `"address"` (with nested `"email"`), path: `["address/email"]` → marks `email` within `address` object (nested path)

**Why escaping is necessary**: Without escaping, there would be ambiguity between:
- A literal key named `"address/email"` 
- The `email` key nested within an `address` object

JSON Pointer escaping resolves this ambiguity. See [RFC 6901](https://www.rfc-editor.org/rfc/rfc6901.html) for the complete specification.

## Supported Algorithms

### Signing Algorithms

- **PS256 (RSA-PSS)** - Default for RSA keys, recommended for security
- **RS256 (RSA-PKCS#1 v1.5)** - Deprecated per [draft-ietf-jose-deprecate-none-rsa15](https://datatracker.ietf.org/doc/draft-ietf-jose-deprecate-none-rsa15/), but still supported for backward compatibility
- **ES256 (EC P-256)** - Elliptic Curve, may be vulnerable to timing attacks during signing
- **EdDSA (Ed25519)** - Recommended for high-security applications

**Note**: RSA keys default to PS256. To use RS256, include `"alg": "RS256"` in your JWK.

### Hash Algorithms

- **SHA-256** - Default algorithm
- **SHA-384**
- **SHA-512**

## Key Format

Keys can be provided in two formats:

1. **Text (JSON string)** - Most convenient, no need to import `jose`:
   ```haskell
   let claims = Map.fromList [("claim", Aeson.String "value")]
   let issuerKey :: T.Text = "{\"kty\":\"RSA\",\"n\":\"...\",\"e\":\"AQAB\",\"d\":\"...\"}"
   result <- createSDJWT SHA256 issuerKey ["claim"] claims
   ```

2. **jose JWK object** - If you're already working with the `jose` library:
   ```haskell
   import Crypto.JOSE.JWK as JWK
   let claims = Map.fromList [("claim", Aeson.String "value")]
   jwk <- loadJWK  -- Your function that returns JWK.JWK
   result <- createSDJWT SHA256 jwk ["claim"] claims
   ```

The library automatically handles both formats through the `JWKLike` type class. Users who don't import `jose` can use Text strings directly, while users already working with `jose` can pass JWK objects without serialization overhead.

**JWK JSON Format Example:**
```json
{
  "kty": "RSA",
  "n": "base64url-encoded-modulus",
  "e": "AQAB",
  "d": "base64url-encoded-private-exponent"
}
```

For public keys, omit the `d` field. See [RFC 7517](https://www.rfc-editor.org/rfc/rfc7517.html) for JWK format specification.

## Documentation

- [RFC 9901](https://www.rfc-editor.org/rfc/rfc9901.html) - The SD-JWT specification
- [RFC 7517](https://www.rfc-editor.org/rfc/rfc7517.html) - JSON Web Key (JWK) format
- [RFC 7519](https://www.rfc-editor.org/rfc/rfc7519.html) - JSON Web Token (JWT)
- [RFC 8725](https://www.rfc-editor.org/rfc/rfc8725.html) - JSON Web Signature (JWS) best practices
- [internal-docs/IMPLEMENTATION_PLAN.md](internal-docs/IMPLEMENTATION_PLAN.md) - Implementation plan
- [internal-docs/TEST_PLAN.md](internal-docs/TEST_PLAN.md) - Test coverage documentation

## License

BSD-3-Clause
