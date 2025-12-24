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

## Status

🚧 **Work in Progress** - This implementation is currently under development.

See [internal-docs/IMPLEMENTATION_PLAN.md](internal-docs/IMPLEMENTATION_PLAN.md) for the detailed implementation plan.

## Installation

```bash
stack build
# or
cabal build
```

## Usage

### Recommended: Use Persona-Specific Modules

The library provides three persona-specific modules for different use cases:

#### For Issuers (Creating SD-JWTs)

⚠️ **Security Warning**: When using Elliptic Curve (EC) keys (ES256 algorithm), be aware that the underlying `jose` library's EC signing implementation may be vulnerable to timing attacks. This affects signing only, not verification. For applications where timing attacks are a concern, consider using RSA (RS256) or Ed25519 (EdDSA) keys instead.

```haskell
import SDJWT.Issuer
import qualified Data.Map.Strict as Map
import qualified Data.Aeson as Aeson

-- Create claims
let claims = Map.fromList
      [ ("sub", Aeson.String "user_123")
      , ("given_name", Aeson.String "John")
      , ("family_name", Aeson.String "Doe")
      ]

-- Create SD-JWT with selective disclosure
keyPair <- generateTestRSAKeyPair  -- From TestKeys module
result <- createSDJWT SHA256 (privateKeyJWK keyPair) ["given_name", "family_name"] claims
```

#### For Holders (Creating Presentations)

```haskell
import SDJWT.Holder
import qualified Data.Text as T

-- Deserialize SD-JWT received from issuer
case deserializeSDJWT sdjwtText of
  Right sdjwt -> do
    -- Select disclosures to include
    case selectDisclosuresByNames sdjwt ["given_name"] of
      Right presentation -> do
        -- Optionally add key binding
        result <- addKeyBinding presentation keyPair "verifier.example.com" "nonce" timestamp
        -- Serialize and send to verifier
        let serialized = serializePresentation presentation
```

#### For Verifiers (Verifying SD-JWTs)

```haskell
import SDJWT.Verifier
import qualified Data.Text as T

-- Deserialize presentation received from holder
case deserializePresentation presentationText of
  Right presentation -> do
    -- Verify the SD-JWT
    result <- verifySDJWT issuerPublicKey presentation
    case result of
      Right processedPayload -> do
        -- Extract claims
        let claims = processedClaims processedPayload
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

## Documentation

- [RFC 9901](https://www.rfc-editor.org/rfc/rfc9901.html) - The specification
- [internal-docs/IMPLEMENTATION_PLAN.md](internal-docs/IMPLEMENTATION_PLAN.md) - Implementation plan

## License

BSD-3-Clause
