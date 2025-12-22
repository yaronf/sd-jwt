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

(Examples will be added as implementation progresses)

## Documentation

- [RFC 9901](https://www.rfc-editor.org/rfc/rfc9901.html) - The specification
- [internal-docs/IMPLEMENTATION_PLAN.md](internal-docs/IMPLEMENTATION_PLAN.md) - Implementation plan

## License

BSD-3-Clause
