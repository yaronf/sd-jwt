# EC Signing Implementation Analysis

## Feasibility: **MODERATELY COMPLEX** ✅ Doable

## Current Situation

- **jose-jwt**: 
  - ✅ Supports RSA (RS256) and EdDSA (Ed25519) signing AND verification
  - ✅ Supports ES256 **verification** (can decode and verify EC-signed JWTs)
  - ❌ Does NOT support ES256 **signing** (cannot create EC-signed JWTs)
- **cryptonite**: Already a dependency, supports EC signing via `Crypto.PubKey.ECDSA`
- **We already have**: Base64url encoding/decoding, JSON handling, JWT header parsing

## What We'd Need to Implement

### 1. **EC Key Parsing from JWK** (Medium complexity)
   - Parse EC private key: `{"kty":"EC","crv":"P-256","d":"...","x":"...","y":"..."}`
   - Convert JWK format to `cryptonite`'s `PrivateKey Curve_P256R1` type
   - Handle base64url decoding of `d`, `x`, `y` coordinates
   - **Complexity**: ~100-150 lines of code

### 2. **JWT Signing with ES256** (Medium complexity)
   - Build JWT header: `{"alg":"ES256","typ":"JWT"}`
   - Base64url encode header and payload
   - Sign `header.payload` using `cryptonite`'s `sign` function
   - Convert signature to JWT format:
     - ES256 signature is DER-encoded (r, s) from cryptonite
     - JWT format requires: `r || s` (concatenated, each 32 bytes for P-256)
     - Need to extract r and s from DER format and concatenate
   - Base64url encode signature
   - Build final JWT: `base64url(header).base64url(payload).base64url(signature)`
   - **Complexity**: ~150-200 lines of code

### 3. **JWT Verification with ES256** ✅ ALREADY AVAILABLE!
   - **Good news**: `jose-jwt` already supports ES256 verification!
   - We can use `jose-jwt`'s `decode` function with `JwsEncoding ES256`
   - Only need to:
     - Parse EC public key from JWK (same as for signing)
     - Update `detectKeyAlgorithm` to return "ES256" for EC keys
     - Update `verifyJWT` to accept "ES256" and use `JwsEncoding Jose.ES256`
   - **Complexity**: ~20-30 lines of code (mostly updating existing code)

### 4. **Signature Format Conversion** (Low complexity) ✅ SIMPLIFIED
   - **Good news**: `cryptonite`'s `Signature` type has direct access to `sign_r` and `sign_s`
   - No DER parsing needed! We can extract r and s directly
   - Convert `Scalar` to `Integer`, then to `ByteString` using `i2ospOf_` (32 bytes for P-256)
   - Concatenate: `r || s` (64 bytes total for P-256)
   - For verification: Split signature into r and s, convert back to `Scalar`
   - **Complexity**: ~50-100 lines of code (much simpler than DER!)

## Total Estimated Complexity

- **Lines of code**: ~250-350 lines (significantly reduced!)
  - EC JWK parsing: ~100-150 lines
  - ES256 signing: ~150-200 lines
  - ES256 verification: ~20-30 lines (just updating existing code)
- **Time estimate**: 1 day of focused work
- **Dependencies**: None! All functionality available in `cryptonite` and `jose-jwt`

## Pros

✅ No external C dependencies  
✅ Uses existing `cryptonite` dependency  
✅ Pure Haskell implementation  
✅ Can reuse existing base64url and JSON utilities  
✅ Maintains consistency with current architecture  

## Cons

⚠️ Need to handle edge cases (padding, key format conversion)  
⚠️ More code to maintain (but less than initially estimated!)  
⚠️ Need thorough testing to ensure correctness  

## Key Simplification Found ✅

**No DER encoding needed!** `cryptonite`'s `Signature` type provides direct access:
```haskell
Signature { sign_r :: Scalar curve, sign_s :: Scalar curve }
```

We can:
- Extract `r` and `s` directly from `Signature`
- Convert `Scalar` → `Integer` → `ByteString` using `i2ospOf_` (from `Crypto.Number.Serialize`)
- Concatenate: `r || s` (32 bytes each for P-256)
- For verification: Split signature, convert back to `Scalar`, construct `Signature`

## Recommendation

**YES, it's realistic and worthwhile** if:
1. We want to avoid C dependencies
2. We need ES256 support for RFC examples
3. We're willing to invest 1-2 days in implementation

The implementation would be:
- Self-contained in `SDJWT.JWT` module
- Use `jose-jwt` for RSA/EdDSA signing AND verification (current behavior)
- Use `jose-jwt` for ES256 **verification** (already supported!)
- Use `cryptonite` directly only for ES256 **signing** (the missing piece)

## Next Steps (if proceeding)

1. ✅ No additional dependencies needed (all in `cryptonite`)
2. Implement EC JWK parsing (convert JWK format to `PrivateKey Curve_P256R1`)
3. Implement ES256 signing:
   - Build JWT header and payload
   - Sign using `cryptonite`'s `sign` function
   - Extract `sign_r` and `sign_s` from `Signature`
   - Convert to ByteString (32 bytes each) and concatenate
   - Base64url encode and build final JWT
4. Implement ES256 verification:
   - ✅ Use `jose-jwt`'s `decode` function with `JwsEncoding Jose.ES256`
   - Update `verifyJWT` to accept "ES256" algorithm
   - Parse EC public key from JWK (same parsing as for signing)
   - **Much simpler**: Let jose-jwt handle all the signature verification!
5. Add comprehensive tests
6. Update `detectKeyAlgorithm` to support EC keys (return "ES256")
7. Update documentation

