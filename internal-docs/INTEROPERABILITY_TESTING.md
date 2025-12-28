# Interoperability Testing with sd-jwt-python

This document outlines how to test our Haskell SD-JWT implementation against the Python reference implementation from [openwallet-foundation-labs/sd-jwt-python](https://github.com/openwallet-foundation-labs/sd-jwt-python).

## Overview

Interoperability testing ensures that SD-JWTs created by one implementation can be correctly parsed and verified by another, which is critical for real-world deployment where different systems may use different implementations.

## Serialization Format Analysis

### Current Status

The Python library supports two serialization formats:

1. **Compact Serialization** (default) - Tilde-separated format: `eyJ...~WyJ...~WyJ...`
   - This is what our Haskell implementation currently supports
   - Used by ~90% of the Python test cases (18 out of 20 test cases)
   - Format: `<JWT>~<Disclosure1>~<Disclosure2>~...~`

2. **JSON Serialization** - JWS JSON Serialization (RFC 7515)
   - Used by only 2 test cases: `json_serialization_flattened` and `json_serialization_general`
   - Format: JSON object with `payload`, `protected`, `signature`/`signatures`, and disclosures in a `disclosures` header property
   - Required for multiple issuer keys (a niche use case)
   - The Python test framework skips header parameter comparison for JSON serialization

### Do We Need JSON Serialization?

**Answer: Not for effective interoperability testing.**

**For basic interoperability**: Compact serialization is sufficient because:
- It's the default format in the Python library
- It covers 90%+ of their test cases
- The core SD-JWT functionality (disclosures, digests, key binding) is identical regardless of serialization format
- Most real-world deployments use compact serialization

**For full interoperability**: JSON serialization would be needed to:
- Pass all Python test cases (including the 2 JSON serialization test cases)
- Support multiple issuer keys (requires JSON serialization)
- Interoperate with systems that exclusively use JSON serialization

**Recommendation**: Focus on compact serialization for interoperability testing initially. JSON serialization can be added later as an optional feature if needed.

## Testing Approaches

### 1. Test Case-Based Testing (Recommended)

The Python library uses YAML specification files (`specification.yml`) that define:
- Input claims (`user_claims`)
- Selective disclosure configuration (`holder_disclosed_claims`)
- Expected verified claims (`expect_verified_user_claims`)
- Test settings (keys, algorithms, serialization format, etc.)

**Strategy**: Parse their `specification.yml` files and run equivalent tests in Haskell.

#### Test Case Structure

Each test case directory contains:
- `specification.yml` - Test case definition
- Generated files (created during test execution):
  - `sd_jwt_issuance.txt` - Issuer output
  - `sd_jwt_presentation.txt` - Holder output

#### Example Test Case (`tests/testcases/array_data_types/specification.yml`)

```yaml
user_claims:
  data_types:
    - !sd null
    - !sd 42
    - !sd 3.14
    - !sd "foo"
    - !sd True
    - !sd ["Test"]  
    - !sd {"foo": "bar"}

holder_disclosed_claims:
  data_types:
    - True
    - True
    - True
    - True
    - True
    - True
    - True

expect_verified_user_claims:
  data_types:
    - null
    - 42
    - 3.14
    - "foo"
    - True
    - ["Test"]
    - {"foo": "bar"}
```

#### Implementation Plan

1. **Parse YAML specifications**:
   ```haskell
   -- test/Interop/TestVectorParser.hs
   data TestCase = TestCase
     { tcUserClaims :: Map.Map T.Text Aeson.Value
     , tcHolderDisclosedClaims :: Map.Map T.Text Aeson.Value
     , tcExpectedVerifiedClaims :: Map.Map T.Text Aeson.Value
     , tcKeyBinding :: Bool
     , tcSerializationFormat :: Maybe T.Text  -- "compact" or "json"
     , tcAddDecoyClaims :: Bool
     , tcExtraHeaderParameters :: Map.Map T.Text Aeson.Value
     }
   ```

2. **Convert Python test case format to Haskell**:
   - Python uses `!sd` YAML tag for selective disclosure
   - We use `markSelectivelyDisclosable` function
   - Map Python claim structure to our `Map.Map T.Text Aeson.Value`

3. **Run equivalent tests**:
   ```haskell
   -- test/Interop/InteropSpec.hs
   describe "Python Test Case Compatibility" $ do
     it "passes array_data_types test case" $ do
       testCase <- loadTestCase "tests/testcases/array_data_types/specification.yml"
       -- Create SD-JWT with same claims
       -- Verify same disclosures produce same verified claims
   ```

**Pros:**
- Tests against real, maintained test cases
- Covers edge cases (arrays, nested objects, data types)
- Version-controlled test vectors

**Cons:**
- Requires YAML parsing
- Need to handle Python-specific claim format (`!sd` tags)
- May need to skip JSON serialization test cases initially

### 2. Round-Trip Testing

Test that SD-JWTs created in one language can be verified in another.

#### Haskell → Python

```haskell
it "Haskell-created SD-JWT can be verified by Python" $ do
  -- Create SD-JWT in Haskell
  sdjwt <- createSDJWT Nothing Nothing SHA256 issuerKey ["given_name"] claims
  let serialized = serializeSDJWT sdjwt
  
  -- Verify in Python (via subprocess)
  (exitCode, stdout, stderr) <- readProcess "python3"
    [ "scripts/python/verify_sd_jwt.py"
    , T.unpack serialized
    ] ""
  
  exitCode `shouldBe` ExitSuccess
```

#### Python → Haskell

```haskell
it "Python-created SD-JWT can be verified by Haskell" $ do
  -- Create SD-JWT in Python
  (exitCode, pythonSDJWT, _) <- readProcess "python3"
    [ "scripts/python/create_sd_jwt.py"
    , "--claims", "{\"given_name\":\"John\"}"
    , "--selective", "given_name"
    ] ""
  
  -- Verify in Haskell
  case deserializeSDJWT (T.pack pythonSDJWT) of
    Right sdjwt -> do
      result <- verifySDJWT issuerPublicKey sdjwt Nothing
      result `shouldSatisfy` isRight
    Left err -> expectationFailure $ "Failed to parse: " ++ show err
```

**Pros:**
- Tests real interoperability
- Can catch format differences
- Validates end-to-end flow

**Cons:**
- Requires Python environment locally
- Slower than pure Haskell tests
- More complex error handling
- Only works with compact serialization (for now)

### 3. Golden File Testing

Store known-good SD-JWT strings from Python implementation and verify we can parse/verify them.

```haskell
-- test/interop/golden/python-array-data-types.txt
eyJhbGciOiJSUzI1NiJ9.eyJkYXRhX3R5cGVzIjp7Il9zZCI6WyJ..."]}~WyJ...~WyJ...

testGoldenPythonSDJWT :: IO ()
testGoldenPythonSDJWT = do
  golden <- readFile "test/interop/golden/python-array-data-types.txt"
  case deserializeSDJWT (T.pack golden) of
    Right sdjwt -> do
      result <- verifySDJWT issuerKey sdjwt Nothing
      case result of
        Right payload -> 
          payload `shouldContainKey` "data_types"
        Left err -> expectationFailure $ "Verification failed: " ++ show err
    Left err -> expectationFailure $ "Failed to parse: " ++ show err
```

**Pros:**
- Simple to implement
- Fast execution
- Version-controlled
- No Python dependency

**Cons:**
- Requires manual generation of golden files
- Less comprehensive than test case-based testing
- Files need to be regenerated when Python library updates

## Recommended Implementation Plan

### Phase 1: Test Case Parser (Week 1)

1. **Create YAML parser for test cases**:
   - Parse `specification.yml` files
   - Convert Python `!sd` tag format to our claim structure
   - Handle test settings (keys, algorithms, etc.)

2. **Create test case loader**:
   ```haskell
   loadTestCase :: FilePath -> IO TestCase
   ```

3. **Map Python test case structure to Haskell**:
   - Convert `user_claims` with `!sd` tags to our selective disclosure format
   - Handle `holder_disclosed_claims` format (boolean flags vs. claim names)
   - Extract expected verified claims

### Phase 2: Basic Interoperability Tests (Week 2)

1. **Start with simple test cases** (skip JSON serialization ones):
   - `array_data_types`
   - `array_of_scalars`
   - `key_binding`
   - `no_sd`

2. **Implement test runner**:
   ```haskell
   runTestCase :: TestCase -> IO (Either String ())
   ```

3. **Compare results**:
   - Verify that our verified claims match `expect_verified_user_claims`
   - Handle minor differences (e.g., claim ordering)

### Phase 3: Round-Trip Testing (Week 3)

1. **Create Python helper scripts**:
   - `scripts/python/create_sd_jwt.py` - Creates SD-JWT from JSON input
   - `scripts/python/verify_sd_jwt.py` - Verifies SD-JWT
   - `scripts/python/create_presentation.py` - Creates presentation

2. **Implement round-trip tests**:
   - Haskell → Python verification
   - Python → Haskell verification

3. **Run locally**:
   - Install Python dependencies: `pip install sd-jwt pyyaml`
   - Run tests: `stack test --test-arguments "--match Interop"`

### Phase 4: Comprehensive Coverage (Week 4+)

1. **Add remaining test cases**:
   - Array edge cases
   - Nested objects
   - Recursive selective disclosure
   - Decoy claims

2. **Generate golden files**:
   - Run Python test cases to generate reference outputs
   - Store as golden files for fast regression testing

3. **Documentation**:
   - Update README with interoperability testing instructions
   - Document any known differences or limitations

## Test Case Coverage

### Test Cases We Can Test (Compact Serialization)

- ✅ `array_data_types` - Various data types in arrays
- ✅ `array_of_scalars` - Simple scalar array elements
- ✅ `array_of_objects` - Object array elements
- ✅ `array_full_sd` - All array elements selectively disclosable
- ✅ `array_none_disclosed` - No array elements disclosed
- ✅ `array_nested_in_plain` - Nested arrays
- ✅ `array_recursive_sd` - Recursive selective disclosure in arrays
- ✅ `key_binding` - Key binding JWT
- ✅ `no_sd` - No selective disclosure
- ✅ `object_data_types` - Various data types in objects
- ✅ `recursions` - Recursive selective disclosure
- ✅ `header_mod` - Custom header parameters

### Test Cases We Skip Initially (JSON Serialization)

- ⏭️ `json_serialization_flattened` - Requires JSON serialization support
- ⏭️ `json_serialization_general` - Requires JSON serialization support

**Note**: These can be added later if JSON serialization is implemented.

## Setup Instructions

### Prerequisites

1. **Clone Python library** (for test cases):
   ```bash
   git clone https://github.com/openwallet-foundation-labs/sd-jwt-python.git /tmp/sd-jwt-python
   ```

2. **Install Python dependencies** (for round-trip testing):
   ```bash
   pip install sd-jwt pyyaml
   ```

3. **Add YAML parsing to Haskell project**:
   ```yaml
   # package.yaml
   dependencies:
     - yaml >= 0.11 && < 0.12
   ```

### Test Structure

```
test/
  interop/
    TestCaseParser.hs      # Parse YAML test cases
    InteropSpec.hs         # Interoperability tests
    PythonHelpers.hs       # Python subprocess helpers
    golden/                # Golden files from Python
      python-array-data-types.txt
      python-key-binding.txt
    vectors/               # Copied Python test cases
      array_data_types/
        specification.yml
      key_binding/
        specification.yml
```

### Running Tests Locally

This is a **one-time manual testing process** to verify interoperability. Run these steps on your local machine:

1. **Clone Python library**:
   ```bash
   git clone https://github.com/openwallet-foundation-labs/sd-jwt-python.git /tmp/sd-jwt-python
   ```

2. **Install Python dependencies**:
   ```bash
   pip install sd-jwt pyyaml
   ```

3. **Set environment variable** (if needed):
   ```bash
   export PYTHON_TEST_CASES_DIR=/tmp/sd-jwt-python/tests/testcases
   ```

4. **Build interoperability test executable**:
   ```bash
   stack build --flag sd-jwt:interop-tests
   ```

5. **Run interoperability tests**:
   ```bash
   stack exec sd-jwt-interop-test
   ```
   
   **Note**: The interoperability tests are completely separate from normal tests:
   - Do NOT run with `stack test` (separate executable)
   - Do NOT build with `stack build` (disabled by default, use `--flag interop-tests` to enable)
   - Build with: `stack build --flag sd-jwt:interop-tests`

**Note**: These tests are not part of the regular CI/CD pipeline. They should be run manually when:
- Verifying compatibility with a new version of the Python library
- Before releasing a new version of the Haskell library
- When investigating interoperability issues

## Known Differences and Limitations

### Serialization Format

- **Python**: Supports both compact and JSON serialization
- **Haskell**: Currently supports only compact serialization
- **Impact**: Cannot test JSON serialization test cases until JSON serialization is implemented

### Claim Format

- **Python**: Uses `!sd` YAML tag for selective disclosure in test cases
- **Haskell**: Uses `markSelectivelyDisclosable` function
- **Impact**: Need to convert between formats when parsing test cases

### Key Format

- **Python**: Accepts JWK as dict or list of dicts
- **Haskell**: Accepts JWK as `Text` (JSON string) or `jose JWK`
- **Impact**: Need to serialize Python keys to JSON for Haskell

## Next Steps

1. **Implement YAML parser** for test case specifications
2. **Create test case converter** from Python format to Haskell format
3. **Implement basic interoperability tests** for simple test cases
4. **Add round-trip testing** with Python subprocess integration
5. **Generate golden files** for regression testing
6. **Document any differences** or limitations discovered during testing

## References

- [Python SD-JWT Implementation](https://github.com/openwallet-foundation-labs/sd-jwt-python)
- [RFC 9901: SD-JWT Specification](https://www.rfc-editor.org/rfc/rfc9901.html)
- [RFC 7515: JWS JSON Serialization](https://www.rfc-editor.org/rfc/rfc7515.html) (for JSON serialization format)
- [OAuth Working Group SD-JWT Resources](https://github.com/oauth-wg/oauth-selective-disclosure-jwt)
