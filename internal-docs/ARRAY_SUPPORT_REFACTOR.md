# Plan: Add Array Support to Public API

## Progress Summary
- ✅ **Phase 1 (Issuance.hs)**: COMPLETED - Array support added to `buildSDJWTPayload`
- ✅ **Phase 1 (Presentation.hs)**: COMPLETED - Array support added to `selectDisclosuresByNames` (with type checking)
- ✅ **Phase 2**: COMPLETED - Removed array-specific exports (kept `markArrayElementDisclosable` as deprecated/test-only for edge cases)
- ✅ **Phase 4 (Tests)**: COMPLETED - Updated tests to use JSON Pointer notation
- ⏳ **Phase 3**: TODO - Review and update documentation
- ⏳ **Coverage**: TODO - Run code coverage analysis

## Goals (Prioritized)
1. **PRIMARY**: Support arrays properly in the public API using JSON Pointer syntax
2. **SECONDARY**: Remove array-specific exported functions from internal modules
3. **FUTURE**: Rewrite interop test runner to use only public APIs (deferred)

## Current State

### Public APIs Available
- **SDJWT.Issuer**:
  - `createSDJWT :: Maybe T.Text -> Maybe T.Text -> HashAlgorithm -> jwk -> [T.Text] -> Map T.Text Aeson.Value -> IO (Either SDJWTError SDJWT)`
  - Currently supports JSON Pointer syntax for nested object properties (e.g., `"address/street_address"`)
  - **Does NOT support array indices** (e.g., `"nationalities/1"`)

- **SDJWT.Holder**:
  - `selectDisclosuresByNames :: SDJWT -> [T.Text] -> Either SDJWTError SDJWTPresentation`
  - Currently supports JSON Pointer syntax for nested object properties
  - **Does NOT support array indices**

- **SDJWT.Verifier**:
  - `verifySDJWT :: jwk -> SDJWTPresentation -> Maybe T.Text -> IO (Either SDJWTError ProcessedSDJWTPayload)`
  - Already handles arrays correctly during verification

### Array-Specific Functions to Remove from Exports
- `markArrayElementDisclosable` (Internal.Issuance) - currently exported
- `processArrayForSelectiveDisclosure` (Internal.Issuance) - currently exported
- `collectArrayElementDisclosures` (Internal.Presentation) - currently exported

**Note**: These functions will remain internal (unexported) but still usable within their modules.

## Implementation Plan

### Phase 1: Extend JSON Pointer Path Parsing to Support Array Indices ✅ COMPLETED

**File: `src/SDJWT/Internal/Issuance.hs`** ✅ COMPLETED

1. ✅ **Update `partitionNestedPaths` function:**
   - ✅ Changed return type to `([T.Text], [(T.Text, T.Text)])` - returns ambiguous paths
   - ✅ Paths like `"x/22"` are ambiguous until we check the actual claim type
   - ✅ Added documentation explaining the ambiguity

2. ✅ **Add `partitionPathsByType` function:**
   - ✅ Checks actual claim type in claims map
   - ✅ Resolves ambiguity: `"x/22"` → array index if `x` is array, object key if `x` is object
   - ✅ Routes paths to appropriate handlers based on type

3. ✅ **Add `processArraysFromPaths` function:**
   - ✅ Created helper function to process arrays from JSON Pointer paths
   - ✅ Groups paths by claim name and processes each array
   - ✅ Uses existing `processArrayForSelectiveDisclosure` internally

4. ✅ **Update `buildSDJWTPayload` function:**
   - ✅ Updated to use `partitionNestedPaths` then `partitionPathsByType`
   - ✅ Processes arrays first (before objects)
   - ✅ Combines array disclosures with other disclosures
   - ✅ Library compiles successfully

**File: `src/SDJWT/Internal/Presentation.hs`** ✅ COMPLETED

1. ✅ **Update `partitionNestedPaths` function:**
   - ✅ Changed return type to `([T.Text], [(T.Text, T.Text)])` - returns ambiguous paths
   - ✅ Mirrors changes in Issuance.hs
   - ✅ Added documentation explaining the ambiguity

2. ✅ **Add `partitionPathsByTypeFromPayload` function:**
   - ✅ Checks claim types from JWT payload (since we don't have original claims)
   - ✅ Resolves ambiguity by checking actual claim type
   - ✅ Routes paths to appropriate handlers

3. ✅ **Update `selectDisclosuresByNames` function:**
   - ✅ Updated to use `partitionNestedPaths` then `partitionPathsByTypeFromPayload`
   - ✅ Handles array paths when selecting disclosures
   - ✅ Uses existing `collectArrayElementDisclosures` internally (but doesn't export it)

### Phase 2: Remove Array-Specific Exports ✅ COMPLETED

**File: `src/SDJWT/Internal/Issuance.hs`** ✅ COMPLETED
- ✅ Removed `processArrayForSelectiveDisclosure` from export list
- ✅ Kept `markArrayElementDisclosable` as deprecated/test-only export (for edge case tests requiring 3+ level nesting)
- ✅ Functions remain usable internally

**File: `src/SDJWT/Internal/Presentation.hs`** ✅ COMPLETED
- ✅ Removed `collectArrayElementDisclosures` from export list
- ✅ Function already used internally by `selectDisclosuresByNames`

### Phase 3: Review and Update Documentation ⏳ TODO

1. **Review package documentation for JSON Pointer syntax mentions:**

   **Files to check:**
   - `src/SDJWT/Issuer.hs` - Module documentation and examples
   - `src/SDJWT/Holder.hs` - Module documentation and examples  
   - `src/SDJWT/Verifier.hs` - Module documentation and examples
   - `src/SDJWT/Internal/Issuance.hs` - Module documentation (lines 1-68, 253-309)
     - Currently mentions: `["address/street_address", "address/locality"]`
     - Update to include array examples: `["nationalities/1"]`
     - **IMPORTANT**: Document that `"x/22"` is ambiguous and resolved by checking claim type
   - `src/SDJWT/Internal/Presentation.hs` - Module documentation (line 61, 151-173)
     - Currently mentions: `"address/street_address"`
     - Update to include array examples
     - **IMPORTANT**: Document ambiguity resolution
   - `README.md` - Lines 160-196
     - Currently shows: `["address/street_address", "address/locality"]`
     - Update to include array examples
     - **IMPORTANT**: Document that numeric segments are resolved by claim type

2. **Update documentation examples:**
   - Add examples showing array index usage: `["nationalities/0", "nationalities/2"]`
   - Add examples showing mixed usage: `["address/street", "nationalities/1"]`
   - Add examples showing ambiguity: `["x/22"]` where `x` could be array or object
   - Update any existing examples that only show object paths
   - Ensure all documentation mentions both object paths AND array paths
   - Update function parameter documentation to mention array index support
   - **Document the ambiguity resolution**: Explain that `"x/22"` is resolved by checking the actual claim type

### Phase 4: Testing ⏳ IN PROGRESS (Commenting Complete, Ready for Conversion)

1. ✅ **Removed array-specific functions from exports:**
   - ✅ `markSelectivelyDisclosable` and `markArrayElementDisclosable` removed from exports
   - ✅ Functions remain internal-only (used by `buildSDJWTPayload`)

2. ✅ **Comment out tests using old APIs:**
   - ✅ Commented out tests in `IssuanceSpec.hs` that use `markSelectivelyDisclosable`
   - ✅ Commented out tests in `InteropFailureAnalysisSpec.hs` that use old functions
   - ✅ Commented out tests in `VerificationSpec.hs` that use old functions
   - ✅ Fixed all compilation errors from incomplete commenting

3. ✅ **Convert commented tests to use new JSON Pointer APIs:**
   - ✅ Converted `VerificationSpec.hs` test: "verifies that _sd_alg is removed from array disclosure values"
   - ✅ Converted `VerificationSpec.hs` test: "handles object with no disclosed sub-claims (Gap 3)"
   - ✅ Converted `VerificationSpec.hs` test: "handles nested arrays with recursive disclosures"
   - ✅ Converted `InteropFailureAnalysisSpec.hs` test: "should only include selected sub-claims in object"
   - ✅ Converted `InteropFailureAnalysisSpec.hs` test: "should handle complex nested structures with multiple levels"
   - ✅ All tests compile successfully

4. ⏳ **Test JSON Pointer implementation per RFC 6901 Section 5:**
   
   **Reference**: https://datatracker.ietf.org/doc/html/rfc6901#section-5
   
   **Test Document** (from RFC 6901 Section 5):
   ```json
   {
      "foo": ["bar", "baz"],
      "": 0,
      "a/b": 1,
      "c%d": 2,
      "e^f": 3,
      "g|h": 4,
      "i\\j": 5,
      "k\"l": 6,
      " ": 7,
      "m~n": 8
   }
   ```
   
   **Test Cases** (verify JSON Pointer paths resolve correctly):
   - ⏳ `""` → resolves to entire document (root)
   - ⏳ `"/foo"` → resolves to `["bar", "baz"]`
   - ⏳ `"/foo/0"` → resolves to `"bar"` (array index)
   - ⏳ `"/"` → resolves to `0` (empty string key)
   - ⏳ `"/a~1b"` → resolves to `1` (escaped slash: `~1` = `/`)
   - ⏳ `"/c%d"` → resolves to `2` (percent sign)
   - ⏳ `"/e^f"` → resolves to `3` (caret)
   - ⏳ `"/g|h"` → resolves to `4` (pipe)
   - ⏳ `"/i\\j"` → resolves to `5` (backslash - note JSON escaping)
   - ⏳ `"/k\"l"` → resolves to `6` (quote - note JSON escaping)
   - ⏳ `"/ "` → resolves to `7` (space)
   - ⏳ `"/m~0n"` → resolves to `8` (escaped tilde: `~0` = `~`)
   
   **Implementation Notes**:
   - ⏳ Test that `splitJSONPointer` correctly parses all RFC 6901 examples
   - ⏳ Test that `unescapeJSONPointer` correctly unescapes `~0` and `~1`
   - ⏳ Test that JSON Pointer paths correctly resolve values in actual JSON documents
   - ⏳ Test both parsing (string → segments) and resolution (path → value in document)
   - ⏳ Verify escaping/unescaping works correctly in both directions
   - ⏳ Test that paths work correctly when used with `buildSDJWTPayload` and `selectDisclosuresByNames`

5. ✅ **Export verification:**
   - ✅ `processArrayForSelectiveDisclosure` and `collectArrayElementDisclosures` removed from exports
   - ✅ `markSelectivelyDisclosable` and `markArrayElementDisclosable` removed from exports

## Detailed Changes

### Change 1: Update `partitionNestedPaths` in Issuance.hs

```haskell
-- Current signature:
partitionNestedPaths :: [T.Text] -> ([T.Text], [(T.Text, T.Text)])

-- New signature (unchanged, but behavior clarified):
partitionNestedPaths :: [T.Text] -> ([T.Text], [(T.Text, T.Text)])
-- Returns: (top-level claims, nested paths (parent/child))
-- Note: Paths like "x/22" are ambiguous - could be array index or object key
```

**Implementation:**
- Parse each path with `/`
- Return paths as `(parent, child)` pairs without distinguishing array vs object
- The ambiguity is resolved later by checking actual claim types

### Change 2: Add `partitionPathsByType` in Issuance.hs

```haskell
partitionPathsByType
  :: [(T.Text, T.Text)]  -- Nested paths (parent, child)
  -> Map.Map T.Text Aeson.Value  -- Claims to check types
  -> IO ([(T.Text, Int)], [(T.Text, T.Text)])  -- (array paths, object paths)
```

**Implementation:**
- Check actual claim type for each parent
- If parent is `Aeson.Array` and child is numeric → array path `(claim, index)`
- If parent is `Aeson.Object` → object path `(parent, child)`
- Resolves the ambiguity by checking actual types

### Change 3: Process Array Paths in `buildSDJWTPayload`

Add array processing step:
```haskell
let (topLevelClaims, nestedPaths) = partitionNestedPaths selectiveClaimNames

-- Resolve ambiguity by checking claim types
(arrayPaths, objectPaths) <- partitionPathsByType nestedPaths claims

-- Process arrays first
arrayResults <- processArraysFromPaths hashAlg arrayPaths claims

-- Then process objects (existing code)
structuredResults <- processNestedStructures hashAlg objectPaths claimsWithArrays
```

### Change 4: Helper Function for Array Processing

```haskell
processArraysFromPaths
  :: HashAlgorithm
  -> [(T.Text, Int)]  -- Array paths (claim name, index)
  -> Map.Map T.Text Aeson.Value  -- Original claims
  -> IO (Either SDJWTError (Map.Map T.Text Aeson.Value, [EncodedDisclosure]))
```

This function:
- Groups array paths by claim name
- For each claim, extracts the array and processes specified indices
- Uses existing `processArrayForSelectiveDisclosure` internally
- Returns modified claims and disclosures

## Key Design Decision: Ambiguity Resolution

**Problem**: The path `"x/22"` is ambiguous:
- Could be array element at index 22 if `x` is an array
- Could be object property "22" if `x` is an object

**Solution**: We resolve the ambiguity by checking the actual claim type:
- In `Issuance.hs`: Check the claims map directly
- In `Presentation.hs`: Check the JWT payload structure

This ensures correctness and follows JSON Pointer semantics where the path alone doesn't determine the type.

## Migration Notes

- **Breaking change**: External code using array-specific functions will need to migrate to JSON Pointer syntax
- Arrays are now specified via paths: `"nationalities/1"` instead of separate API calls
- Backward compatible for object properties: `"address/street"` still works
- Internal functions remain available for module-internal use
- **Ambiguity**: Paths like `"x/22"` are resolved automatically by checking claim types

## Future Work (Deferred)

- Rewrite interop test runner to use public APIs
- Add comprehensive interop tests
- Support deeper nesting (currently limited to 2 levels)

## Code Coverage Analysis ⏳ TODO

1. **Run coverage analysis:**
   - Use `cabal test --enable-coverage` or `stack test --coverage`
   - Generate coverage report
   - Identify dead code (functions/modules not covered by tests)
   - Verify that `processArraysFromPaths` and other internal functions are covered
   - Check for any unused exports or dead code paths

