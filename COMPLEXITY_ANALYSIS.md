# Code Complexity Analysis

## Summary

The codebase shows signs of high complexity, particularly in:
- **Deep nesting** (max depth 18-27 levels)
- **Long functions** (several 50-80+ line functions)
- **Large modules** (Issuance.hs: 931 lines, Presentation.hs: 598 lines, Verification.hs: 543 lines)

## Metrics

### File Sizes
```
931 lines  src/SDJWT/Internal/Issuance.hs
598 lines  src/SDJWT/Internal/Presentation.hs
543 lines  src/SDJWT/Internal/Verification.hs
376 lines  src/SDJWT/Internal/JWT.hs
```

### Nesting Depth (High = Complex)
- `src/SDJWT/Verifier.hs`: **27 levels** ⚠️
- `src/SDJWT/Holder.hs`: **18 levels** ⚠️
- `src/SDJWT/Issuer.hs`: **16 levels** ⚠️

**Recommendation**: Nesting depth > 5 is considered complex. Depth > 10 is very complex.

### Long Functions Identified

#### Issuance.hs
- `buildSDJWTPayload`: ~80 lines - Complex orchestration function
- `processNestedStructures`: ~50 lines - Handles nested object/array processing
- `processObjectPaths`: ~80 lines - Deeply nested recursive processing
- `processArrayPaths`: ~60 lines - Array element processing with recursion

#### Presentation.hs
- `collectFromObject`: ~90 lines - Complex nested disclosure collection
- `collectDisclosuresRecursively`: ~100+ lines - Recursive disclosure traversal

#### Verification.hs
- `processPayload`: ~80 lines - Main payload processing logic
- `processValueForArraysWithSD`: ~50 lines - Array processing with nested logic

## Complexity Assessment Tools

### Available Tools

1. **HLint** (Static Analysis)
   ```bash
   stack install hlint
   hlint src/
   ```
   - Checks for code smells, complexity patterns
   - Suggests simplifications

2. **Weeder** (Dead Code Detection)
   ```bash
   stack install weeder
   weeder
   ```
   - Finds unused exports and dead code

3. **Stan** (Static Analysis)
   ```bash
   stack install stan
   stan analyse
   ```
   - Advanced static analysis with complexity metrics

4. **Manual Metrics**
   - Function length: Count lines per function
   - Nesting depth: Count nested `case`/`if`/`do` blocks
   - Cyclomatic complexity: Count decision points (`if`, `case`, `&&`, `||`)

## Recommendations

### High Priority

1. **Extract Helper Functions from Long Functions**
   - Break `buildSDJWTPayload` into smaller functions:
     - `processTopLevelClaims`
     - `combineStructuredAndRecursive`
     - `buildFinalPayload`
   
   - Break `collectFromObject` into:
     - `collectTopLevelDisclosures`
     - `collectNestedDisclosures`
     - `findDisclosureForClaim`

2. **Reduce Nesting Depth**
   - Extract deeply nested `case`/`if` blocks into helper functions
   - Use `Maybe`/`Either` monadic patterns instead of nested `case`
   - Consider using `Control.Monad.Except` for error handling

3. **Split Large Modules**
   - Consider splitting `Issuance.hs`:
     - `Issuance.Basic` - Simple top-level issuance
     - `Issuance.Nested` - Nested structure processing
     - `Issuance.Recursive` - Recursive disclosure handling
   
   - Consider splitting `Presentation.hs`:
     - `Presentation.Basic` - Simple disclosure selection
     - `Presentation.Recursive` - Recursive disclosure handling
     - `Presentation.Validation` - Disclosure validation

### Medium Priority

4. **Use Records for Function Parameters**
   - Functions with many parameters can use records:
     ```haskell
     data ProcessConfig = ProcessConfig
       { hashAlg :: HashAlgorithm
       , paths :: [[T.Text]]
       , claims :: Aeson.Object
       }
     ```

5. **Extract Common Patterns**
   - Pattern: "Group paths by first segment" appears multiple times
   - Pattern: "Extract digests from _sd array" (already done ✅)
   - Pattern: "Process nested structures recursively"

6. **Simplify Error Handling**
   - Use `ExceptT` or `Either` monad transformers consistently
   - Reduce nested `case` statements for error handling

### Low Priority

7. **Add Type Aliases**
   - Create type aliases for common complex types:
     ```haskell
     type DisclosureMap = Map.Map T.Text (T.Text, Aeson.Value)
     type PathSegments = [[T.Text]]
     ```

8. **Documentation**
   - Add Haddock comments explaining complex algorithms
   - Document why certain functions are complex (RFC requirements)

## Complexity Targets

| Metric | Current | Target | Status |
|--------|---------|--------|--------|
| Max nesting depth | 27 | < 8 | ⚠️ Needs work |
| Max function length | ~100 lines | < 50 lines | ⚠️ Needs work |
| Max module size | 931 lines | < 500 lines | ⚠️ Needs work |
| Functions > 50 lines | ~10 | < 3 | ⚠️ Needs work |

## Next Steps

1. Run HLint and fix suggested simplifications
2. Identify top 3 most complex functions and refactor them
3. Extract helper functions from `buildSDJWTPayload` and `collectFromObject`
4. Measure complexity again after refactoring

## Notes

- Some complexity is inherent to the RFC 9901 specification (nested structures, recursive disclosures)
- The code is functional and correct (all tests pass)
- Refactoring should maintain 100% test coverage
- Consider complexity vs. readability trade-offs

