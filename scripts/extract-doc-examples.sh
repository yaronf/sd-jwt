#!/bin/bash
# Convert README.md code blocks to doctest format
# This script ONLY extracts and converts - no complex transformations
#
# The extracted code is placed in test/ReadmeExamplesDoctest.hs
# which doctest can then run directly.

set -e

README="README.md"
OUTPUT="test/ReadmeExamplesDoctest.hs"
TEMP_README="test/ReadmeExamplesExtracted.tmp"

# Extract README.md code blocks using markdown-unlit
echo "Extracting code from README.md..."
stack exec -- markdown-unlit -h haskell "$README" "$TEMP_README" 2>/dev/null || {
  echo "Warning: markdown-unlit extraction failed, using empty file"
  echo "" > "$TEMP_README"
}

# Generate doctest-compatible Haskell file header
cat > "$OUTPUT" << 'EOF'
{-# LANGUAGE OverloadedStrings #-}
-- | Doctest-compatible file for testing README.md examples
--
-- This file is AUTO-GENERATED from README.md code blocks.
-- To regenerate: ./scripts/extract-doc-examples.sh
--
-- DO NOT EDIT MANUALLY - your changes will be overwritten!
module ReadmeExamplesDoctest where

import SDJWT.Issuer
import SDJWT.Holder
import SDJWT.Verifier
import qualified Data.Map.Strict as Map
import qualified Data.Aeson as Aeson
import qualified Data.Aeson.KeyMap as KeyMap
import qualified Data.Aeson.Key as Key
import qualified Data.Text as T
import Data.Int (Int64)
import TestKeys (generateTestRSAKeyPair, generateTestEd25519KeyPair, TestKeyPair(..))

EOF

# Process extracted code blocks - convert to doctest format with minimal changes
block_num=0
current_block=""
in_block=false

while IFS= read -r line || [ -n "$line" ]; do
  if [[ "$line" =~ ^#line[[:space:]]+[0-9]+[[:space:]]+\"haskell\" ]]; then
    # Process previous block
    if [ "$in_block" = true ] && [ -n "$current_block" ]; then
      # Skip if ONLY imports (no actual code)
      # Check if block has non-import, non-comment content
      has_code=$(echo "$current_block" | grep -v "^import " | grep -v "^--" | grep -v "^$" | head -1)
      if [ -n "$has_code" ]; then
        echo "-- Example from README.md (block $block_num)" >> "$OUTPUT"
        echo "-- >>> :set -XOverloadedStrings" >> "$OUTPUT"
        
        # Convert to doctest format - only replace placeholders, keep everything else
    echo "$current_block" | sed '
      /^import /d
      s/issuerPrivateKeyJWK <- loadPrivateKeyJWK/keyPair <- generateTestRSAKeyPair\
let issuerPrivateKeyJWK = privateKeyJWK keyPair/
      s/holderPrivateKeyJWK <- loadPrivateKeyJWK/holderKeyPair <- generateTestEd25519KeyPair\
let holderPrivateKeyJWK = privateKeyJWK holderKeyPair/
      s/issuerPublicKeyJWK <- loadPublicKeyJWK/issuerKeyPair <- generateTestRSAKeyPair\
let issuerPublicKeyJWK = publicKeyJWK issuerKeyPair/
      s/issuerPublicKey <- loadIssuerPublicKey/issuerKeyPair <- generateTestRSAKeyPair\
let issuerPublicKey = publicKeyJWK issuerKeyPair/
      s/putStrLn.*//g
      /Send serialized/d
      /Send to/d
      /Use verified claims/d
    ' | sed '
      # Replace loadJWK first (before other transformations)
      s|jwk <- loadJWK|keyPair <- generateTestRSAKeyPair\
let jwk = privateKeyJWK keyPair|g
      s|loadJWK|keyPair <- generateTestRSAKeyPair\
let jwk = privateKeyJWK keyPair|g
      # Add setup for sdjwtText in holder example (replace the case statement)
      s|^case deserializeSDJWT sdjwtText of|issuerKeyPair <- generateTestRSAKeyPair\
let claims = Map.fromList [("sub", Aeson.String "user_123"), ("given_name", Aeson.String "John")]\
sdjwtResult <- createSDJWT SHA256 (privateKeyJWK issuerKeyPair) ["given_name"] claims\
case sdjwtResult of\
  Right sdjwt -> let sdjwtText = serializeSDJWT sdjwt\
  Left _ -> error "Failed to create SD-JWT"\
case deserializeSDJWT sdjwtText of|g
      # Add setup for presentationText in verifier example (replace the case statement)
      s|^case deserializePresentation presentationText of|issuerKeyPair <- generateTestRSAKeyPair\
let claims = Map.fromList [("sub", Aeson.String "user_123"), ("given_name", Aeson.String "John")]\
sdjwtResult <- createSDJWT SHA256 (privateKeyJWK issuerKeyPair) ["given_name"] claims\
case sdjwtResult of\
  Right sdjwt -> case selectDisclosuresByNames sdjwt ["given_name"] of\
    Right pres -> let presentationText = serializePresentation pres\
    Left _ -> error "Failed to select disclosures"\
  Left _ -> error "Failed to create SD-JWT"\
case deserializePresentation presentationText of|g
    ' | while IFS= read -r code_line || [ -n "$code_line" ]; do
          if [[ -n "${code_line// }" ]] && [[ ! "$code_line" =~ ^--[[:space:]]*$ ]]; then
            echo "-- >>> $code_line" >> "$OUTPUT"
          fi
        done
        echo "" >> "$OUTPUT"
      fi
      current_block=""
    fi
    block_num=$((block_num + 1))
    in_block=true
  elif [ "$in_block" = true ]; then
    if [[ ! "$line" =~ ^#line ]]; then
      current_block="${current_block}${line}"$'\n'
    fi
  fi
done < "$TEMP_README"

# Process last block
if [ "$in_block" = true ] && [ -n "$current_block" ]; then
  # Skip if ONLY imports (no actual code)
  has_code=$(echo "$current_block" | grep -v "^import " | grep -v "^--" | grep -v "^$" | head -1)
  if [ -n "$has_code" ]; then
    echo "-- Example from README.md (block $block_num)" >> "$OUTPUT"
    echo "-- >>> :set -XOverloadedStrings" >> "$OUTPUT"
    echo "$current_block" | sed '
      /^import /d
      s/issuerPrivateKeyJWK <- loadPrivateKeyJWK/keyPair <- generateTestRSAKeyPair\
let issuerPrivateKeyJWK = privateKeyJWK keyPair/
      s/holderPrivateKeyJWK <- loadPrivateKeyJWK/holderKeyPair <- generateTestEd25519KeyPair\
let holderPrivateKeyJWK = privateKeyJWK holderKeyPair/
      s/issuerPublicKeyJWK <- loadPublicKeyJWK/issuerKeyPair <- generateTestRSAKeyPair\
let issuerPublicKeyJWK = publicKeyJWK issuerKeyPair/
      s/issuerPublicKey <- loadIssuerPublicKey/issuerKeyPair <- generateTestRSAKeyPair\
let issuerPublicKey = publicKeyJWK issuerKeyPair/
      s|jwk <- loadJWK|keyPair <- generateTestRSAKeyPair\
let jwk = privateKeyJWK keyPair|g
      s/putStrLn.*//g
      /Send serialized/d
      /Send to/d
      /Use verified claims/d
    ' | while IFS= read -r code_line || [ -n "$code_line" ]; do
      if [[ -n "${code_line// }" ]] && [[ ! "$code_line" =~ ^--[[:space:]]*$ ]]; then
        echo "-- >>> $code_line" >> "$OUTPUT"
      fi
    done
  fi
fi

echo "Generated $OUTPUT"
