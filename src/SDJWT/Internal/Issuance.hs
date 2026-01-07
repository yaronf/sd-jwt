{-# LANGUAGE OverloadedStrings #-}
-- | SD-JWT issuance: Creating SD-JWTs from claims sets.
--
-- This module provides functions for creating SD-JWTs on the issuer side.
-- It handles marking claims as selectively disclosable, creating disclosures,
-- computing digests, and building the final signed JWT.
--
-- == Nested Structures
--
-- This module supports nested structures (RFC 9901 Sections 6.2 and 6.3) using
-- JSON Pointer syntax (RFC 6901) for specifying nested claim paths.
--
-- === JSON Pointer Syntax
--
-- Nested paths use forward slash (@/@) as a separator. Paths can refer to both
-- object properties and array elements:
--
-- @
-- -- Object properties
-- ["address\/street_address", "address\/locality"]
-- @
--
-- This marks @street_address@ and @locality@ within the @address@ object as
-- selectively disclosable.
--
-- @
-- -- Array elements
-- ["nationalities\/0", "nationalities\/2"]
-- @
--
-- This marks elements at indices 0 and 2 in the @nationalities@ array as
-- selectively disclosable.
--
-- @
-- -- Mixed object and array paths
-- ["address\/street_address", "nationalities\/1"]
-- @
--
-- === Ambiguity Resolution
--
-- Paths with numeric segments (e.g., @["x\/22"]@) are ambiguous:
-- they could refer to an array element at index 22, or an object property
-- with key @"22"@. The library resolves this ambiguity by checking the actual
-- claim type at runtime:
--
-- * If @x@ is an array → @["x\/22"]@ refers to array element at index 22
-- * If @x@ is an object → @["x\/22"]@ refers to object property @"22"@
--
-- This follows JSON Pointer semantics (RFC 6901) where the path alone doesn't
-- determine the type.
--
-- === Escaping Special Characters
--
-- JSON Pointer provides escaping for keys containing special characters:
--
-- * @~1@ represents a literal forward slash @/@
-- * @~0@ represents a literal tilde @~@
--
-- Examples:
--
-- * @["contact~1email"]@ → marks the literal key @"contact\/email"@ as selectively disclosable
-- * @["user~0name"]@ → marks the literal key @"user~name"@ as selectively disclosable
-- * @["address\/email"]@ → marks @email@ within @address@ object as selectively disclosable
--
-- === Nested Structure Patterns
--
-- The module supports two patterns for nested structures:
--
-- 1. /Structured SD-JWT/ (Section 6.2): Parent object stays in payload with @_sd@ array
--    containing digests for sub-claims.
--
-- 2. /Recursive Disclosures/ (Section 6.3): Parent is selectively disclosable, and its
--    disclosure contains an @_sd@ array with digests for sub-claims.
--
-- The pattern is automatically detected based on whether the parent claim is also
-- in the selective claims list.
--
-- === Examples
--
-- Structured SD-JWT (Section 6.2):
--
-- @
-- buildSDJWTPayload SHA256 ["address\/street_address", "address\/locality"] claims
-- @
--
-- This creates a payload where @address@ object contains an @_sd@ array.
--
-- Recursive Disclosures (Section 6.3):
--
-- @
-- buildSDJWTPayload SHA256 ["address", "address\/street_address", "address\/locality"] claims
-- @
--
-- This creates a payload where @address@ digest is in top-level @_sd@, and the
-- @address@ disclosure contains an @_sd@ array with sub-claim digests.
--
-- Array Elements:
--
-- @
-- buildSDJWTPayload SHA256 ["nationalities\/0", "nationalities\/2"] claims
-- @
--
-- This marks array elements at indices 0 and 2 as selectively disclosable.
--
-- Nested Arrays:
--
-- @
-- buildSDJWTPayload SHA256 ["nested_array\/0\/0", "nested_array\/0\/1", "nested_array\/1\/0"] claims
-- @
--
-- This marks nested array elements. The path @["nested_array\/0\/0"]@ refers to
-- element at index 0 of the array at index 0 of @nested_array@.
--
-- Mixed Object and Array Paths:
--
-- @
-- buildSDJWTPayload SHA256 ["address\/street_address", "nationalities\/1"] claims
-- @
--
-- This marks both an object property and an array element as selectively disclosable.
--
-- == Decoy Digests
--
-- Decoy digests are optional random digests added to @_sd@ arrays to obscure
-- the actual number of selectively disclosable claims. This is useful for
-- privacy-preserving applications where you want to hide how many claims are
-- selectively disclosable.
--
-- To use decoy digests:
--
-- 1. Build the SD-JWT payload using buildSDJWTPayload
-- 2. Generate decoy digests using addDecoyDigest
-- 3. Manually add them to the @_sd@ array in the payload
-- 4. Sign the modified payload
--
-- Example:
--
-- @
-- -- Build the initial payload
-- (payload, disclosures) <- buildSDJWTPayload SHA256 ["given_name", "email"] claims
-- 
-- -- Generate decoy digests
-- decoy1 <- addDecoyDigest SHA256
-- decoy2 <- addDecoyDigest SHA256
-- 
-- -- Add decoy digests to the _sd array
-- case payloadValue payload of
--   Aeson.Object obj -> do
--     case KeyMap.lookup "_sd" obj of
--       Just (Aeson.Array sdArray) -> do
--         let decoyDigests = [Aeson.String (unDigest decoy1), Aeson.String (unDigest decoy2)]
--         let updatedSDArray = sdArray <> V.fromList decoyDigests
--         let updatedObj = KeyMap.insert "_sd" (Aeson.Array updatedSDArray) obj
--         -- Sign the updated payload...
--       _ -> -- Handle error
--   _ -> -- Handle error
-- @
--
-- During verification, decoy digests that don't match any disclosure are
-- automatically ignored, so they don't affect verification.
module SDJWT.Internal.Issuance
  ( -- * Public API
    createSDJWT
  , createSDJWTWithDecoys
  , addDecoyDigest
  , buildSDJWTPayload
  , addHolderKeyToClaims
  ) where

import SDJWT.Internal.Types (HashAlgorithm(..), Salt(..), Digest(..), EncodedDisclosure(..), SDJWTPayload(..), SDJWT(..), SDJWTError(..))
import SDJWT.Internal.Utils (generateSalt, hashToBytes, base64urlEncode, splitJSONPointer, unescapeJSONPointer, groupPathsByFirstSegment)
import SDJWT.Internal.Digest (computeDigest, hashAlgorithmToText)
import SDJWT.Internal.Disclosure (createObjectDisclosure, createArrayDisclosure)
import SDJWT.Internal.JWT (signJWTWithHeaders, JWKLike)
import SDJWT.Internal.Monad (SDJWTIO, runSDJWTIO, partitionAndHandle)
import SDJWT.Internal.Issuance.Nested (processNestedStructures, processRecursiveDisclosures)
import SDJWT.Internal.Issuance.Types
  ( TopLevelClaimsConfig(..)
  , TopLevelClaimsResult(..)
  , BuildSDJWTPayloadConfig(..)
  , BuildSDJWTPayloadResult(..)
  , CreateSDJWTConfig(..)
  , CreateSDJWTWithDecoysConfig(..)
  )
import Control.Monad.IO.Class (liftIO)
import qualified Data.Aeson as Aeson
import qualified Data.Aeson.Key as Key
import qualified Data.Aeson.KeyMap as KeyMap
import qualified Data.Map.Strict as Map
import qualified Data.Set as Set
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import qualified Data.Vector as V
import Data.List (sortBy, partition, find)
import Data.Ord (comparing)
import Text.Read (readMaybe)
import Data.Either (partitionEithers)
import Data.Maybe (mapMaybe)
import Control.Monad (replicateM)
import Control.Monad.Except (throwError)

-- | Mark a claim as selectively disclosable (internal use only).
--
-- This function only works for object claims (JSON objects), not for array elements.
-- It's used internally by buildSDJWTPayload and Issuance.Nested.
-- External users should use buildSDJWTPayload or createSDJWT with JSON Pointer paths.
markSelectivelyDisclosable
  :: HashAlgorithm
  -> T.Text  -- ^ Claim name
  -> Aeson.Value  -- ^ Claim value
  -> IO (Either SDJWTError (Digest, EncodedDisclosure))
markSelectivelyDisclosable hashAlg claimName claimValue =
  fmap (\saltBytes ->
    let salt = Salt saltBytes
    in case createObjectDisclosure salt claimName claimValue of
         Left err -> Left err
         Right encodedDisclosure ->
           let digest = computeDigest hashAlg encodedDisclosure
           in Right (digest, encodedDisclosure)
  ) generateSalt


-- | Build SD-JWT payload from claims, marking specified claims as selectively disclosable.
--
-- This function:
--
-- 1. Separates selectively disclosable claims from regular claims
-- 2. Creates disclosures for selectively disclosable claims
-- 3. Computes digests
-- 4. Builds the JSON payload with _sd array containing digests
-- 5. Returns the payload and all disclosures
--
-- Supports nested structures (Section 6.2, 6.3):
--
-- - Use JSON Pointer syntax for nested paths: ["address\/street_address", "address\/locality"]
-- - For Section 6.2 (structured): parent object stays, sub-claims get _sd array within parent
-- - For Section 6.3 (recursive): parent is selectively disclosable, disclosure contains _sd array
-- | Build SD-JWT payload using ExceptT (internal implementation).
buildSDJWTPayloadExceptT
  :: BuildSDJWTPayloadConfig
  -> SDJWTIO BuildSDJWTPayloadResult
buildSDJWTPayloadExceptT config = do
  let hashAlg = buildHashAlg config
  let selectiveClaimNames = buildSelectiveClaimNames config
  let claims = buildClaims config
  
  -- Group claims by nesting level (top-level vs nested)
  let (topLevelClaims, nestedPaths) = partitionNestedPaths selectiveClaimNames
  
  -- Identify recursive disclosures (Section 6.3)
  let recursiveParents = identifyRecursiveParents topLevelClaims nestedPaths
  
  -- Separate recursive disclosures (Section 6.3) from structured disclosures (Section 6.2)
  let (recursivePaths, structuredPaths) = separateRecursiveAndStructuredPaths recursiveParents nestedPaths
  
  -- Process structured nested structures (Section 6.2: structured SD-JWT)
  (structuredPayload, structuredDisclosures, remainingClaimsAfterStructured) <-
    liftIO (processNestedStructures hashAlg structuredPaths claims) >>= either throwError return
  
  -- Process recursive disclosures (Section 6.3)
  (recursiveParentInfo, recursiveDisclosures, remainingClaimsAfterRecursive) <-
    liftIO (processRecursiveDisclosures hashAlg recursivePaths remainingClaimsAfterStructured) >>= either throwError return
  
  -- Process top-level selective claims
  topLevelResult <- processTopLevelSelectiveClaimsExceptT TopLevelClaimsConfig
    { topLevelHashAlg = hashAlg
    , topLevelRecursiveParents = recursiveParents
    , topLevelClaimNames = topLevelClaims
    , topLevelRemainingClaims = remainingClaimsAfterRecursive
    }
  
  -- Extract recursive parent digests
  let recursiveParentDigests = map (\(_, digest, _) -> digest) recursiveParentInfo
  
  -- Combine all disclosures and digests
  let (allDisclosures, allDigests) = combineAllDisclosuresAndDigests
        structuredDisclosures recursiveDisclosures (resultDisclosures topLevelResult)
        recursiveParentDigests (resultDigests topLevelResult)
  
  -- Build final payload
  let payloadObj = KeyMap.union structuredPayload (resultRegularClaims topLevelResult)
  let finalPayload = buildFinalPayloadObject hashAlg payloadObj allDigests
  
  return BuildSDJWTPayloadResult
    { buildPayload = Aeson.Object finalPayload
    , buildDisclosures = allDisclosures
    }

buildSDJWTPayload
  :: HashAlgorithm
  -> [T.Text]  -- ^ Claim names to mark as selectively disclosable (supports JSON Pointer syntax for nested paths)
  -> Aeson.Object  -- ^ Original claims object
  -> IO (Either SDJWTError (SDJWTPayload, [EncodedDisclosure]))
buildSDJWTPayload hashAlg selectiveClaimNames claims = do
  let config = BuildSDJWTPayloadConfig
        { buildHashAlg = hashAlg
        , buildSelectiveClaimNames = selectiveClaimNames
        , buildClaims = claims
        }
  result <- runSDJWTIO (buildSDJWTPayloadExceptT config)
  case result of
    Left err -> return (Left err)
    Right res -> do
      let payload = SDJWTPayload
            { sdAlg = Just hashAlg
            , payloadValue = buildPayload res
            }
      return (Right (payload, buildDisclosures res))

-- | Create a complete SD-JWT (signed).
--
-- This function creates an SD-JWT and signs it using the issuer's key.
-- Creates a complete SD-JWT with signed JWT using jose.
--
-- Returns the created SD-JWT or an error.
--
-- == Standard JWT Claims
--
-- Standard JWT claims (RFC 7519) can be included in the @claims@ map and will be preserved
-- in the issuer-signed JWT payload. During verification, standard claims like @exp@ and @nbf@
-- are automatically validated if present. See RFC 9901 Section 4.1 for details.
--
-- == Example
--
-- @
-- -- Create SD-JWT without typ header
-- result <- createSDJWT Nothing SHA256 issuerKey ["given_name", "family_name"] claims
--
-- -- Create SD-JWT with typ header
-- result <- createSDJWT (Just "sd-jwt") SHA256 issuerKey ["given_name", "family_name"] claims
--
-- -- Create SD-JWT with expiration time
-- let claimsWithExp = Map.insert "exp" (Aeson.Number (fromIntegral expirationTime)) claims
-- result <- createSDJWT (Just "sd-jwt") SHA256 issuerKey ["given_name"] claimsWithExp
-- @
--
createSDJWT
  :: JWKLike jwk => Maybe T.Text  -- ^ Optional typ header value (RFC 9901 Section 9.11 recommends explicit typing). If @Nothing@, no typ header is added. If @Just "sd-jwt"@ or @Just "example+sd-jwt"@, the typ header is included in the JWT header.
  -> Maybe T.Text  -- ^ Optional kid header value (Key ID for key management). If @Nothing@, no kid header is added.
  -> HashAlgorithm  -- ^ Hash algorithm for digests
  -> jwk  -- ^ Issuer private key JWK (Text or jose JWK object)
  -> [T.Text]  -- ^ Claim names to mark as selectively disclosable
  -> Aeson.Object  -- ^ Original claims object. May include standard JWT claims such as @exp@ (expiration time), @nbf@ (not before), @iss@ (issuer), @sub@ (subject), @iat@ (issued at), etc. These standard claims will be validated during verification if present (see 'SDJWT.Internal.Verification.verifySDJWT').
  -> IO (Either SDJWTError SDJWT)
createSDJWT mbTyp mbKid hashAlg issuerPrivateKeyJWK selectiveClaimNames claims = do
  result <- buildSDJWTPayload hashAlg selectiveClaimNames claims
  case result of
    Left err -> return (Left err)
    Right (payload, sdDisclosures) -> do
      -- Sign the JWT with optional typ and kid headers
      signedJWTResult <- signJWTWithHeaders mbTyp mbKid issuerPrivateKeyJWK (payloadValue payload)
      case signedJWTResult of
        Left err -> return (Left err)
        Right signedJWT -> return $ Right $ SDJWT
          { issuerSignedJWT = signedJWT
          , disclosures = sdDisclosures
          }

-- | Create an SD-JWT with optional typ header and decoy digests.
--
-- This function is similar to 'createSDJWT' but automatically adds
-- a specified number of decoy digests to the @_sd@ array to obscure the
-- actual number of selectively disclosable claims.
--
-- Returns the created SD-JWT or an error.
--
-- == Standard JWT Claims
--
-- Standard JWT claims (RFC 7519) can be included in the @claims@ map and will be preserved
-- in the issuer-signed JWT payload. During verification, standard claims like @exp@ and @nbf@
-- are automatically validated if present. See RFC 9901 Section 4.1 for details.
--
-- == Example
--
-- @
-- -- Create SD-JWT with 5 decoy digests, no typ header
-- result <- createSDJWTWithDecoys Nothing SHA256 issuerKey ["given_name", "email"] claims 5
--
-- -- Create SD-JWT with 5 decoy digests and typ header
-- result <- createSDJWTWithDecoys (Just "sd-jwt") SHA256 issuerKey ["given_name", "email"] claims 5
-- @
--
createSDJWTWithDecoys
  :: JWKLike jwk => Maybe T.Text  -- ^ Optional typ header value (e.g., Just "sd-jwt" or Just "example+sd-jwt"). If @Nothing@, no typ header is added.
  -> Maybe T.Text  -- ^ Optional kid header value (Key ID for key management). If @Nothing@, no kid header is added.
  -> HashAlgorithm  -- ^ Hash algorithm for digests
  -> jwk  -- ^ Issuer private key JWK (Text or jose JWK object)
  -> [T.Text]  -- ^ Claim names to mark as selectively disclosable
  -> Aeson.Object  -- ^ Original claims object. May include standard JWT claims such as @exp@ (expiration time), @nbf@ (not before), @iss@ (issuer), @sub@ (subject), @iat@ (issued at), etc. These standard claims will be validated during verification if present (see 'SDJWT.Internal.Verification.verifySDJWT').
  -> Int  -- ^ Number of decoy digests to add (must be >= 0)
  -> IO (Either SDJWTError SDJWT)
createSDJWTWithDecoys mbTyp mbKid hashAlg issuerPrivateKeyJWK selectiveClaimNames claims decoyCount
  | decoyCount < 0 = return $ Left $ InvalidDisclosureFormat "decoyCount must be >= 0"
  | decoyCount == 0 = createSDJWT mbTyp mbKid hashAlg issuerPrivateKeyJWK selectiveClaimNames claims
  | otherwise = do
      -- Build the initial payload
      result <- buildSDJWTPayload hashAlg selectiveClaimNames claims
      case result of
        Left err -> return (Left err)
        Right (payload, sdDisclosures) -> do
          -- Generate decoy digests
          decoys <- replicateM decoyCount (addDecoyDigest hashAlg)
          
          -- Add decoy digests to the _sd array
          case payloadValue payload of
            Aeson.Object obj -> do
              case KeyMap.lookup (Key.fromText "_sd") obj of
                Just (Aeson.Array sdArray) -> do
                  -- Add decoy digests to the array
                  let decoyDigests = map (Aeson.String . unDigest) decoys
                  let updatedSDArray = sdArray <> V.fromList decoyDigests
                  let updatedObj = KeyMap.insert (Key.fromText "_sd") (Aeson.Array updatedSDArray) obj
                  let updatedPayload = payload { payloadValue = Aeson.Object updatedObj }
                  
                  -- Sign the updated payload with optional typ and kid headers
                  signedJWTResult <- signJWTWithHeaders mbTyp mbKid issuerPrivateKeyJWK (payloadValue updatedPayload)
                  case signedJWTResult of
                    Left err -> return (Left err)
                    Right signedJWT -> return $ Right $ SDJWT
                      { issuerSignedJWT = signedJWT
                      , disclosures = sdDisclosures
                      }
                _ -> return $ Left $ InvalidDisclosureFormat "Payload does not contain _sd array"
            _ -> return $ Left $ InvalidDisclosureFormat "Payload is not an object"

-- | Add holder's public key to claims as a @cnf@ claim (RFC 7800).
--
-- This convenience function adds the holder's public key to the claims map
-- in the format required by RFC 7800 for key confirmation:
--
-- @
-- {
--   "cnf": {
--     "jwk": "<holderPublicKeyJWK>"
--   }
-- }
-- @
--
-- The @cnf@ claim is used during key binding to prove that the holder
-- possesses the corresponding private key.
--
-- == Example
--
-- @
-- let holderPublicKeyJWK = "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"...\",\"y\":\"...\"}"
-- let claimsWithCnf = addHolderKeyToClaims holderPublicKeyJWK claims
-- result <- createSDJWT (Just "sd-jwt") SHA256 issuerKey ["given_name"] claimsWithCnf
-- @
--
-- == See Also
--
-- * RFC 7800: Proof-of-Possession Key Semantics for JSON Web Tokens (JWT)
-- * RFC 9901 Section 4.3: Key Binding
addHolderKeyToClaims
  :: T.Text  -- ^ Holder's public key as a JWK JSON string
  -> Aeson.Object  -- ^ Original claims object
  -> Aeson.Object  -- ^ Claims object with @cnf@ claim added
addHolderKeyToClaims holderPublicKeyJWK claims =
  let
    -- Parse the JWK JSON string to ensure it's valid JSON
    -- We'll store it as a JSON object value
    jwkValue = case Aeson.eitherDecodeStrict (TE.encodeUtf8 holderPublicKeyJWK) :: Either String Aeson.Value of
      Left _ -> Aeson.String holderPublicKeyJWK  -- If parsing fails, store as string (let verification catch errors)
      Right parsedJWK -> parsedJWK  -- Store as parsed JSON value
    cnfValue = Aeson.Object $ KeyMap.fromList [("jwk", jwkValue)]
  in
    KeyMap.insert "cnf" cnfValue claims

-- | Generate a decoy digest.
--
-- Decoy digests are random digests that don't correspond to any disclosure.
-- They are used to obscure the actual number of selectively disclosable claims.
--
-- According to RFC 9901 Section 4.2.5, decoy digests should be created by
-- hashing over a cryptographically secure random number, then base64url encoding.
--
-- == Advanced Use
--
-- Decoy digests are an advanced feature used to hide the number of selectively
-- disclosable claims. They are optional and must be manually added to the _sd array
-- if you want to obscure the actual number of selectively disclosable claims.
--
-- To use decoy digests, call this function to generate them and manually add
-- them to the _sd array in your payload. This is useful for privacy-preserving
-- applications where you want to hide how many claims are selectively disclosable.
--
addDecoyDigest
  :: HashAlgorithm
  -> IO Digest
addDecoyDigest hashAlg =
  -- Generate random bytes for the decoy digest
  -- According to RFC 9901, we hash over a cryptographically secure random number
  -- The size doesn't matter much since we're hashing it anyway
  fmap (\randomBytes ->
    -- Hash the random bytes using the specified algorithm
    let hashBytes = hashToBytes hashAlg randomBytes
        -- Base64url encode to create the digest
        digestText = base64urlEncode hashBytes
    in Digest digestText
  ) generateSalt

-- | Sort digests for deterministic ordering in _sd array.
sortDigests :: [Digest] -> [Digest]
sortDigests = sortBy (comparing unDigest)

-- | Identify which nested paths are recursive disclosures (Section 6.3).
--
-- A path is recursive if its first segment is also in topLevelClaims.
-- This means the parent claim is itself selectively disclosable.
identifyRecursiveParents :: [T.Text] -> [[T.Text]] -> Set.Set T.Text
identifyRecursiveParents topLevelClaims nestedPaths =
  let getFirstSegment [] = ""
      getFirstSegment (seg:_) = seg
  in Set.fromList (map getFirstSegment nestedPaths) `Set.intersection` Set.fromList topLevelClaims

-- | Separate recursive disclosures (Section 6.3) from structured disclosures (Section 6.2).
separateRecursiveAndStructuredPaths
  :: Set.Set T.Text  -- ^ Recursive parent claim names
  -> [[T.Text]]  -- ^ All nested paths
  -> ([[T.Text]], [[T.Text]])  -- ^ (recursive paths, structured paths)
separateRecursiveAndStructuredPaths recursiveParents nestedPaths =
  partition (\path -> case path of
    [] -> False
    (first:_) -> Set.member first recursiveParents) nestedPaths

-- | Process top-level selectively disclosable claims (using ExceptT).
--
-- Creates disclosures and digests for top-level claims that are not recursive parents.
-- This version uses ExceptT for cleaner error handling.
processTopLevelSelectiveClaimsExceptT
  :: TopLevelClaimsConfig
  -> SDJWTIO TopLevelClaimsResult
processTopLevelSelectiveClaimsExceptT config = do
  let topLevelClaimsWithoutRecursive = filter (`Set.notMember` topLevelRecursiveParents config) (topLevelClaimNames config)
  let selectiveClaims = KeyMap.filterWithKey
        (\k _ -> Key.toText k `elem` topLevelClaimsWithoutRecursive) (topLevelRemainingClaims config)
  let regularClaims = KeyMap.filterWithKey
        (\k _ -> Key.toText k `notElem` topLevelClaimsWithoutRecursive) (topLevelRemainingClaims config)
  
  -- Create disclosures and digests for top-level selective claims
  -- According to RFC 9901, top-level arrays are treated as object properties
  -- (disclosure format: [salt, claim_name, claim_value])
  disclosureResults <- liftIO $ mapM (\(k, v) -> markSelectivelyDisclosable (topLevelHashAlg config) (Key.toText k) v) (KeyMap.toList selectiveClaims)
  
  -- Check for errors using ExceptT helper
  partitionAndHandle disclosureResults $ \successes -> do
    let (topLevelDigests, topLevelDisclosures) = unzip successes
    return TopLevelClaimsResult
      { resultDigests = topLevelDigests
      , resultDisclosures = topLevelDisclosures
      , resultRegularClaims = regularClaims
      }

-- | Combine all disclosures and digests from structured, recursive, and top-level processing.
combineAllDisclosuresAndDigests
  :: [EncodedDisclosure]  -- ^ Structured disclosures
  -> [EncodedDisclosure]  -- ^ Recursive disclosures
  -> [EncodedDisclosure]  -- ^ Top-level disclosures
  -> [Digest]  -- ^ Recursive parent digests
  -> [Digest]  -- ^ Top-level digests
  -> ([EncodedDisclosure], [Digest])
combineAllDisclosuresAndDigests structuredDisclosures recursiveDisclosures topLevelDisclosures recursiveParentDigests topLevelDigests =
  let allDisclosures = structuredDisclosures ++ recursiveDisclosures ++ topLevelDisclosures
      allDigests = recursiveParentDigests ++ topLevelDigests
  in (allDisclosures, allDigests)

-- | Build the final payload object with _sd_alg and _sd array.
buildFinalPayloadObject
  :: HashAlgorithm
  -> Aeson.Object  -- ^ Base payload (regular claims + structured nested structures)
  -> [Digest]  -- ^ All digests to include in _sd array
  -> Aeson.Object
buildFinalPayloadObject hashAlg basePayload allDigests =
  let payloadWithAlg = KeyMap.insert "_sd_alg" (Aeson.String (hashAlgorithmToText hashAlg)) basePayload
  in if null allDigests
       then payloadWithAlg
       else let sortedDigests = map (Aeson.String . unDigest) (sortDigests allDigests)
            in KeyMap.insert "_sd" (Aeson.Array (V.fromList sortedDigests)) payloadWithAlg

-- | Partition claim names into top-level and nested paths.
--
-- Nested paths use JSON Pointer syntax (RFC 6901) with forward slash as separator.
-- Examples:
--   - "address/street_address" → nested path: ["address", "street_address"]
--   - "nationalities/1" → nested path: ["nationalities", "1"] (could be array index OR object key "1")
--   - "user/profile/email" → nested path: ["user", "profile", "email"]
--   - "nested_array/0/1" → nested path: ["nested_array", "0", "1"]
--
-- Note: The path "x/22" is ambiguous - it could refer to:
--   - Array element at index 22 if "x" is an array
--   - Object property "22" if "x" is an object
-- The actual type is determined when processing the claims (see buildSDJWTPayload).
--
-- Escaping (RFC 6901):
--   - "~1" represents a literal forward slash "/"
--   - "~0" represents a literal tilde "~"
-- Examples:
--   - "contact~1email" → literal key "contact/email" (not a nested path)
--   - "user~0name" → literal key "user~name" (not a nested path)
--
-- Returns: (top-level claims, nested paths as list of segments)
partitionNestedPaths :: [T.Text] -> ([T.Text], [[T.Text]])
partitionNestedPaths claimNames =
  let (topLevel, nested) = partition (not . T.isInfixOf "/") claimNames
      nestedPaths = mapMaybe parseJSONPointerPath nested
      -- Unescape top-level claim names (they may contain ~0 or ~1)
      unescapedTopLevel = map unescapeJSONPointer topLevel
  in (unescapedTopLevel, nestedPaths)
  where
    -- Parse a JSON Pointer path, handling escaping
    -- Returns Nothing if invalid, Just [segments] if valid nested path
    -- Supports arbitrary depth: ["a"], ["a", "b"], ["a", "b", "c"], etc.
    parseJSONPointerPath :: T.Text -> Maybe [T.Text]
    parseJSONPointerPath path = do
      -- Split by "/" but handle escaped slashes
      let segments = splitJSONPointer path
      case segments of
        [] -> Nothing  -- Empty path is invalid
        [_] -> Nothing  -- Single segment is top-level, not nested
        _ -> Just (map unescapeJSONPointer segments)  -- Two or more segments = nested path
