{-# LANGUAGE OverloadedStrings #-}
-- | SD-JWT verification: Verifying SD-JWT presentations.
--
-- This module provides functions for verifying SD-JWT presentations on the verifier side.
-- It handles signature verification, disclosure validation, and payload processing.
module SDJWT.Internal.Verification
  ( -- * Public API
    verifySDJWT
  , verifyKeyBinding
    -- * Internal/Test-only functions
    -- These functions are exported primarily for testing purposes.
    -- Most users should use 'verifySDJWT' instead.
  , verifySDJWTSignature
  , verifySDJWTWithoutSignature
  , verifyDisclosures
  , processPayload
  , extractHashAlgorithm
  , parsePayloadFromJWT
  , extractRegularClaims
  , extractDigestsFromPayload
  ) where

import SDJWT.Internal.Types (HashAlgorithm(..), Digest(..), EncodedDisclosure(..), SDJWTPayload(..), SDJWTPresentation(..), ProcessedSDJWTPayload(..), SDJWTError(..), KeyBindingInfo(..))
import SDJWT.Internal.Digest (extractDigestsFromValue, computeDigest, computeDigestText, parseHashAlgorithm, defaultHashAlgorithm)
import SDJWT.Internal.Disclosure (decodeDisclosure, getDisclosureValue, getDisclosureClaimName)
import SDJWT.Internal.Utils (base64urlDecode)
import SDJWT.Internal.KeyBinding (verifyKeyBindingJWT)
import SDJWT.Internal.JWT (verifyJWT, JWKLike)
import SDJWT.Internal.Monad (SDJWTIO, runSDJWTIO, eitherToExceptT)
import Control.Monad.Except (throwError)
import Control.Monad.IO.Class (liftIO)
import qualified Data.Aeson as Aeson
import qualified Data.Aeson.Key as Key
import qualified Data.Aeson.KeyMap as KeyMap
import qualified Data.Map.Strict as Map
import qualified Data.Text as T
import qualified Data.Vector as V
import qualified Data.Set as Set
import qualified Data.ByteString.Lazy as BSL
import Data.Maybe (mapMaybe, catMaybes)
import Data.Either (partitionEithers)
import Data.Text.Encoding (decodeUtf8)

-- | Complete SD-JWT verification.
--
-- This function performs all verification steps:
--
-- 1. Parses the presentation
-- 2. Verifies issuer signature (required)
-- 3. Validates standard JWT claims (if present): @exp@ (expiration time), @nbf@ (not before), etc.
-- 4. Extracts hash algorithm
-- 5. Verifies disclosures match digests
-- 6. Verifies key binding (if present)
-- 7. Processes payload to reconstruct claims
--
-- Returns the processed payload with all claims (both regular non-selectively-disclosable
-- claims and disclosed selectively-disclosable claims). If a KB-JWT was present and verified,
-- the 'keyBindingInfo' field will contain the holder's public key extracted from the
-- @cnf@ claim, allowing the verifier to use it for subsequent operations.
--
-- == Standard JWT Claims Validation
--
-- Standard JWT claims (RFC 7519) included in the issuer-signed JWT are automatically validated:
--
-- - @exp@ (expiration time): Token is rejected if expired
-- - @nbf@ (not before): Token is rejected if not yet valid
-- - Other standard claims are preserved but not validated by this library
--
-- For testing or debugging purposes where signature verification should be skipped,
-- use 'verifySDJWTWithoutSignature' instead.
verifySDJWT
  :: JWKLike jwk => jwk  -- ^ Issuer public key (Text or jose JWK object)
  -> SDJWTPresentation
  -> Maybe T.Text  -- ^ Required typ header value (Nothing = allow any/none, Just "sd-jwt" = require exactly "sd-jwt")
  -> IO (Either SDJWTError ProcessedSDJWTPayload)
verifySDJWT issuerKey presentation requiredTyp =
  runSDJWTIO $ do
    -- Verify issuer signature (required)
    verifySDJWTSignatureExceptT issuerKey presentation requiredTyp
    verifySDJWTAfterSignatureExceptT presentation

-- | SD-JWT verification without signature verification.
--
-- This function performs verification steps 3-6 of 'verifySDJWT' but skips
-- signature verification. This is useful for testing or debugging, but should
-- NOT be used in production as it does not verify the authenticity of the JWT.
--
-- WARNING: This function does not verify the issuer signature. Only use this
-- function when signature verification is not required (e.g., in tests or
-- when verifying locally-generated JWTs).
verifySDJWTWithoutSignature
  :: SDJWTPresentation
  -> IO (Either SDJWTError ProcessedSDJWTPayload)
verifySDJWTWithoutSignature = runSDJWTIO . verifySDJWTAfterSignatureExceptT

-- | Internal ExceptT version of verifySDJWTAfterSignature.
verifySDJWTAfterSignatureExceptT
  :: SDJWTPresentation
  -> SDJWTIO ProcessedSDJWTPayload
verifySDJWTAfterSignatureExceptT presentation = do
  -- Extract hash algorithm from payload
  alg <- eitherToExceptT $ extractHashAlgorithmFromPresentation presentation
  
  -- Verify disclosures match digests
  eitherToExceptT $ verifyDisclosures alg presentation
  
  -- Verify key binding if present
  case keyBindingJWT presentation of
    Just kbJWT -> do
      -- Extract holder public key from cnf claim in SD-JWT payload
      kbInfo <- liftIO (extractHolderKeyFromPayload presentation) >>= eitherToExceptT
      -- Verify KB-JWT using holder's public key from cnf claim
      -- kbPublicKey is compatible with JWKLike (Text implements JWKLike)
      liftIO (verifyKeyBindingJWT alg (kbPublicKey kbInfo) kbJWT presentation) >>= eitherToExceptT
      -- Process payload to reconstruct claims, including key binding info
      eitherToExceptT $ processPayloadFromPresentation alg presentation (Just kbInfo)
    Nothing -> do
      -- Process payload to reconstruct claims (no key binding)
      eitherToExceptT $ processPayloadFromPresentation alg presentation Nothing

-- | Verify SD-JWT issuer signature.
--
-- Verifies the signature on the issuer-signed JWT using the issuer's public key.
verifySDJWTSignature
  :: JWKLike jwk => jwk  -- ^ Issuer public key (Text or jose JWK object)
  -> SDJWTPresentation  -- ^ SD-JWT presentation to verify
  -> Maybe T.Text  -- ^ Required typ header value (Nothing = allow any typ or none, Just typValue = require typ to be exactly that value)
  -> IO (Either SDJWTError ())
verifySDJWTSignature issuerKey presentation requiredTyp =
  runSDJWTIO $ verifySDJWTSignatureExceptT issuerKey presentation requiredTyp

-- | Internal ExceptT version of verifySDJWTSignature.
verifySDJWTSignatureExceptT
  :: JWKLike jwk => jwk  -- ^ Issuer public key (Text or jose JWK object)
  -> SDJWTPresentation  -- ^ SD-JWT presentation to verify
  -> Maybe T.Text  -- ^ Required typ header value (Nothing = allow any typ or none, Just typValue = require typ to be exactly that value)
  -> SDJWTIO ()
verifySDJWTSignatureExceptT issuerKey presentation requiredTyp = do
  -- Verify JWT signature using verifyJWT (ignore the returned payload value)
  liftIO (verifyJWT issuerKey (presentationJWT presentation) requiredTyp) >>= eitherToExceptT . fmap (const ())

-- | Verify key binding in a presentation.
--
-- Verifies the Key Binding JWT if present in the presentation.
-- This includes verifying the KB-JWT signature and sd_hash.
verifyKeyBinding
  :: JWKLike jwk => HashAlgorithm
  -> jwk  -- ^ Holder public key (Text or jose JWK object)
  -> SDJWTPresentation
  -> IO (Either SDJWTError ())
verifyKeyBinding hashAlg holderKey presentation = do
  case keyBindingJWT presentation of
    Nothing -> return (Right ())  -- No key binding, verification passes
    Just kbJWT -> verifyKeyBindingJWT hashAlg holderKey kbJWT presentation

-- | Verify that all disclosures match digests in the payload.
--
-- This function:
--
-- 1. Computes digest for each disclosure
-- 2. Verifies each digest exists in the payload's _sd array
-- 3. Checks for duplicate disclosures
verifyDisclosures
  :: HashAlgorithm
  -> SDJWTPresentation
  -> Either SDJWTError ()
verifyDisclosures hashAlg presentation = do
  -- Parse payload from JWT
  sdPayload <- parsePayloadFromJWT (presentationJWT presentation)
  
  -- Get all digests from payload
  payloadDigests <- extractDigestsFromPayload sdPayload
  
  -- Get all digests from recursive disclosures (disclosures that contain _sd arrays)
  -- For Section 6.3 recursive disclosures, child digests are in the parent disclosure's _sd array
  recursiveDisclosureDigests <- extractDigestsFromRecursiveDisclosures (selectedDisclosures presentation)
  
  -- Combine all valid digests (payload + recursive disclosures)
  let allValidDigests = Set.fromList (map unDigest (payloadDigests ++ recursiveDisclosureDigests))
  
  -- Compute digests for all disclosures
  let disclosureTexts = map (computeDigestText hashAlg) (selectedDisclosures presentation)
  let disclosureSet = Set.fromList disclosureTexts
  
  -- Check for duplicates (compare by text representation)
  if Set.size disclosureSet /= length disclosureTexts
    then Left $ DuplicateDisclosure "Duplicate disclosures found"
    else return ()
  
  -- Verify each disclosure digest exists in payload or recursive disclosures
  let missingDigests = filter (`Set.notMember` allValidDigests) disclosureTexts
  
  case missingDigests of
    [] -> return ()
    (missing:_) -> Left $ MissingDisclosure $ "Disclosure digest not found in payload: " <> missing

-- | Process SD-JWT payload by replacing digests with disclosure values.
--
-- This function reconstructs the full claims set by:
--
-- 1. Starting with regular (non-selectively disclosable) claims
-- 2. Replacing digests in _sd arrays with actual claim values from disclosures
processPayload
  :: HashAlgorithm
  -> SDJWTPayload
  -> [EncodedDisclosure]
  -> Maybe KeyBindingInfo  -- ^ Key binding info if KB-JWT was present and verified
  -> Either SDJWTError ProcessedSDJWTPayload
processPayload hashAlg sdPayload sdDisclosures mbKeyBindingInfo = do
  -- Start with regular claims (non-selectively disclosable)
  regularClaims <- extractRegularClaims (payloadValue sdPayload)
  
  -- Process disclosures to create maps of digests to claim values
  (objectDisclosureMap, arrayDisclosureMap) <- buildDisclosureMap hashAlg sdDisclosures
  
  -- Replace digests in _sd arrays with actual values and process arrays
  finalClaims <- replaceDigestsWithValues regularClaims objectDisclosureMap arrayDisclosureMap
  
  return $ ProcessedSDJWTPayload { processedClaims = finalClaims, keyBindingInfo = mbKeyBindingInfo }

-- | Extract hash algorithm from presentation.
--
-- Parses the JWT payload and extracts the _sd_alg claim, defaulting to SHA-256.
extractHashAlgorithm
  :: SDJWTPresentation
  -> Either SDJWTError HashAlgorithm
extractHashAlgorithm = extractHashAlgorithmFromPresentation

-- Helper functions

-- | Extract hash algorithm from presentation payload.
extractHashAlgorithmFromPresentation
  :: SDJWTPresentation
  -> Either SDJWTError HashAlgorithm
extractHashAlgorithmFromPresentation presentation =
  fmap (maybe defaultHashAlgorithm id . sdAlg) (parsePayloadFromJWT (presentationJWT presentation))

-- | Extract holder public key from cnf claim in SD-JWT payload.
--
-- The cnf claim (RFC 7800) contains the holder's public key, typically
-- in the format: {"cnf": {"jwk": {...}}}
-- This function extracts the JWK and returns it as a KeyBindingInfo.
extractHolderKeyFromPayload
  :: SDJWTPresentation
  -> IO (Either SDJWTError KeyBindingInfo)
extractHolderKeyFromPayload presentation =
  runSDJWTIO $ extractHolderKeyFromPayloadExceptT presentation

-- | Internal ExceptT version of extractHolderKeyFromPayload.
extractHolderKeyFromPayloadExceptT
  :: SDJWTPresentation
  -> SDJWTIO KeyBindingInfo
extractHolderKeyFromPayloadExceptT presentation = do
  payload <- eitherToExceptT $ parsePayloadFromJWT (presentationJWT presentation)
  
  -- Extract cnf claim from payload
  case payloadValue payload of
    Aeson.Object obj ->
      case KeyMap.lookup "cnf" obj of
        Just (Aeson.Object cnfObj) ->
          -- Extract jwk from cnf object (RFC 7800 jwk confirmation method)
          case KeyMap.lookup "jwk" cnfObj of
            Just jwkValue -> do
              -- Encode JWK as JSON string
              let jwkJson = Aeson.encode jwkValue
              return $ KeyBindingInfo $ decodeUtf8 $ BSL.toStrict jwkJson
            Nothing -> throwError $ InvalidKeyBinding "Missing jwk in cnf claim"
        Just _ -> throwError $ InvalidKeyBinding "cnf claim is not an object"
        Nothing -> throwError $ InvalidKeyBinding "Missing cnf claim in SD-JWT payload"
    _ -> throwError $ InvalidKeyBinding "SD-JWT payload is not an object"

-- | Parse payload from JWT.
--
-- | Parse JWT payload from a JWT string (advanced/internal use).
--
-- Extracts and decodes the JWT payload (middle part) from a JWT string.
-- This function properly decodes the base64url-encoded payload and parses it as JSON.
--
-- This function is exported for advanced use cases and internal library use.
-- Most users should use 'verifySDJWT' or 'verifySDJWTWithoutSignature' instead,
-- which handle payload parsing internally.
--
-- This function is used internally by:
--
-- * 'SDJWT.Presentation' - To parse payloads when selecting disclosures
-- * 'verifyDisclosures' - To extract digests from payloads
-- * 'extractHashAlgorithm' - To extract hash algorithm from payloads
--
-- == Advanced/Internal Use
--
-- This function is primarily used internally by other modules (e.g., 'SDJWT.Internal.Presentation').
-- Most users should use higher-level functions like 'verifySDJWT' instead.
-- Only use this function directly if you need fine-grained control over JWT parsing.
--
parsePayloadFromJWT :: T.Text -> Either SDJWTError SDJWTPayload
parsePayloadFromJWT jwt =
  -- Split JWT into parts (header.payload.signature)
  let parts = T.splitOn "." jwt
  in case parts of
    (_header : payloadPart : _signature) -> do
      -- Decode base64url payload
      payloadBytes <- either (\err -> Left $ JSONParseError $ "Failed to decode JWT payload: " <> err) Right (base64urlDecode payloadPart)
      -- Parse JSON payload
      payloadJson <- either (\err -> Left $ JSONParseError $ "Failed to parse JWT payload: " <> T.pack err) Right (Aeson.eitherDecodeStrict payloadBytes)
      -- Extract hash algorithm from payload
      let hashAlg = extractHashAlgorithmFromPayload payloadJson
      return $ SDJWTPayload
        { sdAlg = hashAlg
        , payloadValue = payloadJson
        }
    _ -> Left $ InvalidSignature "Invalid JWT format: expected header.payload.signature"
  
  where
    -- Extract hash algorithm from payload JSON
    extractHashAlgorithmFromPayload :: Aeson.Value -> Maybe HashAlgorithm
    extractHashAlgorithmFromPayload (Aeson.Object obj) =
      case KeyMap.lookup "_sd_alg" obj of
        Just (Aeson.String algText) -> parseHashAlgorithm algText
        _ -> Nothing
    extractHashAlgorithmFromPayload _ = Nothing

-- | Extract digests from payload's _sd array and arrays with ellipsis objects.
extractDigestsFromPayload :: SDJWTPayload -> Either SDJWTError [Digest]
extractDigestsFromPayload sdPayload = extractDigestsFromValue (payloadValue sdPayload)

-- | Extract digests from recursive disclosures (disclosures that contain _sd arrays).
-- For Section 6.3 recursive disclosures, child digests are in the parent disclosure's _sd array.
extractDigestsFromRecursiveDisclosures
  :: [EncodedDisclosure]
  -> Either SDJWTError [Digest]
extractDigestsFromRecursiveDisclosures disclosures =
  concat <$> mapM (\encDisclosure ->
    case decodeDisclosure encDisclosure of
      Left _ -> Right []  -- Skip invalid disclosures
      Right decoded ->
        let claimValue = getDisclosureValue decoded
        -- Extract digests from _sd arrays in disclosure values
        in extractDigestsFromValue claimValue
    ) disclosures

-- | Extract regular (non-selectively disclosable) claims from payload.
--
-- JWT payloads must be JSON objects (RFC 7519), so this function only accepts
-- Aeson.Object values. Returns an error if given a non-object value.
extractRegularClaims :: Aeson.Value -> Either SDJWTError Aeson.Object
extractRegularClaims (Aeson.Object obj) =
  Right $ KeyMap.filterWithKey (\k _ ->
    let keyText = Key.toText k
    in keyText /= "_sd" && keyText /= "_sd_alg" && keyText /= "cnf"
  ) obj
extractRegularClaims _ = Left $ JSONParseError "JWT payload must be a JSON object"

-- | Build maps from digests to disclosure values.
-- Returns two maps:
--
-- 1. Object disclosures: digest -> (claimName, claimValue)
-- 2. Array disclosures: digest -> value
buildDisclosureMap
  :: HashAlgorithm
  -> [EncodedDisclosure]
  -> Either SDJWTError (Map.Map T.Text (T.Text, Aeson.Value), Map.Map T.Text Aeson.Value)
buildDisclosureMap hashAlg sdDisclosures =
  -- Process each disclosure and separate into object and array disclosures
  (\disclosureResults ->
    -- Partition into object and array results
    let (objectResults, arrayResults) = partitionEithers disclosureResults
    in (Map.fromList objectResults, Map.fromList arrayResults)
  ) <$> mapM (\encDisclosure ->
    decodeDisclosure encDisclosure >>= \decodedDisclosure ->
      let digestText = computeDigestText hashAlg encDisclosure
          claimName = getDisclosureClaimName decodedDisclosure
          claimValue = getDisclosureValue decodedDisclosure
      in return $ case claimName of
           Just name -> Left (digestText, (name, claimValue))  -- Object disclosure
           Nothing -> Right (digestText, claimValue)  -- Array disclosure
    ) sdDisclosures

-- | Replace digests in payload with actual claim values.
-- This function:
--
-- 1. Processes object claims (replaces digests in _sd arrays with values, recursively)
-- 2. Recursively processes arrays to replace {"...": "<digest>"} objects with values
replaceDigestsWithValues
  :: Aeson.Object
  -> Map.Map T.Text (T.Text, Aeson.Value)  -- Object disclosures: digest -> (claimName, claimValue)
  -> Map.Map T.Text Aeson.Value  -- Array disclosures: digest -> value
  -> Either SDJWTError Aeson.Object
replaceDigestsWithValues regularClaims objectDisclosureMap arrayDisclosureMap = do
  -- Process object claims: replace digests in _sd arrays with values (including nested _sd arrays)
  let disclosedClaims = KeyMap.fromList $ map (\(claimName, claimValue) -> (Key.fromText claimName, claimValue)) (Map.elems objectDisclosureMap)
      objectClaims = KeyMap.union disclosedClaims regularClaims
  -- Process arrays recursively to replace {"...": "<digest>"} objects
  -- Also process nested _sd arrays recursively
  -- Note: Array disclosure values may contain _sd arrays (for nested selective disclosure),
  -- so we need to process _sd arrays in those values too
  processArraysInClaimsWithSD (processSDArraysInClaims objectClaims objectDisclosureMap) arrayDisclosureMap objectDisclosureMap

-- | Recursively process _sd arrays in claims to replace digests with values.
processSDArraysInClaims
  :: Aeson.Object
  -> Map.Map T.Text (T.Text, Aeson.Value)  -- Object disclosures: digest -> (claimName, claimValue)
  -> Aeson.Object
processSDArraysInClaims claims objectDisclosureMap =
  KeyMap.map (`processSDArraysInValue` objectDisclosureMap) claims

-- | Recursively process a JSON value to replace digests in _sd arrays with values.
processSDArraysInValue
  :: Aeson.Value
  -> Map.Map T.Text (T.Text, Aeson.Value)  -- Object disclosures: digest -> (claimName, claimValue)
  -> Aeson.Value
processSDArraysInValue (Aeson.Object obj) objectDisclosureMap =
  -- Check if this object has an _sd array
  case KeyMap.lookup "_sd" obj of
    Just (Aeson.Array arr) ->
      -- Extract claims from _sd array digests
      let disclosedClaims = mapMaybe (\el -> case el of
            Aeson.String digest -> 
              -- Look up the claim name and value for this digest
              Map.lookup digest objectDisclosureMap
            _ -> Nothing  -- Not a string digest, skip
            ) (V.toList arr)
      
      -- Build new object: remove _sd and _sd_alg (metadata fields), add disclosed claims, keep other fields
          objWithoutSD = KeyMap.delete "_sd_alg" $ KeyMap.delete "_sd" obj
          objWithDisclosedClaims = foldl (\acc (claimName, claimValue) ->
                KeyMap.insert (Key.fromText claimName) claimValue acc) objWithoutSD disclosedClaims
      -- Recursively process nested objects (including the newly added claims)
          processedObj = KeyMap.map (`processSDArraysInValue` objectDisclosureMap) objWithDisclosedClaims
      in Aeson.Object processedObj
    _ ->
      -- _sd doesn't exist or is not an array, just recursively process nested objects
      Aeson.Object (KeyMap.map (`processSDArraysInValue` objectDisclosureMap) obj)
processSDArraysInValue (Aeson.Array arr) objectDisclosureMap =
  -- Recursively process array elements
  Aeson.Array $ V.map (`processSDArraysInValue` objectDisclosureMap) arr
processSDArraysInValue value _objectDisclosureMap = value  -- Primitive values, keep as is

-- | Recursively process arrays in claims to replace {"...": "<digest>"} objects with values.
-- Also processes _sd arrays in array disclosure values (for nested selective disclosure).
-- | Process arrays in claims, also processing _sd arrays in array disclosure values.
processArraysInClaimsWithSD
  :: Aeson.Object
  -> Map.Map T.Text Aeson.Value  -- Array disclosures: digest -> value
  -> Map.Map T.Text (T.Text, Aeson.Value)  -- Object disclosures: digest -> (claimName, claimValue)
  -> Either SDJWTError Aeson.Object
processArraysInClaimsWithSD claims arrayDisclosureMap objectDisclosureMap = do
  processedPairs <- mapM (\(key, value) -> do
    processedValue <- processValueForArraysWithSD value arrayDisclosureMap objectDisclosureMap
    return (key, processedValue)
    ) (KeyMap.toList claims)
  return $ KeyMap.fromList processedPairs

-- | Remove _sd_alg metadata field while preserving the JSON type structure.
removeSDAlgPreservingType :: Aeson.Value -> Aeson.Value
removeSDAlgPreservingType (Aeson.Object obj') =
  let objWithoutSDAlg = KeyMap.delete "_sd_alg" obj'
  -- Preserve the object type: if empty, return empty object {}, not []
  in if KeyMap.null objWithoutSDAlg
    then Aeson.Object KeyMap.empty
    else Aeson.Object objWithoutSDAlg
removeSDAlgPreservingType (Aeson.Array arr') =
  -- Preserve the array type: if empty, return empty array []
  if V.null arr'
    then Aeson.Array V.empty
    else Aeson.Array arr'
removeSDAlgPreservingType value = value

-- | Process an ellipsis object {"...": "<digest>"} by replacing it with the disclosure value.
processEllipsisObject
  :: Aeson.Object
  -> Map.Map T.Text Aeson.Value  -- Array disclosures: digest -> value
  -> Map.Map T.Text (T.Text, Aeson.Value)  -- Object disclosures: digest -> (claimName, claimValue)
  -> Either SDJWTError (Maybe Aeson.Value)
processEllipsisObject obj arrayDisclosureMap objectDisclosureMap =
  -- Check if this is a {"...": "<digest>"} object
  case KeyMap.lookup (Key.fromText "...") obj of
    Just (Aeson.String digest) ->
      -- Validate that ellipsis object only contains the "..." key
      -- Per RFC 9901 Section 4.2.4.2: "There MUST NOT be any other keys in the object."
      if KeyMap.size obj == 1
        then
          -- Look up the value for this digest
          case Map.lookup digest arrayDisclosureMap of
            Just value -> do
              -- Process _sd arrays in the array disclosure value (for nested selective disclosure)
              let processedSD = processSDArraysInValue value objectDisclosureMap
                  -- Remove _sd_alg (metadata field) from array disclosure values
                  processedWithoutSDAlg = removeSDAlgPreservingType processedSD
              -- Recursively process nested arrays with ellipsis objects (RFC 9901 Section 7.1 Step 2.c.iii.3)
              -- This handles cases where array disclosure values are themselves arrays with ellipsis objects
              processedValue <- processValueForArraysWithSD processedWithoutSDAlg arrayDisclosureMap objectDisclosureMap
              return (Just processedValue)
            Nothing ->
              -- No disclosure found - per RFC 9901 Section 7.3, remove the array element
              -- "Verifiers ignore all selectively disclosable array elements for which
              -- they did not receive a Disclosure."
              return Nothing
        else Left $ InvalidDigest "Ellipsis object must contain only the \"...\" key (RFC 9901 Section 4.2.4.2)"
    _ -> return (Just (Aeson.Object obj))  -- Not an ellipsis object, keep as is

-- | Recursively process a JSON value to replace {"...": "<digest>"} objects in arrays,
-- and also process _sd arrays in array disclosure values (for nested selective disclosure).
processValueForArraysWithSD
  :: Aeson.Value
  -> Map.Map T.Text Aeson.Value  -- Array disclosures: digest -> value
  -> Map.Map T.Text (T.Text, Aeson.Value)  -- Object disclosures: digest -> (claimName, claimValue)
  -> Either SDJWTError Aeson.Value
processValueForArraysWithSD (Aeson.Array arr) arrayDisclosureMap objectDisclosureMap = do
  -- Process each element in the array
  processedElements <- mapM (\el -> processValueForArraysWithSD el arrayDisclosureMap objectDisclosureMap) (V.toList arr)
  -- Replace {"...": "<digest>"} objects with actual values
  -- Per RFC 9901 Section 7.3: "Verifiers ignore all selectively disclosable array elements
  -- for which they did not receive a Disclosure."
  replacedElements <- mapM (\el -> case el of
        Aeson.Object obj -> processEllipsisObject obj arrayDisclosureMap objectDisclosureMap
        _ -> return (Just el)  -- Not an object, keep as is
        ) processedElements
  return $ Aeson.Array $ V.fromList $ catMaybes replacedElements
processValueForArraysWithSD (Aeson.Object obj) arrayDisclosureMap objectDisclosureMap = do
  -- Recursively process nested objects and _sd arrays
  processedPairs <- mapM (\(key, value) -> do
    processedValue <- processValueForArraysWithSD value arrayDisclosureMap objectDisclosureMap
    return (key, processedValue)
    ) (KeyMap.toList obj)
  let processedKeyMap = KeyMap.fromList processedPairs
      -- Also process _sd arrays in this object
      processedWithSD = processSDArraysInValue (Aeson.Object processedKeyMap) objectDisclosureMap
  return processedWithSD
processValueForArraysWithSD value _arrayDisclosureMap _objectDisclosureMap = return value  -- Primitive values, keep as is

-- | Process payload from presentation (convenience function).
processPayloadFromPresentation
  :: HashAlgorithm
  -> SDJWTPresentation
  -> Maybe KeyBindingInfo  -- ^ Key binding info if KB-JWT was present and verified
  -> Either SDJWTError ProcessedSDJWTPayload
processPayloadFromPresentation hashAlg presentation mbKeyBindingInfo = do
  sdPayload <- parsePayloadFromJWT (presentationJWT presentation)
  processPayload hashAlg sdPayload (selectedDisclosures presentation) mbKeyBindingInfo


