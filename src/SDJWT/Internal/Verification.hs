{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE LambdaCase #-}
-- | SD-JWT verification: Verifying SD-JWT presentations.
--
-- This module provides functions for verifying SD-JWT presentations on the verifier side.
-- It handles signature verification, disclosure validation, and payload processing.
module SDJWT.Internal.Verification
  ( verifySDJWT
  , verifySDJWTSignature
  , verifySDJWTWithoutSignature
  , verifyKeyBinding
  , verifyDisclosures
  , processPayload
  , extractHashAlgorithm
  , parsePayloadFromJWT
  ) where

import SDJWT.Internal.Types (HashAlgorithm(..), Digest(..), EncodedDisclosure(..), SDJWTPayload(..), SDJWTPresentation(..), ProcessedSDJWTPayload(..), SDJWTError(..))
import SDJWT.Internal.Digest (extractDigestsFromValue, computeDigest, parseHashAlgorithm, defaultHashAlgorithm)
import SDJWT.Internal.Disclosure (decodeDisclosure, getDisclosureValue, getDisclosureClaimName)
import SDJWT.Internal.Utils (base64urlDecode)
import SDJWT.Internal.KeyBinding (verifyKeyBindingJWT)
import SDJWT.Internal.JWT (verifyJWT, JWKLike)
import qualified Data.Aeson as Aeson
import qualified Data.Aeson.Key as Key
import qualified Data.Aeson.KeyMap as KeyMap
import qualified Data.Map.Strict as Map
import qualified Data.Text as T
import qualified Data.Vector as V
import qualified Data.Set as Set
import qualified Data.ByteString.Lazy as BSL
import Data.Maybe (mapMaybe)
import Data.Either (partitionEithers)
import Control.Monad (when)
import Data.Text.Encoding (decodeUtf8)

-- | Complete SD-JWT verification.
--
-- This function performs all verification steps:
-- 1. Parses the presentation
-- 2. Verifies issuer signature (required)
-- 3. Extracts hash algorithm
-- 4. Verifies disclosures match digests
-- 5. Verifies key binding (if present)
-- 6. Processes payload to reconstruct claims
--
-- Returns the processed payload with all disclosed claims.
--
-- For testing or debugging purposes where signature verification should be skipped,
-- use 'verifySDJWTWithoutSignature' instead.
verifySDJWT
  :: JWKLike jwk => jwk  -- ^ Issuer public key (Text or jose JWK object)
  -> SDJWTPresentation
  -> Maybe T.Text  -- ^ Required typ header value (Nothing = allow any/none, Just "sd-jwt" = require exactly "sd-jwt")
  -> IO (Either SDJWTError ProcessedSDJWTPayload)
verifySDJWT issuerKey presentation requiredTyp = do
  -- Verify issuer signature (required)
  verifyResult <- verifySDJWTSignature issuerKey presentation requiredTyp
  case verifyResult of
    Left err -> return (Left err)
    Right () -> verifySDJWTAfterSignature presentation

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
verifySDJWTWithoutSignature = verifySDJWTAfterSignature

-- | Continue SD-JWT verification after signature verification (if performed).
verifySDJWTAfterSignature
  :: SDJWTPresentation
  -> IO (Either SDJWTError ProcessedSDJWTPayload)
verifySDJWTAfterSignature presentation = do
  -- Extract hash algorithm from payload
  hashAlg <- case extractHashAlgorithmFromPresentation presentation of
    Left err -> return (Left err)
    Right alg -> return (Right alg)
  
  case hashAlg of
    Left err -> return (Left err)
    Right alg -> do
      -- Verify disclosures match digests
      case verifyDisclosures alg presentation of
        Left err -> return (Left err)
        Right () -> do
          -- Verify key binding if present
          case keyBindingJWT presentation of
            Just kbJWT -> do
              -- Extract holder public key from cnf claim in SD-JWT payload
              holderKeyResult <- extractHolderKeyFromPayload presentation
              case holderKeyResult of
                Left err -> return (Left err)
                Right holderKey -> do
                  -- Verify KB-JWT using holder's public key from cnf claim
                  kbVerifyResult <- verifyKeyBindingJWT alg holderKey kbJWT presentation
                  case kbVerifyResult of
                    Left err -> return (Left err)
                    Right () -> do
                      -- Process payload to reconstruct claims
                      case processPayloadFromPresentation alg presentation of
                        Left err -> return (Left err)
                        Right processed -> return (Right processed)
            Nothing -> do
              -- Process payload to reconstruct claims
              case processPayloadFromPresentation alg presentation of
                Left err -> return (Left err)
                Right processed -> return (Right processed)

-- | Verify SD-JWT issuer signature.
--
-- Verifies the signature on the issuer-signed JWT using the issuer's public key.
--
-- Parameters:
-- - issuerKey: Issuer public key (JWK as Text)
-- - presentation: SD-JWT presentation to verify
-- - requiredTyp: If Nothing, allow any typ or none (liberal). If Just typValue, require typ to be exactly that value.
verifySDJWTSignature
  :: JWKLike jwk => jwk  -- ^ Issuer public key (Text or jose JWK object)
  -> SDJWTPresentation
  -> Maybe T.Text  -- ^ Required typ header value (Nothing = allow any/none, Just "sd-jwt" = require exactly "sd-jwt")
  -> IO (Either SDJWTError ())
verifySDJWTSignature issuerKey presentation requiredTyp = do
  -- Verify JWT signature using verifyJWT
  verifiedPayloadResult <- verifyJWT issuerKey (presentationJWT presentation) requiredTyp
  case verifiedPayloadResult of
    Left err -> return (Left err)
    Right _ -> return (Right ())

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
-- 1. Computes digest for each disclosure
-- 2. Verifies each digest exists in the payload's _sd array
-- 3. Checks for duplicate disclosures
verifyDisclosures
  :: HashAlgorithm
  -> SDJWTPresentation
  -> Either SDJWTError ()
verifyDisclosures hashAlg presentation = do
  -- Parse payload from JWT (simplified for now)
  sdPayload <- parsePayloadFromJWT (presentationJWT presentation)
  
  -- Get all digests from payload
  let payloadDigests = extractDigestsFromPayload sdPayload
  
  -- Get all digests from recursive disclosures (disclosures that contain _sd arrays)
  -- For Section 6.3 recursive disclosures, child digests are in the parent disclosure's _sd array
  let recursiveDisclosureDigests = extractDigestsFromRecursiveDisclosures hashAlg (selectedDisclosures presentation)
  
  -- Combine all valid digests (payload + recursive disclosures)
  let allValidDigests = Set.fromList (map unDigest (payloadDigests ++ recursiveDisclosureDigests))
  
  -- Compute digests for all disclosures
  let disclosureDigests = map (computeDigest hashAlg) (selectedDisclosures presentation)
  
  -- Check for duplicates (compare by text representation)
  let disclosureTexts = map unDigest disclosureDigests
  let disclosureSet = Set.fromList disclosureTexts
  when (Set.size disclosureSet /= length disclosureTexts) $
    Left $ DuplicateDisclosure "Duplicate disclosures found"
  
  -- Verify each disclosure digest exists in payload or recursive disclosures
  let missingDigests = filter (\d -> unDigest d `Set.notMember` allValidDigests) disclosureDigests
  
  case missingDigests of
    [] -> return ()
    (missing:_) -> Left $ MissingDisclosure $ "Disclosure digest not found in payload: " <> unDigest missing

-- | Process SD-JWT payload by replacing digests with disclosure values.
--
-- This function reconstructs the full claims set by:
-- 1. Starting with regular (non-selectively disclosable) claims
-- 2. Replacing digests in _sd arrays with actual claim values from disclosures
processPayload
  :: HashAlgorithm
  -> SDJWTPayload
  -> [EncodedDisclosure]
  -> Either SDJWTError ProcessedSDJWTPayload
processPayload hashAlg sdPayload sdDisclosures = do
  -- Start with regular claims (non-selectively disclosable)
  let regularClaims = extractRegularClaims (payloadValue sdPayload)
  
  -- Process disclosures to create maps of digests to claim values
  (objectDisclosureMap, arrayDisclosureMap) <- buildDisclosureMap hashAlg sdDisclosures
  
  -- Replace digests in _sd arrays with actual values and process arrays
  let finalClaims = replaceDigestsWithValues regularClaims objectDisclosureMap arrayDisclosureMap (payloadValue sdPayload)
  
  return $ ProcessedSDJWTPayload { processedClaims = finalClaims }

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
extractHashAlgorithmFromPresentation presentation = do
  sdPayload <- parsePayloadFromJWT (presentationJWT presentation)
  case sdAlg sdPayload of
    Just alg -> return alg
    Nothing -> return defaultHashAlgorithm

-- | Extract holder public key from cnf claim in SD-JWT payload.
--
-- The cnf claim (RFC 7800) contains the holder's public key, typically
-- in the format: {"cnf": {"jwk": {...}}}
-- This function extracts the JWK as a JSON string.
extractHolderKeyFromPayload
  :: SDJWTPresentation
  -> IO (Either SDJWTError T.Text)
extractHolderKeyFromPayload presentation = do
  sdPayload <- case parsePayloadFromJWT (presentationJWT presentation) of
    Left err -> return (Left err)
    Right payload -> return (Right payload)
  
  case sdPayload of
    Left err -> return (Left err)
    Right payload -> do
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
                  return $ Right $ decodeUtf8 $ BSL.toStrict jwkJson
                Nothing -> return $ Left $ InvalidKeyBinding "Missing jwk in cnf claim"
            Just _ -> return $ Left $ InvalidKeyBinding "cnf claim is not an object"
            Nothing -> return $ Left $ InvalidKeyBinding "Missing cnf claim in SD-JWT payload"
        _ -> return $ Left $ InvalidKeyBinding "SD-JWT payload is not an object"

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
parsePayloadFromJWT jwt = do
  -- Split JWT into parts (header.payload.signature)
  let parts = T.splitOn "." jwt
  case parts of
    (_header : payloadPart : _signature) -> do
      -- Decode base64url payload
      payloadBytes <- case base64urlDecode payloadPart of
        Left err -> Left $ JSONParseError $ "Failed to decode JWT payload: " <> err
        Right bs -> Right bs
      
      -- Parse JSON payload
      payloadJson <- case Aeson.eitherDecodeStrict payloadBytes of
        Left err -> Left $ JSONParseError $ "Failed to parse JWT payload: " <> T.pack err
        Right val -> Right val
      
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
extractDigestsFromPayload :: SDJWTPayload -> [Digest]
extractDigestsFromPayload sdPayload = extractDigestsFromValue (payloadValue sdPayload)

-- | Extract digests from recursive disclosures (disclosures that contain _sd arrays).
-- For Section 6.3 recursive disclosures, child digests are in the parent disclosure's _sd array.
extractDigestsFromRecursiveDisclosures
  :: HashAlgorithm
  -> [EncodedDisclosure]
  -> [Digest]
extractDigestsFromRecursiveDisclosures _hashAlg disclosures =
  concatMap (\encDisclosure -> do
    case decodeDisclosure encDisclosure of
      Left _ -> []  -- Skip invalid disclosures
      Right decoded -> do
        let claimValue = getDisclosureValue decoded
        -- Extract digests from _sd arrays in disclosure values
        extractDigestsFromValue claimValue
    ) disclosures

-- | Extract regular (non-selectively disclosable) claims from payload.
extractRegularClaims :: Aeson.Value -> Map.Map T.Text Aeson.Value
extractRegularClaims (Aeson.Object obj) =
  Map.fromList $ mapMaybe (\(k, v) ->
    let keyText = Key.toText k
    in if keyText == "_sd" || keyText == "_sd_alg" || keyText == "cnf"
      then Nothing  -- Skip SD-JWT internal claims
      else Just (keyText, v)
  ) (KeyMap.toList obj)
extractRegularClaims _ = Map.empty

-- | Build maps from digests to disclosure values.
-- Returns two maps:
-- 1. Object disclosures: digest -> (claimName, claimValue)
-- 2. Array disclosures: digest -> value
buildDisclosureMap
  :: HashAlgorithm
  -> [EncodedDisclosure]
  -> Either SDJWTError (Map.Map T.Text (T.Text, Aeson.Value), Map.Map T.Text Aeson.Value)
buildDisclosureMap hashAlg sdDisclosures = do
  -- Process each disclosure and separate into object and array disclosures
  disclosureResults <- mapM (\encDisclosure -> do
    decodedDisclosure <- decodeDisclosure encDisclosure
    let digest = computeDigest hashAlg encDisclosure
    let claimName = getDisclosureClaimName decodedDisclosure
    let claimValue = getDisclosureValue decodedDisclosure
    return $ case claimName of
      Just name -> Left (unDigest digest, (name, claimValue))  -- Object disclosure
      Nothing -> Right (unDigest digest, claimValue)  -- Array disclosure
    ) sdDisclosures
  
  -- Partition into object and array results
  let (objectResults, arrayResults) = partitionEithers disclosureResults
  
  return (Map.fromList objectResults, Map.fromList arrayResults)

-- | Replace digests in payload with actual claim values.
-- This function:
-- 1. Processes object claims (replaces digests in _sd arrays with values, recursively)
-- 2. Recursively processes arrays to replace {"...": "<digest>"} objects with values
replaceDigestsWithValues
  :: Map.Map T.Text Aeson.Value
  -> Map.Map T.Text (T.Text, Aeson.Value)  -- Object disclosures: digest -> (claimName, claimValue)
  -> Map.Map T.Text Aeson.Value  -- Array disclosures: digest -> value
  -> Aeson.Value  -- Original payload
  -> Map.Map T.Text Aeson.Value
replaceDigestsWithValues regularClaims objectDisclosureMap arrayDisclosureMap _payloadValue =
  -- Process object claims: replace digests in _sd arrays with values (including nested _sd arrays)
  let disclosedPairs = Map.elems objectDisclosureMap  -- [(claimName, claimValue)]
      disclosedClaims = Map.fromList disclosedPairs
      objectClaims = Map.union disclosedClaims regularClaims
  
  -- Process arrays recursively to replace {"...": "<digest>"} objects
  -- Also process nested _sd arrays recursively
  in processArraysInClaims (processSDArraysInClaims objectClaims objectDisclosureMap) arrayDisclosureMap

-- | Recursively process _sd arrays in claims to replace digests with values.
processSDArraysInClaims
  :: Map.Map T.Text Aeson.Value
  -> Map.Map T.Text (T.Text, Aeson.Value)  -- Object disclosures: digest -> (claimName, claimValue)
  -> Map.Map T.Text Aeson.Value
processSDArraysInClaims claims objectDisclosureMap =
  Map.map (\value -> processSDArraysInValue value objectDisclosureMap) claims

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
      
      -- Build new object: remove _sd, add disclosed claims, keep other fields
          objWithoutSD = KeyMap.delete "_sd" obj
          objWithDisclosedClaims = foldl (\acc (claimName, claimValue) ->
                KeyMap.insert (Key.fromText claimName) claimValue acc) objWithoutSD disclosedClaims
      
      -- Recursively process nested objects (including the newly added claims)
          processedObj = KeyMap.map (\value -> processSDArraysInValue value objectDisclosureMap) objWithDisclosedClaims
      in Aeson.Object processedObj
    Just _ ->
      -- _sd exists but is not an array, skip processing
      let processedObj = KeyMap.map (\value -> processSDArraysInValue value objectDisclosureMap) obj
      in Aeson.Object processedObj
    Nothing ->
      -- No _sd array, just recursively process nested objects
      let processedObj = KeyMap.map (\value -> processSDArraysInValue value objectDisclosureMap) obj
      in Aeson.Object processedObj
processSDArraysInValue (Aeson.Array arr) objectDisclosureMap =
  -- Recursively process array elements
  Aeson.Array $ V.map (\el -> processSDArraysInValue el objectDisclosureMap) arr
processSDArraysInValue value _objectDisclosureMap = value  -- Primitive values, keep as is

-- | Recursively process arrays in claims to replace {"...": "<digest>"} objects with values.
processArraysInClaims
  :: Map.Map T.Text Aeson.Value
  -> Map.Map T.Text Aeson.Value  -- Array disclosures: digest -> value
  -> Map.Map T.Text Aeson.Value
processArraysInClaims claims arrayDisclosureMap =
  Map.map (\value -> processValueForArrays value arrayDisclosureMap) claims

-- | Recursively process a JSON value to replace {"...": "<digest>"} objects in arrays.
processValueForArrays
  :: Aeson.Value
  -> Map.Map T.Text Aeson.Value  -- Array disclosures: digest -> value
  -> Aeson.Value
processValueForArrays (Aeson.Array arr) arrayDisclosureMap =
  -- Process each element in the array
  let processedElements = V.map (\el -> processValueForArrays el arrayDisclosureMap) arr
      -- Replace {"...": "<digest>"} objects with actual values
      replacedElements = V.map (\el -> case el of
        Aeson.Object obj ->
          -- Check if this is a {"...": "<digest>"} object
          case KeyMap.lookup (Key.fromText "...") obj of
            Just (Aeson.String digest) ->
              -- Look up the value for this digest
              case Map.lookup digest arrayDisclosureMap of
                Just value -> value
                Nothing -> el  -- Digest not found, keep original
            _ -> el  -- Not an ellipsis object, keep as is
        _ -> el  -- Not an object, keep as is
        ) processedElements
  in Aeson.Array replacedElements
processValueForArrays (Aeson.Object obj) arrayDisclosureMap =
  -- Recursively process nested objects
  let processedObj = KeyMap.map (\value -> processValueForArrays value arrayDisclosureMap) obj
  in Aeson.Object processedObj
processValueForArrays value _arrayDisclosureMap = value  -- Primitive values, keep as is

-- | Process payload from presentation (convenience function).
processPayloadFromPresentation
  :: HashAlgorithm
  -> SDJWTPresentation
  -> Either SDJWTError ProcessedSDJWTPayload
processPayloadFromPresentation hashAlg presentation = do
  sdPayload <- parsePayloadFromJWT (presentationJWT presentation)
  processPayload hashAlg sdPayload (selectedDisclosures presentation)


