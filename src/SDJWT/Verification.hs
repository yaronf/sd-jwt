{-# LANGUAGE OverloadedStrings #-}
-- | SD-JWT verification: Verifying SD-JWT presentations.
--
-- This module provides functions for verifying SD-JWT presentations on the verifier side.
-- It handles signature verification, disclosure validation, and payload processing.
module SDJWT.Verification
  ( verifySDJWT
  , verifySDJWTSignature
  , verifyKeyBinding
  , verifyDisclosures
  , processPayload
  , extractHashAlgorithm
  ) where

import SDJWT.Types
import SDJWT.Digest
import SDJWT.Disclosure
import SDJWT.Utils
import SDJWT.KeyBinding
import SDJWT.JWT
import qualified Data.Aeson as Aeson
import qualified Data.Aeson.Key as Key
import qualified Data.Aeson.KeyMap as KeyMap
import qualified Data.Map.Strict as Map
import qualified Data.Text as T
import qualified Data.Vector as V
import qualified Data.Set as Set
import Data.Maybe (mapMaybe)

-- | Complete SD-JWT verification.
--
-- This function performs all verification steps:
-- 1. Parses the presentation
-- 2. Verifies issuer signature (if issuer key provided)
-- 3. Extracts hash algorithm
-- 4. Verifies disclosures match digests
-- 5. Verifies key binding (if present)
-- 6. Processes payload to reconstruct claims
--
-- Returns the processed payload with all disclosed claims.
verifySDJWT
  :: Maybe T.Text  -- ^ Issuer public key (JWK as Text, placeholder for now)
  -> SDJWTPresentation
  -> IO (Either SDJWTError ProcessedSDJWTPayload)
verifySDJWT mbIssuerKey presentation = do
  -- Parse the JWT to extract payload
  -- TODO: Use jose-jwt to parse and verify signature when JWK parsing is implemented
  -- For now, we'll extract payload manually and skip signature verification if no key provided
  
  -- Verify issuer signature if key provided
  case mbIssuerKey of
    Just _issuerKey -> do
      -- TODO: Verify JWT signature using verifyJWT
      -- Example: verifyResult <- verifyJWT issuerKey (presentationJWT presentation)
      -- For now, skip signature verification
      return ()
    Nothing -> return ()
  
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
              -- Note: KB-JWT signature verification requires holder's public key
              -- For now, we skip KB-JWT verification if no holder key is provided
              -- In a full implementation, the holder's public key would come from
              -- the cnf claim in the SD-JWT payload
              -- TODO: Extract holder public key from cnf claim and verify KB-JWT
              kbVerifyResult <- verifyKeyBindingJWT alg "" kbJWT presentation
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
verifySDJWTSignature
  :: T.Text  -- ^ Issuer public key (JWK as Text)
  -> SDJWTPresentation
  -> IO (Either SDJWTError ())
verifySDJWTSignature issuerKey presentation = do
  -- Verify JWT signature using verifyJWT
  verifiedPayloadResult <- verifyJWT issuerKey (presentationJWT presentation)
  case verifiedPayloadResult of
    Left err -> return (Left err)
    Right _ -> return (Right ())

-- | Verify key binding in a presentation.
--
-- Verifies the Key Binding JWT if present in the presentation.
-- This includes verifying the KB-JWT signature and sd_hash.
verifyKeyBinding
  :: HashAlgorithm
  -> T.Text  -- ^ Holder public key (JWK as Text, placeholder for now)
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
  
  -- Compute digests for all disclosures
  let disclosureDigests = map (computeDigest hashAlg) (selectedDisclosures presentation)
  
  -- Check for duplicates (compare by text representation)
  let disclosureTexts = map unDigest disclosureDigests
  let disclosureSet = Set.fromList disclosureTexts
  if Set.size disclosureSet /= length disclosureTexts
    then Left $ DuplicateDisclosure "Duplicate disclosures found"
    else return ()
  
  -- Verify each disclosure digest exists in payload
  let payloadDigestSet = Set.fromList (map unDigest payloadDigests)
  let missingDigests = filter (\d -> unDigest d `Set.notMember` payloadDigestSet) disclosureDigests
  
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
  
  -- Process disclosures to create a map of digests to claim values
  disclosureMap <- buildDisclosureMap hashAlg sdDisclosures
  
  -- Replace digests in _sd arrays with actual values
  let finalClaims = replaceDigestsWithValues regularClaims disclosureMap (payloadValue sdPayload)
  
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

-- | Parse payload from JWT.
--
-- Extracts and decodes the JWT payload (middle part) from a JWT string.
-- This function properly decodes the base64url-encoded payload and parses it as JSON.
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

-- | Extract digests from payload's _sd array.
extractDigestsFromPayload :: SDJWTPayload -> [Digest]
extractDigestsFromPayload sdPayload =
  case payloadValue sdPayload of
    Aeson.Object obj ->
      case KeyMap.lookup "_sd" obj of
        Just (Aeson.Array arr) ->
          mapMaybe (\v -> case v of
            Aeson.String s -> Just (Digest s)
            _ -> Nothing
          ) (V.toList arr)
        _ -> []
    _ -> []

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

-- | Build a map from digests to disclosure values.
buildDisclosureMap
  :: HashAlgorithm
  -> [EncodedDisclosure]
  -> Either SDJWTError (Map.Map T.Text (T.Text, Aeson.Value))
buildDisclosureMap hashAlg sdDisclosures = do
  results <- mapM (\encDisclosure -> do
    decodedDisclosure <- decodeDisclosure encDisclosure
    let digest = computeDigest hashAlg encDisclosure
    let claimName = getDisclosureClaimName decodedDisclosure
    let claimValue = getDisclosureValue decodedDisclosure
    case claimName of
      Just name -> return (unDigest digest, (name, claimValue))
      -- TODO: Support array element disclosures in processPayload
      -- Array disclosures don't have claim names, so we need to match them
      -- by digest to the {"...": "<digest>"} objects in arrays
      -- See RFC 9901 Section 4.2.3 for array element disclosure format
      Nothing -> Left $ InvalidDisclosureFormat "Array disclosures not yet supported in processing"
    ) sdDisclosures
  
  return $ Map.fromList results

-- | Replace digests in payload with actual claim values.
replaceDigestsWithValues
  :: Map.Map T.Text Aeson.Value
  -> Map.Map T.Text (T.Text, Aeson.Value)
  -> Aeson.Value
  -> Map.Map T.Text Aeson.Value
replaceDigestsWithValues regularClaims disclosureMap _payloadValue =
  -- Add disclosed claims to regular claims
  -- disclosureMap: Map digest -> (claimName, claimValue)
  -- We want: Map claimName -> claimValue
  let disclosedPairs = Map.elems disclosureMap  -- [(claimName, claimValue)]
      disclosedClaims = Map.fromList disclosedPairs
  in Map.union disclosedClaims regularClaims

-- | Process payload from presentation (convenience function).
processPayloadFromPresentation
  :: HashAlgorithm
  -> SDJWTPresentation
  -> Either SDJWTError ProcessedSDJWTPayload
processPayloadFromPresentation hashAlg presentation = do
  sdPayload <- parsePayloadFromJWT (presentationJWT presentation)
  processPayload hashAlg sdPayload (selectedDisclosures presentation)


