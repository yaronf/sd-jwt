{-# LANGUAGE OverloadedStrings #-}
-- | Serialization and deserialization of SD-JWT structures.
--
-- This module provides functions to serialize and deserialize SD-JWTs
-- to/from the tilde-separated format specified in RFC 9901.
module SDJWT.Serialization
  ( serializeSDJWT
  , deserializeSDJWT
  , serializePresentation
  , deserializePresentation
  , parseTildeSeparated
  ) where

import SDJWT.Types
import Data.Maybe (fromMaybe)
import qualified Data.Text as T

-- | Serialize SD-JWT to tilde-separated format.
--
-- Format: @<Issuer-signed JWT>~<Disclosure 1>~<Disclosure 2>~...~<Disclosure N>~@
--
-- The last tilde is always present, even if there are no disclosures.
serializeSDJWT :: SDJWT -> T.Text
serializeSDJWT (SDJWT jwt disclosures) =
  let
    disclosureParts = map unEncodedDisclosure disclosures
    allParts = jwt : disclosureParts ++ [""]
  in
    T.intercalate "~" allParts

-- | Deserialize SD-JWT from tilde-separated format.
--
-- Parses a tilde-separated string into an 'SDJWT' structure.
-- Returns an error if the format is invalid or if a Key Binding JWT
-- is present (use 'deserializePresentation' for SD-JWT+KB).
deserializeSDJWT :: T.Text -> Either SDJWTError SDJWT
deserializeSDJWT input =
  case parseTildeSeparated input of
    Left err -> Left err
    Right (jwt, disclosures, Nothing) ->
      -- Verify last part is empty (SD-JWT format)
      Right $ SDJWT jwt disclosures
    Right (_, _, Just _) ->
      Left $ SerializationError "SD-JWT should not have Key Binding JWT (use SD-JWT+KB format)"

-- | Serialize SD-JWT presentation.
--
-- Format: @<Issuer-signed JWT>~<Disclosure 1>~...~<Disclosure N>~[<KB-JWT>]@
--
-- If a Key Binding JWT is present, it is included as the last component.
-- Otherwise, the last component is empty (just a trailing tilde).
serializePresentation :: SDJWTPresentation -> T.Text
serializePresentation (SDJWTPresentation jwt disclosures mbKbJwt) =
  let
    disclosureParts = map unEncodedDisclosure disclosures
    kbPart = fromMaybe "" mbKbJwt
    allParts = jwt : disclosureParts ++ [kbPart]
  in
    T.intercalate "~" allParts

-- | Deserialize SD-JWT presentation.
--
-- Parses a tilde-separated string into an 'SDJWTPresentation' structure.
-- This handles both SD-JWT (without KB-JWT) and SD-JWT+KB (with KB-JWT) formats.
deserializePresentation :: T.Text -> Either SDJWTError SDJWTPresentation
deserializePresentation input =
  case parseTildeSeparated input of
    Left err -> Left err
    Right (jwt, disclosures, mbKbJwt) ->
      Right $ SDJWTPresentation jwt disclosures mbKbJwt

-- | Parse tilde-separated format.
--
-- Low-level function that parses the tilde-separated format and returns
-- the components: (JWT, [Disclosures], Maybe KB-JWT).
--
-- The last component is 'Nothing' for SD-JWT format (empty string after
-- last tilde) or 'Just' KB-JWT for SD-JWT+KB format.
parseTildeSeparated :: T.Text -> Either SDJWTError (T.Text, [EncodedDisclosure], Maybe T.Text)
parseTildeSeparated input =
  let
    parts = T.splitOn "~" input
  in
    case parts of
      [] -> Left $ SerializationError "Empty SD-JWT"
      [jwt] ->
        -- Just JWT, no disclosures or KB-JWT
        Right (jwt, [], Nothing)
      jwt : rest ->
        let
          -- Last part could be empty (SD-JWT) or KB-JWT (SD-JWT+KB)
          (disclosureParts, lastPart) = case reverse rest of
            [] -> ([], Nothing)
            lastItem : revDisclosures ->
              if T.null lastItem
                then (reverse revDisclosures, Nothing)
                else (reverse revDisclosures, Just lastItem)
          disclosures = map EncodedDisclosure disclosureParts
        in
          Right (jwt, disclosures, lastPart)

