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

-- Example from README.md (block 1)
-- >>> :set -XOverloadedStrings
-- >>> -- Create claims
-- >>> let claims = Map.fromList
-- >>>       [ ("sub", Aeson.String "user_123")
-- >>>       , ("given_name", Aeson.String "John")
-- >>>       , ("family_name", Aeson.String "Doe")
-- >>>       ]
-- >>> -- Load issuer's private key (can be Text or jose JWK object)
-- >>> -- Example Text format: "{\"kty\":\"RSA\",\"n\":\"...\",\"e\":\"AQAB\",\"d\":\"...\"}"
-- >>> keyPair <- generateTestRSAKeyPair
-- >>> let issuerPrivateKeyJWK = privateKeyJWK keyPair  -- Your function to load the key (returns Text or JWK.JWK)
-- >>> -- Create SD-JWT with selective disclosure
-- >>> -- PS256 (RSA-PSS) is used by default for RSA keys
-- >>> -- createSDJWT signature: mbTyp mbKid hashAlg key claimNames claims
-- >>> result <- createSDJWT (Just "sd-jwt") Nothing SHA256 issuerPrivateKeyJWK ["given_name", "family_name"] claims
-- >>> case result of
-- >>>   Right sdjwt -> do
-- >>>     let serialized = serializeSDJWT sdjwt
-- >>>   Left err -> 

-- Example from README.md (block 2)
-- >>> :set -XOverloadedStrings
-- >>> -- Deserialize SD-JWT received from issuer
-- >>> issuerKeyPair <- generateTestRSAKeyPair
-- >>> let claims = Map.fromList [("sub", Aeson.String "user_123"), ("given_name", Aeson.String "John")]
-- >>> sdjwtResult <- createSDJWT (Just "sd-jwt") Nothing SHA256 (privateKeyJWK issuerKeyPair) ["given_name"] claims
-- >>> case sdjwtResult of
-- >>>   Right sdjwt -> let sdjwtText = serializeSDJWT sdjwt
-- >>>   Left _ -> error "Failed to create SD-JWT"
-- >>> case deserializeSDJWT sdjwtText of
-- >>>   Right sdjwt -> do
-- >>>     -- Select which disclosures to include in the presentation
-- >>>     -- The holder chooses which claims to reveal (e.g., only "given_name", not "family_name")
-- >>>     case selectDisclosuresByNames sdjwt ["given_name"] of
-- >>>       Right presentation -> do
-- >>>         -- The presentation now contains:
-- >>>         -- - presentationJWT: The issuer-signed JWT (with digests for all claims)
-- >>>         -- - selectedDisclosures: Only the disclosures for "given_name"
-- >>>         -- Optionally add key binding (SD-JWT+KB) for proof of possession
-- >>>         holderKeyPair <- generateTestEd25519KeyPair
-- >>> let holderPrivateKeyJWK = privateKeyJWK holderKeyPair  -- Your function to load holder's private key (Text or jose JWK)
-- >>>         let audience = "verifier.example.com"
-- >>>         let nonce = "random-nonce-12345"
-- >>>         let issuedAt = 1683000000 :: Int64
-- >>>         result <- addKeyBindingToPresentation SHA256 holderPrivateKeyJWK audience nonce issuedAt presentation (Aeson.object [])
-- >>>         case result of
-- >>>           Right presentationWithKB -> do
-- >>>             -- Serialize the presentation: JWT~disclosure1~disclosure2~...~KB-JWT
-- >>>             -- This includes both the issuer-signed JWT and the selected disclosures
-- >>>             let serialized = serializePresentation presentationWithKB
-- >>>             -- The verifier will verify the signature and reconstruct claims from the selected disclosures
-- >>>           Left err -> 
-- >>>       Left err -> 
-- >>>   Left err -> 

-- Example from README.md (block 3)
-- >>> :set -XOverloadedStrings
-- >>> -- Deserialize presentation received from holder
-- >>> issuerKeyPair <- generateTestRSAKeyPair
-- >>> let claims = Map.fromList [("sub", Aeson.String "user_123"), ("given_name", Aeson.String "John")]
-- >>> sdjwtResult <- createSDJWT (Just "sd-jwt") Nothing SHA256 (privateKeyJWK issuerKeyPair) ["given_name"] claims
-- >>> case sdjwtResult of
-- >>>   Right sdjwt -> case selectDisclosuresByNames sdjwt ["given_name"] of
-- >>>     Right pres -> let presentationText = serializePresentation pres
-- >>>     Left _ -> error "Failed to select disclosures"
-- >>>   Left _ -> error "Failed to create SD-JWT"
-- >>> case deserializePresentation presentationText of
-- >>>   Right presentation -> do
-- >>>     -- Load issuer's public key (can be Text or jose JWK object)
-- >>>     issuerKeyPair <- generateTestRSAKeyPair
-- >>> let issuerPublicKeyJWK = publicKeyJWK issuerKeyPair  -- Your function to load issuer's public key (Text or jose JWK)
-- >>>     -- Verify the SD-JWT (optionally require specific typ header)
-- >>>     -- Pass Nothing to allow any typ, or Just "sd-jwt" to require specific typ
-- >>>     result <- verifySDJWT issuerPublicKeyJWK presentation Nothing
-- >>>     case result of
-- >>>       Right processedPayload -> do
-- >>>         -- Extract claims
-- >>>         let claims = processedClaims processedPayload
-- >>>       Left err -> 
-- >>>   Left err -> 

-- Example from README.md (block 5)
-- >>> :set -XOverloadedStrings
-- >>> let claims = Map.fromList
-- >>>       [ ("address", Aeson.Object $ KeyMap.fromList
-- >>>           [ (Key.fromText "street_address", Aeson.String "123 Main St")
-- >>>           , (Key.fromText "locality", Aeson.String "City")
-- >>>           , (Key.fromText "country", Aeson.String "US")
-- >>>           ])
-- >>>       , ("nationalities", Aeson.Array $ V.fromList
-- >>>           [ Aeson.String "US"
-- >>>           , Aeson.String "CA"
-- >>>           , Aeson.String "UK"
-- >>>           ])
-- >>>       ]
-- >>> -- Structured SD-JWT (Section 6.2): parent stays, sub-claims get _sd array
-- >>> result <- buildSDJWTPayload SHA256 ["address/street_address", "address/locality"] claims
-- >>> -- Recursive Disclosures (Section 6.3): parent is selectively disclosable
-- >>> result <- buildSDJWTPayload SHA256 ["address", "address/street_address", "address/locality"] claims
-- >>> -- Array elements: mark elements at indices 0 and 2 as selectively disclosable
-- >>> result <- buildSDJWTPayload SHA256 ["nationalities/0", "nationalities/2"] claims
-- >>> -- Mixed object and array paths
-- >>> result <- buildSDJWTPayload SHA256 ["address/street_address", "nationalities/1"] claims
-- >>> -- Nested arrays: mark element at index 0 of the array at index 0
-- >>> result <- buildSDJWTPayload SHA256 ["nested_array/0/0", "nested_array/1/1"] claims

-- Example from README.md (block 6)
-- >>> :set -XOverloadedStrings
-- >>> let claims = Map.fromList [("claim", Aeson.String "value")]
-- >>> let issuerKey :: T.Text = "{\"kty\":\"RSA\",\"n\":\"...\",\"e\":\"AQAB\",\"d\":\"...\"}"
-- >>> -- createSDJWT takes: mbTyp mbKid hashAlg key claimNames claims
-- >>> result <- createSDJWT Nothing Nothing SHA256 issuerKey ["claim"] claims
-- >>> -- Or with typ header (recommended):
-- >>> result <- createSDJWT (Just "sd-jwt") Nothing SHA256 issuerKey ["claim"] claims

-- Example from README.md (block 7)
-- >>> :set -XOverloadedStrings
-- >>> let claims = Map.fromList [("claim", Aeson.String "value")]
-- >>> keyPair <- generateTestRSAKeyPair
-- >>> let jwk = privateKeyJWK keyPair  -- Your function that returns JWK.JWK
-- >>> -- createSDJWT takes: mbTyp mbKid hashAlg key claimNames claims
-- >>> result <- createSDJWT Nothing Nothing SHA256 jwk ["claim"] claims
-- >>> -- Or with typ header (recommended):
-- >>> result <- createSDJWT (Just "sd-jwt") Nothing SHA256 jwk ["claim"] claims
