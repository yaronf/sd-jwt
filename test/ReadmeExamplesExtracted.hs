#line 46 "haskell"
import SDJWT.Issuer
import qualified Data.Map.Strict as Map
import qualified Data.Aeson as Aeson
import qualified Data.Text as T

-- Create claims
let claims = Map.fromList
      [ ("sub", Aeson.String "user_123")
      , ("given_name", Aeson.String "John")
      , ("family_name", Aeson.String "Doe")
      ]

-- Load issuer's private key (can be Text or jose JWK object)
-- Example Text format: "{\"kty\":\"RSA\",\"n\":\"...\",\"e\":\"AQAB\",\"d\":\"...\"}"
issuerPrivateKeyJWK <- loadPrivateKeyJWK  -- Your function to load the key (returns Text or JWK.JWK)

-- Create SD-JWT with selective disclosure
-- PS256 (RSA-PSS) is used by default for RSA keys
result <- createSDJWT Nothing SHA256 issuerPrivateKeyJWK ["given_name", "family_name"] claims
case result of
  Right sdjwt -> do
    let serialized = serializeSDJWT sdjwt
    -- Send serialized SD-JWT to holder
  Left err -> putStrLn $ "Error creating SD-JWT: " ++ show err
#line 75 "haskell"
import SDJWT.Holder
import qualified Data.Text as T
import Data.Int (Int64)

-- Deserialize SD-JWT received from issuer
case deserializeSDJWT sdjwtText of
  Right sdjwt -> do
    -- Select which disclosures to include in the presentation
    -- The holder chooses which claims to reveal (e.g., only "given_name", not "family_name")
    case selectDisclosuresByNames sdjwt ["given_name"] of
      Right presentation -> do
        -- The presentation now contains:
        -- - presentationJWT: The issuer-signed JWT (with digests for all claims)
        -- - selectedDisclosures: Only the disclosures for "given_name"
        -- Optionally add key binding (SD-JWT+KB) for proof of possession
        holderPrivateKeyJWK <- loadPrivateKeyJWK  -- Your function to load holder's private key (Text or jose JWK)
        let audience = "verifier.example.com"
        let nonce = "random-nonce-12345"
        let issuedAt = 1683000000 :: Int64
        result <- addKeyBindingToPresentation SHA256 holderPrivateKeyJWK audience nonce issuedAt presentation
        case result of
          Right presentationWithKB -> do
            -- Serialize the presentation: JWT~disclosure1~disclosure2~...~KB-JWT
            -- This includes both the issuer-signed JWT and the selected disclosures
            let serialized = serializePresentation presentationWithKB
            -- Send serialized presentation to verifier
            -- The verifier will verify the signature and reconstruct claims from the selected disclosures
          Left err -> putStrLn $ "Error adding key binding: " ++ show err
      Left err -> putStrLn $ "Error selecting disclosures: " ++ show err
  Left err -> putStrLn $ "Error deserializing SD-JWT: " ++ show err
#line 110 "haskell"
import SDJWT.Verifier
import qualified Data.Text as T

-- Deserialize presentation received from holder
case deserializePresentation presentationText of
  Right presentation -> do
    -- Load issuer's public key (can be Text or jose JWK object)
    issuerPublicKeyJWK <- loadPublicKeyJWK  -- Your function to load issuer's public key (Text or jose JWK)
    
    -- Verify the SD-JWT (optionally require specific typ header)
    -- Pass Nothing to allow any typ, or Just "sd-jwt" to require specific typ
    result <- verifySDJWT issuerPublicKeyJWK presentation Nothing
    case result of
      Right processedPayload -> do
        -- Extract claims
        let claims = processedClaims processedPayload
        -- Use verified claims
      Left err -> putStrLn $ "Verification failed: " ++ show err
  Left err -> putStrLn $ "Error deserializing presentation: " ++ show err
#line 137 "haskell"
import SDJWT.Internal.Types
import SDJWT.Internal.Serialization
import SDJWT.Internal.Issuance
-- etc.
#line 148 "haskell"
let claims = Map.fromList
      [ ("address", Aeson.Object $ KeyMap.fromList
          [ (Key.fromText "street_address", Aeson.String "123 Main St")
          , (Key.fromText "locality", Aeson.String "City")
          , (Key.fromText "country", Aeson.String "US")
          ])
      ]

-- Structured SD-JWT (Section 6.2): parent stays, sub-claims get _sd array
result <- buildSDJWTPayload SHA256 ["address/street_address", "address/locality"] claims

-- Recursive Disclosures (Section 6.3): parent is selectively disclosable
result <- buildSDJWTPayload SHA256 ["address", "address/street_address", "address/locality"] claims
#line 206 "haskell"
let issuerKey :: T.Text = "{\"kty\":\"RSA\",\"n\":\"...\",\"e\":\"AQAB\",\"d\":\"...\"}"
result <- createSDJWT Nothing SHA256 issuerKey ["claim"] claims
#line 212 "haskell"
import Crypto.JOSE.JWK as JWK
jwk <- loadJWK  -- Your function that returns JWK.JWK
result <- createSDJWT Nothing SHA256 jwk ["claim"] claims
