{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# OPTIONS_GHC -Wno-name-shadowing #-}
module RFCSpec (spec) where

import Test.Hspec
import Test.QuickCheck
import Test.QuickCheck.Property ((==>))
import TestHelpers
import TestKeys
import SDJWT.Internal.Types
import SDJWT.Internal.Utils
import SDJWT.Internal.Digest
import SDJWT.Internal.Disclosure
import SDJWT.Internal.Serialization
import SDJWT.Internal.Issuance
import SDJWT.Internal.Presentation
import SDJWT.Internal.Verification (verifySDJWT, verifySDJWTSignature, verifySDJWTWithoutSignature, verifyKeyBinding, verifyDisclosures, extractHashAlgorithm)
import SDJWT.Internal.KeyBinding
import SDJWT.Internal.JWT
import qualified Data.Vector as V
import qualified Data.Aeson as Aeson
import qualified Data.Aeson.Key as Key
import qualified Data.Aeson.KeyMap as KeyMap
import qualified Data.Text as T
import Data.Text.Encoding (encodeUtf8, decodeUtf8')
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BSL
import qualified Data.Map.Strict as Map
import Data.Int (Int64)
import Data.Maybe (isJust, mapMaybe)
import Data.List (find, nub)
import Control.Monad (replicateM)

spec :: Spec
spec =     describe "RFC Test Vectors" $ do
    describe "RFC Section 5.1 - Complete Issuer-Signed JWT" $ do
      it "verifies RFC Section 5.1 issuer-signed JWT with RFC public key" $ do
        -- RFC 9901 Section 5.1 provides a complete issuer-signed JWT signed with ES256
        -- This is the JWT from line 1223-1240 of the RFC
        let rfcIssuerSignedJWT = T.concat
              [ "eyJhbGciOiAiRVMyNTYiLCAidHlwIjogImV4YW1wbGUrc2Qtand0In0."
              , "eyJfc2QiOiBbIkNyUWU3UzVrcUJBSHQtbk1ZWGdjNmJkdDJTSDVhVFkxc1VfTS1QZ2tqUEkiLCAiSnpZ"
              , "akg0c3ZsaUgwUjNQeUVNZmVadTZKdDY5dTVxZWhabzdGN0VQWWxTRSIsICJQb3JGYnBL"
              , "dVZ1Nnh5bUphZ3ZrRnNGWEFiUm9jMkpHbEFVQTJCQTRvN2NJIiwgIlRHZjRvTGJnd2Q1"
              , "SlFhSHlLVlFaVTlVZEdFMHc1cnREc3JaemZVYW9tTG8iLCAiWFFfM2tQS3QxWHlYN0tB"
              , "TmtxVlI2eVoyVmE1TnJQSXZQWWJ5TXZSS0JNTSIsICJYekZyendzY002R242Q0pEYzZ2"
              , "Vks4QmtNbmZHOHZPU0tmcFBJWmRBZmRFIiwgImdiT3NJNEVkcTJ4Mkt3LXc1d1BFemFr"
              , "b2I5aFYxY1JEMEFUTjNvUUw5Sk0iLCAianN1OXlWdWx3UVFsaEZsTV8zSmx6TWFTRnpn"
              , "bGhRRzBEcGZheVF3TFVLNCJdLCAiaXNzIjogImh0dHBzOi8vaXNzdWVyLmV4YW1wbGUu"
              , "Y29tIiwgImlhdCI6IDE2ODMwMDAwMDAsICJleHAiOiAxODgzMDAwMDAwLCAic3ViIjog"
              , "InVzZXJfNDIiLCAibmF0aW9uYWxpdGllcyI6IFt7Ii4uLiI6ICJwRm5kamtaX1ZDem15"
              , "VGE2VWpsWm8zZGgta284YUlLUWM5RGxHemhhVllvIn0sIHsiLi4uIjogIjdDZjZKa1B1"
              , "ZHJ5M2xjYndIZ2VaOGtoQXYxVTFPU2xlclAwVmtCSnJXWjAifV0sICJfc2RfYWxnIjog"
              , "InNoYS0yNTYiLCAiY25mIjogeyJqd2siOiB7Imt0eSI6ICJFQyIsICJjcnYiOiAiUC0y"
              , "NTYiLCAieCI6ICJUQ0FFUjE5WnZ1M09IRjRqNFc0dmZTVm9ISVAxSUxpbERsczd2Q2VH"
              , "ZW1jIiwgInkiOiAiWnhqaVdXYlpNUUdIVldLVlE0aGJTSWlyc1ZmdWVjQ0U2dDRqVDlG"
              , "MkhaUSJ9fX0."
              , "MczwjBFGtzf-6WMT-hIvYbkb11NrV1WMO-jTijpMPNbswNzZ87wY2uHz-CXo6R04b7jYrpj9mNRAvVssXou1iw"
              ]
        
        -- RFC public key from Appendix A.5 (line 4706-4711)
        let rfcPublicKeyJWK :: T.Text = "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"b28d4MwZMjw8-00CG4xfnn9SLMVMM19SlqZpVb_uNtQ\",\"y\":\"Xv5zWwuoaTgdS6hV43yI6gBwTnjukmFQQnJ_kCxzqk8\"}"
        
        -- Verify the RFC's JWT with the RFC's public key
        verifyResult <- verifyJWT rfcPublicKeyJWK rfcIssuerSignedJWT Nothing
        case verifyResult of
          Left err -> expectationFailure $ "Failed to verify RFC issuer-signed JWT: " ++ show err
          Right payload -> do
            -- Verify payload structure
            case payload of
              Aeson.Object obj -> do
                -- Check that _sd_alg is present
                case KeyMap.lookup (Key.fromText "_sd_alg") obj of
                  Just (Aeson.String "sha-256") -> return ()
                  _ -> expectationFailure "Missing or incorrect _sd_alg"
                -- Check that _sd array is present
                case KeyMap.lookup (Key.fromText "_sd") obj of
                  Just (Aeson.Array _) -> return ()
                  _ -> expectationFailure "Missing _sd array"
                -- Check that sub claim is present
                case KeyMap.lookup (Key.fromText "sub") obj of
                  Just (Aeson.String "user_42") -> return ()
                  _ -> expectationFailure "Missing or incorrect sub claim"
              _ -> expectationFailure "Payload is not an object"
      
      it "verifies RFC Section 5.1 complete SD-JWT (with disclosures)" $ do
        -- RFC 9901 Section 5.1 provides a complete SD-JWT with all disclosures
        -- This is the SD-JWT from line 1244-1272 of the RFC
        let rfcSDJWT = T.concat
              [ "eyJhbGciOiAiRVMyNTYiLCAidHlwIjogImV4YW1wbGUrc2Qtand0In0."
              , "eyJfc2QiOiBbIkNyUWU3UzVrcUJBSHQtbk1ZWGdjNmJkdDJTSDVhVFkxc1VfTS1QZ2tqUEkiLCAiSnpZ"
              , "akg0c3ZsaUgwUjNQeUVNZmVadTZKdDY5dTVxZWhabzdGN0VQWWxTRSIsICJQb3JGYnBL"
              , "dVZ1Nnh5bUphZ3ZrRnNGWEFiUm9jMkpHbEFVQTJCQTRvN2NJIiwgIlRHZjRvTGJnd2Q1"
              , "SlFhSHlLVlFaVTlVZEdFMHc1cnREc3JaemZVYW9tTG8iLCAiWFFfM2tQS3QxWHlYN0tB"
              , "TmtxVlI2eVoyVmE1TnJQSXZQWWJ5TXZSS0JNTSIsICJYekZyendzY002R242Q0pEYzZ2"
              , "Vks4QmtNbmZHOHZPU0tmcFBJWmRBZmRFIiwgImdiT3NJNEVkcTJ4Mkt3LXc1d1BFemFr"
              , "b2I5aFYxY1JEMEFUTjNvUUw5Sk0iLCAianN1OXlWdWx3UVFsaEZsTV8zSmx6TWFTRnpn"
              , "bGhRRzBEcGZheVF3TFVLNCJdLCAiaXNzIjogImh0dHBzOi8vaXNzdWVyLmV4YW1wbGUu"
              , "Y29tIiwgImlhdCI6IDE2ODMwMDAwMDAsICJleHAiOiAxODgzMDAwMDAwLCAic3ViIjog"
              , "InVzZXJfNDIiLCAibmF0aW9uYWxpdGllcyI6IFt7Ii4uLiI6ICJwRm5kamtaX1ZDem15"
              , "VGE2VWpsWm8zZGgta284YUlLUWM5RGxHemhhVllvIn0sIHsiLi4uIjogIjdDZjZKa1B1"
              , "ZHJ5M2xjYndIZ2VaOGtoQXYxVTFPU2xlclAwVmtCSnJXWjAifV0sICJfc2RfYWxnIjog"
              , "InNoYS0yNTYiLCAiY25mIjogeyJqd2siOiB7Imt0eSI6ICJFQyIsICJjcnYiOiAiUC0y"
              , "NTYiLCAieCI6ICJUQ0FFUjE5WnZ1M09IRjRqNFc0dmZTVm9ISVAxSUxpbERsczd2Q2VH"
              , "ZW1jIiwgInkiOiAiWnhqaVdXYlpNUUdIVldLVlE0aGJTSWlyc1ZmdWVjQ0U2dDRqVDlG"
              , "MkhaUSJ9fX0."
              , "MczwjBFGtzf-6WMT-hIvYbkb11NrV1WMO-jTijpMPNbswNzZ87wY2uHz-CXo6R04b7jYrpj9mNRAvVssXou1iw"
              , "~WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgImdpdmVuX25hbWUiLCAiSm9obiJd"
              , "~WyJlbHVWNU9nM2dTTklJOEVZbnN4QV9BIiwgImZhbWlseV9uYW1lIiwgIkRvZSJd"
              , "~WyI2SWo3dE0tYTVpVlBHYm9TNXRtdlZBIiwgImVtYWlsIiwgImpvaG5kb2VAZXhhbXBsZS5jb20iXQ"
              , "~WyJlSThaV205UW5LUHBOUGVOZW5IZGhRIiwgInBob25lX251bWJlciIsICIrMS0yMDItNTU1LTAxMDEiXQ"
              , "~WyJRZ19PNjR6cUF4ZTQxMmExMDhpcm9BIiwgInBob25lX251bWJlcl92ZXJpZmllZCIsIHRydWVd"
              , "~WyJBSngtMDk1VlBycFR0TjRRTU9xUk9BIiwgImFkZHJlc3MiLCB7InN0cmVldF9hZGRyZXNzIjogIjEyMyBNYWluIFN0IiwgImxvY2FsaXR5IjogIkFueXRvd24iLCAicmVnaW9uIjogIkFueXN0YXRlIiwgImNvdW50cnkiOiAiVVMifV0"
              , "~WyJQYzMzSk0yTGNoY1VfbEhnZ3ZfdWZRIiwgImJpcnRoZGF0ZSIsICIxOTQwLTAxLTAxIl0"
              , "~WyJHMDJOU3JRZmpGWFE3SW8wOXN5YWpBIiwgInVwZGF0ZWRfYXQiLCAxNTcwMDAwMDAwXQ"
              , "~WyJsa2x4RjVqTVlsR1RQVW92TU5JdkNBIiwgIlVTIl0"
              , "~WyJuUHVvUW5rUkZxM0JJZUFtN0FuWEZBIiwgIkRFIl0~"
              ]
        
        -- RFC public key
        let rfcPublicKeyJWK :: T.Text = "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"b28d4MwZMjw8-00CG4xfnn9SLMVMM19SlqZpVb_uNtQ\",\"y\":\"Xv5zWwuoaTgdS6hV43yI6gBwTnjukmFQQnJ_kCxzqk8\"}"
        
        -- Parse the SD-JWT
        case parseTildeSeparated rfcSDJWT of
          Left err -> expectationFailure $ "Failed to parse RFC SD-JWT: " ++ show err
          Right (issuerJWT, disclosures, kbJWT) -> do
            -- Verify issuer signature
            let presentation = SDJWTPresentation issuerJWT disclosures kbJWT
            verifyResult <- verifySDJWTSignature rfcPublicKeyJWK presentation Nothing
            case verifyResult of
              Left err -> expectationFailure $ "Failed to verify RFC SD-JWT signature: " ++ show err
              Right () -> do
                -- Verify disclosures match digests
                let verifyDisclosuresResult = verifyDisclosures SHA256 presentation
                case verifyDisclosuresResult of
                  Left err -> expectationFailure $ "Failed to verify RFC disclosures: " ++ show err
                  Right () -> return ()  -- Success
      
      it "verifies RFC Section 5.2 SD-JWT+KB example" $ do
        -- RFC 9901 Section 5.2 provides a complete SD-JWT+KB example
        -- This includes issuer-signed JWT, selected disclosures, and KB-JWT
        -- From line 1283-1310 of the RFC
        let rfcSDJWTKB = T.concat
              [ "eyJhbGciOiAiRVMyNTYiLCAidHlwIjogImV4YW1wbGUrc2Qtand0In0."
              , "eyJfc2QiOiBbIkNyUWU3UzVrcUJBSHQtbk1ZWGdjNmJkdDJTSDVhVFkxc1VfTS1QZ2tqUEkiLCAiSnpZ"
              , "akg0c3ZsaUgwUjNQeUVNZmVadTZKdDY5dTVxZWhabzdGN0VQWWxTRSIsICJQb3JGYnBL"
              , "dVZ1Nnh5bUphZ3ZrRnNGWEFiUm9jMkpHbEFVQTJCQTRvN2NJIiwgIlRHZjRvTGJnd2Q1"
              , "SlFhSHlLVlFaVTlVZEdFMHc1cnREc3JaemZVYW9tTG8iLCAiWFFfM2tQS3QxWHlYN0tB"
              , "TmtxVlI2eVoyVmE1TnJQSXZQWWJ5TXZSS0JNTSIsICJYekZyendzY002R242Q0pEYzZ2"
              , "Vks4QmtNbmZHOHZPU0tmcFBJWmRBZmRFIiwgImdiT3NJNEVkcTJ4Mkt3LXc1d1BFemFr"
              , "b2I5aFYxY1JEMEFUTjNvUUw5Sk0iLCAianN1OXlWdWx3UVFsaEZsTV8zSmx6TWFTRnpn"
              , "bGhRRzBEcGZheVF3TFVLNCJdLCAiaXNzIjogImh0dHBzOi8vaXNzdWVyLmV4YW1wbGUu"
              , "Y29tIiwgImlhdCI6IDE2ODMwMDAwMDAsICJleHAiOiAxODgzMDAwMDAwLCAic3ViIjog"
              , "InVzZXJfNDIiLCAibmF0aW9uYWxpdGllcyI6IFt7Ii4uLiI6ICJwRm5kamtaX1ZDem15"
              , "VGE2VWpsWm8zZGgta284YUlLUWM5RGxHemhhVllvIn0sIHsiLi4uIjogIjdDZjZKa1B1"
              , "ZHJ5M2xjYndIZ2VaOGtoQXYxVTFPU2xlclAwVmtCSnJXWjAifV0sICJfc2RfYWxnIjog"
              , "InNoYS0yNTYiLCAiY25mIjogeyJqd2siOiB7Imt0eSI6ICJFQyIsICJjcnYiOiAiUC0y"
              , "NTYiLCAieCI6ICJUQ0FFUjE5WnZ1M09IRjRqNFc0dmZTVm9ISVAxSUxpbERsczd2Q2VH"
              , "ZW1jIiwgInkiOiAiWnhqaVdXYlpNUUdIVldLVlE0aGJTSWlyc1ZmdWVjQ0U2dDRqVDlG"
              , "MkhaUSJ9fX0."
              , "MczwjBFGtzf-6WMT-hIvYbkb11NrV1WMO-jTijpMPNbswNzZ87wY2uHz-CXo6R04b7jYrpj9mNRAvVssXou1iw"
              , "~WyJlbHVWNU9nM2dTTklJOEVZbnN4QV9BIiwgImZhbWlseV9uYW1lIiwgIkRvZSJd"
              , "~WyJBSngtMDk1VlBycFR0TjRRTU9xUk9BIiwgImFkZHJlc3MiLCB7InN0cmVldF9hZGRyZXNzIjogIjEyMyBNYWluIFN0IiwgImxvY2FsaXR5IjogIkFueXRvd24iLCAicmVnaW9uIjogIkFueXN0YXRlIiwgImNvdW50cnkiOiAiVVMifV0"
              , "~WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgImdpdmVuX25hbWUiLCAiSm9obiJd"
              , "~WyJsa2x4RjVqTVlsR1RQVW92TU5JdkNBIiwgIlVTIl0"
              , "~eyJhbGciOiAiRVMyNTYiLCAidHlwIjogImtiK2p3dCJ9."
              , "eyJub25jZSI6ICIxMjM0NTY3ODkwIiwgImF1ZCI6ICJodHRwczovL3ZlcmlmaWVyLmV4YW1wbGUub3JnIiwgImlhdCI6IDE3NDg1MzcyNDQsICJzZF9oYXNoIjogIjBfQWYtMkItRWhMV1g1eWRoX3cyeHp3bU82aU02NkJfMlFDRWFuSTRmVVkifQ."
              , "T3SIus2OidNl41nmVkTZVCKKhOAX97aOldMyHFiYjHm261eLiJ1YiuONFiMN8QlCmYzDlBLAdPvrXh52KaLgUQ"
              ]
        
        -- RFC issuer public key
        let rfcIssuerPublicKeyJWK :: T.Text = "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"b28d4MwZMjw8-00CG4xfnn9SLMVMM19SlqZpVb_uNtQ\",\"y\":\"Xv5zWwuoaTgdS6hV43yI6gBwTnjukmFQQnJ_kCxzqk8\"}"
        
        -- KB-JWT public key is in the cnf claim of the issuer-signed JWT
        -- From the issuer-signed JWT payload: cnf.jwk
        let rfcKBPublicKeyJWK :: T.Text = "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"TCAER19Zvu3OHF4j4W4vfSVoHIP1ILilDls7vCeGemc\",\"y\":\"ZxjiWWbZMQGHVWKVQ4hbSIirsVfuecCE6t4jT9F2HZQ\"}"
        
        -- Parse the SD-JWT+KB
        case parseTildeSeparated rfcSDJWTKB of
          Left err -> expectationFailure $ "Failed to parse RFC SD-JWT+KB: " ++ show err
          Right (issuerJWT, disclosures, Just kbJWT) -> do
            -- Verify issuer signature
            let presentation = SDJWTPresentation issuerJWT disclosures (Just kbJWT)
            verifyIssuerResult <- verifySDJWTSignature rfcIssuerPublicKeyJWK presentation Nothing
            case verifyIssuerResult of
              Left err -> expectationFailure $ "Failed to verify RFC issuer signature: " ++ show err
              Right () -> do
                -- Verify disclosures
                let verifyDisclosuresResult = verifyDisclosures SHA256 presentation
                case verifyDisclosuresResult of
                  Left err -> expectationFailure $ "Failed to verify RFC disclosures: " ++ show err
                  Right () -> do
                    -- Verify KB-JWT
                    verifyKBResult <- verifyKeyBindingJWT SHA256 rfcKBPublicKeyJWK kbJWT presentation
                    case verifyKBResult of
                      Left err -> expectationFailure $ "Failed to verify RFC KB-JWT: " ++ show err
                      Right () -> return ()  -- Success
          Right (_, _, Nothing) -> expectationFailure "RFC SD-JWT+KB should have KB-JWT"

