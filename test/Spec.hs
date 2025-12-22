{-# LANGUAGE OverloadedStrings #-}
module Main (main) where

import Test.Hspec
import SDJWT.Types
import SDJWT.Utils
import SDJWT.Digest
import SDJWT.Disclosure
import SDJWT.Serialization
import SDJWT.Issuance
import qualified Data.Aeson as Aeson
import qualified Data.Aeson.KeyMap as KeyMap
import qualified Data.Text as T
import qualified Data.ByteString as BS
import qualified Data.Map.Strict as Map

main :: IO ()
main = hspec $ do
  describe "SDJWT.Utils" $ do
    describe "base64urlEncode" $ do
      it "encodes ByteString to base64url" $ do
        base64urlEncode (BS.pack [72, 101, 108, 108, 111, 44, 32, 87, 111, 114, 108, 100, 33]) `shouldBe` "SGVsbG8sIFdvcmxkIQ"
    
    describe "base64urlDecode" $ do
      it "decodes base64url to ByteString" $ do
        base64urlDecode "SGVsbG8sIFdvcmxkIQ" `shouldBe` Right (BS.pack [72, 101, 108, 108, 111, 44, 32, 87, 111, 114, 108, 100, 33])
      it "handles invalid input" $ do
        base64urlDecode "!!!" `shouldSatisfy` isLeft

  describe "SDJWT.Digest" $ do
    describe "hashAlgorithmToText" $ do
      it "converts SHA256 to sha-256" $ do
        hashAlgorithmToText SHA256 `shouldBe` "sha-256"
      it "converts SHA384 to sha-384" $ do
        hashAlgorithmToText SHA384 `shouldBe` "sha-384"
      it "converts SHA512 to sha-512" $ do
        hashAlgorithmToText SHA512 `shouldBe` "sha-512"
    
    describe "parseHashAlgorithm" $ do
      it "parses sha-256" $ do
        parseHashAlgorithm "sha-256" `shouldBe` Just SHA256
      it "parses sha-384" $ do
        parseHashAlgorithm "sha-384" `shouldBe` Just SHA384
      it "parses sha-512" $ do
        parseHashAlgorithm "sha-512" `shouldBe` Just SHA512
      it "returns Nothing for invalid algorithm" $ do
        parseHashAlgorithm "invalid" `shouldBe` Nothing
    
    describe "computeDigest" $ do
      it "computes digest for a disclosure" $ do
        let disclosure = EncodedDisclosure "WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgImdpdmVuX25hbWUiLCAiSm9obiJd"
        let digest = computeDigest SHA256 disclosure
        unDigest digest `shouldBe` "jsu9yVulwQQlhFlM_3JlzMaSFzglhQG0DpfayQwLUK4"

  describe "SDJWT.Disclosure" $ do
    describe "createObjectDisclosure" $ do
      it "creates a valid object disclosure" $ do
        salt <- generateSalt
        let name = "given_name"
        let value = Aeson.String "John"
        case createObjectDisclosure (Salt salt) name value of
          Right _ -> return ()  -- Success
          Left err -> expectationFailure $ "Failed to create disclosure: " ++ show err
    
    describe "decodeDisclosure" $ do
      it "decodes RFC example disclosure" $ do
        -- From RFC 9901 Section 5.1: given_name disclosure
        let encoded = EncodedDisclosure "WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgImdpdmVuX25hbWUiLCAiSm9obiJd"
        case decodeDisclosure encoded of
          Right disclosure -> do
            getDisclosureClaimName disclosure `shouldBe` Just "given_name"
            getDisclosureValue disclosure `shouldBe` Aeson.String "John"
          Left err -> expectationFailure $ "Failed to decode: " ++ show err

  describe "SDJWT.Serialization" $ do
    describe "serializeSDJWT" $ do
      it "serializes SD-JWT with empty disclosures" $ do
        let jwt = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.test"
        let sdjwt = SDJWT jwt []
        serializeSDJWT sdjwt `shouldBe` "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.test~"
    
    describe "parseTildeSeparated" $ do
      it "parses SD-JWT format" $ do
        let input = "jwt~disclosure1~disclosure2~"
        case parseTildeSeparated input of
          Right (jwt, disclosures, Nothing) -> do
            jwt `shouldBe` "jwt"
            length disclosures `shouldBe` 2
          Left err -> expectationFailure $ "Failed to parse: " ++ show err

  describe "SDJWT.Issuance" $ do
    describe "buildSDJWTPayload" $ do
      it "creates SD-JWT payload with selective disclosures" $ do
        let claims = Map.fromList
              [ ("sub", Aeson.String "user_42")
              , ("given_name", Aeson.String "John")
              , ("family_name", Aeson.String "Doe")
              ]
        let selectiveClaims = ["given_name", "family_name"]
        result <- buildSDJWTPayload SHA256 selectiveClaims claims
        case result of
          Right (payload, disclosures) -> do
            sdAlg payload `shouldBe` Just SHA256
            length disclosures `shouldBe` 2
            -- Check that _sd array exists in payload
            case payloadValue payload of
              Aeson.Object obj -> do
                KeyMap.lookup "_sd" obj `shouldSatisfy` isJust
                KeyMap.lookup "_sd_alg" obj `shouldSatisfy` isJust
                KeyMap.lookup "sub" obj `shouldSatisfy` isJust  -- Regular claim preserved
                KeyMap.lookup "given_name" obj `shouldBe` Nothing  -- Selective claim removed
                KeyMap.lookup "family_name" obj `shouldBe` Nothing  -- Selective claim removed
              _ -> expectationFailure "Payload should be an object"
          Left err -> expectationFailure $ "Failed to build payload: " ++ show err
    
    describe "markSelectivelyDisclosable" $ do
      it "creates disclosure and digest for a claim" $ do
        result <- markSelectivelyDisclosable SHA256 "test_claim" (Aeson.String "test_value")
        case result of
          Right (digest, disclosure) -> do
            unDigest digest `shouldSatisfy` (not . T.null)
            unEncodedDisclosure disclosure `shouldSatisfy` (not . T.null)
          Left err -> expectationFailure $ "Failed to mark claim: " ++ show err

isLeft :: Either a b -> Bool
isLeft (Left _) = True
isLeft _ = False

isJust :: Maybe a -> Bool
isJust (Just _) = True
isJust _ = False
