{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
module DisclosureSpec (spec) where

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
spec = describe "SDJWT.Disclosure" $ do
  describe "createObjectDisclosure" $ do
    it "creates disclosure with string value" $ do
      salt <- generateSalt
      let name = "given_name"
      let value = Aeson.String "John"
      case createObjectDisclosure (Salt salt) name value of
        Right _ -> return ()  -- Success
        Left err -> expectationFailure $ "Failed to create disclosure: " ++ show err
    
    it "creates disclosure with empty string value" $ do
      salt <- generateSalt
      let name = "empty_claim"
      let value = Aeson.String ""
      case createObjectDisclosure (Salt salt) name value of
        Right _ -> return ()  -- Success
        Left err -> expectationFailure $ "Failed to create disclosure: " ++ show err
    
    it "creates disclosure with numeric value" $ do
      salt <- generateSalt
      let name = "age"
      let value = Aeson.Number 42
      case createObjectDisclosure (Salt salt) name value of
        Right _ -> return ()  -- Success
        Left err -> expectationFailure $ "Failed to create disclosure: " ++ show err
    
    it "creates disclosure with object value" $ do
        salt <- generateSalt
        let name = "address"
        let value = Aeson.Object $ KeyMap.fromList [(Key.fromText "street", Aeson.String "123 Main St")]
        case createObjectDisclosure (Salt salt) name value of
          Right _ -> return ()  -- Success
          Left err -> expectationFailure $ "Failed to create disclosure: " ++ show err
    
    describe "createArrayDisclosure" $ do
      it "creates a valid array disclosure" $ do
        salt <- generateSalt
        let value = Aeson.String "US"
        case createArrayDisclosure (Salt salt) value of
          Right _ -> return ()  -- Success
          Left err -> expectationFailure $ "Failed to create disclosure: " ++ show err
      
      it "creates array disclosure with object value" $ do
        salt <- generateSalt
        let value = Aeson.Object $ KeyMap.fromList [(Key.fromText "name", Aeson.String "John")]
        case createArrayDisclosure (Salt salt) value of
          Right _ -> return ()  -- Success
          Left err -> expectationFailure $ "Failed to create disclosure: " ++ show err
    
    describe "encodeDisclosure" $ do
      it "encodes object disclosure" $ do
        salt <- generateSalt
        let name = "test_claim"
        let value = Aeson.String "test_value"
        case createObjectDisclosure (Salt salt) name value of
          Right encoded1 -> do
            case decodeDisclosure encoded1 of
              Right decoded -> do
                -- Round-trip: encode -> decode -> encode should match
                let encoded2 = encodeDisclosure decoded
                unEncodedDisclosure encoded1 `shouldBe` unEncodedDisclosure encoded2
              Left err -> expectationFailure $ "Failed to decode: " ++ show err
          Left err -> expectationFailure $ "Failed to create: " ++ show err
      
      it "encodes array disclosure" $ do
        salt <- generateSalt
        let value = Aeson.String "array_value"
        case createArrayDisclosure (Salt salt) value of
          Right encoded1 -> do
            case decodeDisclosure encoded1 of
              Right decoded -> do
                -- Round-trip: encode -> decode -> encode should match
                let encoded2 = encodeDisclosure decoded
                unEncodedDisclosure encoded1 `shouldBe` unEncodedDisclosure encoded2
              Left err -> expectationFailure $ "Failed to decode: " ++ show err
          Left err -> expectationFailure $ "Failed to create: " ++ show err
    
    describe "getDisclosureSalt" $ do
      it "extracts salt from object disclosure" $ do
        salt <- generateSalt
        let name = "test_claim"
        let value = Aeson.String "test_value"
        case createObjectDisclosure (Salt salt) name value of
          Right encoded -> do
            case decodeDisclosure encoded of
              Right disclosure -> do
                unSalt (getDisclosureSalt disclosure) `shouldBe` salt
              Left err -> expectationFailure $ "Failed to decode: " ++ show err
          Left err -> expectationFailure $ "Failed to create: " ++ show err
      
      it "extracts salt from array disclosure" $ do
        salt <- generateSalt
        let value = Aeson.String "array_value"
        case createArrayDisclosure (Salt salt) value of
          Right encoded -> do
            case decodeDisclosure encoded of
              Right disclosure -> do
                unSalt (getDisclosureSalt disclosure) `shouldBe` salt
              Left err -> expectationFailure $ "Failed to decode: " ++ show err
          Left err -> expectationFailure $ "Failed to create: " ++ show err
    
    describe "decodeDisclosure" $ do
      it "decodes RFC example disclosure" $ do
        -- From RFC 9901 Section 5.1: given_name disclosure
        let encoded = EncodedDisclosure "WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgImdpdmVuX25hbWUiLCAiSm9obiJd"
        case decodeDisclosure encoded of
          Right disclosure -> do
            getDisclosureClaimName disclosure `shouldBe` Just "given_name"
            getDisclosureValue disclosure `shouldBe` Aeson.String "John"
          Left err -> expectationFailure $ "Failed to decode: " ++ show err
      
      it "decodes array disclosure (2 elements)" $ do
        -- Array disclosure: [salt, value]
        salt <- generateSalt
        let value = Aeson.String "US"
        case createArrayDisclosure (Salt salt) value of
          Right encoded -> do
            case decodeDisclosure encoded of
              Right disclosure -> do
                getDisclosureClaimName disclosure `shouldBe` Nothing  -- Array disclosures have no name
                getDisclosureValue disclosure `shouldBe` value
              Left err -> expectationFailure $ "Failed to decode: " ++ show err
          Left err -> expectationFailure $ "Failed to create: " ++ show err
      
      it "fails to decode invalid base64url" $ do
        let invalid = EncodedDisclosure "not-valid-base64url!!!"
        case decodeDisclosure invalid of
          Left (InvalidDisclosureFormat _) -> return ()  -- Expected error
          Left _ -> return ()  -- Any error is acceptable
          Right _ -> expectationFailure "Should fail to decode invalid base64url"
      
      it "fails to decode non-array JSON" $ do
        -- Base64url-encoded JSON object instead of array
        let jsonObj = Aeson.object [("key", Aeson.String "value")]
        let jsonBytes = BS.concat $ BSL.toChunks $ Aeson.encode jsonObj
        let encoded = EncodedDisclosure $ base64urlEncode jsonBytes
        case decodeDisclosure encoded of
          Left (InvalidDisclosureFormat _) -> return ()  -- Expected error
          Left _ -> return ()  -- Any error is acceptable
          Right _ -> expectationFailure "Should fail to decode non-array JSON"
      
      it "fails to decode array with 1 element" $ do
        -- Array with only 1 element (should have 2 or 3)
        let jsonArray = Aeson.Array $ V.fromList [Aeson.String "salt"]
        let jsonBytes = BS.concat $ BSL.toChunks $ Aeson.encode jsonArray
        let encoded = EncodedDisclosure $ base64urlEncode jsonBytes
        case decodeDisclosure encoded of
          Left (InvalidDisclosureFormat msg) -> do
            T.isInfixOf "must have 2 or 3 elements" msg `shouldBe` True
          Left _ -> return ()  -- Any error is acceptable
          Right _ -> expectationFailure "Should fail to decode array with 1 element"
      
      it "fails to decode array with 4+ elements" $ do
        -- Array with 4 elements (should have 2 or 3)
        let jsonArray = Aeson.Array $ V.fromList
              [ Aeson.String "salt"
              , Aeson.String "name"
              , Aeson.String "value"
              , Aeson.String "extra"
              ]
        let jsonBytes = BS.concat $ BSL.toChunks $ Aeson.encode jsonArray
        let encoded = EncodedDisclosure $ base64urlEncode jsonBytes
        case decodeDisclosure encoded of
          Left (InvalidDisclosureFormat msg) -> do
            T.isInfixOf "must have 2 or 3 elements" msg `shouldBe` True
          Left _ -> return ()  -- Any error is acceptable
          Right _ -> expectationFailure "Should fail to decode array with 4+ elements"
      
      it "fails to decode array where first element is not a string" $ do
        -- First element (salt) must be a string
        let jsonArray = Aeson.Array $ V.fromList
              [ Aeson.Number 123  -- Not a string
              , Aeson.String "name"
              , Aeson.String "value"
              ]
        let jsonBytes = BS.concat $ BSL.toChunks $ Aeson.encode jsonArray
        let encoded = EncodedDisclosure $ base64urlEncode jsonBytes
        case decodeDisclosure encoded of
          Left (InvalidDisclosureFormat _) -> return ()  -- Expected error
          Left _ -> return ()  -- Any error is acceptable
          Right _ -> expectationFailure "Should fail when salt is not a string"
      
      it "fails to decode array disclosure where second element is not a string" $ do
        -- For object disclosure (3 elements), second element (name) must be a string
        -- But for array disclosure (2 elements), second element is the value (can be anything)
        -- So this test is for object disclosure
        let jsonArray = Aeson.Array $ V.fromList
              [ Aeson.String "salt"
              , Aeson.Number 123  -- Name should be string
              , Aeson.String "value"
              ]
        let jsonBytes = BS.concat $ BSL.toChunks $ Aeson.encode jsonArray
        let encoded = EncodedDisclosure $ base64urlEncode jsonBytes
        case decodeDisclosure encoded of
          Left (InvalidDisclosureFormat _) -> return ()  -- Expected error
          Left _ -> return ()  -- Any error is acceptable
          Right _ -> expectationFailure "Should fail when claim name is not a string"

