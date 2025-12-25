{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
module PropertySpec (spec) where

import Test.Hspec
import Test.QuickCheck
import Test.QuickCheck.Property ((==>))
import TestHelpers
import SDJWT.Internal.Types
import SDJWT.Internal.Utils
import SDJWT.Internal.Digest
import SDJWT.Internal.Disclosure
import SDJWT.Internal.Serialization
import qualified Data.Text as T
import Data.Text.Encoding (decodeUtf8')
import qualified Data.ByteString as BS
import Control.Monad (replicateM)
import Data.List (nub)

-- QuickCheck Arbitrary instances for property-based testing

instance Arbitrary HashAlgorithm where
  arbitrary = elements [SHA256, SHA384, SHA512]

instance Arbitrary Salt where
  arbitrary = do
    bytes <- vectorOf 16 arbitrary  -- RFC 9901 requires 128 bits (16 bytes)
    return $ Salt (BS.pack bytes)

instance Arbitrary BS.ByteString where
  arbitrary = BS.pack <$> listOf arbitrary

instance Arbitrary T.Text where
  arbitrary = T.pack <$> listOf (choose ('a', 'z'))

spec :: Spec
spec = describe "Property-Based Tests" $ do
  describe "Base64url Encoding/Decoding" $ do
    it "round-trips correctly for any ByteString" $ property $ \bs ->
      case base64urlDecode (base64urlEncode bs) of
        Right decoded -> decoded == bs
        Left _ -> False
  
  describe "Text/ByteString Conversions" $ do
    it "textToByteString and byteStringToText round-trip" $ property $ \txt ->
      byteStringToText (textToByteString txt) == txt
    
    it "byteStringToText and textToByteString round-trip (valid UTF-8)" $ property $ \bs ->
      -- Only test with valid UTF-8 ByteStrings
      case decodeUtf8' bs of
        Right _ -> textToByteString (byteStringToText bs) == bs
        Left _ -> True  -- Discard invalid UTF-8
  
  describe "Salt Generation" $ do
    it "generates 16-byte salts" $ do
        salt <- generateSalt
        BS.length salt `shouldBe` 16
    
    it "generates unique salts (100 samples)" $ do
      salts <- replicateM 100 generateSalt
      let uniqueSalts = nub salts
      length uniqueSalts `shouldBe` length salts
  
  describe "Hash Algorithm" $ do
    it "hashAlgorithmToText and parseHashAlgorithm round-trip" $ property $ \alg ->
      parseHashAlgorithm (hashAlgorithmToText alg) == Just alg
    
    it "parseHashAlgorithm rejects invalid strings" $ property $ \txt ->
      txt `notElem` ["sha-256", "sha-384", "sha-512"] ==>
        parseHashAlgorithm txt == Nothing
  
  describe "Disclosure Encoding/Decoding" $ do
    it "object disclosure round-trips" $ property $ \salt name value ->
      case createObjectDisclosure (Salt salt) name value of
        Right encoded -> case decodeDisclosure encoded of
          Right (DisclosureObject (ObjectDisclosure decodedSalt decodedName decodedValue)) ->
            decodedSalt == Salt salt && decodedName == name && decodedValue == value
          _ -> False
        Left _ -> True  -- Discard if creation fails
    
    it "array disclosure round-trips" $ property $ \salt value ->
      case createArrayDisclosure (Salt salt) value of
        Right encoded -> case decodeDisclosure encoded of
          Right (DisclosureArray (ArrayDisclosure decodedSalt decodedValue)) ->
            decodedSalt == Salt salt && decodedValue == value
          _ -> False
        Left _ -> True  -- Discard if creation fails
    
    it "encodeDisclosure and decodeDisclosure round-trip for object disclosures" $ property $ \salt name value ->
      case createObjectDisclosure (Salt salt) name value of
        Right encoded1 -> case decodeDisclosure encoded1 of
          Right disclosure -> encodeDisclosure disclosure == encoded1
          Left _ -> False
        Left _ -> True  -- Discard if creation fails
    
    it "encodeDisclosure and decodeDisclosure round-trip for array disclosures" $ property $ \salt value ->
      case createArrayDisclosure (Salt salt) value of
        Right encoded1 -> case decodeDisclosure encoded1 of
          Right disclosure -> encodeDisclosure disclosure == encoded1
          Left _ -> False
        Left _ -> True  -- Discard if creation fails
  
  describe "Digest Computation" $ do
    it "same disclosure produces same digest" $ property $ \alg salt name value ->
      case createObjectDisclosure (Salt salt) name value of
        Right encoded ->
          let digest1 = computeDigest alg encoded
              digest2 = computeDigest alg encoded
          in digest1 == digest2
        Left _ -> True  -- Discard if creation fails
    
    it "different salts produce different digests" $ property $ \alg salt1 salt2 name value ->
      salt1 /= salt2 ==>
        case (createObjectDisclosure (Salt salt1) name value, createObjectDisclosure (Salt salt2) name value) of
          (Right enc1, Right enc2) -> computeDigest alg enc1 /= computeDigest alg enc2
          _ -> True  -- Discard if creation fails
    
    it "different values produce different digests" $ property $ \alg salt name value1 value2 ->
      value1 /= value2 ==>
        case (createObjectDisclosure (Salt salt) name value1, createObjectDisclosure (Salt salt) name value2) of
          (Right enc1, Right enc2) -> computeDigest alg enc1 /= computeDigest alg enc2
          _ -> True  -- Discard if creation fails
    
    it "verifyDigest succeeds for correct digest" $ property $ \alg salt name value ->
        case createObjectDisclosure (Salt salt) name value of
        Right encoded ->
          let digest = computeDigest alg encoded
          in verifyDigest alg digest encoded
        Left _ -> True  -- Discard if creation fails
    
    it "verifyDigest fails for incorrect digest" $ property $ \alg salt name value ->
        case createObjectDisclosure (Salt salt) name value of
        Right encoded ->
          let correctDigest = computeDigest alg encoded
              wrongDigest = Digest (T.reverse (unDigest correctDigest))
          in verifyDigest alg wrongDigest encoded == False
        Left _ -> True  -- Discard if creation fails
  
  describe "Serialization" $ do
    it "serializeSDJWT and deserializeSDJWT round-trip (no KB)" $ property $ \jwt disclosures ->
      let sdjwt = SDJWT jwt (map EncodedDisclosure disclosures)
          serialized = serializeSDJWT sdjwt
      in case deserializeSDJWT serialized of
        Right (SDJWT decodedJWT decodedDisclosures) ->
          decodedJWT == jwt && decodedDisclosures == map EncodedDisclosure disclosures
        Left _ -> False
    
    it "serializePresentation and deserializePresentation round-trip (no KB)" $ property $ \jwt disclosures ->
      let presentation = SDJWTPresentation jwt (map EncodedDisclosure disclosures) Nothing
          serialized = serializePresentation presentation
      in case deserializePresentation serialized of
        Right (SDJWTPresentation decodedJWT decodedDisclosures decodedKB) ->
          decodedJWT == jwt && decodedDisclosures == map EncodedDisclosure disclosures && decodedKB == Nothing
        Left _ -> False
    
    it "serializePresentation and deserializePresentation round-trip (with KB)" $ property $ \jwt disclosures kbJWT ->
      -- Only test with non-empty JWTs (empty strings aren't valid JWTs)
      jwt /= "" && kbJWT /= "" ==>
        let presentation = SDJWTPresentation jwt (map EncodedDisclosure disclosures) (Just kbJWT)
            serialized = serializePresentation presentation
        in case deserializePresentation serialized of
          Right (SDJWTPresentation decodedJWT decodedDisclosures decodedKB) ->
            decodedJWT == jwt && decodedDisclosures == map EncodedDisclosure disclosures && decodedKB == Just kbJWT
          Left _ -> False
  
  describe "Hash Algorithm Properties" $ do
    it "hashAlgorithmToText never returns empty string" $ property $ \alg ->
      hashAlgorithmToText alg /= ""
    
    it "parseHashAlgorithm round-trips with hashAlgorithmToText" $ property $ \alg ->
      parseHashAlgorithm (hashAlgorithmToText alg) == Just alg
    
    it "defaultHashAlgorithm returns SHA256" $
      defaultHashAlgorithm `shouldBe` SHA256
  
  describe "Disclosure Properties" $ do
    it "getDisclosureSalt extracts correct salt from object disclosure" $ property $ \salt name value ->
        case createObjectDisclosure (Salt salt) name value of
        Right encoded -> case decodeDisclosure encoded of
          Right disclosure -> getDisclosureSalt disclosure == Salt salt
          Left _ -> False
        Left _ -> True  -- Discard if creation fails
    
    it "getDisclosureSalt extracts correct salt from array disclosure" $ property $ \salt value ->
        case createArrayDisclosure (Salt salt) value of
        Right encoded -> case decodeDisclosure encoded of
          Right disclosure -> getDisclosureSalt disclosure == Salt salt
          Left _ -> False
        Left _ -> True  -- Discard if creation fails
    
    it "getDisclosureClaimName returns Nothing for array disclosures" $ property $ \salt value ->
        case createArrayDisclosure (Salt salt) value of
        Right encoded -> case decodeDisclosure encoded of
          Right disclosure -> getDisclosureClaimName disclosure == Nothing
          Left _ -> False
        Left _ -> True  -- Discard if creation fails
    
    it "getDisclosureClaimName returns Just name for object disclosures" $ property $ \salt name value ->
      case createObjectDisclosure (Salt salt) name value of
        Right encoded -> case decodeDisclosure encoded of
          Right disclosure -> getDisclosureClaimName disclosure == Just name
          Left _ -> False
        Left _ -> True  -- Discard if creation fails
