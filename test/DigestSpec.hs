{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
module DigestSpec (spec) where

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
spec = describe "SDJWT.Digest" $ do
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
    
    it "returns Nothing for empty string" $ do
      parseHashAlgorithm "" `shouldBe` Nothing
  
  describe "defaultHashAlgorithm" $ do
    it "returns SHA256 as default" $ do
      defaultHashAlgorithm `shouldBe` SHA256
    
    describe "computeDigest" $ do
      it "computes digest for a disclosure with SHA256" $ do
        let disclosure = EncodedDisclosure "WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgImdpdmVuX25hbWUiLCAiSm9obiJd"
        let digest = computeDigest SHA256 disclosure
        unDigest digest `shouldBe` "jsu9yVulwQQlhFlM_3JlzMaSFzglhQG0DpfayQwLUK4"
      
      it "computes digest for a disclosure with SHA384" $ do
        let disclosure = EncodedDisclosure "WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgImdpdmVuX25hbWUiLCAiSm9obiJd"
        let digest = computeDigest SHA384 disclosure
        -- SHA384 produces different digest than SHA256
        unDigest digest `shouldNotBe` "jsu9yVulwQQlhFlM_3JlzMaSFzglhQG0DpfayQwLUK4"
        -- Digest should be non-empty
        T.length (unDigest digest) `shouldSatisfy` (> 0)
      
      it "computes digest for a disclosure with SHA512" $ do
        let disclosure = EncodedDisclosure "WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgImdpdmVuX25hbWUiLCAiSm9obiJd"
        let digest = computeDigest SHA512 disclosure
        -- SHA512 produces different digest than SHA256
        unDigest digest `shouldNotBe` "jsu9yVulwQQlhFlM_3JlzMaSFzglhQG0DpfayQwLUK4"
        -- Digest should be non-empty
        T.length (unDigest digest) `shouldSatisfy` (> 0)
      
      it "produces same digest for same disclosure and algorithm" $ do
        let disclosure = EncodedDisclosure "WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgImdpdmVuX25hbWUiLCAiSm9obiJd"
        let digest1 = computeDigest SHA256 disclosure
        let digest2 = computeDigest SHA256 disclosure
        unDigest digest1 `shouldBe` unDigest digest2
    
    describe "verifyDigest" $ do
      it "verifies correct digest for SHA256" $ do
        let disclosure = EncodedDisclosure "WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgImdpdmVuX25hbWUiLCAiSm9obiJd"
        let digest = computeDigest SHA256 disclosure
        verifyDigest SHA256 digest disclosure `shouldBe` True
      
      it "verifies correct digest for SHA384" $ do
        let disclosure = EncodedDisclosure "WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgImdpdmVuX25hbWUiLCAiSm9obiJd"
        let digest = computeDigest SHA384 disclosure
        verifyDigest SHA384 digest disclosure `shouldBe` True
      
      it "verifies correct digest for SHA512" $ do
        let disclosure = EncodedDisclosure "WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgImdpdmVuX25hbWUiLCAiSm9obiJd"
        let digest = computeDigest SHA512 disclosure
        verifyDigest SHA512 digest disclosure `shouldBe` True
      
      it "rejects incorrect digest" $ do
        let disclosure = EncodedDisclosure "WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgImdpdmVuX25hbWUiLCAiSm9obiJd"
        let wrongDigest = Digest "wrong-digest-value"
        verifyDigest SHA256 wrongDigest disclosure `shouldBe` False
      
      it "rejects digest computed with different algorithm" $ do
        let disclosure = EncodedDisclosure "WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgImdpdmVuX25hbWUiLCAiSm9obiJd"
        let sha256Digest = computeDigest SHA256 disclosure
        -- SHA256 digest should not verify with SHA384
        verifyDigest SHA384 sha256Digest disclosure `shouldBe` False

