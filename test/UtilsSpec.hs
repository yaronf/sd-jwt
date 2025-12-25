{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
module UtilsSpec (spec) where

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
spec = describe "SDJWT.Utils" $ do
    describe "base64urlEncode" $ do
      it "encodes ByteString to base64url" $ do
        base64urlEncode (BS.pack [72, 101, 108, 108, 111, 44, 32, 87, 111, 114, 108, 100, 33]) `shouldBe` "SGVsbG8sIFdvcmxkIQ"
    
    describe "base64urlDecode" $ do
      it "decodes base64url to ByteString" $ do
        base64urlDecode "SGVsbG8sIFdvcmxkIQ" `shouldBe` Right (BS.pack [72, 101, 108, 108, 111, 44, 32, 87, 111, 114, 108, 100, 33])
      it "handles invalid input" $ do
        base64urlDecode "!!!" `shouldSatisfy` isLeft
    
    describe "textToByteString" $ do
      it "converts Text to ByteString" $ do
        textToByteString "Hello, World!" `shouldBe` BS.pack [72, 101, 108, 108, 111, 44, 32, 87, 111, 114, 108, 100, 33]
      it "handles empty Text" $ do
        textToByteString "" `shouldBe` BS.empty
      it "handles Unicode characters" $ do
        textToByteString "Hello 世界" `shouldBe` BS.pack [72, 101, 108, 108, 111, 32, 228, 184, 150, 231, 149, 140]
    
    describe "byteStringToText" $ do
      it "converts ByteString to Text" $ do
        byteStringToText (BS.pack [72, 101, 108, 108, 111, 44, 32, 87, 111, 114, 108, 100, 33]) `shouldBe` "Hello, World!"
      it "handles empty ByteString" $ do
        byteStringToText BS.empty `shouldBe` ""
      it "handles Unicode characters" $ do
        byteStringToText (BS.pack [72, 101, 108, 108, 111, 32, 228, 184, 150, 231, 149, 140]) `shouldBe` "Hello 世界"
    
    describe "generateSalt" $ do
      it "generates 16-byte salt" $ do
        salt <- generateSalt
        BS.length salt `shouldBe` 16
      it "generates different salts each time" $ do
        salt1 <- generateSalt
        salt2 <- generateSalt
        salt1 `shouldNotBe` salt2  -- Very unlikely to be the same

