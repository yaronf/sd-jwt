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
    
    describe "splitJSONPointer" $ do
      it "splits simple path" $ do
        splitJSONPointer "a/b" `shouldBe` ["a", "b"]
      
      it "splits path with multiple segments" $ do
        splitJSONPointer "a/b/c" `shouldBe` ["a", "b", "c"]
      
      it "handles empty path" $ do
        splitJSONPointer "" `shouldBe` []
      
      it "handles path starting with slash (strips leading slash)" $ do
        -- Note: Function strips leading slashes for relative path compatibility
        splitJSONPointer "/a/b" `shouldBe` ["a", "b"]
      
      it "handles path ending with slash (strips trailing slash)" $ do
        -- Note: Function doesn't create trailing empty segments
        splitJSONPointer "a/b/" `shouldBe` ["a", "b"]
      
      it "handles multiple consecutive slashes (collapses them)" $ do
        -- Note: Function collapses consecutive slashes
        splitJSONPointer "a//b" `shouldBe` ["a", "b"]
      
      it "handles escaped slash (~1)" $ do
        splitJSONPointer "a~1b" `shouldBe` ["a/b"]
      
      it "handles escaped tilde (~0)" $ do
        splitJSONPointer "a~0b" `shouldBe` ["a~b"]
      
      it "handles escaped slash followed by separator" $ do
        -- "a~1" becomes "a/", then "/" is separator, so we get ["a/", "b"]
        splitJSONPointer "a~1/b" `shouldBe` ["a/", "b"]
      
      it "handles escaped tilde followed by separator" $ do
        splitJSONPointer "a~0/b" `shouldBe` ["a~", "b"]
      
      it "handles multiple escaped sequences" $ do
        splitJSONPointer "a~1b~0c" `shouldBe` ["a/b~c"]
      
      it "handles escaped sequences at start" $ do
        splitJSONPointer "~1a/b" `shouldBe` ["/a", "b"]
        splitJSONPointer "~0a/b" `shouldBe` ["~a", "b"]
      
      it "handles escaped sequences at end" $ do
        splitJSONPointer "a/b~1" `shouldBe` ["a", "b/"]
        splitJSONPointer "a/b~0" `shouldBe` ["a", "b~"]
      
      it "handles complex nested path with escapes" $ do
        splitJSONPointer "address/street~1address/locality" `shouldBe` ["address", "street/address", "locality"]
      
      it "handles tilde not followed by 0 or 1" $ do
        splitJSONPointer "a~2b" `shouldBe` ["a~2b"]
      
      it "handles incomplete escape sequence at end" $ do
        splitJSONPointer "a~" `shouldBe` ["a~"]
      
      it "handles escape sequence at end of segment" $ do
        splitJSONPointer "a~1" `shouldBe` ["a/"]
        splitJSONPointer "a~0" `shouldBe` ["a~"]
      
      it "handles only slashes (returns empty list)" $ do
        -- Note: Function strips leading slashes and collapses consecutive ones
        splitJSONPointer "/" `shouldBe` []
        splitJSONPointer "//" `shouldBe` []
      
      it "handles only escaped sequences" $ do
        splitJSONPointer "~1" `shouldBe` ["/"]
        splitJSONPointer "~0" `shouldBe` ["~"]
        splitJSONPointer "~1~0" `shouldBe` ["/~"]
      
      it "handles mixed regular and escaped characters" $ do
        splitJSONPointer "foo~1bar/baz~0qux" `shouldBe` ["foo/bar", "baz~qux"]
      
      it "handles RFC 6901 example: empty path" $ do
        splitJSONPointer "" `shouldBe` []
      
      it "handles RFC 6901 example: root path (strips leading slash)" $ do
        -- Note: Function is designed for relative paths, strips leading "/"
        splitJSONPointer "/" `shouldBe` []
      
      it "handles RFC 6901 example: nested object" $ do
        splitJSONPointer "a/b/c" `shouldBe` ["a", "b", "c"]
      
      it "handles RFC 6901 example: escaped characters" $ do
        splitJSONPointer "a~1b~0c" `shouldBe` ["a/b~c"]
    
    describe "unescapeJSONPointer" $ do
      it "unescapes escaped slash" $ do
        unescapeJSONPointer "a~1b" `shouldBe` "a/b"
      
      it "unescapes escaped tilde" $ do
        unescapeJSONPointer "a~0b" `shouldBe` "a~b"
      
      it "unescapes multiple escaped sequences" $ do
        unescapeJSONPointer "a~1b~0c" `shouldBe` "a/b~c"
      
      it "handles empty string" $ do
        unescapeJSONPointer "" `shouldBe` ""
      
      it "handles string with no escapes" $ do
        unescapeJSONPointer "abc" `shouldBe` "abc"
      
      it "handles only escaped slash" $ do
        unescapeJSONPointer "~1" `shouldBe` "/"
      
      it "handles only escaped tilde" $ do
        unescapeJSONPointer "~0" `shouldBe` "~"
      
      it "handles consecutive escapes" $ do
        unescapeJSONPointer "~1~0" `shouldBe` "/~"
      
      it "handles tilde not followed by 0 or 1" $ do
        unescapeJSONPointer "a~2b" `shouldBe` "a~2b"
      
      it "handles incomplete escape at end" $ do
        unescapeJSONPointer "a~" `shouldBe` "a~"
      
      it "handles escape at start" $ do
        unescapeJSONPointer "~1a" `shouldBe` "/a"
        unescapeJSONPointer "~0a" `shouldBe` "~a"
      
      it "handles escape at end" $ do
        unescapeJSONPointer "a~1" `shouldBe` "a/"
        unescapeJSONPointer "a~0" `shouldBe` "a~"

