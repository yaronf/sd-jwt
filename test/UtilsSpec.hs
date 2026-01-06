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
import Text.Read (readMaybe)

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
    
    describe "JSON Pointer path resolution (RFC 6901 Section 5)" $ do
      -- Test document from RFC 6901 Section 5
      let testDoc = Aeson.object
            [  (Key.fromText "foo", Aeson.Array $ V.fromList [Aeson.String "bar", Aeson.String "baz"])
            ,  (Key.fromText "", Aeson.Number 0)
            ,  (Key.fromText "a/b", Aeson.Number 1)
            ,  (Key.fromText "c%d", Aeson.Number 2)
            ,  (Key.fromText "e^f", Aeson.Number 3)
            ,  (Key.fromText "g|h", Aeson.Number 4)
            ,  (Key.fromText "i\\j", Aeson.Number 5)
            , (Key.fromText "k\"l", Aeson.Number 6)
            ,  (Key.fromText " ", Aeson.Number 7)
            ,  (Key.fromText "m~n", Aeson.Number 8)
            ]
      
      -- Helper function to resolve a JSON Pointer path in a JSON document
      let resolvePath :: [T.Text] -> Aeson.Value -> Maybe Aeson.Value
          resolvePath [] value = Just value  -- Empty path = root
          resolvePath (seg:rest) value = case value of
            Aeson.Object obj -> do
              let key = Key.fromText seg
              nestedValue <- KeyMap.lookup key obj
              resolvePath rest nestedValue
            Aeson.Array arr -> do
              idx <- readMaybe (T.unpack seg) :: Maybe Int
              if idx >= 0 && idx < V.length arr
                then resolvePath rest (arr V.! idx)
                else Nothing
            _ -> Nothing
      
      it "resolves empty path to entire document" $ do
        resolvePath [] testDoc `shouldBe` Just testDoc
      
      it "resolves /foo to array" $ do
        let segments = splitJSONPointer "foo"
        resolvePath (map unescapeJSONPointer segments) testDoc `shouldBe` Just (Aeson.Array $ V.fromList [Aeson.String "bar", Aeson.String "baz"])
      
      it "resolves /foo/0 to first array element" $ do
        let segments = splitJSONPointer "foo/0"
        resolvePath (map unescapeJSONPointer segments) testDoc `shouldBe` Just (Aeson.String "bar")
      
      it "resolves / (empty string key) to 0" $ do
        -- Note: splitJSONPointer strips leading slashes, so "/" becomes []
        -- For the empty string key, we need to manually construct the path
        -- In RFC 6901, "/" refers to the empty string key, but our function
        -- is designed for relative paths. We test the empty string key directly.
        let segments = [""]  -- Single empty segment = empty string key
        resolvePath (map unescapeJSONPointer segments) testDoc `shouldBe` Just (Aeson.Number 0)
      
      it "resolves /a~1b (escaped slash) to 1" $ do
        let segments = splitJSONPointer "a~1b"
        resolvePath (map unescapeJSONPointer segments) testDoc `shouldBe` Just (Aeson.Number 1)
      
      it "resolves /c%d (percent sign) to 2" $ do
        let segments = splitJSONPointer "c%d"
        resolvePath (map unescapeJSONPointer segments) testDoc `shouldBe` Just (Aeson.Number 2)
      
      it "resolves /e^f (caret) to 3" $ do
        let segments = splitJSONPointer "e^f"
        resolvePath (map unescapeJSONPointer segments) testDoc `shouldBe` Just (Aeson.Number 3)
      
      it "resolves /g|h (pipe) to 4" $ do
        let segments = splitJSONPointer "g|h"
        resolvePath (map unescapeJSONPointer segments) testDoc `shouldBe` Just (Aeson.Number 4)
      
      it "resolves /i\\j (backslash) to 5" $ do
        let segments = splitJSONPointer "i\\j"
        resolvePath (map unescapeJSONPointer segments) testDoc `shouldBe` Just (Aeson.Number 5)
      
      it "resolves /k\"l (quote) to 6" $ do
        let segments = splitJSONPointer "k\"l"
        resolvePath (map unescapeJSONPointer segments) testDoc `shouldBe` Just (Aeson.Number 6)
      
      it "resolves /  (space) to 7" $ do
        let segments = splitJSONPointer " "
        resolvePath (map unescapeJSONPointer segments) testDoc `shouldBe` Just (Aeson.Number 7)
      
      it "resolves /m~0n (escaped tilde) to 8" $ do
        let segments = splitJSONPointer "m~0n"
        resolvePath (map unescapeJSONPointer segments) testDoc `shouldBe` Just (Aeson.Number 8)
      
      it "works with buildSDJWTPayload for RFC 6901 test document" $ do
        let claims = KeyMap.fromList

              [  (Key.fromText "foo", Aeson.Array $ V.fromList [Aeson.String "bar", Aeson.String "baz"])
              ,  (Key.fromText "", Aeson.Number 0)
              ,  (Key.fromText "a/b", Aeson.Number 1)
              ,  (Key.fromText "c%d", Aeson.Number 2)
              ,  (Key.fromText "e^f", Aeson.Number 3)
              ,  (Key.fromText "g|h", Aeson.Number 4)
              ,  (Key.fromText "i\\j", Aeson.Number 5)
              , ("k\"l", Aeson.Number 6)
              ,  (Key.fromText " ", Aeson.Number 7)
              ,  (Key.fromText "m~n", Aeson.Number 8)
              ]
        -- Test marking various paths as selectively disclosable
        result <- buildSDJWTPayload SHA256 ["foo/0", "a~1b", "m~0n"] claims
        case result of
          Right (_payload, _disclosures) -> return ()  -- Success
          Left err -> expectationFailure $ "Failed to build payload: " ++ show err
      
      it "works with selectDisclosuresByNames for RFC 6901 test document" $ do
        let claims = KeyMap.fromList

              [  (Key.fromText "foo", Aeson.Array $ V.fromList [Aeson.String "bar", Aeson.String "baz"])
              ,  (Key.fromText "", Aeson.Number 0)
              ,  (Key.fromText "a/b", Aeson.Number 1)
              ,  (Key.fromText "m~n", Aeson.Number 8)
              ]
        keyPair <- generateTestRSAKeyPair
        -- Create SD-JWT with RFC 6901 paths
        result <- createSDJWT Nothing Nothing SHA256 (privateKeyJWK keyPair) ["foo/0", "a~1b", "m~0n"] claims
        case result of
          Right sdjwt -> do
            -- Select disclosures using RFC 6901 paths
            case selectDisclosuresByNames sdjwt ["foo/0", "a~1b", "m~0n"] of
              Right _presentation -> return ()  -- Success
              Left err -> expectationFailure $ "Failed to select disclosures: " ++ show err
          Left err -> expectationFailure $ "Failed to create SD-JWT: " ++ show err

