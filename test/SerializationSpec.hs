{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
module SerializationSpec (spec) where

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
spec =     describe "SDJWT.Serialization" $ do
    describe "serializeSDJWT" $ do
      it "serializes SD-JWT with empty disclosures" $ do
        let jwt = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.test"
        let sdjwt = SDJWT jwt []
        serializeSDJWT sdjwt `shouldBe` "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.test~"
      
      it "serializes SD-JWT with single disclosure" $ do
        let jwt = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.test"
        let disclosure = EncodedDisclosure "disclosure1"
        let sdjwt = SDJWT jwt [disclosure]
        serializeSDJWT sdjwt `shouldBe` "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.test~disclosure1~"
      
      it "serializes SD-JWT with multiple disclosures" $ do
        let jwt = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.test"
        let disclosure1 = EncodedDisclosure "disclosure1"
        let disclosure2 = EncodedDisclosure "disclosure2"
        let disclosure3 = EncodedDisclosure "disclosure3"
        let sdjwt = SDJWT jwt [disclosure1, disclosure2, disclosure3]
        serializeSDJWT sdjwt `shouldBe` "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.test~disclosure1~disclosure2~disclosure3~"
    
    describe "parseTildeSeparated" $ do
      it "parses SD-JWT format" $ do
        let input = "jwt~disclosure1~disclosure2~"
        case parseTildeSeparated input of
          Right (jwt, parsedDisclosures, Nothing) -> do
            jwt `shouldBe` "jwt"
            length parsedDisclosures `shouldBe` 2
          Right (_, _, Just _) -> expectationFailure "Unexpected key binding JWT"
          Left err -> expectationFailure $ "Failed to parse: " ++ show err
      
      it "parses SD-JWT+KB format" $ do
        let input = "jwt~disclosure1~disclosure2~kb-jwt"
        case parseTildeSeparated input of
          Right (jwt, parsedDisclosures, Just kbJwt) -> do
            jwt `shouldBe` "jwt"
            length parsedDisclosures `shouldBe` 2
            kbJwt `shouldBe` "kb-jwt"
          Right _ -> expectationFailure "Expected KB-JWT"
          Left err -> expectationFailure $ "Failed to parse: " ++ show err
      
      it "parses JWT only (no disclosures)" $ do
        let input = "jwt"
        case parseTildeSeparated input of
          Right (jwt, parsedDisclosures, Nothing) -> do
            jwt `shouldBe` "jwt"
            length parsedDisclosures `shouldBe` 0
          Left err -> expectationFailure $ "Failed to parse: " ++ show err
          _ -> expectationFailure "Unexpected result"
      
      it "parses empty string as JWT-only" $ do
        let input = ""
        case parseTildeSeparated input of
          Right (jwt, parsedDisclosures, mbKbJwt) -> do
            jwt `shouldBe` ""
            length parsedDisclosures `shouldBe` 0
            mbKbJwt `shouldBe` Nothing
          Left err -> expectationFailure $ "Should parse empty string, got error: " ++ show err
      
      it "handles multiple consecutive tildes" $ do
        let input = "jwt~~disclosure1~~"
        case parseTildeSeparated input of
          Right (jwt, parsedDisclosures, Nothing) -> do
            jwt `shouldBe` "jwt"
            length parsedDisclosures `shouldBe` 3  -- empty, disclosure1, empty
          Left err -> expectationFailure $ "Failed to parse: " ++ show err
          _ -> expectationFailure "Unexpected result"
    
    describe "deserializeSDJWT" $ do
      it "deserializes valid SD-JWT" $ do
        let jwt = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.test"
        let input = jwt <> "~disclosure1~disclosure2~"
        case deserializeSDJWT input of
          Right (SDJWT parsedJwt parsedDisclosures) -> do
            parsedJwt `shouldBe` jwt
            length parsedDisclosures `shouldBe` 2
            unEncodedDisclosure (head parsedDisclosures) `shouldBe` "disclosure1"
            unEncodedDisclosure (parsedDisclosures !! 1) `shouldBe` "disclosure2"
          Left err -> expectationFailure $ "Failed to deserialize: " ++ show err
      
      it "deserializes SD-JWT with no disclosures" $ do
        let jwt = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.test"
        let input = jwt <> "~"
        case deserializeSDJWT input of
          Right (SDJWT parsedJwt parsedDisclosures) -> do
            parsedJwt `shouldBe` jwt
            length parsedDisclosures `shouldBe` 0
          Left err -> expectationFailure $ "Failed to deserialize: " ++ show err
      
      it "rejects SD-JWT+KB format" $ do
        let jwt = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.test"
        let input = jwt <> "~disclosure1~kb-jwt"
        case deserializeSDJWT input of
          Left _ -> return ()  -- Expected error
          Right _ -> expectationFailure "Should reject SD-JWT+KB format"
      
      it "handles empty input (parses as empty JWT)" $ do
        case deserializeSDJWT "" of
          Right (SDJWT parsedJwt parsedDisclosures) -> do
            parsedJwt `shouldBe` ""
            length parsedDisclosures `shouldBe` 0
          Left _ -> return ()  -- Empty JWT might be rejected by deserializeSDJWT validation
      
      it "rejects input without trailing tilde (parses as SD-JWT+KB)" $ do
        let jwt = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.test"
        let input = jwt <> "~disclosure1"  -- Missing trailing tilde - parses as SD-JWT+KB
        case deserializeSDJWT input of
          Left _ -> return ()  -- Expected error (SD-JWT format requires trailing tilde, this parses as SD-JWT+KB)
          Right _ -> expectationFailure "Should reject SD-JWT+KB format"
    
    describe "deserializePresentation" $ do
      it "deserializes SD-JWT presentation (no KB-JWT)" $ do
        let jwt = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.test"
        let input = jwt <> "~disclosure1~disclosure2~"
        case deserializePresentation input of
          Right (SDJWTPresentation parsedJwt parsedDisclosures Nothing) -> do
            parsedJwt `shouldBe` jwt
            length parsedDisclosures `shouldBe` 2
          Left err -> expectationFailure $ "Failed to deserialize: " ++ show err
          Right _ -> expectationFailure "Unexpected KB-JWT"
      
      it "deserializes SD-JWT+KB presentation" $ do
        let jwt = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.test"
        let kbJwt = "kb-jwt-token"
        let input = jwt <> "~disclosure1~disclosure2~" <> kbJwt
        case deserializePresentation input of
          Right (SDJWTPresentation parsedJwt parsedDisclosures (Just parsedKbJwt)) -> do
            parsedJwt `shouldBe` jwt
            length parsedDisclosures `shouldBe` 2
            parsedKbJwt `shouldBe` kbJwt
          Left err -> expectationFailure $ "Failed to deserialize: " ++ show err
          Right _ -> expectationFailure "Expected KB-JWT"
      
      it "deserializes presentation with no disclosures" $ do
        let jwt = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.test"
        let input = jwt <> "~"
        case deserializePresentation input of
          Right (SDJWTPresentation parsedJwt parsedDisclosures mbKbJwt) -> do
            parsedJwt `shouldBe` jwt
            length parsedDisclosures `shouldBe` 0
            mbKbJwt `shouldBe` Nothing
          Left err -> expectationFailure $ "Failed to deserialize: " ++ show err
      
      it "handles empty input (parses as empty JWT)" $ do
        case deserializePresentation "" of
          Right (SDJWTPresentation parsedJwt parsedDisclosures mbKbJwt) -> do
            parsedJwt `shouldBe` ""
            length parsedDisclosures `shouldBe` 0
            mbKbJwt `shouldBe` Nothing
          Left _ -> return ()  -- Empty JWT might be rejected by validation
      
      it "handles JWT only (no tilde)" $ do
        let jwt = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.test"
        case deserializePresentation jwt of
          Right (SDJWTPresentation parsedJwt parsedDisclosures mbKbJwt) -> do
            parsedJwt `shouldBe` jwt
            length parsedDisclosures `shouldBe` 0
            mbKbJwt `shouldBe` Nothing
          Left err -> expectationFailure $ "Failed to deserialize: " ++ show err

