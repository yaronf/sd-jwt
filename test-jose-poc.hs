#!/usr/bin/env stack
-- stack --resolver lts-22.0 script --package jose --package aeson --package bytestring --package text --package lens

{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeApplications #-}

import qualified Crypto.JOSE as Jose
import qualified Crypto.JOSE.JWS as JWS
import qualified Crypto.JOSE.JWK as JWK
import qualified Crypto.JOSE.Header as Header
import qualified Crypto.JWT as JWT
import qualified Data.Aeson as Aeson
import qualified Data.ByteString.Lazy as LBS
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import Control.Lens ((&), (?~))

main :: IO ()
main = do
  putStrLn "=== Testing jose package with custom typ headers ===\n"
  
  -- Load test keys from test-keys.json
  keysContent <- LBS.readFile "test/test-keys.json"
  case Aeson.eitherDecode keysContent of
    Left err -> putStrLn $ "Failed to load test keys: " ++ err
    Right keysObj -> do
      -- Test 1: EC signing with custom typ header
      putStrLn "Test 1: EC P-256 (ES256) signing with typ: 'kb+jwt'"
      testECSigningWithTyp keysObj
      
      -- Test 2: RSA signing with custom typ header
      putStrLn "\nTest 2: RSA (RS256) signing with typ: 'kb+jwt'"
      testRSASigningWithTyp keysObj
      
      -- Test 3: EdDSA signing with custom typ header
      putStrLn "\nTest 3: EdDSA signing with typ: 'kb+jwt'"
      testEdDSASigningWithTyp keysObj
      
      putStrLn "\n=== All tests completed ==="

-- Extract key from JSON object
extractKey :: Aeson.Value -> T.Text -> T.Text -> Maybe T.Text
extractKey keysObj keyType keyKind =
  case keysObj of
    Aeson.Object obj -> case Aeson.lookup keyType obj of
      Just (Aeson.Object keyObj) -> case Aeson.lookup keyKind keyObj of
        Just (Aeson.String keyText) -> Just keyText
        _ -> Nothing
      _ -> Nothing
    _ -> Nothing

-- Test EC signing with custom typ header
testECSigningWithTyp :: Aeson.Value -> IO ()
testECSigningWithTyp keysObj = do
  case extractKey keysObj "ec" "private" of
    Nothing -> putStrLn "Failed to extract EC private key"
    Just ecJWKText -> do
      case Aeson.eitherDecodeStrict (TE.encodeUtf8 ecJWKText) of
        Left err -> putStrLn $ "Failed to parse EC JWK: " ++ err
        Right jwkValue -> do
          case JWK.fromJSON jwkValue of
            Left err -> putStrLn $ "Failed to create JWK: " ++ show err
            Right jwk -> do
              -- Create header with custom typ
              result <- Jose.runJOSE $ do
                alg <- JWS.bestJWSAlg jwk
                let header = JWS.newJWSHeaderProtected alg
                -- Set typ header using lens
                let headerWithTyp = header & Header.typ ?~ Header.newHeaderParamProtected "kb+jwt"
                let payload = Aeson.object [("test", Aeson.String "ec-value")]
                let payloadBS = LBS.toStrict $ Aeson.encode payload
                JWS.signJWS payloadBS [(headerWithTyp, jwk)]
              
              case result of
                Left err -> putStrLn $ "EC signing failed: " ++ show err
                Right jws -> do
                  putStrLn "✓ EC signing succeeded!"
                  -- Encode to compact JWT format
                  case JWS.encodeCompact jws of
                    Left err -> putStrLn $ "Failed to encode: " ++ show err
                    Right compact -> do
                      putStrLn $ "  Compact JWT: " ++ T.unpack (T.take 80 compact) ++ "..."
                      -- Decode and verify typ header
                      case JWS.decodeCompact compact of
                        Left err -> putStrLn $ "Failed to decode: " ++ show err
                        Right decoded -> do
                          let sigs = JWS.signatures decoded
                          case sigs of
                            [] -> putStrLn "  ✗ No signatures found"
                            (sig:_) -> do
                              let hdr = JWS.header sig
                              putStrLn $ "  Header alg: " ++ show (JWS.alg hdr)
                              -- Check typ header
                              case Header.typ hdr of
                                Nothing -> putStrLn "  ✗ WARNING: typ header not found!"
                                Just typParam -> do
                                  let typValue = Header.param typParam
                                  if typValue == "kb+jwt"
                                    then putStrLn $ "  ✓ typ header: " ++ T.unpack typValue
                                    else putStrLn $ "  ✗ typ header mismatch: " ++ T.unpack typValue ++ " (expected 'kb+jwt')"

-- Test RSA signing with custom typ header
testRSASigningWithTyp :: Aeson.Value -> IO ()
testRSASigningWithTyp keysObj = do
  case extractKey keysObj "rsa" "private" of
    Nothing -> putStrLn "Failed to extract RSA private key"
    Just rsaJWKText -> do
      case Aeson.eitherDecodeStrict (TE.encodeUtf8 rsaJWKText) of
        Left err -> putStrLn $ "Failed to parse RSA JWK: " ++ err
        Right jwkValue -> do
          case JWK.fromJSON jwkValue of
            Left err -> putStrLn $ "Failed to create JWK: " ++ show err
            Right jwk -> do
              -- Create header with custom typ
              result <- Jose.runJOSE $ do
                alg <- JWS.bestJWSAlg jwk
                let header = JWS.newJWSHeaderProtected alg
                -- Set typ header using lens
                let headerWithTyp = header & Header.typ ?~ Header.newHeaderParamProtected "kb+jwt"
                let payload = Aeson.object [("test", Aeson.String "rsa-value")]
                let payloadBS = LBS.toStrict $ Aeson.encode payload
                JWS.signJWS payloadBS [(headerWithTyp, jwk)]
              
              case result of
                Left err -> putStrLn $ "RSA signing failed: " ++ show err
                Right jws -> do
                  putStrLn "✓ RSA signing succeeded!"
                  -- Encode to compact JWT format
                  case JWS.encodeCompact jws of
                    Left err -> putStrLn $ "Failed to encode: " ++ show err
                    Right compact -> do
                      putStrLn $ "  Compact JWT: " ++ T.unpack (T.take 80 compact) ++ "..."
                      -- Decode and verify typ header
                      case JWS.decodeCompact compact of
                        Left err -> putStrLn $ "Failed to decode: " ++ show err
                        Right decoded -> do
                          let sigs = JWS.signatures decoded
                          case sigs of
                            [] -> putStrLn "  ✗ No signatures found"
                            (sig:_) -> do
                              let hdr = JWS.header sig
                              putStrLn $ "  Header alg: " ++ show (JWS.alg hdr)
                              -- Check typ header
                              case Header.typ hdr of
                                Nothing -> putStrLn "  ✗ WARNING: typ header not found!"
                                Just typParam -> do
                                  let typValue = Header.param typParam
                                  if typValue == "kb+jwt"
                                    then putStrLn $ "  ✓ typ header: " ++ T.unpack typValue
                                    else putStrLn $ "  ✗ typ header mismatch: " ++ T.unpack typValue ++ " (expected 'kb+jwt')"

-- Test EdDSA signing with custom typ header
testEdDSASigningWithTyp :: Aeson.Value -> IO ()
testEdDSASigningWithTyp keysObj = do
  case extractKey keysObj "ed25519" "private" of
    Nothing -> putStrLn "Failed to extract Ed25519 private key"
    Just edJWKText -> do
      case Aeson.eitherDecodeStrict (TE.encodeUtf8 edJWKText) of
        Left err -> putStrLn $ "Failed to parse Ed25519 JWK: " ++ err
        Right jwkValue -> do
          case JWK.fromJSON jwkValue of
            Left err -> putStrLn $ "Failed to create JWK: " ++ show err
            Right jwk -> do
              -- Create header with custom typ
              result <- Jose.runJOSE $ do
                alg <- JWS.bestJWSAlg jwk
                let header = JWS.newJWSHeaderProtected alg
                -- Set typ header using lens
                let headerWithTyp = header & Header.typ ?~ Header.newHeaderParamProtected "kb+jwt"
                let payload = Aeson.object [("test", Aeson.String "ed25519-value")]
                let payloadBS = LBS.toStrict $ Aeson.encode payload
                JWS.signJWS payloadBS [(headerWithTyp, jwk)]
              
              case result of
                Left err -> putStrLn $ "EdDSA signing failed: " ++ show err
                Right jws -> do
                  putStrLn "✓ EdDSA signing succeeded!"
                  -- Encode to compact JWT format
                  case JWS.encodeCompact jws of
                    Left err -> putStrLn $ "Failed to encode: " ++ show err
                    Right compact -> do
                      putStrLn $ "  Compact JWT: " ++ T.unpack (T.take 80 compact) ++ "..."
                      -- Decode and verify typ header
                      case JWS.decodeCompact compact of
                        Left err -> putStrLn $ "Failed to decode: " ++ show err
                        Right decoded -> do
                          let sigs = JWS.signatures decoded
                          case sigs of
                            [] -> putStrLn "  ✗ No signatures found"
                            (sig:_) -> do
                              let hdr = JWS.header sig
                              putStrLn $ "  Header alg: " ++ show (JWS.alg hdr)
                              -- Check typ header
                              case Header.typ hdr of
                                Nothing -> putStrLn "  ✗ WARNING: typ header not found!"
                                Just typParam -> do
                                  let typValue = Header.param typParam
                                  if typValue == "kb+jwt"
                                    then putStrLn $ "  ✓ typ header: " ++ T.unpack typValue
                                    else putStrLn $ "  ✗ typ header mismatch: " ++ T.unpack typValue ++ " (expected 'kb+jwt')"

