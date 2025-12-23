#!/usr/bin/env stack
-- stack --resolver lts-21 runghc --package cryptonite --package jose-jwt --package aeson --package bytestring --package text
-- NOTE: cryptonite is deprecated in favor of crypton, but jose-jwt still requires cryptonite

import qualified Crypto.PubKey.RSA as RSA
import qualified Crypto.PubKey.ECC.Generate as ECGen
import Crypto.PubKey.ECC.ECDSA (KeyPair(..), PrivateKey(..), PublicKey(..))
import Crypto.PubKey.ECC.Types (getCurveByName, CurveName(..))
import Crypto.Random (getSystemDRG, withDRG)
import qualified Jose.Jwk as Jose
import qualified Data.Aeson as Aeson
import qualified Data.Aeson.Key as Key
import qualified Data.Text.Encoding as TE
import qualified Data.ByteString.Lazy as BSL
import qualified Data.Text as T

main :: IO ()
main = do
  -- Generate first RSA key pair (2048 bits = 256 bytes, current standard)
  putStrLn "Generating first 2048-bit RSA key pair (this may take a minute)..."
  drg1 <- getSystemDRG
  -- RSA.generate takes key size in BYTES, so 256 bytes = 2048 bits
  let (rsaPub, rsaPriv) = fst $ withDRG drg1 (RSA.generate 256 (65537 :: Integer))
  
  let rsaPrivateJwk = Jose.RsaPrivateJwk rsaPriv Nothing Nothing Nothing
  let rsaPublicJwk = Jose.RsaPublicJwk rsaPub Nothing Nothing Nothing
  let rsaPrivateJSON = Aeson.encode rsaPrivateJwk
  let rsaPublicJSON = Aeson.encode rsaPublicJwk
  let rsaPrivateText = TE.decodeUtf8 $ BSL.toStrict rsaPrivateJSON
  let rsaPublicText = TE.decodeUtf8 $ BSL.toStrict rsaPublicJSON
  
  -- Generate second RSA key pair (for testing signature verification with wrong key)
  putStrLn "Generating second 2048-bit RSA key pair (this may take a minute)..."
  drg2 <- getSystemDRG
  let (rsaPub2, rsaPriv2) = fst $ withDRG drg2 (RSA.generate 256 (65537 :: Integer))
  
  let rsaPrivateJwk2 = Jose.RsaPrivateJwk rsaPriv2 Nothing Nothing Nothing
  let rsaPublicJwk2 = Jose.RsaPublicJwk rsaPub2 Nothing Nothing Nothing
  let rsaPrivateJSON2 = Aeson.encode rsaPrivateJwk2
  let rsaPublicJSON2 = Aeson.encode rsaPublicJwk2
  let rsaPrivateText2 = TE.decodeUtf8 $ BSL.toStrict rsaPrivateJSON2
  let rsaPublicText2 = TE.decodeUtf8 $ BSL.toStrict rsaPublicJSON2
  
  -- Generate EC key pair
  putStrLn "Generating EC P-256 key pair..."
  drg3 <- getSystemDRG
  let curve = getCurveByName SEC_p256r1
  let (ecPub, ecPriv) = fst $ withDRG drg3 (ECGen.generate curve)
  let publicPoint = public_q ecPub
  let privateNumber = private_d ecPriv
  let ecKeyPair = KeyPair curve publicPoint privateNumber
  let ecPrivateJwk = Jose.EcPrivateJwk ecKeyPair Nothing Nothing Nothing Jose.P_256
  let ecPublicJwk = Jose.EcPublicJwk ecPub Nothing Nothing Nothing Jose.P_256
  let ecPrivateJSON = Aeson.encode ecPrivateJwk
  let ecPublicJSON = Aeson.encode ecPublicJwk
  let ecPrivateText = TE.decodeUtf8 $ BSL.toStrict ecPrivateJSON
  let ecPublicText = TE.decodeUtf8 $ BSL.toStrict ecPublicJSON
  
  -- Output JSON
  let output = Aeson.object
        [ (Key.fromString "rsa", Aeson.object
            [ (Key.fromString "private", Aeson.String rsaPrivateText)
            , (Key.fromString "public", Aeson.String rsaPublicText)
            ])
        , (Key.fromString "rsa2", Aeson.object
            [ (Key.fromString "private", Aeson.String rsaPrivateText2)
            , (Key.fromString "public", Aeson.String rsaPublicText2)
            ])
        , (Key.fromString "ec", Aeson.object
            [ (Key.fromString "private", Aeson.String ecPrivateText)
            , (Key.fromString "public", Aeson.String ecPublicText)
            ])
        ]
  
  BSL.writeFile "test/test-keys.json" (Aeson.encode output)
  putStrLn "Keys written to test/test-keys.json"

