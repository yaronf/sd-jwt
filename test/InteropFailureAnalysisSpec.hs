{-# LANGUAGE OverloadedStrings #-}

module InteropFailureAnalysisSpec where

import Test.Hspec
import qualified Data.Aeson as Aeson
import qualified Data.Aeson.Key as Key
import qualified Data.Aeson.KeyMap as KeyMap
import qualified Data.Map.Strict as Map
import qualified Data.Text as T
import qualified Data.Vector as V
import qualified Data.ByteString.Lazy as BSL
import SDJWT.Internal.Types (HashAlgorithm(..), ProcessedSDJWTPayload(..), SDJWTError(..), Digest(..), SDJWT(..), EncodedDisclosure(..), SDJWTPresentation(..), SDJWTPayload(..))
import SDJWT.Internal.Issuance (buildSDJWTPayload, createSDJWT)
-- NOTE: Tests using markSelectivelyDisclosable or markArrayElementDisclosable need to be
-- rewritten to use JSON Pointer paths with createSDJWT. These functions are now internal-only.
import SDJWT.Internal.Presentation (selectDisclosuresByNames)
import SDJWT.Internal.Verification (verifySDJWTWithoutSignature)
import SDJWT.Internal.Utils (base64urlEncode)
import SDJWT.Internal.JWT (signJWTWithHeaders)
import TestKeys (generateTestRSAKeyPair, TestKeyPair(..))

-- Test cases based on failing Python interop tests
-- These tests reproduce the exact failing scenarios from the interop tests
-- They are expected to FAIL until the bugs are fixed

spec :: Spec
spec = describe "Interop Failure Analysis" $ do
  describe "array_nested_in_plain" $ do
    it "should handle nested arrays with selectively disclosable elements" $ do
      -- Test case: nested_array: [[!sd "foo", !sd "bar"], [!sd "baz", !sd "qux"]]
      -- holder_disclosed_claims: nested_array: [[True, False], [False, True]]
      -- Expected: nested_array: [["foo"], ["qux"]]
      -- Current Behavior: Getting [] (empty array)
      --
      -- This reproduces the bug where nested array element disclosures aren't
      -- correctly selected and included in the presentation.
      
      -- Create claims with nested array: [["foo", "bar"], ["baz", "qux"]]
      let claims = KeyMap.fromList

            [  (Key.fromText "nested_array", Aeson.Array $ V.fromList
                [ Aeson.Array $ V.fromList [Aeson.String "foo", Aeson.String "bar"]
                , Aeson.Array $ V.fromList [Aeson.String "baz", Aeson.String "qux"]
                ])
            ]
      
      -- Get test keys for signing
      keyPair <- generateTestRSAKeyPair
      
      -- Create SD-JWT with nested array paths: mark ALL elements as selectively disclosable
      -- [[!sd "foo", !sd "bar"], [!sd "baz", !sd "qux"]]
      result <- createSDJWT Nothing Nothing SHA256 (privateKeyJWK keyPair) 
        ["nested_array/0/0", "nested_array/0/1", "nested_array/1/0", "nested_array/1/1"] claims
      
      case result of
        Right sdjwt -> do
          -- Select disclosures using selectDisclosuresByNames
          -- holder_disclosed_claims: nested_array: [[True, False], [False, True]]
          -- This means we're disclosing nested_array[0][0] (foo) and nested_array[1][1] (qux)
          case selectDisclosuresByNames sdjwt ["nested_array/0/0", "nested_array/1/1"] of
            Left err -> expectationFailure $ "Failed to select disclosures: " ++ show err
            Right presentation -> do
              -- Verify
              verificationResult <- verifySDJWTWithoutSignature presentation
              case verificationResult of
                Right processed -> do
                  let processedClaimsMap = processedClaims processed
                  case KeyMap.lookup (Key.fromText "nested_array") processedClaimsMap of
                    Just (Aeson.Array arr) -> do
                      -- Expected: [["foo"], ["qux"]]
                      V.length arr `shouldBe` 2
                      case arr V.!? 0 of
                        Just (Aeson.Array inner1) -> do
                          V.length inner1 `shouldBe` 1
                          inner1 V.!? 0 `shouldBe` Just (Aeson.String "foo")
                        _ -> expectationFailure "First element should be array with 'foo'"
                      case arr V.!? 1 of
                        Just (Aeson.Array inner2) -> do
                          V.length inner2 `shouldBe` 1
                          inner2 V.!? 0 `shouldBe` Just (Aeson.String "qux")
                        _ -> expectationFailure "Second element should be array with 'qux'"
                    _ -> expectationFailure "nested_array claim not found or not an array"
                Left err -> expectationFailure $ "Verification failed: " ++ show err
        Left err -> expectationFailure $ "Failed to create SD-JWT: " ++ show err

  -- NOTE: Tests below use markSelectivelyDisclosable/markArrayElementDisclosable which are now internal-only.
  -- These tests need to be rewritten to use createSDJWT with JSON Pointer paths.
  -- describe "array_recursive_sd" $ do
  --   it "should return empty arrays when no disclosures are selected" $ do
  --     -- NOTE: This test uses markSelectivelyDisclosable/markArrayElementDisclosable which are now internal-only.
  --     -- It needs to be rewritten to use createSDJWT with JSON Pointer paths.
  --     pending "Test needs to be rewritten to use JSON Pointer paths"
  -- )

  -- NOTE: Tests below use markSelectivelyDisclosable which is now internal-only.
  -- These tests need to be rewritten to use createSDJWT with JSON Pointer paths.
  -- describe "array_none_disclosed" $ do
  --   it "should return empty object when no sub-claims are disclosed" $ do
  --     -- Test case: is_over has all selectively disclosable sub-claims
  --     -- holder_disclosed_claims: is_over: {"21": False} (none are True)
  --     -- Expected: is_over: {}
  --     -- Current Behavior: Missing is_over claim entirely
  --     
  --     -- NOTE: This test uses markSelectivelyDisclosable which is now internal-only.
  --     -- It needs to be rewritten to use createSDJWT with JSON Pointer paths.
  --     pending "Test needs to be rewritten to use JSON Pointer paths"
  --     -- subClaim13Result <- markSelectivelyDisclosable SHA256 "13" (Aeson.Bool False)
  --     -- subClaim18Result <- markSelectivelyDisclosable SHA256 "18" (Aeson.Bool True)
  --     -- subClaim21Result <- markSelectivelyDisclosable SHA256 "21" (Aeson.Bool False)
  --     
  --     -- case (subClaim13Result, subClaim18Result, subClaim21Result) of
  --       (Right (digest13, _disclosure13), Right (digest18, _disclosure18), Right (digest21, _disclosure21)) -> do
  --         -- Step 2: Create object with _sd array (all sub-claims are selectively disclosable)
  --         let jwtPayload = Aeson.object
  --               [  (Key.fromText "_sd_alg", Aeson.String "sha-256")
  --               ,  (Key.fromText "is_over", Aeson.Object $ KeyMap.fromList
  --                   [  (Key.fromText "_sd_alg", Aeson.String "sha-256")
  --                   ,  (Key.fromText "_sd", Aeson.Array $ V.fromList
  --                       [ Aeson.String (unDigest digest13)
  --                       , Aeson.String (unDigest digest18)
  --                       , Aeson.String (unDigest digest21)
  --                       ])
  --                   ])
  --               ]
  --         
  --         -- Encode JWT payload
  --         let jwtPayloadBS = BSL.toStrict $ Aeson.encode jwtPayload
  --         let encodedPayload = base64urlEncode jwtPayloadBS
  --         let mockJWT = T.concat ["eyJhbGciOiJSUzI1NiJ9.", encodedPayload, ".signature"]
  --         
  --         -- Step 3: Create presentation with NO disclosures (none selected)
  --         let presentation = SDJWTPresentation mockJWT [] Nothing
  --         
  --         -- Step 4: Verify
  --         result <- verifySDJWTWithoutSignature presentation
  --         case result of
  --           Right processed -> do
  --             let claims = processedClaims processed
  --             -- Expected: is_over: {}
  --             -- Current bug: is_over missing entirely
  --             case KeyMap.lookup (Key.fromText "is_over") claims of
  --               Just (Aeson.Object obj) ->
  --                 KeyMap.size obj `shouldBe` 0
  --               _ -> expectationFailure "is_over should be present as empty object {}"
  --           Left err -> expectationFailure $ "Verification failed: " ++ show err
  --       _ -> expectationFailure "Failed to create sub-claim disclosures"
  -- )

  describe "array_of_nulls" $ do
    it "should remove undisclosed selectively disclosable null values" $ do
      -- Test case: null_values: [null, !sd null, !sd null, null]
      -- holder_disclosed_claims: {} (no disclosures selected)
      -- Expected: null_values: [null, null] (only non-selectively-disclosable nulls remain)
      -- Current Behavior: Getting all 4 nulls
      
      -- Create claims with array containing null values
      -- Indices 1 and 2 should be selectively disclosable
      let claims = KeyMap.fromList

            [  (Key.fromText "null_values", Aeson.Array $ V.fromList
                [ Aeson.Null  -- Index 0: Non-selectively disclosable
                , Aeson.Null  -- Index 1: Selectively disclosable
                , Aeson.Null  -- Index 2: Selectively disclosable
                , Aeson.Null  -- Index 3: Non-selectively disclosable
                ])
            ]
      
      -- Use buildSDJWTPayload with JSON Pointer to mark indices 1 and 2
      result <- buildSDJWTPayload SHA256 ["null_values/1", "null_values/2"] claims
      case result of
        Left err -> expectationFailure $ "Failed to build SD-JWT payload: " ++ show err
        Right (payload, _disclosures) -> do
          -- Create JWT from payload
          let payloadBS = BSL.toStrict $ Aeson.encode (payloadValue payload)
          let encodedPayload = base64urlEncode payloadBS
          let mockJWT = T.concat ["eyJhbGciOiJSUzI1NiJ9.", encodedPayload, ".signature"]
          
          -- Create presentation with NO disclosures (no disclosures selected)
          let presentation = SDJWTPresentation mockJWT [] Nothing
          
          -- Step 4: Verify
          result <- verifySDJWTWithoutSignature presentation
          case result of
            Right processed -> do
              let claims = processedClaims processed
              case KeyMap.lookup (Key.fromText "null_values") claims of
                Just (Aeson.Array arr) -> do
                  -- Expected: [null, null] (only non-selectively-disclosable nulls)
                  -- Current bug: [null, null, null, null] (all nulls)
                  V.length arr `shouldBe` 2
                  arr V.!? 0 `shouldBe` Just Aeson.Null
                  arr V.!? 1 `shouldBe` Just Aeson.Null
                _ -> expectationFailure "null_values claim not found or not an array"
            Left err -> expectationFailure $ "Verification failed: " ++ show err
        _ -> expectationFailure "Failed to create null disclosures"

  describe "array_full_sd" $ do
    it "should only include selected sub-claims in object" $ do
      -- Test case: is_over has all selectively disclosable sub-claims
      -- holder_disclosed_claims: is_over: {"21": False, "18": True, "13": False}
      -- Expected: is_over: {"18": False}
      -- Current Behavior: Getting {"13": True, "18": False, "21": False}
      
      -- Create claims with object containing sub-claims
      let claims = KeyMap.fromList

            [  (Key.fromText "is_over", Aeson.Object $ KeyMap.fromList
                [  (Key.fromText "13", Aeson.Bool True)
                ,  (Key.fromText "18", Aeson.Bool False)
                ,  (Key.fromText "21", Aeson.Bool False)
                ])
            ]
      
      -- Use buildSDJWTPayload with JSON Pointer paths to mark sub-claims as selectively disclosable
      result <- buildSDJWTPayload SHA256 ["is_over/13", "is_over/18", "is_over/21"] claims
      case result of
        Left err -> expectationFailure $ "Failed to build SD-JWT payload: " ++ show err
        Right (payload, allDisclosures) -> do
          -- Create JWT from payload
          let payloadBS = BSL.toStrict $ Aeson.encode (payloadValue payload)
          let encodedPayload = base64urlEncode payloadBS
          let mockJWT = T.concat ["eyJhbGciOiJSUzI1NiJ9.", encodedPayload, ".signature"]
          
          -- Create SDJWT with all disclosures
          let sdjwt = SDJWT mockJWT allDisclosures
          
          -- Select disclosures - only "18" should be selected (holder_disclosed_claims: {"18": True})
          -- The bug is that selectDisclosuresByNames might include all sub-claims
          case selectDisclosuresByNames sdjwt ["is_over/18"] of
            Left err -> expectationFailure $ "Failed to select disclosures: " ++ show err
            Right presentation -> do
              -- Verify
              result <- verifySDJWTWithoutSignature presentation
              case result of
                Right processed -> do
                  let claims = processedClaims processed
                  case KeyMap.lookup (Key.fromText "is_over") claims of
                    Just (Aeson.Object obj) -> do
                      -- Expected: {"18": False} (only "18" is selected)
                      -- Current bug: {"13": True, "18": False, "21": False} (all included)
                      KeyMap.size obj `shouldBe` 1
                      KeyMap.lookup (Key.fromText "18") obj `shouldBe` Just (Aeson.Bool False)
                      -- "13" and "21" should not be present
                      KeyMap.lookup (Key.fromText "13") obj `shouldBe` Nothing
                      KeyMap.lookup (Key.fromText "21") obj `shouldBe` Nothing
                    _ -> expectationFailure "is_over should be an object"
                Left err -> expectationFailure $ "Verification failed: " ++ show err

  describe "recursions" $ do
    it "should handle complex nested structures with multiple levels" $ do
      -- Test case: Multiple levels of nested selective disclosure
      -- user_claims:
      --   foo: [!sd "one", !sd "two"]
      --   bar: {!sd "red": 1, !sd "green": 2}
      --   qux: [!sd [!sd "blue", !sd "yellow"]]
      --   baz: [!sd [!sd "orange", !sd "purple"], !sd [!sd "black"]]
      --
      -- This tests comprehensive recursive processing:
      -- 1. Array element disclosures
      -- 2. Nested object disclosures
      -- 3. Nested array disclosures (arrays within arrays)
      -- 4. Multiple levels of recursion
      
      -- Create claims with complex nested structures
      -- foo: [!sd "one", !sd "two"]
      -- bar: {!sd "red": 1, !sd "green": 2}
      -- qux: [!sd [!sd "blue", !sd "yellow"]]
      -- baz: [!sd [!sd "orange", !sd "purple"], !sd [!sd "black"]]
      let claims = KeyMap.fromList

            [  (Key.fromText "foo", Aeson.Array $ V.fromList [Aeson.String "one", Aeson.String "two"])
            ,  (Key.fromText "bar", Aeson.Object $ KeyMap.fromList
                [  (Key.fromText "red", Aeson.Number 1)
                ,  (Key.fromText "green", Aeson.Number 2)
                ])
            ,  (Key.fromText "qux", Aeson.Array $ V.fromList
                [ Aeson.Array $ V.fromList [Aeson.String "blue", Aeson.String "yellow"]
                ])
            ,  (Key.fromText "baz", Aeson.Array $ V.fromList
                [ Aeson.Array $ V.fromList [Aeson.String "orange", Aeson.String "purple"]
                , Aeson.Array $ V.fromList [Aeson.String "black"]
                ])
            ]
      
      -- Use buildSDJWTPayload with JSON Pointer paths for all nested structures
      result <- buildSDJWTPayload SHA256
        [ "foo/0", "foo/1"  -- Array elements
        , "bar/red", "bar/green"  -- Object sub-claims
        , "qux/0/0", "qux/0/1"  -- Nested array elements
        , "baz/0/0", "baz/0/1", "baz/1/0"  -- Nested array elements
        ] claims
      case result of
        Left err -> expectationFailure $ "Failed to build SD-JWT payload: " ++ show err
        Right (payload, allDisclosures) -> do
          -- Create JWT from payload
          let payloadBS = BSL.toStrict $ Aeson.encode (payloadValue payload)
          let encodedPayload = base64urlEncode payloadBS
          let mockJWT = T.concat ["eyJhbGciOiJSUzI1NiJ9.", encodedPayload, ".signature"]
          
          -- Create SDJWT with all disclosures
          let sdjwt = SDJWT mockJWT allDisclosures
          
          -- Select disclosures for all claims to test comprehensive recursive processing
          -- For bar (structured SD-JWT Section 6.2), selecting "bar" should include all sub-claims
          -- But to be safe, let's explicitly select bar's sub-claims
          case selectDisclosuresByNames sdjwt ["foo", "bar/red", "bar/green", "qux", "baz"] of
            Left err -> expectationFailure $ "Failed to select disclosures: " ++ show err
            Right presentation -> do
              -- Verify
              result <- verifySDJWTWithoutSignature presentation
              case result of
                Left err -> expectationFailure $ "Verification failed: " ++ show err
                Right processed -> do
                  let claims = processedClaims processed
                  
                  -- Verify foo: should have both elements
                  case KeyMap.lookup (Key.fromText "foo") claims of
                    Just (Aeson.Array fooArr) -> do
                      V.length fooArr `shouldBe` 2
                      fooArr V.!? 0 `shouldBe` Just (Aeson.String "one")
                      fooArr V.!? 1 `shouldBe` Just (Aeson.String "two")
                    _ -> expectationFailure "foo should be an array with 2 elements"
                  
                  -- Verify bar: should have both sub-claims
                  case KeyMap.lookup (Key.fromText "bar") claims of
                    Just (Aeson.Object barObj) -> do
                      KeyMap.size barObj `shouldBe` 2
                      KeyMap.lookup (Key.fromText "red") barObj `shouldBe` Just (Aeson.Number 1)
                      KeyMap.lookup (Key.fromText "green") barObj `shouldBe` Just (Aeson.Number 2)
                    _ -> expectationFailure "bar should be an object with 2 sub-claims"
                  
                  -- Verify qux: should have nested array with both elements
                  case KeyMap.lookup (Key.fromText "qux") claims of
                    Just (Aeson.Array quxArr) -> do
                      V.length quxArr `shouldBe` 1
                      case quxArr V.!? 0 of
                        Just (Aeson.Array quxInnerArr) -> do
                          V.length quxInnerArr `shouldBe` 2
                          quxInnerArr V.!? 0 `shouldBe` Just (Aeson.String "blue")
                          quxInnerArr V.!? 1 `shouldBe` Just (Aeson.String "yellow")
                        _ -> expectationFailure "qux[0] should be an array with 2 elements"
                    _ -> expectationFailure "qux should be an array with 1 element"
                  
                  -- Verify baz: should have nested arrays
                  case KeyMap.lookup (Key.fromText "baz") claims of
                    Just (Aeson.Array bazArr) -> do
                      V.length bazArr `shouldBe` 2
                      -- First nested array
                      case bazArr V.!? 0 of
                        Just (Aeson.Array bazInner1) -> do
                          V.length bazInner1 `shouldBe` 2
                          bazInner1 V.!? 0 `shouldBe` Just (Aeson.String "orange")
                          bazInner1 V.!? 1 `shouldBe` Just (Aeson.String "purple")
                        _ -> expectationFailure "baz[0] should be an array with 2 elements"
                      -- Second nested array
                      case bazArr V.!? 1 of
                        Just (Aeson.Array bazInner2) -> do
                          V.length bazInner2 `shouldBe` 1
                          bazInner2 V.!? 0 `shouldBe` Just (Aeson.String "black")
                        _ -> expectationFailure "baz[1] should be an array with 1 element"
                    _ -> expectationFailure "baz should be an array with 2 elements"
