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
import SDJWT.Internal.Issuance (markArrayElementDisclosable, markSelectivelyDisclosable, buildSDJWTPayload)
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
      
      -- Step 1: Create disclosures for inner array elements
      inner1FooResult <- markArrayElementDisclosable SHA256 (Aeson.String "foo")
      inner1BarResult <- markArrayElementDisclosable SHA256 (Aeson.String "bar")
      case (inner1FooResult, inner1BarResult) of
        (Right (fooDigest1, fooDisclosure1), Right (barDigest1, _barDisclosure1)) -> do
          inner2BazResult <- markArrayElementDisclosable SHA256 (Aeson.String "baz")
          inner2QuxResult <- markArrayElementDisclosable SHA256 (Aeson.String "qux")
          case (inner2BazResult, inner2QuxResult) of
            (Right (_bazDigest2, _bazDisclosure2), Right (quxDigest2, quxDisclosure2)) -> do
              -- Step 2: Create outer array element disclosures
              let innerArray1 = Aeson.Array $ V.fromList
                    [ Aeson.Object $ KeyMap.fromList [(Key.fromText "...", Aeson.String (unDigest fooDigest1))]
                    , Aeson.Object $ KeyMap.fromList [(Key.fromText "...", Aeson.String (unDigest barDigest1))]
                    ]
              outer1Result <- markArrayElementDisclosable SHA256 innerArray1
              case outer1Result of
                Right (outer1Digest, outer1Disclosure) -> do
                  let bazDigest2 = case inner2BazResult of Right (d, _) -> d; _ -> error "unreachable"
                  let innerArray2 = Aeson.Array $ V.fromList
                        [ Aeson.Object $ KeyMap.fromList [(Key.fromText "...", Aeson.String (unDigest bazDigest2))]
                        , Aeson.Object $ KeyMap.fromList [(Key.fromText "...", Aeson.String (unDigest quxDigest2))]
                        ]
                  outer2Result <- markArrayElementDisclosable SHA256 innerArray2
                  case outer2Result of
                    Right (outer2Digest, outer2Disclosure) -> do
                      -- Step 3: Create JWT payload with outer array containing ellipsis objects
                      let jwtPayload = Aeson.object
                            [ ("_sd_alg", Aeson.String "sha-256")
                            , ("nested_array", Aeson.Array $ V.fromList
                                [ Aeson.Object $ KeyMap.fromList [(Key.fromText "...", Aeson.String (unDigest outer1Digest))]
                                , Aeson.Object $ KeyMap.fromList [(Key.fromText "...", Aeson.String (unDigest outer2Digest))]
                                ])
                            ]
                      
                      -- Encode JWT payload
                      let jwtPayloadBS = BSL.toStrict $ Aeson.encode jwtPayload
                      let encodedPayload = base64urlEncode jwtPayloadBS
                      let mockJWT = T.concat ["eyJhbGciOiJSUzI1NiJ9.", encodedPayload, ".signature"]
                      
                      -- Step 4: Create SDJWT with ALL disclosures
                      let allDisclosures = [outer1Disclosure, outer2Disclosure, fooDisclosure1, quxDisclosure2]
                      let sdjwt = SDJWT mockJWT allDisclosures
                      
                      -- Step 5: Select disclosures using selectDisclosuresByNames
                      -- This simulates what the interop test runner does
                      -- The bug is that this doesn't correctly select nested array element disclosures
                      case selectDisclosuresByNames sdjwt ["nested_array"] of
                        Left err -> expectationFailure $ "Failed to select disclosures: " ++ show err
                        Right presentation -> do
                          -- Step 6: Verify
                          result <- verifySDJWTWithoutSignature presentation
                          case result of
                            Right processed -> do
                              let claims = processedClaims processed
                              case Map.lookup "nested_array" claims of
                                Just (Aeson.Array arr) -> do
                                  -- Expected: [["foo"], ["qux"]]
                                  -- Current bug: [] (empty array)
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
                    Left err -> expectationFailure $ "Failed to create outer array element 2 disclosure: " ++ show err
                Left err -> expectationFailure $ "Failed to create outer array element 1 disclosure: " ++ show err
            _ -> expectationFailure "Failed to create inner array 2 disclosures"
        _ -> expectationFailure "Failed to create inner array 1 disclosures"

  describe "array_recursive_sd" $ do
    it "should return empty arrays when no disclosures are selected" $ do
      -- Test case: array_with_recursive_sd has selectively disclosable elements
      -- holder_disclosed_claims: {} (empty - no disclosures selected)
      -- Expected: array_with_recursive_sd: ["boring", []], test2: []
      -- Current Behavior: Getting arrays with ellipsis objects still present
      
      -- Step 1: Create disclosures for selectively disclosable elements
      nestedFooResult <- markSelectivelyDisclosable SHA256 "foo" (Aeson.String "bar")
      nestedBazResult <- markSelectivelyDisclosable SHA256 "baz" (Aeson.Object $ KeyMap.fromList [("qux", Aeson.String "quux")])
      case (nestedFooResult, nestedBazResult) of
        (Right (fooDigest, _fooDisclosure), Right (bazDigest, _bazDisclosure)) -> do
          -- Create object with _sd array
          let nestedObject = Aeson.object
                [ ("_sd_alg", Aeson.String "sha-256")
                , ("_sd", Aeson.Array $ V.fromList
                    [ Aeson.String (unDigest fooDigest)
                    , Aeson.String (unDigest bazDigest)
                    ])
                ]
          
          arrayElement1Result <- markArrayElementDisclosable SHA256 nestedObject
          case arrayElement1Result of
            Right (arrayDigest1, _arrayDisclosure1) -> do
              -- Element 2: array with selectively disclosable elements
              arrayEl2FooResult <- markArrayElementDisclosable SHA256 (Aeson.String "foo")
              arrayEl2BarResult <- markArrayElementDisclosable SHA256 (Aeson.String "bar")
              case (arrayEl2FooResult, arrayEl2BarResult) of
                (Right (fooDigest2, _fooDisclosure2), Right (barDigest2, _barDisclosure2)) -> do
                  let innerArray = Aeson.Array $ V.fromList
                        [ Aeson.Object $ KeyMap.fromList [(Key.fromText "...", Aeson.String (unDigest fooDigest2))]
                        , Aeson.Object $ KeyMap.fromList [(Key.fromText "...", Aeson.String (unDigest barDigest2))]
                        ]
                  arrayElement2Result <- markArrayElementDisclosable SHA256 innerArray
                  case arrayElement2Result of
                    Right (arrayDigest2, _arrayDisclosure2) -> do
                      -- test2: array with selectively disclosable elements
                      test2FooResult <- markArrayElementDisclosable SHA256 (Aeson.String "foo")
                      test2BarResult <- markArrayElementDisclosable SHA256 (Aeson.String "bar")
                      case (test2FooResult, test2BarResult) of
                        (Right (test2FooDigest, _test2FooDisclosure), Right (test2BarDigest, _test2BarDisclosure)) -> do
                          -- Create JWT payloads
                          let jwtPayload1 = Aeson.object
                                [ ("_sd_alg", Aeson.String "sha-256")
                                , ("array_with_recursive_sd", Aeson.Array $ V.fromList
                                    [ Aeson.String "boring"  -- Non-selectively disclosable
                                    , Aeson.Object $ KeyMap.fromList [(Key.fromText "...", Aeson.String (unDigest arrayDigest1))]
                                    , Aeson.Object $ KeyMap.fromList [(Key.fromText "...", Aeson.String (unDigest arrayDigest2))]
                                    ])
                                ]
                          
                          let jwtPayload2 = Aeson.object
                                [ ("_sd_alg", Aeson.String "sha-256")
                                , ("test2", Aeson.Array $ V.fromList
                                    [ Aeson.Object $ KeyMap.fromList [(Key.fromText "...", Aeson.String (unDigest test2FooDigest))]
                                    , Aeson.Object $ KeyMap.fromList [(Key.fromText "...", Aeson.String (unDigest test2BarDigest))]
                                    ])
                                ]
                          
                          -- Encode JWT payloads
                          let jwtPayloadBS1 = BSL.toStrict $ Aeson.encode jwtPayload1
                          let encodedPayload1 = base64urlEncode jwtPayloadBS1
                          let mockJWT1 = T.concat ["eyJhbGciOiJSUzI1NiJ9.", encodedPayload1, ".signature"]
                          
                          let jwtPayloadBS2 = BSL.toStrict $ Aeson.encode jwtPayload2
                          let encodedPayload2 = base64urlEncode jwtPayloadBS2
                          let mockJWT2 = T.concat ["eyJhbGciOiJSUzI1NiJ9.", encodedPayload2, ".signature"]
                          
                          -- Create presentations with NO disclosures (empty holder_disclosed_claims)
                          let presentation1 = SDJWTPresentation mockJWT1 [] Nothing
                          let presentation2 = SDJWTPresentation mockJWT2 [] Nothing
                          
                          -- Verify - should remove all ellipsis objects
                          result1 <- verifySDJWTWithoutSignature presentation1
                          result2 <- verifySDJWTWithoutSignature presentation2
                          
                          case (result1, result2) of
                            (Right processed1, Right processed2) -> do
                              let claims1 = processedClaims processed1
                              let claims2 = processedClaims processed2
                              
                              -- array_with_recursive_sd should have only "boring" (non-selectively disclosable)
                              -- Per RFC 9901 Section 7.3 Step 2.d: "Remove all array elements for which
                              -- the digest was not found in the previous step."
                              case Map.lookup "array_with_recursive_sd" claims1 of
                                Just (Aeson.Array arr1) -> do
                                  -- Expected: ["boring"] (only non-selectively-disclosable element remains)
                                  -- Undisclosed ellipsis objects should be removed per RFC 9901
                                  V.length arr1 `shouldBe` 1
                                  arr1 V.!? 0 `shouldBe` Just (Aeson.String "boring")
                                _ -> expectationFailure "array_with_recursive_sd claim not found or not an array"
                              
                              -- test2 should be empty array
                              case Map.lookup "test2" claims2 of
                                Just (Aeson.Array arr2) -> do
                                  -- Expected: []
                                  -- Current bug: ellipsis objects still present
                                  V.length arr2 `shouldBe` 0
                                _ -> expectationFailure "test2 claim not found or not an array"
                            (Left err1, _) -> expectationFailure $ "Verification 1 failed: " ++ show err1
                            (_, Left err2) -> expectationFailure $ "Verification 2 failed: " ++ show err2
                        _ -> expectationFailure "Failed to create test2 disclosures"
                    Left err -> expectationFailure $ "Failed to create array element 2 disclosure: " ++ show err
                _ -> expectationFailure "Failed to create array element 2 inner disclosures"
            Left err -> expectationFailure $ "Failed to create array element 1 disclosure: " ++ show err
        _ -> expectationFailure "Failed to create nested disclosures"

  describe "array_none_disclosed" $ do
    it "should return empty object when no sub-claims are disclosed" $ do
      -- Test case: is_over has all selectively disclosable sub-claims
      -- holder_disclosed_claims: is_over: {"21": False} (none are True)
      -- Expected: is_over: {}
      -- Current Behavior: Missing is_over claim entirely
      
      -- Step 1: Create disclosures for sub-claims
      subClaim13Result <- markSelectivelyDisclosable SHA256 "13" (Aeson.Bool False)
      subClaim18Result <- markSelectivelyDisclosable SHA256 "18" (Aeson.Bool True)
      subClaim21Result <- markSelectivelyDisclosable SHA256 "21" (Aeson.Bool False)
      
      case (subClaim13Result, subClaim18Result, subClaim21Result) of
        (Right (digest13, _disclosure13), Right (digest18, _disclosure18), Right (digest21, _disclosure21)) -> do
          -- Step 2: Create object with _sd array (all sub-claims are selectively disclosable)
          let jwtPayload = Aeson.object
                [ ("_sd_alg", Aeson.String "sha-256")
                , ("is_over", Aeson.object
                    [ ("_sd_alg", Aeson.String "sha-256")
                    , ("_sd", Aeson.Array $ V.fromList
                        [ Aeson.String (unDigest digest13)
                        , Aeson.String (unDigest digest18)
                        , Aeson.String (unDigest digest21)
                        ])
                    ])
                ]
          
          -- Encode JWT payload
          let jwtPayloadBS = BSL.toStrict $ Aeson.encode jwtPayload
          let encodedPayload = base64urlEncode jwtPayloadBS
          let mockJWT = T.concat ["eyJhbGciOiJSUzI1NiJ9.", encodedPayload, ".signature"]
          
          -- Step 3: Create presentation with NO disclosures (none selected)
          let presentation = SDJWTPresentation mockJWT [] Nothing
          
          -- Step 4: Verify
          result <- verifySDJWTWithoutSignature presentation
          case result of
            Right processed -> do
              let claims = processedClaims processed
              -- Expected: is_over: {}
              -- Current bug: is_over missing entirely
              case Map.lookup "is_over" claims of
                Just (Aeson.Object obj) ->
                  KeyMap.size obj `shouldBe` 0
                _ -> expectationFailure "is_over should be present as empty object {}"
            Left err -> expectationFailure $ "Verification failed: " ++ show err
        _ -> expectationFailure "Failed to create sub-claim disclosures"

  describe "array_of_nulls" $ do
    it "should remove undisclosed selectively disclosable null values" $ do
      -- Test case: null_values: [null, !sd null, !sd null, null]
      -- holder_disclosed_claims: {} (no disclosures selected)
      -- Expected: null_values: [null, null] (only non-selectively-disclosable nulls remain)
      -- Current Behavior: Getting all 4 nulls
      
      -- Step 1: Create disclosures for selectively disclosable null values
      nullDisclosure1Result <- markArrayElementDisclosable SHA256 Aeson.Null
      nullDisclosure2Result <- markArrayElementDisclosable SHA256 Aeson.Null
      
      case (nullDisclosure1Result, nullDisclosure2Result) of
        (Right (nullDigest1, _nullDisclosure1), Right (nullDigest2, _nullDisclosure2)) -> do
          -- Step 2: Create JWT payload with array containing:
          -- - null (non-selectively disclosable)
          -- - ellipsis object for null (selectively disclosable)
          -- - ellipsis object for null (selectively disclosable)
          -- - null (non-selectively disclosable)
          let jwtPayload = Aeson.object
                [ ("_sd_alg", Aeson.String "sha-256")
                , ("null_values", Aeson.Array $ V.fromList
                    [ Aeson.Null
                    , Aeson.Object $ KeyMap.fromList [(Key.fromText "...", Aeson.String (unDigest nullDigest1))]
                    , Aeson.Object $ KeyMap.fromList [(Key.fromText "...", Aeson.String (unDigest nullDigest2))]
                    , Aeson.Null
                    ])
                ]
          
          -- Encode JWT payload
          let jwtPayloadBS = BSL.toStrict $ Aeson.encode jwtPayload
          let encodedPayload = base64urlEncode jwtPayloadBS
          let mockJWT = T.concat ["eyJhbGciOiJSUzI1NiJ9.", encodedPayload, ".signature"]
          
          -- Step 3: Create presentation with NO disclosures (no disclosures selected)
          let presentation = SDJWTPresentation mockJWT [] Nothing
          
          -- Step 4: Verify
          result <- verifySDJWTWithoutSignature presentation
          case result of
            Right processed -> do
              let claims = processedClaims processed
              case Map.lookup "null_values" claims of
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
      
      -- Step 1: Create disclosures for sub-claims
      -- Note: The actual values in the disclosures are what matter
      subClaim13Result <- markSelectivelyDisclosable SHA256 "13" (Aeson.Bool True)
      subClaim18Result <- markSelectivelyDisclosable SHA256 "18" (Aeson.Bool False)
      subClaim21Result <- markSelectivelyDisclosable SHA256 "21" (Aeson.Bool False)
      
      case (subClaim13Result, subClaim18Result, subClaim21Result) of
        (Right (digest13, disclosure13), Right (digest18, disclosure18), Right (digest21, disclosure21)) -> do
          -- Step 2: Create object with _sd array
          let jwtPayload = Aeson.object
                [ ("_sd_alg", Aeson.String "sha-256")
                , ("is_over", Aeson.object
                    [ ("_sd_alg", Aeson.String "sha-256")
                    , ("_sd", Aeson.Array $ V.fromList
                        [ Aeson.String (unDigest digest13)
                        , Aeson.String (unDigest digest18)
                        , Aeson.String (unDigest digest21)
                        ])
                    ])
                ]
          
          -- Encode JWT payload
          let jwtPayloadBS = BSL.toStrict $ Aeson.encode jwtPayload
          let encodedPayload = base64urlEncode jwtPayloadBS
          let mockJWT = T.concat ["eyJhbGciOiJSUzI1NiJ9.", encodedPayload, ".signature"]
          
          -- Step 3: Create SDJWT with all disclosures
          let allDisclosures = [disclosure13, disclosure18, disclosure21]
          let sdjwt = SDJWT mockJWT allDisclosures
          
          -- Step 4: Select disclosures - only "18" should be selected (holder_disclosed_claims: {"18": True})
          -- The bug is that selectDisclosuresByNames might include all sub-claims
          case selectDisclosuresByNames sdjwt ["is_over/18"] of
            Left err -> expectationFailure $ "Failed to select disclosures: " ++ show err
            Right presentation -> do
              -- Step 5: Verify
              result <- verifySDJWTWithoutSignature presentation
              case result of
                Right processed -> do
                  let claims = processedClaims processed
                  case Map.lookup "is_over" claims of
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
        _ -> expectationFailure "Failed to create sub-claim disclosures"

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
      
      -- Step 1: Create disclosures for foo array elements
      fooOneResult <- markArrayElementDisclosable SHA256 (Aeson.String "one")
      fooTwoResult <- markArrayElementDisclosable SHA256 (Aeson.String "two")
      case (fooOneResult, fooTwoResult) of
        (Right (fooOneDigest, fooOneDisclosure), Right (fooTwoDigest, fooTwoDisclosure)) -> do
          -- Step 2: Create disclosures for bar object sub-claims
          barRedResult <- markSelectivelyDisclosable SHA256 "red" (Aeson.Number 1)
          barGreenResult <- markSelectivelyDisclosable SHA256 "green" (Aeson.Number 2)
          case (barRedResult, barGreenResult) of
            (Right (barRedDigest, barRedDisclosure), Right (barGreenDigest, barGreenDisclosure)) -> do
              -- Step 3: Create disclosures for qux nested array elements
              quxBlueResult <- markArrayElementDisclosable SHA256 (Aeson.String "blue")
              quxYellowResult <- markArrayElementDisclosable SHA256 (Aeson.String "yellow")
              case (quxBlueResult, quxYellowResult) of
                (Right (quxBlueDigest, quxBlueDisclosure), Right (quxYellowDigest, quxYellowDisclosure)) -> do
                  -- Create inner array with ellipsis objects
                  let quxInnerArray = Aeson.Array $ V.fromList
                        [ Aeson.Object $ KeyMap.fromList [(Key.fromText "...", Aeson.String (unDigest quxBlueDigest))]
                        , Aeson.Object $ KeyMap.fromList [(Key.fromText "...", Aeson.String (unDigest quxYellowDigest))]
                        ]
                  -- Create disclosure for outer array element (which contains the inner array)
                  quxOuterResult <- markArrayElementDisclosable SHA256 quxInnerArray
                  case quxOuterResult of
                    Right (quxOuterDigest, quxOuterDisclosure) -> do
                      -- Step 4: Create disclosures for baz nested arrays
                      bazOrangeResult <- markArrayElementDisclosable SHA256 (Aeson.String "orange")
                      bazPurpleResult <- markArrayElementDisclosable SHA256 (Aeson.String "purple")
                      case (bazOrangeResult, bazPurpleResult) of
                        (Right (bazOrangeDigest, bazOrangeDisclosure), Right (bazPurpleDigest, bazPurpleDisclosure)) -> do
                          -- Create first inner array
                          let bazInnerArray1 = Aeson.Array $ V.fromList
                                [ Aeson.Object $ KeyMap.fromList [(Key.fromText "...", Aeson.String (unDigest bazOrangeDigest))]
                                , Aeson.Object $ KeyMap.fromList [(Key.fromText "...", Aeson.String (unDigest bazPurpleDigest))]
                                ]
                          bazOuter1Result <- markArrayElementDisclosable SHA256 bazInnerArray1
                          case bazOuter1Result of
                            Right (bazOuter1Digest, bazOuter1Disclosure) -> do
                              bazBlackResult <- markArrayElementDisclosable SHA256 (Aeson.String "black")
                              case bazBlackResult of
                                Right (bazBlackDigest, bazBlackDisclosure) -> do
                                  -- Create second inner array
                                  let bazInnerArray2 = Aeson.Array $ V.fromList
                                        [ Aeson.Object $ KeyMap.fromList [(Key.fromText "...", Aeson.String (unDigest bazBlackDigest))]
                                        ]
                                  bazOuter2Result <- markArrayElementDisclosable SHA256 bazInnerArray2
                                  case bazOuter2Result of
                                    Right (bazOuter2Digest, bazOuter2Disclosure) -> do
                                      -- Step 5: Create JWT payload manually
                                      -- Create bar object with _sd array
                                      let barObject = Aeson.object
                                            [ ("_sd_alg", Aeson.String "sha-256")
                                            , ("_sd", Aeson.Array $ V.fromList
                                                [ Aeson.String (unDigest barRedDigest)
                                                , Aeson.String (unDigest barGreenDigest)
                                                ])
                                            ]
                                      
                                      -- Build JWT payload with arrays containing ellipsis objects
                                      let jwtPayload = Aeson.object
                                            [ ("_sd_alg", Aeson.String "sha-256")
                                            , ("foo", Aeson.Array $ V.fromList
                                                [ Aeson.Object $ KeyMap.fromList [(Key.fromText "...", Aeson.String (unDigest fooOneDigest))]
                                                , Aeson.Object $ KeyMap.fromList [(Key.fromText "...", Aeson.String (unDigest fooTwoDigest))]
                                                ])
                                            , ("bar", barObject)
                                            , ("qux", Aeson.Array $ V.fromList
                                                [ Aeson.Object $ KeyMap.fromList [(Key.fromText "...", Aeson.String (unDigest quxOuterDigest))]
                                                ])
                                            , ("baz", Aeson.Array $ V.fromList
                                                [ Aeson.Object $ KeyMap.fromList [(Key.fromText "...", Aeson.String (unDigest bazOuter1Digest))]
                                                , Aeson.Object $ KeyMap.fromList [(Key.fromText "...", Aeson.String (unDigest bazOuter2Digest))]
                                                ])
                                            ]
                                      
                                      -- Encode JWT payload
                                      let jwtPayloadBS = BSL.toStrict $ Aeson.encode jwtPayload
                                      let encodedPayload = base64urlEncode jwtPayloadBS
                                      let mockJWT = T.concat ["eyJhbGciOiJSUzI1NiJ9.", encodedPayload, ".signature"]
                                      
                                      -- Collect all disclosures
                                      let allDisclosures = [fooOneDisclosure, fooTwoDisclosure, barRedDisclosure, barGreenDisclosure,
                                                            quxOuterDisclosure, quxBlueDisclosure, quxYellowDisclosure,
                                                            bazOuter1Disclosure, bazOrangeDisclosure, bazPurpleDisclosure,
                                                            bazOuter2Disclosure, bazBlackDisclosure]
                                      let sdjwt = SDJWT mockJWT allDisclosures
                                      
                                      -- Step 6: Select disclosures for all claims
                                      -- Select all claims to test comprehensive recursive processing
                                      -- For bar (structured SD-JWT Section 6.2), selecting "bar" should include all sub-claims
                                      -- But to be safe, let's explicitly select bar's sub-claims
                                      case selectDisclosuresByNames sdjwt ["foo", "bar/red", "bar/green", "qux", "baz"] of
                                        Left err -> expectationFailure $ "Failed to select disclosures: " ++ show err
                                        Right presentation -> do
                                          -- Step 7: Verify
                                          result <- verifySDJWTWithoutSignature presentation
                                          case result of
                                            Left err -> expectationFailure $ "Verification failed: " ++ show err
                                            Right processed -> do
                                              let claims = processedClaims processed
                                              
                                              -- Verify foo: should have both elements
                                              case Map.lookup "foo" claims of
                                                Just (Aeson.Array fooArr) -> do
                                                  V.length fooArr `shouldBe` 2
                                                  fooArr V.!? 0 `shouldBe` Just (Aeson.String "one")
                                                  fooArr V.!? 1 `shouldBe` Just (Aeson.String "two")
                                                _ -> expectationFailure "foo should be an array with 2 elements"
                                              
                                              -- Verify bar: should have both sub-claims
                                              case Map.lookup "bar" claims of
                                                Just (Aeson.Object barObj) -> do
                                                  KeyMap.size barObj `shouldBe` 2
                                                  KeyMap.lookup (Key.fromText "red") barObj `shouldBe` Just (Aeson.Number 1)
                                                  KeyMap.lookup (Key.fromText "green") barObj `shouldBe` Just (Aeson.Number 2)
                                                _ -> expectationFailure "bar should be an object with 2 sub-claims"
                                              
                                              -- Verify qux: should have nested array with both elements
                                              case Map.lookup "qux" claims of
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
                                              case Map.lookup "baz" claims of
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
                                    Left err -> expectationFailure $ "Failed to create baz outer 2 disclosure: " ++ show err
                                Left err -> expectationFailure $ "Failed to create baz black disclosure: " ++ show err
                            Left err -> expectationFailure $ "Failed to create baz outer 1 disclosure: " ++ show err
                        _ -> expectationFailure "Failed to create baz orange/purple disclosures"
                    Left err -> expectationFailure $ "Failed to create qux outer disclosure: " ++ show err
                _ -> expectationFailure "Failed to create qux blue/yellow disclosures"
            _ -> expectationFailure "Failed to create bar red/green disclosures"
        _ -> expectationFailure "Failed to create foo one/two disclosures"
