{-# LANGUAGE OverloadedStrings #-}
module Main (main) where

import Test.Hspec
import UtilsSpec
import DigestSpec
import DisclosureSpec
import SerializationSpec
import IssuanceSpec
import PresentationSpec
import VerificationSpec
import KeyBindingSpec
import JWTSpec
import RFCSpec
import PropertySpec

main :: IO ()
main = hspec $ do
  UtilsSpec.spec
  DigestSpec.spec
  DisclosureSpec.spec
  SerializationSpec.spec
  IssuanceSpec.spec
  PresentationSpec.spec
  VerificationSpec.spec
  KeyBindingSpec.spec
  JWTSpec.spec
  RFCSpec.spec
  PropertySpec.spec
