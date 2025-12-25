{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
-- | Shared test helpers and QuickCheck Arbitrary instances.
module TestHelpers
  ( decodeDisclosures
  , isLeft
  ) where

import SDJWT.Internal.Types
import SDJWT.Internal.Disclosure
import Data.Maybe (mapMaybe)

-- | Decode a list of encoded disclosures, filtering out any that fail to decode.
-- This is a common pattern in tests where we want to decode disclosures and work with them.
decodeDisclosures :: [EncodedDisclosure] -> [Disclosure]
decodeDisclosures = mapMaybe (\enc -> case decodeDisclosure enc of
  Right dec -> Just dec
  Left _ -> Nothing
  )

-- | Check if an Either value is Left.
isLeft :: Either a b -> Bool
isLeft (Left _) = True
isLeft _ = False
