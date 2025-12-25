{-# LANGUAGE OverloadedStrings #-}
-- | Convenience module for SD-JWT holders.
--
-- This module re-exports everything needed to receive SD-JWTs and create
-- presentations. It provides a focused API for the holder role, excluding
-- modules that holders don't need (like Issuance and Verification).
--
-- == Usage
--
-- For holders, import this module instead of the main 'SDJWT' module:
--
-- @
-- import SDJWT.Holder
-- @
--
-- This gives you access to:
--
-- * 'SDJWT.Internal.Types' - Core data types
-- * 'SDJWT.Internal.Serialization' - Deserialize SD-JWTs and serialize presentations
-- * 'SDJWT.Internal.Presentation' - Select disclosures and create presentations
-- * 'SDJWT.Internal.KeyBinding' - Add key binding to presentations (SD-JWT+KB)
--
-- == Example
--
-- >>> :set -XOverloadedStrings
-- >>> import SDJWT.Holder
-- >>> import qualified Data.Text as T
-- >>> import Data.Int (Int64)
-- >>> -- Deserialize SD-JWT received from issuer
-- >>> -- let sdjwtText = "eyJhbGciOiJSUzI1NiJ9..."
-- >>> -- case deserializeSDJWT (T.pack sdjwtText) of
-- >>> --   Right sdjwt -> selectDisclosuresByNames sdjwt ["given_name"]
-- >>> --   Left err -> Left err
-- >>> -- Optionally add key binding (SD-JWT+KB) for proof of possession
-- >>> -- holderPrivateKeyJWK <- loadPrivateKeyJWK
-- >>> -- addKeyBindingToPresentation SHA256 holderPrivateKeyJWK "verifier.example.com" "nonce123" (1234567890 :: Int64) presentation
module SDJWT.Holder
  ( module SDJWT.Internal.Types
  , module SDJWT.Internal.Serialization
  , module SDJWT.Internal.Presentation
  , module SDJWT.Internal.KeyBinding
  ) where

import SDJWT.Internal.Types
import SDJWT.Internal.Serialization
import SDJWT.Internal.Presentation
import SDJWT.Internal.KeyBinding

