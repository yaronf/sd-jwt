-- | SD-JWT: Selective Disclosure for JSON Web Tokens (RFC 9901)
--
-- This module re-exports the persona-specific modules for convenient access.
-- Most users should import the specific persona module they need instead.
--
-- == Recommended Usage
--
-- Import the persona-specific module for your role:
--
-- @
-- import SDJWT.Issuer   -- For creating and issuing SD-JWTs
-- import SDJWT.Holder   -- For receiving SD-JWTs and creating presentations
-- import SDJWT.Verifier -- For verifying SD-JWT presentations
-- @
--
-- == Advanced Usage
--
-- For library developers or advanced users who need low-level access,
-- import specific Internal modules as needed:
--
-- @
-- import SDJWT.Internal.Types
-- import SDJWT.Internal.Serialization
-- import SDJWT.Internal.Issuance
-- -- etc.
-- @
--
module SDJWT
  ( module SDJWT.Issuer
  , module SDJWT.Holder
  , module SDJWT.Verifier
  ) where

import SDJWT.Issuer
import SDJWT.Holder
import SDJWT.Verifier
