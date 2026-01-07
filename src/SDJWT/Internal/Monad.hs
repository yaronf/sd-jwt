{-# LANGUAGE OverloadedStrings #-}
-- | Monad utilities for SD-JWT operations.
--
-- This module provides ExceptT-based utilities for cleaner error handling
-- in IO contexts.
module SDJWT.Internal.Monad
  ( SDJWTIO
  , runSDJWTIO
  , eitherToExceptT
  , partitionAndHandle
  ) where

import SDJWT.Internal.Types (SDJWTError)
import Control.Monad.Except (ExceptT, runExceptT, throwError)
import Control.Monad.IO.Class (MonadIO, liftIO)
import Data.Either (partitionEithers)

-- | Type alias for IO operations that can fail with SDJWTError.
type SDJWTIO = ExceptT SDJWTError IO

-- | Run an SDJWTIO computation.
runSDJWTIO :: SDJWTIO a -> IO (Either SDJWTError a)
runSDJWTIO = runExceptT

-- | Convert an Either to ExceptT.
eitherToExceptT :: Monad m => Either SDJWTError a -> ExceptT SDJWTError m a
eitherToExceptT = either throwError return

-- | Handle partitionEithers results in ExceptT context.
handlePartitionEithers
  :: Monad m
  => [SDJWTError]  -- ^ Errors from partitionEithers
  -> [a]  -- ^ Successes from partitionEithers
  -> ([a] -> ExceptT SDJWTError m b)  -- ^ Success handler
  -> ExceptT SDJWTError m b
handlePartitionEithers errors successes handler =
  case errors of
    (err:_) -> throwError err
    [] -> handler successes

-- | Helper to partition Either results and handle in ExceptT context.
partitionAndHandle
  :: Monad m
  => [Either SDJWTError a]  -- ^ List of Either results
  -> ([a] -> ExceptT SDJWTError m b)  -- ^ Success handler
  -> ExceptT SDJWTError m b
partitionAndHandle results handler =
  let (errors, successes) = partitionEithers results
  in handlePartitionEithers errors successes handler

