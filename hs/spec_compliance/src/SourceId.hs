{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TemplateHaskell #-}

-- |
-- This module exports a source id in a way that works well within a nix build (no
-- .git available) and outside nix, according to this logic:
--
--  * If `git` works, use `git describe`
--  * Else, if $out is set (so this is a nix build), extract an identifier from the out hash
--  * Else, it says something like unidentified build.
--
-- This is an early experiment. If successful, this logic ought to move into a
-- library, and maybe also implemented for rust artifacts. (see RPL-101)
--
-- Note that cabal build will not recompile this module if it does not have to, so in local development, this is less reliable than it should. See
-- https://www.joachim-breitner.de/blog/772-Template_Haskell_recompilation
-- for more details.
module SourceId where

import Control.Exception
import Control.Monad
import Data.List
import Data.List.Split
import Language.Haskell.TH
import System.Environment
import System.Process

id :: String
id =
  $( stringE <=< runIO $ do
       -- Leniently calls git, and removes final newline from git’s output
       let readGit args =
             intercalate "\n" . lines
               <$> catch
                 (readCreateProcess ((proc "git" args) {std_err = CreatePipe}) "")
                 (\(_ :: IOException) -> return "")

       inGit <- readGit ["rev-parse", "--is-inside-work-tree"]
       if inGit == "true"
         then readGit ["describe", "--tags", "--match=v*", "--dirty"]
         else
           lookupEnv "out" >>= \case
             Just path
               | ["", "nix", "store", base] <- splitOn "/" path,
                 let hash = takeWhile (/= '-') base ->
                   return $ intercalate "-" (chunksOf 8 hash)
             Just path -> fail $ "SourceId: unparsable $out=" ++ path
             Nothing -> return "unidentified"
   )
