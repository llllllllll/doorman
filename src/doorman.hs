-----------------------------------------------------------------------------
-- |
-- Module      :  doorman
-- Copyright   :  Joe Jevnik 28.9.2013
-- License     :  GPL v2
--
-- Maintainer  :  Joe Jevnik
-- Stability   :  experimental
-- Portability :  requires xclip
--
-- Password manager.
--
-----------------------------------------------------------------------------

import Control.Applicative ((<$>))
import Control.Monad (when)
import Data.Char
import Data.Digest.Pure.MD5 (md5)
import Data.List (find)
import qualified Data.ByteString.Lazy.Char8 as B (ByteString,pack)
import System.Directory (getHomeDirectory,removeFile)
import System.Environment (getArgs)
import System.IO (hFlush,hSetEcho,stdin,stdout)
import System.Process (system)
import System.Posix.User (setEffectiveUserID)


-- --------------------------------------------------------------------------
-- PassPair type

-- |The type for a lookup key / password pair.
type PassPair = (String,B.ByteString)

-- --------------------------------------------------------------------------
-- files

-- |Password library that stores passwords to be processed to return the final
-- returnable password.
pass_lib :: FilePath
pass_lib = "/usr/share/doorman/pass_lib"

-- |The file holding the hash of the master password."
hash_fl :: FilePath
hash_fl = "/usr/share/doorman/master"

-- |The hash of the master password.
io_master_hash :: IO String
io_master_hash = readFile hash_fl




-- --------------------------------------------------------------------------
-- Main / test cases.
main :: IO ()
main = parse_args =<< getArgs

parse_args :: [String] -> IO ()
parse_args args
    | null args = error "Usage: [OPTION] [PARAMS]"
    | head args == "-r" = recall_params (length args) args
    | head args == "-s" = set_params (length args) args
    | head args == "-m" = master_params (length args) args
    | head args == "-i" = init_params (length args) args
    | head args == "-h" || head args == "--help" = help_msg
    | otherwise = error "invalid command"

-- --------------------------------------------------------------------------
-- File reading and parsing

-- |Parses a string for PassPairs. This function expects a valid String
-- that contains parse_pairs printed in the format of the pass_lib file.
parse_pairs :: String -> [PassPair]
parse_pairs str = map (\l -> ( takeWhile (/= ':') l
                             , B.pack (tail (dropWhile (/= ':') l))
                             )) $ lines str

get_pair :: String -> [PassPair] -> Maybe PassPair
get_pair name ps = find (\p -> fst p == name) ps

get_seed :: PassPair -> String
get_seed = show . snd

-- |Compares the hash of the input password to the saved hash of the master
-- password.

valid_pass :: String -> String -> Bool
valid_pass pre_hash post_hash = show (md5 (B.pack pre_hash)) == post_hash

-- |Makes an end password from a master password and a seed.
mk_pass :: String -> String -> String
mk_pass master seed = let p1 = show $ md5 (B.pack (master ++ seed))
                      in filter (`notElem` "\"'`")
                             $ scanl1 (\x y -> chr
                                       $ ((ord x * ord y) `rem` 93) + 33) p1


-- --------------------------------------------------------------------------
-- Functions that will be called from parse_args directly
-- These function check for the proper params to then pass on the their
-- respective functions.

recall_params ::Int -> [String] -> IO ()
recall_params ln args
    | ln == 1 = do
        putStr "Password Name: "
        hFlush stdout
        name <- getLine
        putStr "Master Password: "
        hFlush stdout
        hSetEcho stdin False
        pass <- getLine
        hSetEcho stdin True
        putStrLn ""
        recall_pass  (reverse $ pass:name:args)
    | ln == 2 = do
        putStr "Master Password: "
        hFlush stdout
        hSetEcho stdin False
        pass <- getLine
        hSetEcho stdin True
        putStrLn ""
        recall_pass  (args ++ [pass])
    | otherwise = recall_pass  args

set_params :: Int -> [String] -> IO ()
set_params ln args
    | ln == 1 = do
        putStr "Password Name: "
        hFlush stdout
        name <- getLine
        putStr "Seed: "
        seed <- getLine
        putStr "Master Password: "
        hFlush stdout
        hSetEcho stdin False
        pass <- getLine
        hSetEcho stdin True
        putStrLn ""
        set_pass (reverse $ pass:seed:name:args)
    | ln == 2 = do
        putStr "Seed: "
        hFlush stdout
        seed <- getLine
        putStr "Master Password: "
        hFlush stdout
        hSetEcho stdin False
        pass <- getLine
        hSetEcho stdin True
        putStrLn ""
        set_pass (args ++ [seed,pass])
    | ln == 3 = do
        putStr "Master Password: "
        hFlush stdout
        hSetEcho stdin False
        pass <- getLine
        hSetEcho stdin True
        putStrLn ""
        set_pass (args ++ [pass])
    | otherwise = set_pass args


master_params :: Int -> [String] -> IO ()
master_params ln args
    | ln == 1 = do
        putStr "New Master: "
        hFlush stdout
        hSetEcho stdin False
        new <- getLine
        putStr "Master Password: "
        pass <- getLine
        hSetEcho stdin True
        set_master (reverse $ pass:new:args)
    | ln == 2 = do
        putStr "Master Password: "
        hFlush stdout
        hSetEcho stdin False
        pass <- getLine
        hSetEcho stdin True
        set_master (args ++ [pass])
    | otherwise = set_master args

init_params :: Int -> [String] -> IO ()
init_params ln args
    | ln == 1 = do
        putStr "New Master: "
        hFlush stdout
        hSetEcho stdin False
        new <- getLine
        hSetEcho stdin True
        init_master (reverse $ new:args)
    | otherwise = init_master args


-- |Prints the help dialogue.
help_msg :: IO ()
help_msg = putStrLn $ "Commands:\n"
           ++ "  -r [NAME] [MASTER] - recalls the password of NAME.\n"
           ++ "  -s [NAME] [SEED] [MASTER] - changes the seed for NAME.\n"
           ++ "  -m [NEWMASTER] [OLDMASTER] - changes the master password.\n"
           ++ "  -i [INPUT] - hashes INPUT, used when making a first master.\n"
           ++ "  -h - prints this message."

-- --------------------------------------------------------------------------
-- Functions that will be called after *_params has checked that it is safe

-- |Pushes the password requested to the clipboard
recall_pass :: [String] -> IO ()
recall_pass args = do
    master_hash <- io_master_hash
    fl          <- readFile pass_lib
    let pass = args!!2
    when (not $ valid_pass pass master_hash) $ error "Incorrect password"
    case get_pair (args!!1) (parse_pairs fl) of
        Nothing -> error "No password set for that name"
        Just p  -> (system $ "echo \"" ++ mk_pass pass (get_seed p)
                    ++ "\" | xclip -selection c") >> return ()

-- |Sets a password seed for a name.
set_pass :: [String] -> IO ()
set_pass args = do
    master_hash <- io_master_hash
    fl          <- unlines . (filter (\l -> takeWhile (/= ':') l /= args!!1)) .
                    lines <$> readFile pass_lib
    let pass = args!!3
    when (not $ valid_pass pass master_hash) $ error "Incorrect password"
    removeFile pass_lib
    appendFile pass_lib (fl ++ args!!1 ++ ":" ++ args !!2)

-- |Allows the user to change their master password.
set_master :: [String] -> IO ()
set_master args = do
    hash_file   <- io_master_hash
    master_hash <- io_master_hash >>= readFile
    let pass = args!!2
    when (not $ valid_pass pass master_hash) $ error "Incorrect password"
    removeFile hash_fl
    appendFile hash_fl (show $ md5 (B.pack pass))

-- |Allows the user to set a first master password.
init_master :: [String] -> IO ()
init_master args = let pass = args!!1
                   in putStrLn (show $ md5 (B.pack pass))
