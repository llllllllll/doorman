-----------------------------------------------------------------------------
-- |
-- Program     :  doorman v2.0
-- Copyright   :  Joe Jevnik 19.10.2013
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
import Control.Monad (unless,void,join)
import Data.Bits
import Data.Char
import Data.Digest.Pure.SHA
import Data.List (find,intersperse)
import Data.String.Utils (split)
import qualified Data.ByteString.Lazy.Char8 as B (ByteString,pack)
import System.Directory (getHomeDirectory,removeFile)
import System.Environment (getArgs)
import System.IO (hFlush,hSetEcho,stdin,stdout)
import System.Process (system)

-- --------------------------------------------------------------------------
-- PassPair type

-- |The type for a lookup key / password pair.
type PassPair = (String,String)

-- --------------------------------------------------------------------------
-- files

-- |Password library that stores passwords to be processed to return the final
-- returnable password.
pass_lib :: FilePath
pass_lib = "/usr/share/doorman/pass_lib"

master_fl :: FilePath
master_fl = "/usr/share/doorman/master"

-- --------------------------------------------------------------------------
-- Main / test cases.
main :: IO ()
main = parse_args =<< getArgs

parse_args :: [String] -> IO ()
parse_args as
    | null as = error "Usage: [OPTION] [PARAMS]"
    | head as == "-r" = recall_params (length as) as False
    | head as == "-p" = recall_params (length as) as True
    | head as == "-s" = set_params (length as) as
    | head as == "-m" = master_params (length as) as
    | head as == "-i" = init_params (length as) as False
    | head as == "-h" = init_params (length as) as True
    | head as == "-H" || head as == "--help" = help_msg
    | otherwise = error "invalid command"

-- --------------------------------------------------------------------------
-- File reading and parsing

-- |Parses a string for PassPairs. This function expects a valid String
-- that contains parse_pairs printed in the format of the pass_lib file.
parse_pairs :: String -> [PassPair]
parse_pairs str = bld [] $ filter (not . null) $ split ":" str
  where
      bld ps [] = ps
      bld ps (name:seed:rs) = bld ((name,seed):ps) rs


-- |Filter Print: Filters out the given PassPair and then formats the rest to be
-- output to the file.
fprint_pairs :: PassPair -> String -> String
fprint_pairs p fl = bld "" $ p:(filter (/=p) $ parse_pairs fl)
  where
      bld str [] = str
      bld str (p:ps) = bld (':':fst p ++ ':':snd p ++ str) ps


-- |Returns the pair with the given name or Nothing if it does not exits.
get_pair :: String -> [PassPair] -> Maybe PassPair
get_pair name = find (\p -> fst p == name)

get_seed :: PassPair -> String
get_seed = snd

-- |Compares the hash of the input password to the saved hash of the master
-- password.
valid_pass :: String -> String -> Bool
valid_pass pass hash = hash == (showDigest $ sha256 $ B.pack pass)

-- |Makes an end password from a master password and a seed.
mk_pass :: String -> String -> String
mk_pass master seed = let p1 = showDigest $ sha512 (B.pack (master ++ seed))
                      in filter (`notElem` "\"'`")
                             $ scanl1 (\x y -> chr
                                       $ ((ord x * ord y) `rem` 93) + 33) p1

-- |Converts the master to an int list by hashing and taking the ord of the
-- chars to be xor'd for decrytion.
strord :: String -> [Int]
strord str = cycle $ map ord $ showDigest $ sha512 $ B.pack str

-- --------------------------------------------------------------------------
-- Functions that will be called from parse_as directly
-- These function check for the proper params to then pass on the their
-- respective functions.

-- |Accumulates all parameters for '-r' and '-p'.
recall_params ::Int -> [String] -> Bool -> IO ()
recall_params ln as b
    | ln == 1 = do
        putStr "Password name: "
        hFlush stdout
        name <- getLine
        putStr "Master password: "
        hFlush stdout
        hSetEcho stdin False
        pass <- getLine
        hSetEcho stdin True
        putStrLn ""
        recall_pass (reverse $ pass:name:as) b
    | ln == 2 = do
        putStr "Master password: "
        hFlush stdout
        hSetEcho stdin False
        pass <- getLine
        hSetEcho stdin True
        putStrLn ""
        recall_pass  (as ++ [pass]) b
    | otherwise = recall_pass as b

-- |Accumulates all parameters for '-s'.
set_params :: Int -> [String] -> IO ()
set_params ln as
    | ln == 1 = do
        putStr "Password name: "
        hFlush stdout
        name <- getLine
        putStr "Seed: "
        seed <- getLine
        putStr "Master password: "
        hFlush stdout
        hSetEcho stdin False
        pass <- getLine
        hSetEcho stdin True
        putStrLn ""
        set_pass (reverse $ pass:seed:name:as)
    | ln == 2 = do
        putStr "Seed: "
        hFlush stdout
        seed <- getLine
        putStr "Master password: "
        hFlush stdout
        hSetEcho stdin False
        pass <- getLine
        hSetEcho stdin True
        putStrLn ""
        set_pass (as ++ [seed,pass])
    | ln == 3 = do
        putStr "Master password: "
        hFlush stdout
        hSetEcho stdin False
        pass <- getLine
        hSetEcho stdin True
        putStrLn ""
        set_pass (as ++ [pass])
    | otherwise = set_pass as

-- |Accumulates all parameters for '-m'.
master_params :: Int -> [String] -> IO ()
master_params ln as
    | ln == 1 = do
        putStr "New master: "
        hFlush stdout
        hSetEcho stdin False
        new <- getLine
        putStr "\nRepeat new master: "
        hFlush stdout
        hSetEcho stdin False
        new2 <- getLine
        putStr "\nMaster password: "
        pass <- getLine
        hSetEcho stdin True
        set_master (reverse $ pass:new2:new:as)
    | ln == 2 = do
        putStr "Repeat new master: "
        hFlush stdout
        hSetEcho stdin False
        new2 <- getLine
        putStr "\nMaster password: "
        pass <- getLine
        hSetEcho stdin True
        set_master (as ++ [new2,pass])
    | ln == 3 = do
        putStr "Master password: "
        hFlush stdout
        hSetEcho stdin False
        pass <- getLine
        hSetEcho stdin True
        set_master (as ++ [pass])
    | otherwise = set_master as

-- |Accumulates all params for '-i' and '-h'.
init_params :: Int -> [String] -> Bool -> IO ()
init_params ln as b
    | ln == 1 = do
        putStr "Input: "
        hFlush stdout
        new <- getLine
        init_master (reverse $ new:as) b
    | otherwise = init_master as b

-- |Prints the help dialogue.
help_msg :: IO ()
help_msg = putStrLn $ "Commands:\n"
           ++ "  -r [NAME] [MASTER] - copies the password of NAME.\n"
           ++ "  -p [NAME] [MASTER] - prints the password of NAME.\n"
           ++ "  -s [NAME] [SEED] [MASTER] - changes the seed for NAME.\n"
           ++ "  -m [NEWMASTER] [OLDMASTER] - changes the master password.\n"
           ++ "  -h [INPUT] - hashes INPUT and prints to a new line.\n"
           ++ "  -i [INPUT] - hashes INPUT, used when making a first master.\n"
           ++ "  -H --help - prints this message."

-- --------------------------------------------------------------------------
-- Functions that will be called after *_params has checked that it is safe

-- |Recalls the given password. if b is True, then prints the password to
-- stdout. If b is False, pushes the password to the clipboard. This function
-- handles both '-r' and '-p'.
recall_pass :: [String] -> Bool -> IO ()
recall_pass as b = do
    let pass = as!!2
    master_hash <- readFile master_fl
    f' <- map read . lines <$> readFile pass_lib
    let fl =  map chr . zipWith xor f' $ strord pass
    unless (valid_pass pass master_hash) $ error "Incorrect password"
    case get_pair (as!!1) (parse_pairs fl) of
        Nothing -> error "No password set for that name"
        Just p  -> if b
                     then putStrLn (mk_pass pass (get_seed p))
                     else void (system $ "echo \"" ++ mk_pass pass (get_seed p)
                                           ++ "\" | xclip -selection c")

-- |Sets a password seed for a name. This function handles '-s'.
set_pass :: [String] -> IO ()
set_pass as = do
    let name = as!!1
        seed = as!!2
        pass = as!!3
    master_hash <- readFile master_fl
    f' <- map read . lines <$> readFile pass_lib
    let fl = map chr . zipWith xor f' $ strord pass
    unless (valid_pass pass master_hash) $ error "Incorrect password"
    removeFile pass_lib
    appendFile pass_lib $ join $ intersperse "\n" $ map show $ zipWith xor
                   (map ord $ fprint_pairs (name,seed) fl)
                   (strord pass)

-- |Allows the user to change their master password.
-- This function handles '-m'.
set_master :: [String] -> IO ()
set_master as = do
    let pass         = as!!3
        new_pass_dup = as!!2
        new_pass     = as!!1
    master_hash <- readFile master_fl
    f' <- map read . lines <$> readFile pass_lib
    let fl = map chr . zipWith xor f' $ strord pass
    unless (valid_pass pass master_hash) $ error "Incorrect password"
    unless (new_pass == new_pass_dup) $ error "Passwords do not match"
    removeFile master_fl
    appendFile master_fl $ showDigest $ sha256 $ B.pack new_pass
    removeFile pass_lib
    appendFile pass_lib $ join $ intersperse "\n" $ map show
                   $ zipWith xor (map ord $ fprint_pairs ("","") fl)
                         (strord new_pass)

-- |Allows the user to set a first master password. This function handles '-i'
-- and '-h'.
init_master :: [String] -> Bool -> IO ()
init_master as b = let pass = as!!1
                     in if b
                        then putStrLn $ showDigest $ sha256 $ B.pack pass
                        else putStr   $ showDigest $ sha256 $ B.pack pass
