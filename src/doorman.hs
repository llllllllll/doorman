-----------------------------------------------------------------------------
-- |
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
parse_args args
    | null args = error "Usage: [OPTION] [PARAMS]"
    | head args == "-r" = recall_params (length args) args False
    | head args == "-p" = recall_params (length args) args True
    | head args == "-s" = set_params (length args) args
    | head args == "-m" = master_params (length args) args
    | head args == "-i" = init_params (length args) args False
    | head args == "-h" = init_params (length args) args True
    | head args == "-H" || head args == "--help" = help_msg
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


-- |Formats the PassPairs to be printed to the file.
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

-- |Converts the master to an int list to be xor'd for decrytion.
strord :: String -> [Int]
strord str = cycle $ map ord $ showDigest $ sha512 $ B.pack str

-- --------------------------------------------------------------------------
-- Functions that will be called from parse_args directly
-- These function check for the proper params to then pass on the their
-- respective functions.

-- |Accumulates all parameters for '-r' and '-p'.
recall_params ::Int -> [String] -> Bool -> IO ()
recall_params ln args b
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
        recall_pass (reverse $ pass:name:args) b
    | ln == 2 = do
        putStr "Master Password: "
        hFlush stdout
        hSetEcho stdin False
        pass <- getLine
        hSetEcho stdin True
        putStrLn ""
        recall_pass  (args ++ [pass]) b
    | otherwise = recall_pass args b

-- |Accumulates all parameters for '-s'.
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

-- |Accumulates all parameters for '-m'.
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

-- |Accumulates all params for '-i' and '-h'.
init_params :: Int -> [String] -> Bool -> IO ()
init_params ln args b
    | ln == 1 = do
        putStr "Input: "
        hFlush stdout
        new <- getLine
        init_master (reverse $ new:args) b
    | otherwise = init_master args b

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
recall_pass args b = do
    let pass = args!!2
    master_hash <- readFile master_fl 
    f' <- map read . lines <$> readFile pass_lib
    let fl =  map chr . zipWith xor f' $ strord pass
    putStrLn $ fl
    unless (valid_pass pass master_hash) $ error "Incorrect password"
    case get_pair (args!!1) (parse_pairs fl) of
        Nothing -> error "No password set for that name"
        Just p  -> if b
                     then void (system $ "echo \"" ++ mk_pass pass (get_seed p)
                                           ++ "\" | xclip -selection c")
                     else putStrLn (mk_pass pass (get_seed p))

-- |Sets a password seed for a name. This function handles '-s'.
set_pass :: [String] -> IO ()
set_pass args = do
    let name = args!!1
        seed = args!!2
        pass = args!!3
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
set_master args = do
    let pass = args!!2
        new_pass = args!!1
    master_hash <- readFile master_fl
    f' <- map read . lines <$> readFile pass_lib
    let fl = map chr . zipWith xor f' $ strord pass
    unless (valid_pass pass master_hash) $ error "Incorrect password"
    removeFile master_fl
    appendFile master_fl $ showDigest $ sha256 $ B.pack new_pass
    removeFile pass_lib
    appendFile pass_lib $ join $ intersperse "\n" $ map show 
                   $ zipWith xor (map ord $ fprint_pairs ("","") fl) (strord new_pass)
    

-- |Allows the user to set a first master password. This function handles '-i'
-- and '-h'.
init_master :: [String] -> Bool -> IO ()
init_master args b = let pass = args!!1
                     in if b
                        then putStrLn $ showDigest $ sha256 $ B.pack pass
                        else putStr   $ showDigest $ sha256 $ B.pack pass
