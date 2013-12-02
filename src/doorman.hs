-----------------------------------------------------------------------------
--
-- Program     :  doorman v2.2.2
-- Copyright   :  Joe Jevnik 2.12.2013
-- License     :  GPL v2
--
-- Maintainer  :  Joe Jevnik
-- Stability   :  experimental
-- Portability :  requires xclip
--
-- Password manager.
--
-----------------------------------------------------------------------------

{-# LANGUAGE CPP,OverloadedStrings #-}

import Control.Applicative                       ((<$>))
import Control.Concurrent                        (threadDelay)
import Control.Monad                             (unless,void,join)
import Data.Bits                                 (xor)
import Data.Char                                 (chr,ord)
import Data.Digest.Pure.SHA                      (sha256,sha512,showDigest)
import Data.List                                 (find,intersperse,sort)
import Data.Map                                  (Map)
import qualified Data.Map as M
import Data.Maybe                                (fromMaybe)
import Data.String.Utils                         (split)
import Data.Word                                 (Word8)
import Data.ByteString.Lazy                      (ByteString,append,singleton)
import qualified Data.ByteString.Lazy as B       ( readFile,head
                                                 , unpack,pack,take,appendFile )
import Data.ByteString.Lazy.Char8                (cons,snoc)
import qualified Data.ByteString.Lazy.Char8 as C ( pack,unpack,putStrLn
                                                 , lines,split )
import System.Directory                          (getHomeDirectory,removeFile)
import System.Environment                        (getArgs)
import System.IO                                 (hFlush,hSetEcho,stdin,stdout)
import System.Process                            (system)
import System.Posix.Files                        ( unionFileModes,ownerReadMode
                                                 , ownerWriteMode,setFileMode)
import System.Posix.User                         ( getRealUserID
                                                 , getEffectiveUserID
                                                 , setEffectiveUserID)
import System.Console.GetOpt                     ( ArgOrder(..),OptDescr(..)
                                                 , ArgDescr(..),getOpt)

-- --------------------------------------------------------------------------
-- data types

-- The type for a lookup key / password pair.
-- (Name,Literal,Length,Seed)
type PassType = (ByteString,Bool,Word8,ByteString)

-- The possible flags that can be passed, and their data.
data Flag = Version | Help | Recall String | Print String
          | Set String | Hash String | Init String | Load String

-- --------------------------------------------------------------------------
-- constants and files.

pass_lib :: FilePath
pass_lib = "/usr/share/doorman/pass_lib"

master_fl :: FilePath
master_fl = "/usr/share/doorman/master"

version_num :: String
version_num = "2.2.2"

-- --------------------------------------------------------------------------
-- Main / arg handling cases.
main :: IO ()
main = getArgs >>= \as -> handle_flags (getOpt RequireOrder options as)

--Parses the command line args.
options :: [OptDescr Flag]
options =
    [ Option ['v'] ["version"] (NoArg Version) "Displays version information"
    , Option ['H'] ["help"]    (NoArg Help) "Prints the help dialog"
    , Option ['r'] ["recall"]  (ReqArg Recall "PASS_NAME")
             "Pushes the given password to the clipboard"
    , Option ['p'] ["print"]   (ReqArg Print "PASS_NAME")
             "Prints the given password to stdout"
    , Option ['s'] ["set"]     (OptArg parse_setopts "SET_OPTS")
                 "set a new password, require: (c)aps, (n)umbers, \
                  l(iteral) or (s)pecial chars"
    , Option ['h'] ["h512"]    (ReqArg Hash "INPUT")
                 "Hashes the input with a sha512"
    , Option ['i'] ["h256"]    (ReqArg Init "INPUT")
                 "Hashes the input with a sha256"
    , Option ['l'] ["load"]    (ReqArg Load "LOAD_OPT")
                 "How to load the new file: (o)verwrite or (m)erge"
    ]

-- Parses the options for setting a pass.
parse_setopts :: Maybe String -> Flag
parse_setopts = Set . fromMaybe ""

-- Parses the options
handle_flags :: ([Flag],[String],[String]) -> IO ()
handle_flags (fs,ss,es) = mapM_ (handle_flag ss) fs
  where
      handle_flag _ Version     = putStrLn $ "doorman version "  ++ version_num
                                  ++ "\nby Joe Jevnik"
      handle_flag _ Help        = putStrLn help_msg
      handle_flag ss (Recall p) = recall_params (length ss) ss False p
      handle_flag ss (Print p)  = recall_params (length ss) ss True p
      handle_flag ss (Set os)   = set_params    (length ss) ss os
      handle_flag ss (Hash s)   = hash_str                  s True
      handle_flag ss (Init s)   = hash_str                  s False
      handle_flag ss (Load o)   = load_params   (length ss) ss o


-- --------------------------------------------------------------------------
-- dealing with PassTypes

get_name :: PassType -> ByteString
get_name (n,_,_,_) = n

get_lit :: PassType -> Bool
get_lit (_,l,_,_) = l

get_len :: PassType -> Word8
get_len (_,_,l,_) = l

get_seed :: PassType -> ByteString
get_seed (_,_,_,s) = s

-- --------------------------------------------------------------------------
-- File reading and parsing

get_master_hash :: IO ByteString
get_master_hash = head . C.lines <$> B.readFile master_fl

--Parses a string for PassTypes. This function expects a valid String
-- that contains parse_passes printed in the format of the pass_lib file.
parse_passes :: ByteString -> Map ByteString PassType
parse_passes str = M.fromList [(get_name v,v) | v <- map read_pass
                                                     $ C.lines str]
  where
      read_pass str = let p = C.split ':' str
                      in (head p,p!!1 /= "0",B.head (p!!2),p!!3)

--Filter Print: Filters out the list for any names that are the same as p,
--  and then formats the rest to be output to the file.
fprint_passes :: PassType -> Map ByteString PassType -> ByteString
fprint_passes p ps = bld "" $ p:(filter (\pa -> get_name pa /= get_name p) ps)
  where
      bld str [] = str
      bld str (p:ps)
          = bld (((get_name p `snoc` ':') `append` ((if get_lit p
                                                       then '1'
                                                       else '0') `cons`
                                                    (':' `cons`
                                                     (singleton (get_len p))))
                  `snoc` ':') `append` get_seed p) ps

--Filter Print: Filters out the list for any names that are the same as p,
--  and then formats the rest to be output to the file.
print_passes :: Map ByteString PassType -> ByteString
print_passes ps = bld "" $ map snd $ M.toList ps
  where
      bld str [] = str
      bld str (p:ps)
          = bld (((get_name p `snoc` ':') `append` ((if get_lit p
                                                       then '1'
                                                       else '0') `cons`
                                                    (':' `cons`
                                                     (singleton (get_len p))))
                  `snoc` ':') `append` get_seed p) ps

-- XOR encrypts the string.
encrypt :: ByteString -> ByteString -> ByteString
encrypt pass str = B.pack $  zipWith xor
                   (cycle $ B.unpack pass) (B.unpack str)

-- XOR decrypts the string.
unencrypt :: ByteString -> ByteString -> ByteString
unencrypt pass fl = B.pack $ zipWith xor (cycle $ B.unpack pass)
                    (B.unpack fl)

--Returns the pair with the given name or Nothing if it does not exits.
get_pass_type :: ByteString -> [PassType] -> Maybe PassType
get_pass_type name = find (\p -> get_name p == name)

--Compares the hash of the input password to the saved hash of the master
-- password.
valid_pass :: ByteString -> ByteString -> Bool
valid_pass pass hash = C.unpack hash == (showDigest $ sha256 pass)

--Makes an end password from a master password and a seed.
mk_pass :: ByteString -> ByteString -> String
mk_pass master seed = let p1 = showDigest $ sha512 (master `append` seed)
                      in filter (`notElem` "\"'`")
                             $ scanl1 (\x y -> chr
                                       $ ((ord x * ord y) `rem` 93) + 33) p1

--Converts the master to an int list by hashing and taking the ord of the
-- chars to be xor'd for decrytion.
strord :: String -> [Int]
strord str = cycle $ map ord $ showDigest $ sha512 $ C.pack str

--Error to throw if the password is wrong. This includes a 2 second delay.
incpasswderr :: IO ()
incpasswderr = threadDelay 3000000 >> error "Incorrect password"

-- --------------------------------------------------------------------------
-- Functions that will be called from parse_as directly
-- These function check for the proper params to then pass on the their
-- respective functions.

--Accumulates all parameters for '-r' and '-p'.
recall_params :: Int -> [String] -> Bool -> String -> IO ()
recall_params ln as b p
    | ln == 0 = do
        putStr "Master password: "
        hFlush stdout
        hSetEcho stdin False
        pass <- getLine
        hSetEcho stdin True
        putStrLn ""
        recall_pass (C.pack pass) b (C.pack p)
    | otherwise = recall_pass (C.pack $ head as) b (C.pack p)

--Accumulates all parameters for '-s'.
set_params :: Int -> [String] -> String ->  IO ()
set_params ln as os
    | ln == 0 = do
        putStr "Password name: "
        hFlush stdout
        name <- getLine
        putStr "Length: "
        hFlush stdout
        len <- getLine
        hFlush stdout
        putStr "Seed: "
        seed <- getLine
        putStr "Master password: "
        hFlush stdout
        hSetEcho stdin False
        pass <- getLine
        hSetEcho stdin True
        putStrLn ""
        set_pass (map C.pack $ name:len:seed:[pass]) os
    | ln == 1 = do
        putStr "Length: "
        len <- getLine
        hFlush stdout
        putStr "Seed: "
        hFlush stdout
        seed <- getLine
        putStr "Master password: "
        hFlush stdout
        hSetEcho stdin False
        pass <- getLine
        hSetEcho stdin True
        putStrLn ""
        set_pass (map C.pack $ as ++ [len,seed,pass]) os
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
        set_pass (map C.pack $ as ++ [seed,pass]) os
    | ln == 3 = do
        putStr "Master password: "
        hFlush stdout
        hSetEcho stdin False
        pass <- getLine
        hSetEcho stdin True
        putStrLn ""
        set_pass (map C.pack $ as ++ [pass]) os
    | otherwise = set_pass (map C.pack as) os

--Accumilates all parameters for '-l'.
load_params :: Int -> [String] -> String -> IO ()
load_params ls as opts
    | ls == 0 = do
        putStr "Path to new pass_lib: "
        hFlush stdout
        nw <- getLine
        putStr "\nMaster password: "
        pass <- getLine
        hSetEcho stdin True
        load_pass_lib (map C.pack [nw,pass]) opts
    | ls == 1 = do
        putStr "\nMaster password: "
        pass <- getLine
        hSetEcho stdin True
        load_pass_lib (map C.pack $ as ++ [pass]) opts
    | otherwise = load_pass_lib (map C.pack as) opts

--Prints the help dialogue.
help_msg :: String
help_msg = "Commands:\n\
\t-r [NAME] [MASTER] - copies the password of NAME.\n\
\t-p [NAME] [MASTER] - prints the password of NAME.\n\
\t-s [NAME] [SEED] [MASTER] - changes the seed for NAME.\n\
\t-m [NEWMASTER] [OLDMASTER] - changes the master password.\n\
\t-h [INPUT] - hashes INPUT and prints to a new line.\n\
\t-i [INPUT] - hashes INPUT, used when making a first master.\n\
\t-l [m | o] [PATHTONEWFILE] [MATER] - merges or overwrites the\
\n\t\tpassword library with the new file provided. Merging uses\n\
\t\tthe new file's seeds in the case of a collision.\n\
\t-H --help - prints this message."

-- --------------------------------------------------------------------------
-- Functions that will be called after *_params has checked that it is safe

--Recalls the given password. if b is True, then prints the password to
-- stdout. If b is False, pushes the password to the clipboard. This function
-- handles both '-r' and '-p'.
recall_pass :: ByteString -> Bool -> ByteString -> IO ()
recall_pass pass b name = do
    master_hash <- get_master_hash
    fl <- unencrypt master_hash <$> B.readFile pass_lib
    unless (valid_pass pass master_hash) incpasswderr
    case get_pass_type name (parse_passes fl) of
        Nothing -> error "No password set for that name"
        Just p  -> if b
                     then C.putStrLn $ B.take (fromIntegral $ get_len p)
                              (if get_lit p
                                 then get_seed p
                                 else C.pack $ mk_pass pass (get_seed p))
                     else void (system $ "echo \""
                                ++ (C.unpack $ B.take (fromIntegral $ get_len p)
                                         (if get_lit p
                                            then get_seed p
                                            else C.pack $ mk_pass pass
                                                     (get_seed p)))
                                       ++ "\" | xclip -selection c")

--Sets a password seed for a name. This function handles '-s'.
set_pass :: [ByteString] -> String -> IO ()
set_pass [name,len,seed,pass] opts = do
    master_hash <- get_master_hash
    fl <- unencrypt master_hash <$> B.readFile pass_lib
    unless (valid_pass pass master_hash) incpasswderr
    unless (test_pass seed (sort opts) pass)
               $ error "test failed, try another seed"
    removeFile pass_lib
    B.appendFile pass_lib $ encrypt master_hash
         $ fprint_passes (name,('l' `elem` opts),B.head len,seed)
         $ parse_passes fl
    setFileMode pass_lib (unionFileModes ownerReadMode ownerWriteMode)
  where
      test_pass seed opts pass
          | any (`notElem` "clns") opts = error "options must be c, n, or s"
          | opts `elem` ["c","cl"]
              = any (`elem` ['A'..'Z']) $ mk_pass pass seed
          | opts `elem` ["n","ln"]
              = any (`elem` ['0'..'9']) $ mk_pass pass seed
          | opts `elem` ["s","ls"]
              = any (\c -> c `notElem` ['0'..'9']
                           || c `notElem` ['a'..'z']
                           || c `notElem` ['A'..'Z'])
                $ mk_pass pass seed
          | opts `elem` ["cn","cln"]
              = any (\c -> c `elem` ['A'..'Z']
                           && c `elem` ['0'..'9']) $ mk_pass pass seed
          | opts `elem` ["cs","cls"]
              = any (\c -> c `elem` ['A'..'Z']
                           && (c `notElem` ['0'..'9']
                               || c `notElem` ['a'..'z']
                               || c `notElem` ['A'..'Z'])) $ mk_pass pass seed
          | opts `elem` ["ns","lns"]
              = any (\c -> c `elem` ['0'..'9']
                           && (c `notElem` ['0'..'9']
                               || c `notElem` ['a'..'z']
                               || c `notElem` ['A'..'Z'])) $ mk_pass pass seed
          | opts `elem` ["cns","clns"]
              = any (\c -> c `elem` ['A'..'Z']
                           && c `elem` ['0'..'9']
                           && (c `notElem` ['0'..'9']
                               || c `notElem` ['a'..'z']
                               || c `notElem` ['A'..'Z'])) $ mk_pass pass seed
          | otherwise = True


--Allows the user to set a first master password. This function handles '-i'
-- and '-h'.
hash_str :: String -> Bool -> IO ()
hash_str pass True  = putStrLn $ showDigest $ sha512 $ C.pack pass
hash_str pass False = putStrLn $ showDigest $ sha256 $ C.pack pass

--Alows the user to load and merge, or load an overwrite their password lib
-- with a new password lib.
load_pass_lib :: [ByteString] -> String -> IO ()
load_pass_lib [new_lib,pass] opt
    | opt == "m" = do
        dmid <- getEffectiveUserID
        master_hash <- get_master_hash
        unless (valid_pass pass master_hash) incpasswderr
        fl <- unencrypt master_hash <$> B.readFile pass_lib
        let old_pairs = parse_passes fl
        getRealUserID >>= setEffectiveUserID
        new_fl <- unencrypt master_hash <$> B.readFile (C.unpack new_lib)
        let new_pairs = let pp = parse_passes new_fl
                        in filter (`notElem` pp) old_pairs
        setEffectiveUserID dmid
        removeFile pass_lib
        B.appendFile pass_lib $ encrypt master_hash
             $ print_passes $ parse_passes fl
        setFileMode pass_lib (unionFileModes ownerReadMode ownerWriteMode)
    | opt == "o" = do
        master_hash <- get_master_hash
        unless (valid_pass pass master_hash) incpasswderr
        dmid <- getEffectiveUserID
        getRealUserID >>= setEffectiveUserID
        new_fl <- readFile (C.unpack new_lib)
        removeFile pass_lib
        appendFile pass_lib new_fl
        setFileMode pass_lib (unionFileModes ownerReadMode ownerWriteMode)
    | otherwise = do
        error $ "Invalid option: '" ++ opt ++ "': expected 'm' for merge or 'o'"
              ++ " for overwrite"
