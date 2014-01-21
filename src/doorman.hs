-----------------------------------------------------------------------------
-- |
-- Program     :  doorman v3.0.1
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

import Prelude                            hiding (lookup)
import Control.Applicative                       ((<$>))
import Control.Concurrent                        (threadDelay)
import Control.Monad                             (unless,void)
import Data.Bits                                 (xor)
import Data.ByteString.Lazy                      (ByteString,append,singleton)
import qualified Data.ByteString.Lazy as B       ( readFile,head
                                                 , unpack,pack,take,appendFile )
import Data.ByteString.Lazy.Char8                (cons,snoc,readInt)
import qualified Data.ByteString.Lazy.Char8 as C ( pack,unpack,putStrLn
                                                 , lines,split )
import Data.Char                                 ( chr,ord,isUpper
                                                 , isDigit,isSymbol )
import Data.Digest.Pure.SHA                      (sha256,sha512,showDigest)
import Data.List                                 (sort)
import Data.Map                                  ( Map,delete,insert,difference
                                                 , toList,fromList,lookup)
import Data.Maybe                                (fromMaybe)
import Data.Word                                 (Word8)
import System.Console.GetOpt                     ( ArgOrder(..),OptDescr(..)
                                                 , ArgDescr(..),getOpt)
import System.Directory                          (removeFile)
import System.Environment                        (getArgs)
import System.IO                                 (hSetEcho,stdin,stdout,hFlush)
import System.Process                            (system)
import System.Posix.Files                        ( unionFileModes,ownerReadMode
                                                 , ownerWriteMode,setFileMode)
import System.Posix.User                         ( getRealUserID
                                                 , getEffectiveUserID
                                                 , setEffectiveUserID)

-- --------------------------------------------------------------------------
-- data types

-- | The type for a lookup key / password pair.
data PasswordData = PasswordData { passName :: ByteString
                                 , isLit    :: Bool
                                 , passLen  :: Word8
                                 , passSeed :: ByteString
                                 }

-- | The possible flags that can be passed, and their data.
data Flag = Version | Help | Recall String | Print String
          | Set String | Hash512 String | Hash256 String | Load String

-- --------------------------------------------------------------------------
-- constants and files.

passLib :: FilePath
passLib = "/usr/share/doorman/pass_lib"

masterFl :: FilePath
masterFl = "/usr/share/doorman/master"

versionNum :: String
versionNum = "3.0.1"

-- --------------------------------------------------------------------------
-- Main / arg handling cases.

main :: IO ()
main = getArgs >>= \as -> handleFlags (getOpt RequireOrder options as)

-- | Parses the command line args.
options :: [OptDescr Flag]
options =
    [ Option ['v'] ["version"] (NoArg Version) "Displays version information"
    , Option ['H'] ["help"]    (NoArg Help) "Prints the help dialog"
    , Option ['r'] ["recall"]  (ReqArg Recall "PASS_NAME")
                 "Pushes the given password to the clipboard"
    , Option ['p'] ["print"]   (ReqArg Print "PASS_NAME")
             "Prints the given password to stdout"
    , Option ['s'] ["set"]     (OptArg parseSetOpts "SET_OPTS")
                 "set a new password, require: (c)aps, (n)umbers, \
                  l(iteral) or (s)pecial chars"
    , Option ['h'] ["h512"]    (ReqArg Hash512 "INPUT")
                 "Hashes the input with a sha512"
    , Option ['i'] ["h256"]    (ReqArg Hash256 "INPUT")
                 "Hashes the input with a sha256"
    , Option ['l'] ["load"]    (ReqArg Load "LOAD_OPT")
                 "How to load the new file: (o)verwrite or (m)erge"
    ]

-- | Parses the options for setting a pass.
parseSetOpts :: Maybe String -> Flag
parseSetOpts = Set . fromMaybe ""

-- | Parses the options
handleFlags :: ([Flag],[String],[String]) -> IO ()
handleFlags ([],_,_)   = putStrLn "Usage: doorman [COMMAND]... [PARAM]..."
handleFlags (fs,ss,es) = mapM_ (handleFlag ss) fs
  where
      handleFlag _   Version    = putStrLn $ "doorman version "  ++ versionNum
                                  ++ "\nby Joe Jevnik"
      handleFlag _   Help       = putStrLn helpMsg
      handleFlag ss (Recall p)  = accumRecallParams (length ss) ss False p
      handleFlag ss (Print p)   = accumRecallParams (length ss) ss True p
      handleFlag ss (Set os)    = accumSetParams    (length ss) ss os
      handleFlag ss (Hash512 s) = hashStr                        s True
      handleFlag ss (Hash256 s) = hashStr                        s False
      handleFlag ss (Load o)    = accumLoadParams   (length ss) ss o

-- --------------------------------------------------------------------------
-- File reading and parsing

-- | Return the hash of the master password that is saved.
getMasterHash :: IO ByteString
getMasterHash = head . C.lines <$> B.readFile masterFl

getPassLib :: ByteString -> IO ByteString
getPassLib masterHash = xorPass masterHash <$> B.readFile passLib

-- | Parses a string for PasswordDatas. This function expects a valid String
-- that contains parsePasses printed in the format of the passLib file.
parsePasses :: ByteString -> Map ByteString PasswordData
parsePasses str = fromList [(passName v,v) | v <- map readPass $ C.lines str]
  where
      readPass str = let p = C.split ':' str
                     in PasswordData { passName = head p
                                     , isLit    = p!!1 /= "0"
                                     , passLen  = parseLen $ p!!2
                                     , passSeed = p!!3
                                     }

-- | Parses the length properly.
parseLen :: ByteString -> Word8
parseLen = fromIntegral . fst . fromMaybe (error "bad length in parse")
           . readInt

-- | Filter Print: Filters out the list for any names that are the same as p,
-- and then formats the rest to be output to the file.
fPrintPasses :: PasswordData -> Map ByteString PasswordData -> ByteString
fPrintPasses p ps = bld "" $ p:(map snd $ toList $ delete (passName p) ps)

-- | Filter Print: Filters out the list for any names that are the same as p,
-- and then formats the rest to be output to the file.
printPasses :: Map ByteString PasswordData -> ByteString
printPasses = bld "" . map snd . toList

-- | Builds the string to be printed (shared between fprint and print passes.
bld :: ByteString -> [PasswordData] -> ByteString
bld = foldr (\p ps -> (((((passName p `snoc` ':')
                          `append` ((if isLit p
                                       then '1'
                                       else '0') `cons`
                                    (':' `cons` (C.pack $ show (passLen p))))
                                       `snoc` ':') `append` passSeed p)
                        `snoc` '\n') `append` ps))

-- | XORs the strings.
xorPass :: ByteString -> ByteString -> ByteString
xorPass pass str = B.pack $ zipWith xor (cycle $ B.unpack pass) (B.unpack str)

-- | Compares the hash of the input password to the saved hash of the master
-- password.
isValidPass :: ByteString -> ByteString -> Bool
isValidPass pass hash = C.unpack hash == (showDigest $ sha256 pass)

-- | Makes an end password from a master password and a seed.
genPassword :: ByteString -> ByteString -> String
genPassword master seed = let p1 = showDigest $ sha512 (master `append` seed)
                          in filter (`notElem` "\"'`")
                                 $ scanl1 (\x y -> chr
                                           $ ((ord x * ord y) `rem` 93) + 33) p1

-- | Error to throw if the password is wrong. This includes a 2 second delay.
incPasswordErr :: IO ()
incPasswordErr = threadDelay 1000000 >> error "Incorrect password"

-- | prints the string and then flushes the buffer.
pFlush :: String -> IO ()
pFlush str = putStr str >> hFlush stdout

-- | Prompts the user for their master password.
promptMasterPass :: IO String
promptMasterPass = do
    pFlush "Master password: " >> hSetEcho stdout False
    str <- getLine
    hSetEcho stdout True >> putStrLn ""
    return str

-- | Prompts the user to input the password.
promptName :: IO String
promptName = pFlush "Password name: " >> getLine

-- | Prompts the user to input the length of the password.
promptLen :: IO String
promptLen = pFlush "Password length: " >> getLine

-- | Prompts the user to input the seed for the password.
promptSeed :: IO String
promptSeed = pFlush "Seed: " >> getLine

-- --------------------------------------------------------------------------
-- Functions that will be called from parse_as directly
-- These function check for the proper params to then pass on the their
-- respective functions.

-- | Accumulates all parameters for '-r' and '-p'.
accumRecallParams :: Int -> [String] -> Bool -> String -> IO ()
accumRecallParams 0 as b p = do
    pass <- promptMasterPass
    recallPass (C.pack pass) b (C.pack p)
accumRecallParams _ as b p = recallPass (C.pack $ head as) b (C.pack p)

-- | Accumulates all parameters for '-s'.
accumSetParams :: Int -> [String] -> String ->  IO ()
accumSetParams 0 as os = do
    name <- promptName
    len  <- promptLen
    seed <- promptSeed
    pass <- promptMasterPass
    setPass (map C.pack $ name:len:seed:[pass]) os
accumSetParams 1 as os = do
    len  <- promptLen
    seed <- promptSeed
    pass <- promptMasterPass
    setPass (map C.pack $ as ++ [len,seed,pass]) os
accumSetParams 2 as os = do
    seed <- promptSeed
    pass <- promptMasterPass
    setPass (map C.pack $ as ++ [seed,pass]) os
accumSetParams 3 as os = do
    pass <- promptMasterPass
    setPass (map C.pack $ as ++ [pass]) os
accumSetParams _ as os = setPass (map C.pack as) os

-- | Accumilates all parameters for '-l'.
accumLoadParams :: Int -> [String] -> String -> IO ()
accumLoadParams 0 as opts = do
    putStr "Path to new passLib: "
    nw <- getLine
    pass <- promptMasterPass
    loadPassLib (map C.pack [nw,pass]) opts
accumLoadParams 1 as opts = do
    pass <- promptMasterPass
    loadPassLib (map C.pack $ as ++ [pass]) opts
accumLoadParams _ as opts = loadPassLib (map C.pack as) opts

-- | Prints the help dialogue.
helpMsg :: String
helpMsg = "Usage:\n\n    doorman [COMMAND]... [PARAM]...\n\nCommands:\n\
  -r [NAME] [MASTER] - copies the password of NAME.\n\
  -p [NAME] [MASTER] - prints the password of NAME.\n\
  -s[OPTS] [NAME] [LENGTH] [SEED] [MASTER] - changes the seed for NAME.\n\
  -h [INPUT] - hashes INPUT with a sha512.\n\
  -i [INPUT] - hashes INPUT with a sha256.\n\
  -l [m | o] [PATHTONEWFILE] [MASTER] - merges or overwrites the \n\
    password library with the new file provided. Merging uses\n\
    the new file's seeds in the case of a collision.\n\
  -v --version - prints version information.\n\
  -H --help - prints this message."

-- --------------------------------------------------------------------------
-- Functions that will be called after *_params has checked that it is safe

-- | Recalls the given password. if b is True, then prints the password to
-- stdout. If b is False, pushes the password to the clipboard. This function
-- handles both '-r' and '-p'.
recallPass :: ByteString -> Bool -> ByteString -> IO ()
recallPass pass b name = do
    masterHash <- getMasterHash
    unless (isValidPass pass masterHash) incPasswordErr
    fl <- getPassLib masterHash
    case lookup name (parsePasses fl) of
        Nothing -> error "No password set for that name"
        Just p  -> if b
                     then C.putStrLn $ B.take (fromIntegral $ passLen p)
                              (if isLit p
                                 then passSeed p
                                 else C.pack $ genPassword pass (passSeed p))
                     else void (system $ "echo \""
                                ++ (C.unpack $ B.take (fromIntegral $ passLen p)
                                         (if isLit p
                                            then passSeed p
                                            else C.pack $ genPassword pass
                                                     (passSeed p)))
                                       ++ "\" | xclip -selection c")

-- | Sets a password seed for a name. This function handles '-s'.
setPass :: [ByteString] -> String -> IO ()
setPass [name,len,seed,pass] opts = do
    masterHash <- getMasterHash
    unless (isValidPass pass masterHash) incPasswordErr
    fl <- getPassLib masterHash
    unless (testPass seed (sort opts) pass)
               $ error "test failed, try another seed"
    removeFile passLib
    B.appendFile passLib $ xorPass masterHash
         $ fPrintPasses PasswordData { passName = name
                                     , isLit    = 'l' `elem` opts
                                     , passLen  = parseLen len
                                     , passSeed = seed
                                     } $ parsePasses fl
    setFileMode passLib (unionFileModes ownerReadMode ownerWriteMode)
  where
      chToFunc 'c' = any isUpper
      chToFunc 'n' = any isDigit
      chToFunc 's' = any isSymbol
      chToFunc ch  = const True
      testPass seed opts pass
          | any (`notElem` "clns") opts = error "options must be c, n, or s"
          | otherwise = let ps = genPassword pass seed
                        in all (\ch -> chToFunc ch ps) opts


-- | Allows the user to hash strings using sha512 and sha256.
-- This function handles '-i' and '-h'.
hashStr :: String -> Bool -> IO ()
hashStr pass b = putStrLn $ (if b
                               then showDigest . sha512
                               else showDigest . sha256) $ C.pack pass

-- | Allows the user to load and merge, or load an overwrite their password lib
-- with a new password lib.
loadPassLib ::[ByteString] -> String -> IO ()
loadPassLib [newLib,pass] "m" = do
    dmid <- getEffectiveUserID
    masterHash <- getMasterHash
    unless (isValidPass pass masterHash) incPasswordErr
    fl <- getPassLib masterHash
    getRealUserID >>= setEffectiveUserID
    new_fl <- xorPass masterHash <$> B.readFile (C.unpack newLib)
    let newPairs = difference (parsePasses new_fl) (parsePasses fl)
    setEffectiveUserID dmid
    removeFile passLib
    B.appendFile passLib $ xorPass masterHash $ printPasses $ newPairs
    setFileMode passLib (unionFileModes ownerReadMode ownerWriteMode)
loadPassLib [newLib,pass] "o" = do
    masterHash <- getMasterHash
    unless (isValidPass pass masterHash) incPasswordErr
    dmid <- getEffectiveUserID
    getRealUserID >>= setEffectiveUserID
    newFl <- readFile (C.unpack newLib)
    removeFile passLib
    appendFile passLib newFl
    setFileMode passLib (unionFileModes ownerReadMode ownerWriteMode)
loadPassLib _ opt = error $ "Invalid option: '" ++ opt
                    ++ "': expected 'm' for merge or 'o' for overwrite"
