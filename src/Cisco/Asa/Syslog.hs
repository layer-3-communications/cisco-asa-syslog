{-# language MagicHash #-}
{-# language NamedFieldPuns #-}

module Cisco.Asa.Syslog
  ( Message(..)
  , P106100(..)
  , Endpoint(..)
  , decode
  ) where

import Prelude hiding (id)

import Data.Bytes (Bytes)
import Data.Bytes.Parser (Parser)
import Data.Word (Word16)
import GHC.Exts (Ptr(Ptr))
import Net.Types (IP)

import qualified Data.Bytes.Parser as Parser
import qualified Data.Bytes.Parser.Latin as Latin
import qualified Net.IP as IP

data Message
  = M106100 !P106100

data P106100 = P106100
  { id :: {-# UNPACK #-} !Bytes
  , action :: {-# UNPACK #-} !Bytes
  , protocol :: {-# UNPACK #-} !Bytes
  , source :: !Endpoint
  , destination :: !Endpoint
  }

data Endpoint = Endpoint
  { interface :: {-# UNPACK #-} !Bytes
  , address :: {-# UNPACK #-} !IP
  , port :: {-# UNPACK #-} !Word16
  }

decode :: Bytes -> Maybe Message
decode = Parser.parseBytesMaybe parser

parser :: Parser () s Message
parser = do
  Latin.char5 () '%' 'A' 'S' 'A' '-'
  sev <- Latin.decWord ()
  Latin.char () '-'
  msgNum <- Latin.decWord ()
  Latin.char2 () ':' ' '
  case sev of
    6 -> case msgNum of
      106100 -> M106100 <$> parser106100
      _ -> Parser.fail ()
    _ -> Parser.fail ()

parser106100 :: Parser () s P106100
parser106100 = do
  Parser.cstring () (Ptr "access-list "#)
  id <- Parser.takeTrailedBy () 0x20
  action <- Parser.takeTrailedBy () 0x20
  protocol <- Parser.takeTrailedBy () 0x20
  source <- parserEndpoint
  Latin.char4 () ' ' '-' '>' ' '
  destination <- parserEndpoint
  pure P106100{id,action,protocol,source,destination}

parserEndpoint :: Parser () s Endpoint
parserEndpoint = do
  interface <- Parser.takeTrailedBy () 0x2F
  address <- IP.parserUtf8Bytes ()
  Latin.char () '('
  port <- Latin.decWord16 ()
  Latin.char () ')'
  pure Endpoint{interface,address,port}
