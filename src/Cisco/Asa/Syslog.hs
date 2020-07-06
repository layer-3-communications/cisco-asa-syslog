{-# language DuplicateRecordFields #-}
{-# language MagicHash #-}
{-# language NamedFieldPuns #-}

module Cisco.Asa.Syslog
  ( Message(..)
  , P106100(..)
  , P302016(..)
  , Endpoint(..)
  , decode
  ) where

import Prelude hiding (id)

import Data.Bytes (Bytes)
import Data.Bytes.Parser (Parser)
import Data.Word (Word16,Word64)
import GHC.Exts (Ptr(Ptr))
import Net.Types (IP)

import qualified Data.Bytes.Parser as Parser
import qualified Data.Bytes.Parser.Latin as Latin
import qualified Net.IP as IP

data Message
  = M106100 !P106100
  | M302016 !P302016

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

data P302016 = P302016
  { number :: {-# UNPACK #-} !Word64
  , source :: !Endpoint
  , destination :: !Endpoint
  , bytes :: !Word64
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
      302016 -> M302016 <$> parser302016
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

-- Looks for endpoint as: intf/ipaddr(port)
parserEndpoint :: Parser () s Endpoint
parserEndpoint = do
  interface <- Parser.takeTrailedBy () 0x2F
  address <- IP.parserUtf8Bytes ()
  Latin.char () '('
  port <- Latin.decWord16 ()
  Latin.char () ')'
  pure Endpoint{interface,address,port}

-- Looks for endpoint as: intf:ipaddr/port
-- Cisco encodes endpoints differently in different kinds of logs.
parserEndpointAlt :: Parser () s Endpoint
parserEndpointAlt = do
  interface <- Parser.takeTrailedBy () 0x3A
  address <- IP.parserUtf8Bytes ()
  Latin.char () '/'
  port <- Latin.decWord16 ()
  pure Endpoint{interface,address,port}

parser302016 :: Parser () s P302016
parser302016 = do
  Parser.cstring () (Ptr "Teardown UDP connection "#)
  number <- Latin.decWord64 ()
  Parser.cstring () (Ptr " for "#)
  source <- parserEndpointAlt
  Parser.cstring () (Ptr " to "#)
  destination <- parserEndpointAlt
  Parser.cstring () (Ptr " duration "#)
  Parser.skipTrailedBy () 0x20
  Parser.cstring () (Ptr "bytes "#)
  bytes <- Latin.decWord64 ()
  pure P302016{number,source,destination,bytes}

