{-# language DuplicateRecordFields #-}
{-# language LambdaCase #-}
{-# language MagicHash #-}
{-# language NamedFieldPuns #-}

module Cisco.Asa.Syslog
  ( Message(..)
  , P106100(..)
  , P302013(..)
  , P302014(..)
  , P302016(..)
  , P302015(..)
  , P305012(..)
  , Endpoint(..)
  , Duration(..)
  , decode
  ) where

import Prelude hiding (id)

import Data.Bytes (Bytes)
import Data.Bytes.Parser (Parser)
import Data.Word (Word8,Word16,Word64)
import GHC.Exts (Ptr(Ptr))
import Net.Types (IP)

import qualified Data.Bytes.Parser as Parser
import qualified Data.Bytes.Parser.Latin as Latin
import qualified Net.IP as IP

data Message
  = M106100 !P106100
    -- ^ These may be TCP, UDP, or ICMP.
  | M302016 !P302016
    -- ^ These are always UDP.
  | M302015 !P302015
    -- ^ These are always UDP.
  | M305012 !P305012
    -- ^ These may be TCP, UDP, or ICMP.
  | M302014 !P302014
    -- ^ These are always TCP.
  | M302013 !P302013
    -- ^ These are always TCP.

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
  } deriving (Eq)

data P302016 = P302016
  { number :: {-# UNPACK #-} !Word64
  , destination :: !Endpoint
  , source :: !Endpoint
  , duration :: {-# UNPACK #-} !Duration
  , bytes :: !Word64
  }

data P302015 = P302015
  { number :: {-# UNPACK #-} !Word64
  , destination :: !Endpoint
  , source :: !Endpoint
  }

data P305012 = P305012
  { protocol :: {-# UNPACK #-} !Bytes
    -- ^ TCP, UDP, or ICMP
  , real :: !Endpoint
  , mapped :: !Endpoint
  }

data P302014 = P302014
  { number :: {-# UNPACK #-} !Word64
  , destination :: !Endpoint
  , source :: !Endpoint
  , duration :: {-# UNPACK #-} !Duration
  , bytes :: !Word64
  }
  
data P302013 = P302013
  { number :: {-# UNPACK #-} !Word64
  , destination :: !Endpoint
  , source :: !Endpoint
  }

data Duration = Duration
  { hours :: !Word64
  , minutes :: !Word8
  , seconds :: !Word8
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
      302013 -> M302013 <$> parser302013
      302014 -> M302014 <$> parser302014
      302016 -> M302016 <$> parser302016
      302015 -> M302015 <$> parser302015
      305012 -> M305012 <$> parser305012
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

parser302014 :: Parser () s P302014
parser302014 = do
  Parser.cstring () (Ptr "Teardown TCP connection "#)
  number <- Latin.decWord64 ()
  Parser.cstring () (Ptr " for "#)
  destination <- parserEndpointAlt
  Parser.cstring () (Ptr " to "#)
  source <- parserEndpointAlt
  Parser.cstring () (Ptr " duration "#)
  duration <- parserDuration
  Parser.cstring () (Ptr " bytes "#)
  bytes <- Latin.decWord64 ()
  -- Ignore reason for teardown and initiator of teardown. Support
  -- for this can always be added later if needed. 
  pure P302014{number,source,destination,duration,bytes}

parser302013 :: Parser () s P302013
parser302013 = do
  Parser.cstring () (Ptr "Built "#)
  Latin.any () >>= \case
    'i' -> Parser.cstring () (Ptr "nbound TCP connection "#)
    'o' -> Parser.cstring () (Ptr "utbound TCP connection "#)
    _ -> Parser.fail ()
  number <- Latin.decWord64 ()
  Parser.cstring () (Ptr " for "#)
  destination <- parserEndpointAlt
  -- Discards NAT address
  Latin.char2 () ' ' '('
  Latin.skipTrailedBy () ')'
  Parser.cstring () (Ptr " to "#)
  source <- parserEndpointAlt
  -- Discards NAT address
  Latin.char2 () ' ' '('
  Latin.skipTrailedBy () ')'
  -- Ignore reason for teardown and initiator of teardown. Support
  -- for this can always be added later if needed. 
  pure P302013{number,source,destination}

parser302016 :: Parser () s P302016
parser302016 = do
  Parser.cstring () (Ptr "Teardown UDP connection "#)
  number <- Latin.decWord64 ()
  Parser.cstring () (Ptr " for "#)
  destination <- parserEndpointAlt
  Parser.cstring () (Ptr " to "#)
  source <- parserEndpointAlt
  Parser.cstring () (Ptr " duration "#)
  duration <- parserDuration
  Parser.cstring () (Ptr " bytes "#)
  bytes <- Latin.decWord64 ()
  pure P302016{number,source,destination,duration,bytes}

-- Discards the NAT addresses.
parser302015 :: Parser () s P302015
parser302015 = do
  Parser.cstring () (Ptr "Built outbound UDP connection "#)
  number <- Latin.decWord64 ()
  Parser.cstring () (Ptr " for "#)
  destination <- parserEndpointAlt
  Latin.char2 () ' ' '('
  Latin.skipTrailedBy () ')'
  Parser.cstring () (Ptr " to "#)
  source <- parserEndpointAlt
  Latin.char2 () ' ' '('
  Latin.skipTrailedBy () ')'
  pure P302015{number,source,destination}

parser305012 :: Parser () s P305012
parser305012 = do
  Parser.cstring () (Ptr "Teardown "#)
  Latin.skipTrailedBy () ' ' -- keyword is: static or dynamic
  protocol <- Parser.takeTrailedBy () 0x20
  Parser.cstring () (Ptr "translation from "#)
  real <- parserEndpointAlt
  Parser.cstring () (Ptr " to "#)
  mapped <- parserEndpointAlt
  Parser.cstring () (Ptr " duration "#)
  pure P305012{protocol,real,mapped}

parserDuration :: Parser () s Duration
parserDuration = do
  hours <- Latin.decWord64 ()
  Latin.char () ':'
  minutes <- Latin.decWord8 () 
  Latin.char () ':'
  seconds <- Latin.decWord8 () 
  pure Duration{hours,minutes,seconds}
