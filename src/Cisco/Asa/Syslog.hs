{-# language DuplicateRecordFields #-}
{-# language LambdaCase #-}
{-# language MagicHash #-}
{-# language NamedFieldPuns #-}

module Cisco.Asa.Syslog
  ( Message(..)
  , P106015(..)
  , P106100(..)
  , P106023(..)
  , P111010(..)
  , P302013(..)
  , P302014(..)
  , P302016(..)
  , P302015(..)
  , P305012(..)
  , P722036(..)
  , Peer(..)
  , Endpoint(..)
  , Duration(..)
  , Direction(..)
  , decode
  ) where

import Prelude hiding (id,length)

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
  | M111010 !P111010
    -- ^ These are not network traffic.
  | M106023 !P106023
    -- ^ Denied network traffic. At least TCP and UDP.
  | M106015 !P106015
    -- ^ Denied TCP connections.
  | M722036 !P722036
    -- ^ Transmitting large packet (UDP)

-- | Cisco uses the keywords @inbound@ and @outbound@ in some logs. The
-- keyword @inbound@ means that a connection was initiated from @outside@
-- (also a word with a special meaning). Similarly, @outbound@ means that
-- a connection was initiated from @inside@. Direction is used to indicate
-- who the server and client are in a TCP session. Consider:
--
-- > <166>%ASA-6-302013: Built inbound TCP connection 153620014 for outside:192.0.2.13/56813 (192.0.2.13/56813) to identity:192.0.2.241/443 (192.0.2.241/443)
-- > <166>%ASA-6-302013: Built outbound TCP connection 153620015 for identity:192.0.2.229/443 (192.0.2.229/443) to outside:192.0.2.5/60134 (192.0.2.5/60134)
--
-- In the first log, @192.0.2.13/56813@ initiated the connection, but in the
-- second log, @192.0.2.5/60134@ initiated the connection. Undoubtedly, this
-- is a confusing way to do this, but it is how Cisco does it. Logs with
-- @for@ and @to@ fields also have a @direction@ field that provides a
-- way to interpret them.
data Direction = Inbound | Outbound

-- | An IP address and a port.
data Peer = Peer
  { address :: {-# UNPACK #-} !IP
  , port :: {-# UNPACK #-} !Word16
  } deriving (Eq)

-- | An IP address, a port, and an interface name.
data Endpoint = Endpoint
  { interface :: {-# UNPACK #-} !Bytes
  , address :: {-# UNPACK #-} !IP
  , port :: {-# UNPACK #-} !Word16
  } deriving (Eq)

data P106100 = P106100
  { id :: {-# UNPACK #-} !Bytes
  , action :: {-# UNPACK #-} !Bytes
  , protocol :: {-# UNPACK #-} !Bytes
  , source :: !Endpoint
  , destination :: !Endpoint
  }

data P302016 = P302016
  { number :: {-# UNPACK #-} !Word64
  , destination :: !Endpoint
  , source :: !Endpoint
  , duration :: {-# UNPACK #-} !Duration
  , bytes :: !Word64
  }

data P302015 = P302015
  { direction :: !Direction
  , number :: {-# UNPACK #-} !Word64
  , for :: !Endpoint
  , to :: !Endpoint
  }

data P106015 = P106015
  { from :: !Peer
  , to :: !Peer
  }

data P305012 = P305012
  { protocol :: {-# UNPACK #-} !Bytes
    -- ^ TCP, UDP, or ICMP
  , real :: !Endpoint
  , mapped :: !Endpoint
  }

data P106023 = P106023
  { protocol :: {-# UNPACK #-} !Bytes
  , source :: !Endpoint
  , destination :: !Endpoint
  , acl :: {-# UNPACK #-} !Bytes
    -- ^ ACL ID
  }

-- | Note: From a 302014 log alone, it is not possible to determine
-- which endpoint is the source and which endpoint is the destination.
-- The only options are:
--
-- * Use the session number to match it with its corresponding 302013 log.
-- * Guess that a low port number is the destination.
data P302014 = P302014
  { number :: {-# UNPACK #-} !Word64
  , for :: !Endpoint
  , to :: !Endpoint
  , duration :: {-# UNPACK #-} !Duration
  , bytes :: !Word64
  }

data P302013 = P302013
  { number :: {-# UNPACK #-} !Word64
  , direction :: !Direction
  , for :: !Endpoint
  , to :: !Endpoint
  }

-- Example from Cisco docs:
-- %ASA-5-111010: User username , running application-name from IP ip addr , executed cmd 
data P111010 = P111010
  { username :: {-# UNPACK #-} !Bytes
  , application :: {-# UNPACK #-} !Bytes
  , managementStation :: {-# UNPACK #-} !IP
  , command :: {-# UNPACK #-} !Bytes
  }

-- Example from test suite: %ASA-6-722036: Group <MY-GRP> User <jdoe> IP <192.0.2.188> Transmitting large packet 1236 (threshold 1200).
data P722036 = P722036
  { group :: {-# UNPACK #-} !Bytes
  , user :: {-# UNPACK #-} !Bytes
  , destination :: {-# UNPACK #-} !IP
  , length :: {-# UNPACK #-} !Word64
  , threshold :: {-# UNPACK #-} !Word64
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
  _ <- Latin.decWord ()
  Latin.char () '-'
  msgNum <- Latin.decWord ()
  Latin.char2 () ':' ' '
  case msgNum of
    106015 -> M106015 <$> parser106015
    106023 -> M106023 <$> parser106023
    106100 -> M106100 <$> parser106100
    111010 -> M111010 <$> parser111010
    302013 -> M302013 <$> parser302013
    302014 -> M302014 <$> parser302014
    302015 -> M302015 <$> parser302015
    302016 -> M302016 <$> parser302016
    305012 -> M305012 <$> parser305012
    722036 -> M722036 <$> parser722036
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

parser106015 :: Parser () s P106015
parser106015 = do
  Parser.cstring () (Ptr "Deny TCP (no connection) from "#)
  from <- parserPeer
  Parser.cstring () (Ptr " to "#)
  to <- parserPeer
  -- Discard flags and interface. Possibly remedy this later.
  pure P106015{from,to}

-- Looks for endpoint as: ipaddr/port
parserPeer :: Parser () s Peer
parserPeer = do
  address <- IP.parserUtf8Bytes ()
  Latin.char () '/'
  port <- Latin.decWord16 ()
  pure Peer{address,port}

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
  for <- parserEndpointAlt
  Parser.cstring () (Ptr " to "#)
  to <- parserEndpointAlt
  Parser.cstring () (Ptr " duration "#)
  duration <- parserDuration
  Parser.cstring () (Ptr " bytes "#)
  bytes <- Latin.decWord64 ()
  -- Ignore reason for teardown and initiator of teardown. Support
  -- for this can always be added later if needed. 
  pure P302014{number,for,to,duration,bytes}

parser302013 :: Parser () s P302013
parser302013 = do
  Parser.cstring () (Ptr "Built "#)
  direction <- directionParser
  Parser.cstring () (Ptr " TCP connection "#)
  number <- Latin.decWord64 ()
  Parser.cstring () (Ptr " for "#)
  for <- parserEndpointAlt
  -- Discards NAT address
  Latin.char2 () ' ' '('
  Latin.skipTrailedBy () ')'
  Parser.cstring () (Ptr " to "#)
  to <- parserEndpointAlt
  -- Discards NAT address
  Latin.char2 () ' ' '('
  Latin.skipTrailedBy () ')'
  pure P302013{number,direction,for,to}

directionParser :: Parser () s Direction
directionParser = Latin.any () >>= \case
  'i' -> do
    Parser.cstring () (Ptr "nbound"#)
    pure Inbound
  'o' -> do
    Parser.cstring () (Ptr "utbound"#)
    pure Outbound
  _ -> Parser.fail ()

parser302015 :: Parser () s P302015
parser302015 = do
  Parser.cstring () (Ptr "Built "#)
  direction <- directionParser
  Parser.cstring () (Ptr " UDP connection "#)
  number <- Latin.decWord64 ()
  Parser.cstring () (Ptr " for "#)
  for <- parserEndpointAlt
  -- Discards NAT address
  Latin.char2 () ' ' '('
  Latin.skipTrailedBy () ')'
  Parser.cstring () (Ptr " to "#)
  to <- parserEndpointAlt
  -- Discards NAT address
  Latin.char2 () ' ' '('
  Latin.skipTrailedBy () ')'
  pure P302015{number,direction,for,to}

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

parser111010 :: Parser () s P111010
parser111010 = do
  Parser.cstring () (Ptr "User '"#)
  username <- Parser.takeTrailedBy () 0x27 -- single quote
  Parser.cstring () (Ptr ", running '"#)
  application <- Parser.takeTrailedBy () 0x27 -- single quote
  Parser.cstring () (Ptr " from IP "#)
  managementStation <- IP.parserUtf8Bytes ()
  Parser.cstring () (Ptr ", executed '"#)
  command <- Parser.takeTrailedBy () 0x27 -- single quote
  pure P111010{username,application,managementStation,command}

parser106023 :: Parser () s P106023
parser106023 = do
  Parser.cstring () (Ptr "Deny "#)
  protocol <- Parser.takeTrailedBy () 0x20
  Parser.cstring () (Ptr "src "#)
  source <- parserEndpointAlt
  Parser.cstring () (Ptr " dst "#)
  destination <- parserEndpointAlt
  Parser.cstring () (Ptr " by access-group \""#)
  acl <- Parser.takeTrailedBy () 0x22 -- double quote
  pure P106023{protocol,source,destination,acl}

parser722036 :: Parser () s P722036
parser722036 = do
  Parser.cstring () (Ptr "Group <"#)
  group <- Parser.takeTrailedBy () 0x3E
  Parser.cstring () (Ptr " User <"#)
  user <- Parser.takeTrailedBy () 0x3E
  Parser.cstring () (Ptr " IP <"#)
  destination <- IP.parserUtf8Bytes ()
  Parser.cstring () (Ptr "> Transmitting large packet "#)
  length <- Latin.decWord64 ()
  Parser.cstring () (Ptr " (threshold "#)
  threshold <- Latin.decWord64 ()
  pure P722036{group,user,destination,length,threshold}

parserDuration :: Parser () s Duration
parserDuration = do
  hours <- Latin.decWord64 ()
  Latin.char () ':'
  minutes <- Latin.decWord8 () 
  Latin.char () ':'
  seconds <- Latin.decWord8 () 
  pure Duration{hours,minutes,seconds}
