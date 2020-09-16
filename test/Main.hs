{-# language DuplicateRecordFields #-}
{-# language NamedFieldPuns #-}

import Cisco.Asa.Syslog
import Data.Bytes (Bytes)

import qualified Data.Bytes as Bytes
import qualified Net.IP as IP
import qualified Net.IPv4 as IPv4

main :: IO ()
main = do
  putStrLn "Starting"
  putStrLn "Test A"
  case decode msgA of
    Nothing -> fail "Could not decode message A"
    Just (M106100 P106100{protocol}) -> do
      assert "protocol" (protocol == Bytes.fromLatinString "tcp")
    Just _ -> fail "Decoded message A incorrectly"
  putStrLn "Test B"
  case decode msgB of
    Nothing -> fail "Could not decode message B"
    Just (M302016 P302016{bytes}) -> do
      assert "bytes" (bytes == 390)
    Just _ -> fail "Decoded message B incorrectly"
  putStrLn "Test C"
  case decode msgC of
    Nothing -> fail "Could not decode message C"
    Just (M302015 P302015{number}) -> do
      assert "number" (number == 64659852)
    Just _ -> fail "Decoded message C incorrectly"
  putStrLn "Test D"
  case decode msgD of
    Nothing -> fail "Could not decode message D"
    Just (M305012 P305012{real}) -> do
      assert "real" $ real == Endpoint
        { interface = Bytes.fromLatinString "traffic"
        , address = IP.fromIPv4 (IPv4.fromOctets 10 67 101 21)
        , port = 12395
        }
    Just _ -> fail "Decoded message D incorrectly"
  putStrLn "Test E"
  case decode msgE of
    Nothing -> fail "Could not decode message E"
    Just (M302014 P302014{bytes}) -> do
      assert "bytes" (bytes == 10316)
    Just _ -> fail "Decoded message E incorrectly"
  putStrLn "Test F"
  case decode msgF of
    Nothing -> fail "Could not decode message F"
    Just (M302013 P302013{}) -> pure ()
    Just _ -> fail "Decoded message F incorrectly"
  putStrLn "Test G"
  case decode msgG of
    Nothing -> fail "Could not decode message G"
    Just (M111010 P111010{command}) ->
      assert "command" (command == Bytes.fromLatinString "no logging message 304001")
    Just _ -> fail "Decoded message G incorrectly"
  putStrLn "Test H"
  case decode msgH of
    Nothing -> fail "Could not decode message H"
    Just (M106023 P106023{acl}) ->
      assert "acl" (acl == Bytes.fromLatinString "inside")
    Just _ -> fail "Decoded message H incorrectly"
  putStrLn "Test I"
  case decode msgI of
    Nothing -> fail "Could not decode message I"
    Just (M302015 P302015{number}) -> do
      assert "number" (number == 154464809)
    Just _ -> fail "Decoded message I incorrectly"
  putStrLn "Test J"
  case decode msgJ of
    Nothing -> fail "Could not decode message J"
    Just (M106015 P106015{from}) -> do
      assert "from" (from == Peer
        {address = IP.fromIPv4 (IPv4.fromOctets 192 0 2 31)
        ,port = 61458
        })
    Just _ -> fail "Decoded message J incorrectly"
  putStrLn "Test K"
  case decode msgK of
    Nothing -> fail "Could not decode message K"
    Just (M722036 P722036{destination}) -> do
      assert "source" (destination == IP.fromIPv4 (IPv4.fromOctets 192 0 2 188))
    Just _ -> fail "Decoded message K incorrectly"
  putStrLn "Finished"

assert :: String -> Bool -> IO ()
assert ctx b = if b then pure () else fail ctx

msgA :: Bytes
msgA = Bytes.fromLatinString "%ASA-6-106100: access-list public denied tcp Private/192.0.2.42(99) -> DMZ/192.0.2.200(18132) hit-cnt 1 first hit [0xef7602a0, 0x00000000]"

msgB :: Bytes
msgB = Bytes.fromLatinString "%ASA-6-302016: Teardown UDP connection 61355178 for foo:10.65.55.198/137 to bar:172.16.17.40/137 duration 0:02:01 bytes 390"

msgC :: Bytes
msgC = Bytes.fromLatinString "%ASA-6-302015: Built outbound UDP connection 64659852 for outside:8.8.8.8/53 (8.8.8.8/53) to traffic:10.66.106.13/3905 (192.0.2.20/3905)"

msgD :: Bytes
msgD = Bytes.fromLatinString "%ASA-6-305012: Teardown dynamic UDP translation from traffic:10.67.101.21/12395 to outside:192.0.2.201/12395 duration 0:00:00"

msgE :: Bytes
msgE = Bytes.fromLatinString "%ASA-6-302014: Teardown TCP connection 142097270 for outside:192.0.2.136/443 to traffic:192.0.2.50/52310 duration 0:00:30 bytes 10316 TCP FINs from traffic"

msgF :: Bytes
msgF = Bytes.fromLatinString "%ASA-6-302013: Built inbound TCP connection 142561430 for traffic:192.0.2.33/53716 (192.0.2.59/53716) to inside1:192.0.2.98/55443 (192.0.2.163/55443)"

msgG :: Bytes
msgG = Bytes.fromLatinString "%ASA-5-111010: User 'enable_15', running 'CLI' from IP 192.0.2.12, executed 'no logging message 304001'"

msgH :: Bytes
msgH = Bytes.fromLatinString "%ASA-4-106023: Deny udp src Inside:192.0.2.15/57462 dst Public:192.0.2.65/5558 by access-group \"inside\" [0xb17391c9, 0xfbd90cb4]"

msgI :: Bytes
msgI = Bytes.fromLatinString "%ASA-6-302015: Built inbound UDP connection 154464809 for traffic:192.0.2.74/123 (192.0.2.74/123) to inside1:172.16.18.49/123 (172.16.18.49/123)"

msgJ :: Bytes
msgJ = Bytes.fromLatinString "%ASA-6-106015: Deny TCP (no connection) from 192.0.2.31/61458 to 192.0.2.38/443 flags RST  on interface traffic"

msgK :: Bytes
msgK = Bytes.fromLatinString "%ASA-6-722036: Group <MY-GRP> User <jdoe> IP <192.0.2.188> Transmitting large packet 1236 (threshold 1200)."
