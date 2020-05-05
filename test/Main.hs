{-# language NamedFieldPuns #-}

import Cisco.Asa.Syslog
import Data.Bytes (Bytes)

import qualified Data.Bytes as Bytes

main :: IO ()
main = do
  putStrLn "Starting"
  putStrLn "Test A"
  case decode msgA of
    Nothing -> fail "Could not decode message A"
    Just (M106100 P106100{protocol}) -> do
      assert "protocol" (protocol == Bytes.fromLatinString "tcp")
    Just _ -> fail "Decoded message A incorrectly"
  putStrLn "Finished"

assert :: String -> Bool -> IO ()
assert ctx b = if b then pure () else fail ctx

msgA :: Bytes
msgA = Bytes.fromLatinString "%ASA-6-106100: access-list public denied tcp Private/192.0.2.42(99) -> DMZ/192.0.2.200(18132) hit-cnt 1 first hit [0xef7602a0, 0x00000000]"
