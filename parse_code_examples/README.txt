===================================
資料
===================================
udp.pcap: (UE-side) downlink udp
tcp.pcap: (UE-side) downlink tcp
mix.pcap: (UE-side) downlink tcp/udp (透過兩個 port 同時傳 udp/tcp，手機端把兩者的資料混在同個 pcap 檔)

_server.pcap: (server-side)

Setting: 
每 0.3 秒傳一個 packet
每個 packet 250 bytes


===================================
_parser.py
===================================
解析檔                  <= INPUT_FILE
udp_packet_parser.py <= udp.pcap/mix.pcap
tcp_packet_parser.py <= tcp.pcap/mix.pcap