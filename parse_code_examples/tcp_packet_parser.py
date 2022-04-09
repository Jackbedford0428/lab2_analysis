import os
import numpy as np
import pandas as pd
import datetime as dt
import matplotlib.pyplot as plt
import dpkt
import socket
from dpkt.compat import compat_ord
import enum
from pprint import pprint


# Using enum class to create enumerations
class Payload(enum.IntEnum):
    # !!! Define the length of each packet payload (bytes) !!!
    LENGTH = 250
class StrEnum(str, enum.Enum):
    pass
class Server(StrEnum):
    # !!! Define Server IP (Public/Private) !!!
    PUB_IP = '140.112.20.183'
    PVT_IP = '192.168.1.248'  # ifconfig

def to_utc8(ts):
    """Convert a timestamp to a readable type (at utc-8)
       
       Args:
           ts (float): timestamp composed of datetimedec + microsecond (e.g., 1644051509.989306)
       Returns:
           datetime.datetime: Readable timestamp (at utc-8)
    """
    return (dt.datetime.utcfromtimestamp(ts) + dt.timedelta(hours=8))

def mac_addr(address):
    """Convert a MAC address to a readable/printable string

       Args:
           address (str): a MAC address in hex form (e.g. '\x01\x02\x03\x04\x05\x06')
       Returns:
           str: Printable/readable MAC address
    """
    return ':'.join('%02x' % compat_ord(b) for b in address)

def inet_to_str(inet):
    """Convert inet object to a string

        Args:
            inet (inet struct): inet network address
        Returns:
            str: Printable/readable IP address
    """
    # First try ipv4 and then ipv6
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)

def print_packet(timestamp, buf, idx, fltr=False):
    """Print out information about a packet
       
       Args:
           timestamp: timestamp of a packet in dpkt pcap reader object
           buf: content of a packets in dpkt pcap reader object
           idx: no. of the capture in pcap reader
           fltr (bool): display the info of specific data only (warning message of others still displayed)
       Returns:
           bool: whether it is data we want
    """
    # Print out the timestamp in UTC
    msg1 = 'Timestamp: %s' % str(to_utc8(timestamp))

    # Unpack the Ethernet frame (mac src/dst, ethertype)
    try:
        eth = dpkt.ethernet.Ethernet(buf)
        msg2 = 'Ethernet Frame: %s %s %d' % (mac_addr(eth.src), mac_addr(eth.dst), eth.type)
    except dpkt.NeedData:
        print('Warning: dpkt.NeedData for dpkt.ethernet.Ethernet, try dpkt.sll.SLL (no.%d)' % idx)
        try:
            eth = dpkt.sll.SLL(buf)
        except dpkt.NeedData:
            print('Warning: dpkt.NeedData for dpkt.sll.SLL (no.%d)' % idx)

    # Make sure the Ethernet data contains an IP packet
    if isinstance(eth, dpkt.ethernet.Ethernet):
        if not isinstance(eth.data, dpkt.ip.IP):
            print('Non IP Packet type not supported %s, try dpkt.sll.SLL (no.%d)' % (eth.data.__class__.__name__, idx))
            try:
                eth = dpkt.sll.SLL(buf)
            except dpkt.NeedData:
                print('Warning: dpkt.NeedData for dpkt.sll.SLL (no.%d)' % idx)
    if not isinstance(eth.data, dpkt.ip.IP):
        print('Non IP Packet type not supported %s, forcing the data type into dpkt.ip.IP (no.%d)' % (eth.data.__class__.__name__, idx))
        try:
            vlan_tag = dpkt.ethernet.VLANtag8021Q(eth.data[:4])
            ip = dpkt.ip.IP(eth.data[4:])
        except:
            print('Warning: The Ethernet data does not contain an IP packet (no.%d)' % idx)
    else:
        # Unpack the data within the Ethernet frame (the IP packet)
        # Pulling out src, dst, length, fragment info, TTL, and Protocol
        ip = eth.data

    if fltr:
        # ACK, SYN has no payload (i.e., payload size is zero)
        if (len(ip.data.data) == 0) or ((ip.len - (20+32)) % Payload.LENGTH != 0):
            return False

    # Pull out fragment information (flags and offset all packed into off field, so use bitmasks)
    do_not_fragment = bool(ip.off & dpkt.ip.IP_DF)
    more_fragments = bool(ip.off & dpkt.ip.IP_MF)
    fragment_offset = ip.off & dpkt.ip.IP_OFFMASK

    # Print out the info
    print('----------------------------------------------------------------------')
    print('no.%d' % idx)
    print(msg1)
    print(msg2)
    print('IP: %s -> %s   (len=%d ttl=%d DF=%d MF=%d offset=%d)' % \
          (inet_to_str(ip.src), inet_to_str(ip.dst), ip.len, ip.ttl, do_not_fragment, more_fragments, fragment_offset))
    if (ip.len - (20+32)) % Payload.LENGTH == 0:
        tcp = ip.data
        # tcp.ulen: len( hdr(header)+pyl(payload) )
        print('TCP: %d -> %d                   (len=%d pyl_len=%d)' % \
              (tcp.sport, tcp.dport, tcp.__hdr_len__+len(tcp.opts)+len(tcp.data), len(tcp.data)))
        clogged_num = len(tcp.data) // Payload.LENGTH
        ofst = 0
        if clogged_num > 1:
            print('     clogged')
        for i in range(clogged_num):
            datetimedec = int(tcp.data.hex()[ofst+0:ofst+8], 16)
            microsec = int(tcp.data.hex()[ofst+8:ofst+16], 16)
            pyl_time = str(to_utc8((datetimedec + microsec / 1e6)))
            # seq = int(tcp.data.hex()[ofst+16:ofst+24], 16)
            seq = tcp.seq
            print('     %s      (seq=%d)' % (pyl_time, seq))
            ofst += (Payload.LENGTH*2)  # 1 byte == 2 hexadecimal digits
    print()
    return True

def print_packets(pcap, N=50, fltr=False):
    """Print out information about each packet in the pcap reader

       Args:
           pcap: dpkt pcap reader object (dpkt.pcap.Reader)
           N (int): maximal display number (default: 50)
           fltr (bool): display the info of specific data only (warning message of others still displayed)
    """
    print('=======================================================================')
    # For each packet in the pcap process the contents
    try:
        count = 0
        for i, (timestamp, buf) in enumerate(pcap):
            if count >= N:
                continue
            flag = print_packet(timestamp, buf, i+1, fltr)
            if flag:
                count += 1
    except dpkt.NeedData:
        print('Warning: dpkt.NeedData occurs when iterating pcap reader')

def get_timestamp_DL(pcap):
    """Calculate latency of each arrived packet and analyze the packet loss events

       Args:
           pcap: dpkt pcap reader object (dpkt.pcap.Reader) for UE-side data
       Returns:
           timestamp_list (list): list of timestamps for each packet on UE-side
    """

    # This for loop parse the payload of the iperf3 tcp packets and store the timestamps and the sequence numbers in timestamp_list; 
    # The timestamp is stored in the first 8 bytes, and the sequence number is stored in the 9-12 bytes
    # -------------------------------------------------------------------------------------------------
    timestamp_list = []
    # duplicate packets: 在不同時間點重複收到相同的 seq number (i.e., 發送時間相同的 payload)
    # 雖然 tcp 存在 retransmission，但一般而言，若發生 retransmission，代表前面的 packet 掉了
    # 因此仍推斷 duplicate packets 為不合理的現象，只記錄初次收到的時間戳記，後續收到則忽略不計
    # !!! 即便 retransmission 發生也可能是因為回程的 ACK 沒有被收到，仍然先只記錄初次收到該 packet 的 timestamp !!!
    seq_set = set()
    try:
        for i, (ts, buf) in enumerate(pcap):

            # Extract payload of the tcp packet
            # ---------------------------------
            eth = dpkt.sll.SLL(buf)

            # Unpack the data within the SLL frame (the IP packet)
            if not isinstance(eth.data, dpkt.ip.IP):
                try:
                    vlan_tag = dpkt.ethernet.VLANtag8021Q(eth.data[:4])
                    ip = dpkt.ip.IP(eth.data[4:])
                except:
                    continue
            else:
                ip = eth.data
            
            # Here we set the length checking to be Payload.LENGTH * N + (20+32) to screen out the control messages
            # ACK, SYN has no payload (i.e., payload size is zero)
            if (len(ip.data.data) == 0) or ((ip.len - (20+32)) % Payload.LENGTH != 0):
                continue
            
            # Neglect uplink data
            if inet_to_str(ip.dst) == Server.PUB_IP:
                continue

            # ---------------------- only DL data left ----------------------
            tcp = ip.data

            # clogged packets: 一個 capture 之中，可能存在多個 payload 黏在一起傳
            clogged_num = len(tcp.data) // Payload.LENGTH
            ofst = 0
            for i in range(clogged_num):
                datetimedec = int(tcp.data.hex()[ofst+0:ofst+8], 16)
                microsec = int(tcp.data.hex()[ofst+8:ofst+16], 16)
                pyl_time = str(to_utc8(datetimedec + microsec/1e6))
                # seq = int(tcp.data.hex()[ofst+16:ofst+24], 16)
                seq = tcp.seq
                # !!! 若有中途重啟 iperf (seq number 重置為 1)，推定此前的資料作廢，故重置 timestamp_list 和 seq_set !!!
                # !!! 但目前 tcp_seq-num 抓的是 hdr 中的 raw sequence num (而非 relative seq num)，因此出現 seq num 為 1 的機率微乎其微 !!!
                # !!! 建議實驗時先開 tcpdump 再開 iperf，若需要重啟 iperf，就兩個都一起重開 !!!
                if (seq == 1) and ((pyl_time, seq) not in seq_set):
                    timestamp_list = []
                    seq_set = set()
                if (pyl_time, seq) not in seq_set:
                    # timestamp 格式
                    # ts (float): pcap timestamp (e.g., 1644051509.989306)
                    # datetimedec (int): payload timestamp (e.g., 1644051509)
                    # microsec (int): payload timestamp (e.g., 989306)
                    # seq (int): payload sequence number (e.g., 1)
                    timestamp_list.append((ts, datetimedec, microsec, seq))
                    seq_set.add((pyl_time, seq))
                ofst += (Payload.LENGTH*2)  # 1 byte == 2 hexadecimal digits

    except dpkt.NeedData:
        print('Warning: dpkt.NeedData occurs when iterating pcap reader')

    # 由於前述的兩個處理，可以假定 seq number 不會重複出現，以 seq number 作排序
    # 因為存在 clogged packet，因此 stimestamp[0] 有機會重複
    timestamp_list = sorted(timestamp_list, key = lambda v : v[3])  # We consider out of order tcp packets
    timestamp_list = [(to_utc8(s[0]), to_utc8(s[1]+s[2]/1e6), s[3]) for s in timestamp_list]

    return timestamp_list


if __name__ == "__main__":
    # cellphone_file = "tcp.pcap"
    cellphone_file = "mix.pcap"
    
    f = open(cellphone_file, "rb")
    pcap = dpkt.pcap.Reader(f)
    print_packets(pcap, 20, fltr=True)

    f = open(cellphone_file, "rb")
    pcap = dpkt.pcap.Reader(f)
    ts_list = get_timestamp_DL(pcap)

    prev = ts_list[0]
    ls = []
    for i, item in enumerate(ts_list):
        if i == 0:
            continue
        dif = item[1] - prev[1]
        # print(dif)
        ls.append(dif)
        prev = item
    print('---------------------------')
    print('min    intv', min(ls))
    print('max    intv', max(ls))
    print('median intv', np.median(ls))
    print()

