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
from udp_packet_parser import *
from tcp_packet_parser import *


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

def print_packet(timestamp, buf, idx, type_, fltr=False):
    """Print out information about a packet
       
       Args:
           timestamp: timestamp of a packet in dpkt pcap reader object
           buf: content of a packets in dpkt pcap reader object
           idx: no. of the capture in pcap reader
           fltr (bool): display the info of specific data only (some warning message of others will still display)
       Returns:
           bool: whether it is data we want
    """
    if type_ == 'udp':
        return print_packet_udp(timestamp, buf, idx, fltr)
    elif type_ == 'tcp':
        return print_packet_tcp(timestamp, buf, idx, fltr)

def print_packets(pcap, type_, N=50, fltr=False):
    """Print out information about each packet in the pcap reader

       Args:
           pcap: dpkt pcap reader object (dpkt.pcap.Reader)
           N (int): maximal display number (default: 50)
           fltr (bool): display the info of specific data only (some warning message of others will still display)
    """
    if type_ == 'udp':
        print_packets_udp(pcap, N, fltr)
    elif type_ == 'tcp':
        print_packets_tcp(pcap, N, fltr)

def get_timestamp_DL(pcap, type_):
    """Calculate latency of each arrived packet and analyze the packet loss events

       Args:
           pcap: dpkt pcap reader object (dpkt.pcap.Reader) for UE-side data
       Returns:
           timestamp_list (list): list of timestamps for each packet on UE-side
    """
    if type_ == 'udp':
        return get_timestamp_DL_udp(pcap)
    elif type_ == 'tcp':
        return get_timestamp_DL_tcp(pcap)


if __name__ == "__main__":
    # cellphone_file = ""
    # cellphone_file = "udp.pcap"
    cellphone_file = "../data/5G/moving/01.pcap"
    
    f = open(cellphone_file, "rb")
    pcap = dpkt.pcap.Reader(f)
    # print_packets(pcap, 'udp', 100000, fltr=True)
    print_packets(pcap, 'tcp', 100000, fltr=True)

    f = open(cellphone_file, "rb")
    pcap = dpkt.pcap.Reader(f)
    # ts_list = get_timestamp_DL(pcap, 'udp')
    ts_list = get_timestamp_DL(pcap, 'tcp')

    # print('----------------------------------------------------------------------')
    # pprint(ts_list)
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

