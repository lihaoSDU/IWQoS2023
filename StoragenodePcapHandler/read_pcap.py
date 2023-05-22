'''
tshark -r storj-upload-by-uplink.pcap  -T fields -E separator=, -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport > analyze.log
'''
import os
import scapy
import argparse
import os
import sys
import time
from scapy.utils import RawPcapReader
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.dns import DNS, dnstypes
from scapy.layers.dns import DNSRR, DNSQR, DNSRRSOA

from scapy.layers.inet import icmptypes, icmpcodes
from scapy.data import IP_PROTOS, ETHER_TYPES
import logging
from collections import defaultdict
from collections import Counter

storagenode_ip_list = []


def process(self):
    # ************
    # program entry
    # ************
    print('Opening {}...'.format(self.pcap_name))

    for (pkt_data, pkt_metadata,) in RawPcapReader(self.pcap_name):
        self.packet_count += 1
        if self.packet_count % 50000 == 0:
            logging.warning('packet number: {}'.format(self.packet_count))
            print('packet number: {}'.format(self.packet_count))


if __name__ == '__main__':
    path = r'E:\博士研究生\Project\decentralized_cloud_storage_network\dss-measurement\pcap\test1\storj-download-by-uplink_five_tuple.log'
    with open(path) as file:
        for line in file.readlines():
            # if 'tcp' in line.strip():
            #     print(line.strip())
            try:
                src_ip, src_port, dst_ip, dst_port = line.strip().split(',')
                if src_ip not in storagenode_ip_list:
                    storagenode_ip_list.append(src_ip)
                    print(src_ip, src_port)

            except Exception as e:
                print(e)
    #
    # for key, value in Counter(storagenode_ip_list).items():
    #     print(key, value)
    print(len(storagenode_ip_list))

