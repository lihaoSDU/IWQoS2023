'''
Function: extracting TCP/DNS info from the pcap, making sure the specifically flow belongs to Storage Node, Client, or
Satellite Node.
IMPORTANT: ** Please check your nodes_ip before running the script. **
Usage: python3 storj_pcap_handler.py --node storage --pcap /home/lihao/work/storj/pcap/storage_node_dumped/eth0_node_dumped_202103092130.pcap
'''
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

from StoragenodePcapHandler.packets_types import flags_types, DNS_opcodes, nodes_ip


class PacketBase(object):
    def __init__(self):

        self.local_ip = nodes_ip[args.node]
        self.remote_ip = None
        self.local_port = None
        self.remote_port = None
        self.ip_proto = None

        self.relative_offset_ack = 0
        self.relative_offset_seq = 0
        self.relative_offset_timestamp = 0

        self.packet_count = 0
        self.tcp_flow_count = 0
        self.udp_flow_count = 0

        self.satellite_ip_list = list()


class ConnectionBase(PacketBase):
    def __init__(self):
        super(ConnectionBase, self).__init__()
        
        self.src_port = None
        self.dst_port = None
        self.src_ip = None
        self.dst_ip = None

        self.tcp_seq = None
        self.tcp_ack = None

        self.unique_ips = defaultdict(int)


class PacketHandlerUtils(object):
    def __init__(self):
        self.timestamp = 0
        self.local_ip = nodes_ip[args.node]
        self.remote_ip = None
        self.local_port = None
        self.remote_port = None

    def printable_timestamp(slef, ts, resol):

        ts_sec = ts // resol
        ts_subsec = ts % resol
        ts_sec_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(ts_sec))
        slef.timestamp = '{}.{}'.format(ts_sec, ts_subsec)
        return '{}.{}'.format(ts_sec_str, ts_subsec)

    def meta_pkt_timestamp(self, pkt_metadata, pkt_count):

        pkt_ordinal = pkt_count

        if len(pkt_metadata) == 4:
            self.timestamp = '{}.{}'.format(pkt_metadata.sec, pkt_metadata.usec)
            ts_sec_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(pkt_metadata.sec))
            logging.info('Packet in connection: Packet #{} Timestamp {}'.format(pkt_ordinal, ts_sec_str))

        elif len(pkt_metadata) == 5:
            pkt_timestamp = (pkt_metadata.tshigh << 32) | pkt_metadata.tslow
            pkt_timestamp_resolution = pkt_metadata.tsresol

            Timestamp = self.printable_timestamp(pkt_timestamp, pkt_timestamp_resolution)
            logging.info('Packet in connection: Packet #{} Timestamp {}'.format(pkt_ordinal, Timestamp))

        return self.timestamp

    def identify_ssh(self, src_port, dst_port):
        if src_port == 22 or dst_port == 22:
            return True
        return False

    def conn_tuple(self, src_ip, src_port, dst_ip, dst_port, ip_proto):

        if src_ip == self.local_ip:
            self.local_ip = src_ip
            self.local_port = src_port
            self.remote_ip = dst_ip
            self.remote_port = dst_port

        elif dst_ip == self.local_ip:
            self.local_ip = dst_ip
            self.local_port = dst_port
            self.remote_ip = src_ip
            self.remote_port = src_port

        connection_tuple = "{local_ip}_{local_port}_{remote_ip}_{remote_port}_{ip_proto}".format(
            local_ip=self.local_ip,
            local_port=self.local_port,
            remote_ip=self.remote_ip,
            remote_port=self.remote_port,
            ip_proto=ip_proto
        )

        return connection_tuple


class StorjPcapHandlerBase(ConnectionBase, PacketBase):
    def __init__(self, pcap_name):
        super(StorjPcapHandlerBase, self).__init__()
        self.pcap_name = pcap_name

    def node_state_judgement(self, connection_tuple):

        tcp_flow = self.unique_ips[connection_tuple]

        # first SYN packet of the flow
        # first SYN,ACK packet of the flow
        # last FIN,ACK packet of the flow though still have RST packet, but we only use the FIN,ACK's raw ack and seq
        syn_packet = tcp_flow[list(tcp_flow.keys())[0]]
        syn_ack_packet = tcp_flow[list(tcp_flow.keys())[1]]
        fin_ack_packet = tcp_flow[list(tcp_flow.keys())[-1]]

        self.relative_offset_seq = fin_ack_packet['tcp_seq'] - syn_ack_packet['tcp_seq']
        self.relative_offset_ack = fin_ack_packet['tcp_ack'] - syn_ack_packet['tcp_ack']
        self.relative_offset_timestamp = float(fin_ack_packet['timestamp']) - float(syn_packet['timestamp'])

        remote_port = connection_tuple.split('_')[-2]
        remote_ip = connection_tuple.split('_')[-3]

        # case 1: http flow
        if remote_port == '80':
            logging.info('A HTTP flow: {}'.format(connection_tuple))
            return connection_tuple

        # case 2: satellite node flow
        if str(remote_port) == '7777':
            logging.info('A connect with the Satellite flow: {}'.format(connection_tuple))
            return connection_tuple

        # case 3: normal tcp flow
        if syn_ack_packet['flags'] == 'SYN_ACK' and fin_ack_packet['flags'] == 'FIN_ACK':
            if self.relative_offset_seq < self.relative_offset_ack:
                logging.warning("{} is an upload flow, uploading spent {}s".format(
                    connection_tuple, self.relative_offset_timestamp))
            else:
                logging.warning("{} is a download flow, downloading spent {}s".format(
                    connection_tuple, self.relative_offset_timestamp))

            return connection_tuple

        # case 4: RST,ACK flow due to client shutdown signal
        if syn_ack_packet['flags'] == 'SYN_ACK' and fin_ack_packet['flags'] == 'RST_ACK':
            self.relative_offset_seq = fin_ack_packet['tcp_seq'] - syn_ack_packet['tcp_ack']
            self.relative_offset_ack = fin_ack_packet['tcp_ack'] - syn_ack_packet['tcp_seq']
            self.relative_offset_timestamp = float(fin_ack_packet['timestamp']) - float(syn_packet['timestamp'])

            if self.relative_offset_seq > self.relative_offset_ack:
                logging.warning("{} is an upload flow, uploading spent {}s".format(
                    connection_tuple, self.relative_offset_timestamp))
            else:
                logging.warning("{} is a download flow, downloading spent {}s".format(
                    connection_tuple, self.relative_offset_timestamp))

            return connection_tuple

    def process(self):
        # ************
        # program entry
        # ************
        print('Opening {}...'.format(self.pcap_name))

        for (pkt_data, pkt_metadata, ) in RawPcapReader(self.pcap_name):
            self.packet_count += 1
            if self.packet_count % 50000 == 0:
                logging.warning('packet number: {}'.format(self.packet_count))
                print('packet number: {}'.format(self.packet_count))

            packet_handler_utils = PacketHandlerUtils()
            self.timestamp = packet_handler_utils.meta_pkt_timestamp(pkt_metadata, self.packet_count)

            # convert to Ether layer packet pattern
            ether_pkt = Ether(pkt_data)

            if ETHER_TYPES[ether_pkt.type] != 'IPv4':
                # disregard non-IPv4 packets
                continue

            # convert to IP layer packet pattern
            ip_pkt = ether_pkt[IP]
            if (ip_pkt.flags == 'MF') or (ip_pkt.frag != 0):
                # Determine the TCP payload length. IP fragmentation will mess up this
                # logic, so first check that this is an un-fragmented packet
                logging.error('No support for fragmented IP packets')
                break

            self.src_ip = ip_pkt.src
            self.dst_ip = ip_pkt.dst
            self.ip_proto = IP_PROTOS[ip_pkt.proto]

            if self.ip_proto == 'icmp':
                icmp_pcap_handler = PcapHandlerICMP()
                icmp_pcap_handler.parse_icmp_packet(self.packet_count, self.timestamp, ip_pkt)

            if self.ip_proto == 'udp':
                # In captured storage node traffic, there is no UDP/DNS flow
                PcapHandlerDNS.parse_dns_packet(self, self.timestamp, self.ip_proto, ip_pkt)

            if self.ip_proto == 'tcp':
                is_ssh, connection_tuple = PcapHandlerTCP.parse_tcp_packet(self, ip_pkt)
                if is_ssh:
                    continue

                if len(str(connection_tuple).split('_')) == 5:
                    # {local_ip}_{local_port}_{remote_ip}_{remote_port}_{ip_proto}
                    five_tuple = self.node_state_judgement(connection_tuple)

            if self.packet_count == -1:
                break

        print('{} contains {} packets, {} TCP flows, {} UDP flows'.format(self.pcap_name, self.packet_count,
                                                                          self.tcp_flow_count, self.udp_flow_count))


class PcapHandlerICMP(StorjPcapHandlerBase):
    def __init__(self):
        super(PcapHandlerICMP, self).__init__(StorjPcapHandlerBase)

    def parse_icmp_packet(self, packet_count, timestamp, ip_pkt):
        icmp_pkt = ip_pkt[ICMP]

        icmp_pkt_type = icmptypes[icmp_pkt.type]
        if icmp_pkt.type in icmpcodes.keys():
            icmp_pkt_code = icmpcodes[icmp_pkt.type][icmp_pkt.code]
        else:
            icmp_pkt_code = icmp_pkt.code
        icmp_pkt_chksum = icmp_pkt.chksum
        icmp_pkt_id = icmp_pkt.id
        icmp_pkt_seq = icmp_pkt.seq

        logging.info("ICMP: {}".format([packet_count, timestamp, ip_pkt.src, ip_pkt.dst, IP_PROTOS[ip_pkt.proto],
                                        icmp_pkt_type, icmp_pkt_code, icmp_pkt_chksum, icmp_pkt_id, icmp_pkt_seq]))


class PcapHandlerDNS(ConnectionBase, PacketBase):
    def __init__(self):
        super(PcapHandlerDNS, self).__init__()

    def parse_dns_packet(self, timestamp, ip_proto, ip_pkt):

        src_ip = ip_pkt.src
        dst_ip = ip_pkt.dst

        udp_pkt = ip_pkt[UDP]
        src_port = udp_pkt.sport
        dst_port = udp_pkt.dport
        udp_pkt_len = udp_pkt.len
        udp_pkt_chksum = udp_pkt.chksum

        packet_handler_utils = PacketHandlerUtils()

        connection_tuple = packet_handler_utils.conn_tuple(src_ip, src_port, dst_ip, dst_port, ip_proto)
        connection_tuple_to_latest_identifier = {}

        connection_tuple_to_latest_identifier.update({'packet_count': self.packet_count})
        connection_tuple_to_latest_identifier.update({'timestamp': timestamp})
        connection_tuple_to_latest_identifier.update({'src_ip': src_ip})
        connection_tuple_to_latest_identifier.update({'dst_ip': dst_ip})
        connection_tuple_to_latest_identifier.update({'src_port': src_port})
        connection_tuple_to_latest_identifier.update({'dst_port': dst_port})
        connection_tuple_to_latest_identifier.update({'proto': ip_proto})

        connection_tuple_to_latest_identifier.update({'udp_pkt_len': udp_pkt_len})
        connection_tuple_to_latest_identifier.update({'udp_pkt_chksum': udp_pkt_chksum})

        if 'DNS' in udp_pkt:
            # **** DNS flow ****
            dns_pkt = udp_pkt[DNS]

            dns_pkt_opcode = udp_pkt[DNS].opcode  # {0: "QUERY", 1: "IQUERY", 2: "STATUS"}
            connection_tuple_to_latest_identifier.update({'DNS_opcodes': DNS_opcodes[dns_pkt_opcode]})

            if 'DNSQR' in dns_pkt:
                dns_pkt_qname = dns_pkt.qd.qname
                dns_pkt_qtype = dnstypes[dns_pkt.qd.qtype]
                connection_tuple_to_latest_identifier.update({'dns_pkt_qtype': dns_pkt_qtype})
                connection_tuple_to_latest_identifier.update({'dns_pkt_qname': dns_pkt_qname.decode()})

            if 'DNSRR' in dns_pkt:
                dnsrr_pkt = dns_pkt[DNSRR]

                dnsrr_pkt_rrname = dnsrr_pkt.rrname.decode()
                dnsrr_pkt_type = dnstypes[dnsrr_pkt.type]
                dnsrr_pkt_rdata = dnsrr_pkt.rdata

                if [1] * 4 == [x.isdigit() and 0 <= int(x) <= 255 for x in dnsrr_pkt_rdata.split(".")]:
                    if dnsrr_pkt_rdata not in self.satellite_ip_list:
                        self.satellite_ip_list.append(dnsrr_pkt_rdata)

                connection_tuple_to_latest_identifier.update({'dnsrr_pkt_rrname': dnsrr_pkt_rrname})
                connection_tuple_to_latest_identifier.update({'dnsrr_pkt_type': dnsrr_pkt_type})
                connection_tuple_to_latest_identifier.update({'dnsrr_pkt_rdata': dnsrr_pkt_rdata})

            if 'DNSRRSOA' in dns_pkt:
                dnsrrsoa_pkt = dns_pkt[DNSRRSOA]

                dnsrrsoa_pkt_rrname = dnsrrsoa_pkt.rrname.decode()
                dnsrrsoa_pkt_mname = dnsrrsoa_pkt.mname.decode()
                dnsrrsoa_pkt_rname = dnsrrsoa_pkt.rname.decode()
                dnsrrsoa_pkt_type = dnstypes[dnsrrsoa_pkt.type]
                connection_tuple_to_latest_identifier.update({'dnsrrsoa_pkt_rrname': dnsrrsoa_pkt_rrname})
                connection_tuple_to_latest_identifier.update({'dnsrrsoa_pkt_mname': dnsrrsoa_pkt_mname})
                connection_tuple_to_latest_identifier.update({'dnsrrsoa_pkt_rname': dnsrrsoa_pkt_rname})
                connection_tuple_to_latest_identifier.update({'dnsrrsoa_pkt_type': dnsrrsoa_pkt_type})

            if dns_pkt.ar != None:
                # TODO
                print('dns_pkt.ar:', repr(dns_pkt))

            if connection_tuple not in self.unique_ips.keys():
                identifier = {}
                self.udp_flow_count += 1
                identifier.update({str(self.packet_count): connection_tuple_to_latest_identifier})
                self.unique_ips.update({connection_tuple: identifier})
            else:
                self.unique_ips[connection_tuple].update({str(self.packet_count): connection_tuple_to_latest_identifier})

        elif 'NTPHeader' in udp_pkt:
            logging.info("DNS: {}".format([self.packet_count, timestamp, src_ip, dst_ip,
                                           src_port, dst_port]))
        else:
            logging.error("DNS: {}".format([self.packet_count, timestamp, src_ip, dst_ip,
                                           src_port, dst_port]))

        return 0


class PcapHandlerTCP(StorjPcapHandlerBase):
    def __init__(self):
        super(PcapHandlerTCP, self).__init__(StorjPcapHandlerBase)

    def parse_tcp_packet(self, ip_pkt):
        tcp_pkt = ip_pkt[TCP]

        self.src_port = tcp_pkt.sport
        self.dst_port = tcp_pkt.dport

        # we don't consider SSH flow
        is_ssh = PacketHandlerUtils().identify_ssh(self.src_port, self.dst_port)
        if is_ssh:
            return is_ssh, None

        # tcp flow info
        self.tcp_seq = tcp_pkt.seq
        self.tcp_ack = tcp_pkt.ack
        tcp_pkt_dataofs = tcp_pkt.dataofs
        tcp_pkt_reserved = tcp_pkt.reserved
        tcp_pkt_flags = tcp_pkt.flags
        tcp_pkt_window = tcp_pkt.window
        tcp_pkt_chksum = tcp_pkt.chksum
        tcp_pkt_is_tls = False

        packet_handler_utils = PacketHandlerUtils()
        connection_tuple = packet_handler_utils.conn_tuple(self.src_ip, self.src_port, self.dst_ip,
                                                           self.dst_port, self.ip_proto)
        self.remote_ip = str(connection_tuple).split('_')[-3]

        logging.info("TCP: {}".format([self.packet_count, self.timestamp, self.src_ip, self.dst_ip, self.src_port,
                                       self.dst_port, self.tcp_seq, self.tcp_ack, flags_types[str(tcp_pkt.flags)]]))

        connection_tuple_to_latest_identifier = {}
        connection_tuple_to_latest_identifier.update({'packet_count': self.packet_count})
        connection_tuple_to_latest_identifier.update({'timestamp': self.timestamp})
        connection_tuple_to_latest_identifier.update({'src_ip': self.src_ip})
        connection_tuple_to_latest_identifier.update({'dst_ip': self.dst_ip})
        connection_tuple_to_latest_identifier.update({'src_port': self.src_port})
        connection_tuple_to_latest_identifier.update({'dst_port': self.dst_port})
        connection_tuple_to_latest_identifier.update({'proto': self.ip_proto})

        connection_tuple_to_latest_identifier.update({'tcp_seq': self.tcp_seq})
        connection_tuple_to_latest_identifier.update({'tcp_ack': self.tcp_ack})
        connection_tuple_to_latest_identifier.update({'flags': flags_types[str(tcp_pkt_flags)]})

        connection_tuple_to_latest_identifier.update({'tcp_pkt_dataofs': tcp_pkt_dataofs})
        connection_tuple_to_latest_identifier.update({'tcp_pkt_reserved': tcp_pkt_reserved})
        connection_tuple_to_latest_identifier.update({'tcp_pkt_window': tcp_pkt_window})
        connection_tuple_to_latest_identifier.update({'tcp_pkt_chksum': tcp_pkt_chksum})

        if 'Raw' in tcp_pkt:
            if str(self.src_port) != '80' and str(self.dst_port) != '80':
                tcp_pkt_is_tls = True
        connection_tuple_to_latest_identifier.update({'tcp_pkt_is_tls': tcp_pkt_is_tls})

        if connection_tuple not in self.unique_ips.keys():
            if flags_types[str(tcp_pkt_flags)] == 'SYN':
                # first SYN packet in three handshake process
                self.tcp_flow_count += 1
                identifier = {}
                identifier.update({str(self.packet_count): connection_tuple_to_latest_identifier})
                self.unique_ips.update({connection_tuple: identifier})
        else:
            self.unique_ips[connection_tuple].update({str(self.packet_count): connection_tuple_to_latest_identifier})
            # here in storage mode, we set src_ip as local ip. If in client mode, we set src_ip as remote ip
            if args.node == 'storage':
                fin_ack_src_ip = self.local_ip
            elif args.node == 'client':
                fin_ack_src_ip = self.remote_ip

            if flags_types[str(tcp_pkt_flags)] == 'RST_ACK':
                # last one packet if {RST,ACK}.
                logging.error('number: {}, RST_ACK flow: {}'.format(self.packet_count, connection_tuple))
                return False, connection_tuple

            if flags_types[str(tcp_pkt_flags)] == 'FIN_ACK' and (self.src_ip == fin_ack_src_ip):
                # last one packet if {FIN,ACK}.
                return False, connection_tuple

        return False, None


if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='PCAP reader')
    parser.add_argument('--pcap', metavar='<pcap file name>',
                        default=r'',
                        help='pcap file to parse', required=False)
    parser.add_argument('--node', metavar='<node (client, storage)>', help='handle different node types traffic',
                        default='storage', required=False)
    parser.add_argument('--log_name', default='storage_flow.log')
    args = parser.parse_args()

    logging.basicConfig(level=logging.WARNING, format='%(asctime)s - %(name)s - %(message)s',
                        filename=args.log_name)

    file_name = args.pcap
    if not os.path.isfile(file_name):
        print('"{}" does not exist'.format(file_name), file=sys.stderr)
        sys.exit(-1)

    if args.node not in nodes_ip.keys():
        print('"{}" is not a correct node name'.format(args.node), file=sys.stderr)
        sys.exit(-1)

    storj_pcap_handler_base = StorjPcapHandlerBase(pcap_name=file_name)
    storj_pcap_handler_base.process()

    sys.exit(0)