from scapy.all import *
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.dns import DNS, dnstypes
from scapy.layers.inet import icmptypes

nodes_ip = {
    'client': '10.0.4.4',
    'storage': '192.168.32.52'
}

storjshare_ips = ['145.40.73.79', '136.144.59.173', '145.40.69.109', '145.40.93.133', '145.40.93.125']

flags_types = {
    'A': 'ACK',
    'S': 'SYN',
    'SA': 'SYN_ACK',
    'P': 'PSH',
    'PA': 'PSH_ACK',
    'R': 'RST',
    'FA': 'FIN_ACK',
    'RA': 'RST_ACK',
    'FPA': 'FIN_PUSH_ACK',

    'SEC': 'SYN_ECN_CWR',
    'SAE': 'SAE',
    'PAC': 'PAC',
    'AC': 'AC',
    'FPU': 'FPU',
    'SAEC': 'SAEC',
    'RAC': 'RAC',
}

ip_info = {
    'ip_version': None,
    'ip_ihl': None,
    'ip_tos': None,
    'ip_len': None,
    'ip_id': None,
    'ip_flags': None,

    'ip_frag': None,
    'ip_ttl': None,
    'ip_chksum': None,
    'ip_src': None,
    'ip_dst': None,

    'ip_options': None,
    'ip_proto': None,
}

DNS_opcodes = {0: "QUERY", 1: "IQUERY", 2: "STATUS"}


def rdpcap_pcap(self):
    raw_pkts = rdpcap(self.pcap_name)
    count = 0

    for raw_pkt in raw_pkts:
        print("raw_pkt: {} \n".format(dir(raw_pkt)))
        print(raw_pkt.summary)
        # raw_pkt.show()

        count += 1

        ether_pkt = raw_pkt[Ether]
        ether_dst = ether_pkt.dst
        ether_src = ether_pkt.src
        ether_type = ETHER_TYPES[ether_pkt.type]

        if ether_type != 'IPv4':
            continue

        # ip information data
        ip_pkt = raw_pkt[IP]

        ip_version = ip_pkt.version
        ip_ihl = ip_pkt.ihl
        ip_tos = ip_pkt.tos
        ip_len = ip_pkt.len
        ip_id = ip_pkt.id
        ip_flags = ip_pkt.flags
        ip_frag = ip_pkt.frag
        ip_ttl = ip_pkt.ttl
        ip_chksum = ip_pkt.chksum
        ip_src = ip_pkt.src
        ip_dst = ip_pkt.dst
        ip_options = ip_pkt.options
        ip_proto = IP_PROTOS[ip_pkt.proto]

        if ip_proto == 'icmp':
            icmp_pkt = ip_pkt[ICMP]

            icmp_pkt_type = icmptypes[icmp_pkt.type]
            icmp_pkt_code = icmp_pkt.code
            icmp_pkt_chksum = icmp_pkt.chksum
            icmp_pkt_id = icmp_pkt.id
            icmp_pkt_seq = icmp_pkt.seq
            # print('ICMP: ', icmptypes[icmp_pkt.type], icmp_pkt.code, icmp_pkt.chksum, icmp_pkt.id, icmp_pkt.seq)

        elif ip_proto == 'udp':
            udp_pkt = ip_pkt[UDP]

            udp_pkt_sport = udp_pkt.sport
            udp_pkt_dport = udp_pkt.dport
            udp_pkt_len = udp_pkt.len
            udp_pkt_chksum = udp_pkt.chksum

            if 'DNSQR' and 'DNSRRSOA' in udp_pkt:
                dns_pkt_opcode = udp_pkt[DNS].opcode  # {0: "QUERY", 1: "IQUERY", 2: "STATUS"}
                dns_pkt_qd = udp_pkt[DNS].qd
                dns_pkt_qname = dns_pkt_qd.qname
                dns_pkt_qtype = dnstypes[dns_pkt_qd.qtype]

                dns_pkt_rrname = udp_pkt[DNS].ns.rrname
                dns_pkt_mname = udp_pkt[DNS].ns.mname
                dns_pkt_rname = udp_pkt[DNS].ns.rname

        elif ip_proto == 'tcp':
            tcp_pkt = ip_pkt[TCP]

            tcp_pkt_sport = tcp_pkt.sport
            tcp_pkt_dport = tcp_pkt.dport
            tcp_pkt_seq = tcp_pkt.seq
            tcp_pkt_ack = tcp_pkt.ack
            tcp_pkt_dataofs = tcp_pkt.dataofs
            tcp_pkt_reserved = tcp_pkt.reserved
            tcp_pkt_flags = tcp_pkt.flags
            tcp_pkt_window = tcp_pkt.window
            tcp_pkt_chksum = tcp_pkt.chksum
            tcp_pkt_urgptr = tcp_pkt.urgptr
            tcp_pkt_options = tcp_pkt.options

            if len(tcp_pkt_options) > 0:
                Timestamp = [value for (key, value) in tcp_pkt_options if key == 'Timestamp']

            if 'Raw' in tcp_pkt:
                tcp_pkt_load = tcp_pkt.load