import time
from scapy.all import sniff, send
from scapy.layers.inet import IP, TCP, UDP
from argparse import ArgumentParser


def start_sniffing():
    tcp_filter = 'tcp[tcpflags] & (tcp-syn|tcp-push) != 0 and port 4242'
    sniff(filter=tcp_filter, prn=lambda x: x.summary(), count=1)
    udp_filter = 'udp and port 2323'
    sniff(filter=udp_filter, prn=lambda x: x.summary(), count=1)


def start_sending():
    tcp_packet = IP(dst="192.168.1.1") / TCP(dport=4242, flags=10)
    send(tcp_packet, count=1)
    time.sleep(1)
    udp_packet = IP(dst="192.168.1.1") / UDP(dport=2323)
    send(udp_packet, count=1)


def main():
    parser = ArgumentParser()
    subparsers = parser.add_subparsers()

    sniff_parser = subparsers.add_parser("sniff")
    sniff_parser.set_defaults(func=start_sniffing)

    send_parser = subparsers.add_parser("send")
    send_parser.set_defaults(func=start_sending)

    options = parser.parse_args()
    options.func()


if __name__ == '__main__':
    main()
