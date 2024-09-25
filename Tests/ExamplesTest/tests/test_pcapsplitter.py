import pytest
import os
from typing import Any
import ipaddress
from scapy.all import rdpcap, IP, IPv6, TCP, UDP
from .test_utils import ExampleTest


class TestPcapSplitter(ExampleTest):
    pytestmark = [pytest.mark.pcapsplitter, pytest.mark.no_network]

    def run_example(self, **kwargs) -> Any:
        if "timeout" not in kwargs:
            kwargs["timeout"] = 20

        return super().run_example(**kwargs)

    def test_split_by_file_size(self, tmpdir):
        args = {
            "-f": os.path.join("pcap_examples", "many-protocols.pcap"),
            "-o": tmpdir,
            "-m": "file-size",
            "-p": "100000",
        }
        self.run_example(args=args)
        assert len(os.listdir(tmpdir)) == 30
        for filename in os.listdir(tmpdir):
            if not os.path.splitext(filename)[0].endswith("29"):
                assert (
                    98500 <= os.path.getsize(os.path.join(tmpdir, filename)) <= 101500
                )

    def test_split_by_packet_count(self, tmpdir):
        args = {
            "-f": os.path.join("pcap_examples", "many-protocols.pcap"),
            "-o": tmpdir,
            "-m": "packet-count",
            "-p": "300",
        }
        self.run_example(args=args)
        assert len(os.listdir(tmpdir)) == 16
        for filename in os.listdir(tmpdir):
            if not os.path.splitext(filename)[0].endswith("15"):
                packets = rdpcap(os.path.join(tmpdir, filename))
                assert len(packets) == 300

    def test_split_by_client_ip(self, tmpdir):
        args = {
            "-f": os.path.join("pcap_examples", "many-protocols.pcap"),
            "-o": tmpdir,
            "-m": "client-ip",
        }
        self.run_example(args=args)
        assert len(os.listdir(tmpdir)) == 5
        for filename in os.listdir(tmpdir):
            packets = rdpcap(os.path.join(tmpdir, filename))
            if os.path.splitext(filename)[0].endswith("miscellaneous"):
                for packet in packets:
                    assert not packet.haslayer(TCP) and not packet.haslayer(UDP)
            else:
                ip_addr = os.path.splitext(filename)[0][25:]
                try:
                    ip_addr = ipaddress.ip_address(ip_addr.replace("-", "."))
                except ValueError:
                    ip_addr = ipaddress.ip_address(ip_addr.replace("-", ":"))
                for packet in packets:
                    assert packet.haslayer(TCP) or packet.haslayer(UDP)
                    if isinstance(ip_addr, ipaddress.IPv4Address):
                        assert packet.haslayer(IP)
                        assert (
                            ipaddress.ip_address(packet[IP].src) == ip_addr
                            or ipaddress.ip_address(packet[IP].dst) == ip_addr
                        )
                    else:
                        assert packet.haslayer(IPv6)
                        assert (
                            ipaddress.ip_address(packet[IPv6].src) == ip_addr
                            or ipaddress.ip_address(packet[IPv6].dst) == ip_addr
                        )

    def test_split_by_server_ip(self, tmpdir):
        args = {
            "-f": os.path.join("pcap_examples", "many-protocols.pcap"),
            "-o": tmpdir,
            "-m": "server-ip",
        }
        self.run_example(args=args)
        assert len(os.listdir(tmpdir)) == 60
        for filename in os.listdir(tmpdir):
            packets = rdpcap(os.path.join(tmpdir, filename))
            if os.path.splitext(filename)[0].endswith("miscellaneous"):
                for packet in packets:
                    assert not packet.haslayer(TCP) and not packet.haslayer(UDP)
            else:
                ip_addr = os.path.splitext(filename)[0][25:]
                try:
                    ip_addr = ipaddress.ip_address(ip_addr.replace("-", "."))
                except ValueError:
                    ip_addr = ipaddress.ip_address(ip_addr.replace("-", ":"))
                for packet in packets:
                    assert packet.haslayer(TCP) or packet.haslayer(UDP)
                    if isinstance(ip_addr, ipaddress.IPv4Address):
                        assert packet.haslayer(IP)
                        assert (
                            ipaddress.ip_address(packet[IP].src) == ip_addr
                            or ipaddress.ip_address(packet[IP].dst) == ip_addr
                        )
                    else:
                        assert packet.haslayer(IPv6)
                        assert (
                            ipaddress.ip_address(packet[IPv6].src) == ip_addr
                            or ipaddress.ip_address(packet[IPv6].dst) == ip_addr
                        )

    def test_split_by_server_port(self, tmpdir):
        args = {
            "-f": os.path.join("pcap_examples", "many-protocols.pcap"),
            "-o": tmpdir,
            "-m": "server-port",
        }
        self.run_example(args=args)
        assert len(os.listdir(tmpdir)) == 7
        for filename in os.listdir(tmpdir):
            packets = rdpcap(os.path.join(tmpdir, filename))
            if os.path.splitext(filename)[0].endswith("miscellaneous"):
                for packet in packets:
                    assert not packet.haslayer(TCP) and not packet.haslayer(UDP)
            else:
                server_port = int(os.path.splitext(filename)[0][27:])
                for packet in packets:
                    assert (
                        packet.haslayer(TCP)
                        and (
                            packet[TCP].sport == server_port
                            or packet[TCP].dport == server_port
                        )
                    ) or (
                        packet.haslayer(UDP)
                        and (
                            packet[UDP].sport == server_port
                            or packet[UDP].dport == server_port
                        )
                    )

    def test_split_by_client_port(self, tmpdir):
        args = {
            "-f": os.path.join("pcap_examples", "many-protocols.pcap"),
            "-o": tmpdir,
            "-m": "client-port",
        }
        self.run_example(args=args)
        assert len(os.listdir(tmpdir)) == 254
        for filename in os.listdir(tmpdir):
            packets = rdpcap(os.path.join(tmpdir, filename))
            if os.path.splitext(filename)[0].endswith("miscellaneous"):
                for packet in packets:
                    assert not packet.haslayer(TCP) and not packet.haslayer(UDP)
            else:
                client_port = int(os.path.splitext(filename)[0][27:])
                for packet in packets:
                    assert (
                        packet.haslayer(TCP)
                        and (
                            packet[TCP].sport == client_port
                            or packet[TCP].dport == client_port
                        )
                    ) or (
                        packet.haslayer(UDP)
                        and (
                            packet[UDP].sport == client_port
                            or packet[UDP].dport == client_port
                        )
                    )

    def test_split_by_ip_src_dst(self, tmpdir):
        args = {
            "-f": os.path.join("pcap_examples", "many-protocols.pcap"),
            "-o": tmpdir,
            "-m": "ip-src-dst",
        }
        self.run_example(args=args)
        assert len(os.listdir(tmpdir)) == 65
        ip_src_dst_map = {}
        for filename in os.listdir(tmpdir):
            packets = rdpcap(os.path.join(tmpdir, filename))
            if packets[0].haslayer(IP):
                ip_type = IP
                ip_src_dst = frozenset([packets[0][IP].src, packets[0][IP].dst])
            elif packets[0].haslayer(IPv6):
                ip_type = IPv6
                ip_src_dst = frozenset([packets[0][IPv6].src, packets[0][IPv6].dst])
            else:
                non_ip = frozenset([])
                assert non_ip not in ip_src_dst_map
                ip_src_dst_map[non_ip] = True
                continue
            assert ip_src_dst not in ip_src_dst_map
            ip_src_dst_map[ip_src_dst] = True
            for packet in packets:
                assert packet.haslayer(ip_type)
                assert ip_src_dst == frozenset(
                    [packet[ip_type].src, packet[ip_type].dst]
                )

    def test_split_by_connection(self, tmpdir):
        args = {
            "-f": os.path.join("pcap_examples", "many-protocols.pcap"),
            "-o": tmpdir,
            "-m": "connection",
        }
        self.run_example(args=args)
        assert len(os.listdir(tmpdir)) == 254
        connection_map = {}
        for filename in os.listdir(tmpdir):
            packets = rdpcap(os.path.join(tmpdir, filename))
            if packets[0].haslayer(TCP):
                trans_layer = TCP
            elif packets[0].haslayer(UDP):
                trans_layer = UDP
            else:
                trans_layer = None

            if trans_layer is not None:
                net_layer = IP if packets[0].haslayer(IP) else IPv6
            else:
                net_layer = None

            if net_layer is not None and trans_layer is not None:
                conn = frozenset(
                    [
                        trans_layer,
                        packets[0][net_layer].src,
                        packets[0][net_layer].dst,
                        packets[0][trans_layer].sport,
                        packets[0][trans_layer].dport,
                    ]
                )
            else:
                conn = frozenset([])

            assert conn not in connection_map
            connection_map[conn] = True

            if len(conn) == 0:
                continue

            for packet in packets:
                assert packet.haslayer(net_layer) and packet.haslayer(trans_layer)

                packet_conn = frozenset(
                    [
                        trans_layer,
                        packet[net_layer].src,
                        packet[net_layer].dst,
                        packet[trans_layer].sport,
                        packet[trans_layer].dport,
                    ]
                )

                assert packet_conn == conn

    def test_split_by_bpf_filter(self, tmpdir):
        args = {
            "-f": os.path.join("pcap_examples", "many-protocols.pcap"),
            "-o": tmpdir,
            "-m": "bpf-filter",
            "-p": "udp",
        }
        self.run_example(args=args)
        assert len(os.listdir(tmpdir)) == 2

        for filename in os.listdir(tmpdir):
            packets = rdpcap(os.path.join(tmpdir, filename))
            match_bpf = not os.path.splitext(filename)[0].endswith("not-match-bpf")
            for packet in packets:
                assert packet.haslayer(UDP) == match_bpf

    def test_split_by_round_robin(self, tmpdir):
        divide_by = 10
        args = {
            "-f": os.path.join("pcap_examples", "many-protocols.pcap"),
            "-o": tmpdir,
            "-m": "round-robin",
            "-p": str(divide_by),
        }
        self.run_example(args=args)
        num_of_packets_per_file = int(
            len(rdpcap(os.path.join("pcap_examples", "many-protocols.pcap")))
            / divide_by
        )
        assert len(os.listdir(tmpdir)) == divide_by
        for filename in os.listdir(tmpdir):
            assert (
                num_of_packets_per_file
                <= len(rdpcap(os.path.join(tmpdir, filename)))
                <= num_of_packets_per_file + 1
            )

    def test_input_file_not_given(self):
        args = {}
        completed_process = self.run_example(args=args, expected_return_code=1)
        assert "ERROR: Input file name was not given" in completed_process.stdout

    def test_output_dir_not_given(self):
        args = {"-f": os.path.join("pcap_examples", "many-protocols.pcap")}
        completed_process = self.run_example(args=args, expected_return_code=1)
        assert "ERROR: Output directory name was not given" in completed_process.stdout

    def test_split_method_not_given(self, tmpdir):
        args = {
            "-f": os.path.join("pcap_examples", "many-protocols.pcap"),
            "-o": tmpdir,
        }
        completed_process = self.run_example(args=args, expected_return_code=1)
        assert "ERROR: Split method was not given" in completed_process.stdout

    def test_output_dir_not_exist(self):
        args = {
            "-f": os.path.join("pcap_examples", "many-protocols.pcap"),
            "-o": "blablablalba12345",
        }
        completed_process = self.run_example(args=args, expected_return_code=1)
        assert "ERROR: Output directory doesn't exist" in completed_process.stdout

    def test_input_file_not_exist(self, tmpdir):
        args = {
            "-f": os.path.join("pcap_examples", "many-protocols123.pcap"),
            "-o": tmpdir,
            "-m": "ip-src-dst",
        }
        completed_process = self.run_example(args=args, expected_return_code=1)
        assert "ERROR: Error opening input pcap file" in completed_process.stdout

    def test_split_method_not_exist(self, tmpdir):
        args = {
            "-f": os.path.join("pcap_examples", "many-protocols123.pcap"),
            "-o": tmpdir,
            "-m": "blabla",
        }
        completed_process = self.run_example(args=args, expected_return_code=1)
        assert "ERROR: Unknown method 'blabla'" in completed_process.stdout
