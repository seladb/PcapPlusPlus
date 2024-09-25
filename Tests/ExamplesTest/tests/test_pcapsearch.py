import pytest
import ntpath
from .test_utils import ExampleTest


class TestPcapSearch(ExampleTest):
    pytestmark = [pytest.mark.pcapsearch, pytest.mark.no_network]

    @pytest.mark.parametrize(
        "search_criteria,expected_packet_count",
        [
            pytest.param("tcp port 80", 3541, id="tcp_port_80"),
            pytest.param("icmp", 92, id="icmp"),
            pytest.param("ip6", 4502, id="ipv6"),
        ],
    )
    def test_filters(self, search_criteria, expected_packet_count):
        args = {"-d": "pcap_examples", "-s": search_criteria}
        completed_process = self.run_example(args=args)
        assert (
            "%s packets were matched to search criteria" % (expected_packet_count)
        ) in completed_process.stdout

    def test_exact_file_format(self):
        args = {"-d": "pcap_examples", "-s": "udp"}
        completed_process = self.run_example(args=args)
        expected = set(
            [
                (2690, "ip-frag.pcap"),
                (35, "ipv6.pcapng"),
                (269, "many-protocols.pcap"),
                (1, "tcp-reassembly.pcap"),
            ]
        )
        actual = set()
        for line in completed_process.stdout.splitlines():
            words = line.split(" ")
            if words is not None:
                try:
                    num_of_packets = int(words[0])
                    file_name = ntpath.basename(words[-1].replace("'", ""))
                    actual.add((num_of_packets, file_name))
                except Exception:
                    pass

        assert expected.issubset(actual)

    def test_different_file_extensions(self):
        args = {"-d": "pcap_examples", "-s": "ip6", "-e": "pcapng,dmp"}
        completed_process = self.run_example(args=args)
        assert ".dmp'" in completed_process.stdout
        assert ".pcapng'" in completed_process.stdout
        assert ".pcap'" not in completed_process.stdout

    def test_no_args(self):
        args = {}
        completed_process = self.run_example(args=args, expected_return_code=1)
        assert "ERROR: Input directory was not given" in completed_process.stdout

    def test_invalid_dir(self):
        args = {"-d": "dir_that_doesnt_exist", "-s": "udp"}
        completed_process = self.run_example(args=args, expected_return_code=1)
        assert "ERROR: Cannot find or open input directory" in completed_process.stdout

    def test_invalid_filter(self):
        args = {"-d": "pcap_examples", "-s": "invalid_filter"}
        completed_process = self.run_example(args=args, expected_return_code=1)
        assert "ERROR: Search criteria isn't valid" in completed_process.stdout
