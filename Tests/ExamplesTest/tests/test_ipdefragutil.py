from os import path
import pytest
from .test_utils import ExampleTest
import filecmp


class TestIPDefragUtil(ExampleTest):
    pytestmark = [pytest.mark.ipdefragutil, pytest.mark.no_network]

    def test_sanity(self, tmpdir):
        args = {
            "": path.join("pcap_examples", "frag_http_req.pcap"),
            "-o": path.join(tmpdir, "output.pcap"),
        }
        completed_process = self.run_example(args=args)
        assert filecmp.cmp(
            path.join(tmpdir, "output.pcap"),
            path.join("expected_output", "http_req.pcap"),
            shallow=False,
        )
        with open(path.join("expected_output", "ipdefragutil_sanity.txt")) as f:
            assert f.read() == completed_process.stdout

    def test_multiple_frag_packets(self, tmpdir):
        args = {
            "": path.join("pcap_examples", "ip-frag.pcap"),
            "-o": path.join(tmpdir, "output.pcap"),
        }
        completed_process = self.run_example(args=args)
        assert filecmp.cmp(
            path.join(tmpdir, "output.pcap"),
            path.join("expected_output", "no-ip-frag.pcap"),
            shallow=False,
        )
        with open(
            path.join("expected_output", "ipdefragutil_multiple_frag_packets.txt")
        ) as f:
            assert f.read() == completed_process.stdout

    def test_ipv6(self, tmpdir):
        args = {
            "": path.join("pcap_examples", "ipv6-frag.pcap"),
            "-o": path.join(tmpdir, "output.pcap"),
        }
        completed_process = self.run_example(args=args)
        assert filecmp.cmp(
            path.join(tmpdir, "output.pcap"),
            path.join("expected_output", "no-ipv6-frag.pcap"),
            shallow=False,
        )
        with open(path.join("expected_output", "ipdefragutil_ipv6.txt")) as f:
            assert f.read() == completed_process.stdout

    def test_defrag_all(self, tmpdir):
        args = {
            "": path.join("pcap_examples", "ip-frag.pcap"),
            "-o": path.join(tmpdir, "output.pcap"),
            "-a": "",
        }
        completed_process = self.run_example(args=args)
        assert filecmp.cmp(
            path.join(tmpdir, "output.pcap"),
            path.join("expected_output", "no-ip-frag-all.pcap"),
            shallow=False,
        )
        with open(path.join("expected_output", "ipdefragutil_all.txt")) as f:
            assert f.read() == completed_process.stdout

    def test_defrag_ip_ids(self, tmpdir):
        args = {
            "": path.join("pcap_examples", "ip-frag.pcap"),
            "-o": path.join(tmpdir, "output.pcap"),
            "-d": "7863,7861,2222",
        }
        completed_process = self.run_example(args=args)
        assert filecmp.cmp(
            path.join(tmpdir, "output.pcap"),
            path.join("expected_output", "no-frag-ip-ids.pcap"),
            shallow=False,
        )
        with open(path.join("expected_output", "ipdefragutil_ip_ids.txt")) as f:
            assert f.read() == completed_process.stdout

    def test_input_file_missing(self):
        args = {}
        completed_process = self.run_example(args=args, expected_return_code=1)
        assert "ERROR: Input file name was not given" in completed_process.stdout
