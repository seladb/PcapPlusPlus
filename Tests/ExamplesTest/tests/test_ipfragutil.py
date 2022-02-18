from os import path
import pytest
from .test_utils import ExampleTest
import filecmp


class TestIPFragUtil(ExampleTest):
    pytestmark = [pytest.mark.ipfragutil, pytest.mark.no_network]

    def test_sanity(self, tmpdir):
        args = {
            "": path.join("pcap_examples", "http_req.pcap"),
            "-o": path.join(tmpdir, "output.pcap"),
            "-s": "128",
        }
        completed_process = self.run_example(args=args)
        assert filecmp.cmp(
            path.join(tmpdir, "output.pcap"),
            path.join("expected_output", "http_req_frag.pcap"),
            shallow=False,
        )
        with open(path.join("expected_output", "ipfragutil_sanity.txt")) as f:
            assert f.read() == completed_process.stdout

    def test_missing_input_file(self):
        args = {}
        completed_process = self.run_example(args=args, expected_return_code=1)
        assert "ERROR: Input file name was not given" in completed_process.stdout

    def test_missing_output_file(self):
        args = {
            "": path.join("pcap_examples", "http_req.pcap"),
        }
        completed_process = self.run_example(args=args, expected_return_code=1)
        assert "ERROR: Output file name was not given" in completed_process.stdout

    def test_missing_frag_size(self, tmpdir):
        args = {
            "": path.join("pcap_examples", "http_req.pcap"),
            "-o": path.join(tmpdir, "output.pcap"),
        }
        completed_process = self.run_example(args=args, expected_return_code=1)
        assert (
            "ERROR: Need to choose fragment size using the '-s' flag"
            in completed_process.stdout
        )

    def test_wrong_frag_size(self, tmpdir):
        args = {
            "": path.join("pcap_examples", "http_req.pcap"),
            "-o": path.join(tmpdir, "output.pcap"),
            "-s": "52",
        }
        completed_process = self.run_example(args=args, expected_return_code=1)
        assert "ERROR: Fragment size must divide by 8" in completed_process.stdout

    def test_ip_ids(self, tmpdir):
        args = {
            "": path.join("pcap_examples", "http-packets.pcap"),
            "-o": path.join(tmpdir, "output.pcap"),
            "-s": "256",
            "-d": "22574,22582",
        }
        completed_process = self.run_example(args=args)
        assert filecmp.cmp(
            path.join(tmpdir, "output.pcap"),
            path.join("expected_output", "ipfragutil_ip_ids.pcap"),
            shallow=False,
        )
        with open(path.join("expected_output", "ipfragutil_ip_ids.txt")) as f:
            assert f.read() == completed_process.stdout

    def test_bpf_filter(self, tmpdir):
        args = {
            "": path.join("pcap_examples", "http-packets.pcap"),
            "-o": path.join(tmpdir, "output.pcap"),
            "-s": "256",
            "-f": "tcp src port 8881",
        }
        completed_process = self.run_example(args=args)
        assert filecmp.cmp(
            path.join(tmpdir, "output.pcap"),
            path.join("expected_output", "ipfragutil_bpf_filter.pcap"),
            shallow=False,
        )
        with open(path.join("expected_output", "ipfragutil_bpf_filter.txt")) as f:
            assert f.read() == completed_process.stdout
