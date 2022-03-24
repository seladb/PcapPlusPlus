from os import path
import pytest
from .test_utils import text_file_contains, ExampleTest


class TestPcapPrinter(ExampleTest):
    pytestmark = [pytest.mark.pcapprinter, pytest.mark.no_network]

    def test_sanity(self, tmpdir):
        args = {
            "": path.join("pcap_examples", "many-protocols.pcap"),
            "-o": path.join(tmpdir, "output.txt"),
        }
        self.run_example(args=args)
        assert text_file_contains(
            path.join(tmpdir, "output.txt"),
            expected_content="Finished. Printed 4709 packets",
        )

    def test_input_file_missing(self):
        args = {}
        completed_process = self.run_example(args=args, expected_return_code=1)
        assert "ERROR: Input file name was not given" in completed_process.stdout

    def test_print_count_packets(self, tmpdir):
        args = {
            "": path.join("pcap_examples", "many-protocols.pcap"),
            "-o": path.join(tmpdir, "output.txt"),
            "-c": "10",
        }
        self.run_example(args=args)
        assert text_file_contains(
            file_path=path.join(tmpdir, "output.txt"),
            expected_content="Finished. Printed 10 packets",
        )

    def test_filter(self, tmpdir):
        args = {
            "": path.join("pcap_examples", "many-protocols.pcap"),
            "-o": path.join(tmpdir, "output.txt"),
            "-i": "net 10.0.0.1",
        }
        self.run_example(args=args)
        assert text_file_contains(
            file_path=path.join(tmpdir, "output.txt"),
            expected_content="Finished. Printed 4666 packets",
        )

    def test_snoop(self, tmpdir):
        args = {
            "": path.join("pcap_examples", "solaris.snoop"),
            "-o": path.join(tmpdir, "output.txt"),
        }
        self.run_example(args=args)
        assert text_file_contains(
            path.join(tmpdir, "output.txt"),
            expected_content="Finished. Printed 250 packets",
        )
