from os import path
import pytest
from .test_utils import ExampleTest, compare_stdout_with_file


class TestHttpAnalyzer(ExampleTest):
    pytestmark = [pytest.mark.httpanalyzer, pytest.mark.no_network]

    @pytest.mark.parametrize(
        "pcap_file,expected_report_file",
        [
            pytest.param("http-packets2.pcap", "httpanalyzer_sanity.txt", id="sanity"),
            pytest.param(
                "many-protocols.pcap",
                "httpanalyzer_manyprotocols.txt",
                id="many_protocols",
            ),
        ],
    )
    def test_from_pcap(self, pcap_file, expected_report_file):
        def ignore_sample_time(line):
            return line.startswith("Sample time")

        args = {
            "-f": path.join("pcap_examples", pcap_file),
        }
        completed_process = self.run_example(args=args)
        compare_stdout_with_file(
            completed_process.stdout,
            path.join("expected_output", expected_report_file),
            ignore_sample_time,
        )

    def test_no_arg_provided(self):
        args = {}
        completed_process = self.run_example(args=args, expected_return_code=1)
        assert (
            "ERROR: Neither interface nor input pcap file were provided"
            in completed_process.stdout
        )
