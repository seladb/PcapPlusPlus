from os import path
import json
import xml.etree.ElementTree as ET
import pytest
import yaml
from .test_utils import ExampleTest


class TestPcapSerializer(ExampleTest):
    pytestmark = [pytest.mark.pcapserializer]

    @pytest.mark.no_network
    def test_json(self, tmpdir):
        output_file = path.join(tmpdir, "output.json")
        args = {
            "-f": path.join("pcap_examples", "many-protocols.pcap"),
            "-o": output_file,
        }
        completed_process = self.run_example(args=args)
        assert "Serializing packets from file" in completed_process.stdout
        assert "Finished. Serialized 4709 packets" in completed_process.stdout
        with open(output_file) as f:
            packets = json.load(f)
        assert len(packets) == 4709
        assert packets[0]["layers"][0]["protocolName"] == "Ethernet"

    @pytest.mark.no_network
    def test_json_to_stdout(self):
        args = {
            "-f": path.join("pcap_examples", "many-protocols.pcap"),
            "-c": "10",
        }
        completed_process = self.run_example(args=args)
        assert len(json.loads(completed_process.stdout)) == 10
        assert completed_process.stderr == ""

    @pytest.mark.no_network
    def test_yaml(self, tmpdir):
        output_file = path.join(tmpdir, "output.yaml")
        args = {
            "-f": path.join("pcap_examples", "many-protocols.pcap"),
            "-F": "yaml",
            "-c": "5",
            "-o": output_file,
        }
        completed_process = self.run_example(args=args)
        assert "Finished. Serialized 5 packets" in completed_process.stdout
        with open(output_file) as f:
            packets = yaml.safe_load(f)
        assert len(packets) == 5
        assert packets[0]["layers"][0]["protocolName"] == "Ethernet"

    @pytest.mark.no_network
    def test_xml(self, tmpdir):
        output_file = path.join(tmpdir, "output.xml")
        args = {
            "-f": path.join("pcap_examples", "ipv6.pcapng"),
            "-F": "xml",
            "-o": output_file,
        }
        completed_process = self.run_example(args=args)
        assert "Finished. Serialized 35 packets" in completed_process.stdout
        root = ET.parse(output_file).getroot()
        assert root.tag == "packets"
        assert len(root.findall("packet")) == 35

    @pytest.mark.no_network
    def test_filter(self, tmpdir):
        output_file = path.join(tmpdir, "output.json")
        args = {
            "-f": path.join("pcap_examples", "many-protocols.pcap"),
            "-e": "net 10.0.0.1",
            "-o": output_file,
        }
        completed_process = self.run_example(args=args)
        assert "Finished. Serialized 4666 packets" in completed_process.stdout
        with open(output_file) as f:
            assert len(json.load(f)) == 4666

    @pytest.mark.no_network
    def test_no_input(self):
        completed_process = self.run_example(args={}, expected_return_code=1)
        assert (
            "ERROR: Neither input file nor interface were provided"
            in completed_process.stdout
        )

    @pytest.mark.no_network
    def test_both_inputs(self):
        args = {
            "-f": path.join("pcap_examples", "many-protocols.pcap"),
            "-i": "lo",
        }
        completed_process = self.run_example(args=args, expected_return_code=1)
        assert (
            "ERROR: Please provide either an input file or an interface, not both"
            in completed_process.stdout
        )

    @pytest.mark.no_network
    def test_unknown_format(self):
        args = {
            "-f": path.join("pcap_examples", "many-protocols.pcap"),
            "-F": "csv",
        }
        completed_process = self.run_example(args=args, expected_return_code=1)
        assert "ERROR: Unknown output format 'csv'" in completed_process.stdout

    @pytest.mark.no_network
    @pytest.mark.parametrize("packet_count", ["0", "-5"])
    def test_invalid_packet_count(self, packet_count):
        args = {
            "-f": path.join("pcap_examples", "many-protocols.pcap"),
            "-c": packet_count,
        }
        completed_process = self.run_example(args=args, expected_return_code=1)
        assert (
            "ERROR: Packet count must be a positive number" in completed_process.stdout
        )

    @pytest.mark.no_network
    def test_input_file_not_found(self):
        args = {"-f": path.join("pcap_examples", "no_such_file.pcap")}
        completed_process = self.run_example(args=args, expected_return_code=1)
        assert (
            "ERROR: Error opening input file '"
            + path.join("pcap_examples", "no_such_file.pcap")
            + "'"
            in completed_process.stdout
        )

    @pytest.mark.no_network
    def test_invalid_filter(self):
        args = {
            "-f": path.join("pcap_examples", "many-protocols.pcap"),
            "-e": "invalid filter",
        }
        completed_process = self.run_example(args=args, expected_return_code=1)
        assert "ERROR: Couldn't set filter 'invalid filter'" in completed_process.stdout

    @pytest.mark.no_network
    def test_output_file_cannot_be_opened(self, tmpdir):
        output_file = path.join(tmpdir, "no_such_dir", "output.json")
        args = {
            "-f": path.join("pcap_examples", "many-protocols.pcap"),
            "-o": output_file,
        }
        completed_process = self.run_example(args=args, expected_return_code=1)
        assert (
            f"ERROR: Couldn't open output file '{output_file}'"
            in completed_process.stdout
        )

    @pytest.mark.no_network
    def test_interface_not_found(self):
        args = {"-i": "no_such_interface"}
        completed_process = self.run_example(args=args, expected_return_code=1)
        assert (
            "ERROR: Couldn't find interface by provided IP address or name"
            in completed_process.stdout
        )

    @pytest.mark.no_network
    def test_unknown_option(self):
        completed_process = self.run_example(args={"-z": ""}, expected_return_code=1)
        assert "Usage:" in completed_process.stdout

    @pytest.mark.interface_needed
    def test_invalid_filter_live(self, interface_ip_name, use_sudo):
        args = {"-i": interface_ip_name, "-e": "invalid filter"}
        completed_process = self.run_example(
            args=args, expected_return_code=1, requires_root=use_sudo
        )
        assert "ERROR: Couldn't set filter 'invalid filter'" in completed_process.stdout
