import os
import filecmp
import pytest
from test_utils import ExampleTest

class TestTcpReassembly(ExampleTest):
	pytestmark = [pytest.mark.tcpreassembly, pytest.mark.no_network]

	def test_sanity(self, tmpdir):
		args = {
			'-r': os.path.join('pcap_examples', 'tcp-reassembly.pcap'),
			'-o': tmpdir,
			'-m': ''
		}
		self.run_example(args=args)
		assert len(os.listdir(tmpdir)) == 2
		expected_dir = os.path.join('expected_output', 'tcpreassembly_sanity')
		match, mismatch, errors = filecmp.cmpfiles(tmpdir, expected_dir, os.listdir(expected_dir))
		assert len(errors) == 0
		assert len(mismatch) == 0
		assert len(match) == 2

	def test_multiple_streams(self, tmpdir):
		args = {
			'-r': os.path.join('pcap_examples', 'http-packets.pcap'),
			'-o': tmpdir
		}
		self.run_example(args=args)
		assert len(os.listdir(tmpdir)) == 12
		expected_dir = os.path.join('expected_output', 'tcpreassembly_multiple_streams')
		match, mismatch, errors = filecmp.cmpfiles(tmpdir, expected_dir, os.listdir(expected_dir))
		assert len(errors) == 0
		assert len(mismatch) == 0
		assert len(match) == 12

	def test_bpf_filter(self, tmpdir):
		args = {
			'-r': os.path.join('pcap_examples', 'http-packets.pcap'),
			'-o': tmpdir,
			'-e': 'port 8868'
		}
		self.run_example(args=args)
		assert len(os.listdir(tmpdir)) == 1
		expected_dir = os.path.join('expected_output', 'tcpreassembly_filter')
		match, mismatch, errors = filecmp.cmpfiles(tmpdir, expected_dir, os.listdir(expected_dir))
		assert len(errors) == 0
		assert len(mismatch) == 0
		assert len(match) == 1

	def test_write_each_side_to_separate_file(self, tmpdir):
		args = {
			'-r': os.path.join('pcap_examples', 'tcp-reassembly.pcap'),
			'-o': tmpdir,
			'-s': ''
		}
		self.run_example(args=args)
		assert len(os.listdir(tmpdir)) == 2
		expected_dir = os.path.join('expected_output', 'tcpreassembly_sides')
		match, mismatch, errors = filecmp.cmpfiles(tmpdir, expected_dir, os.listdir(expected_dir))
		assert len(errors) == 0
		assert len(mismatch) == 0
		assert len(match) == 2

