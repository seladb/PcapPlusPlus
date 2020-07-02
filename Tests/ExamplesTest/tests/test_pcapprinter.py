from os import path
import pytest
from test_utils import run_example, text_file_contains

class TestPcapPrinter(object):
	pytestmark = [pytest.mark.pcapprinter, pytest.mark.no_network]

	def test_sanity(self, tmpdir):
		args = {
			'': path.join('pcap_examples', 'many-protocols.pcap'),
			'-o': path.join(tmpdir, 'output.txt')
		}
		run_example(example_name='PcapPrinter', args=args)
		assert text_file_contains(path.join(tmpdir, 'output.txt'), expected_content='Finished. Printed 4709 packets')

	def test_input_file_missing(self):
		args = {}
		completed_process = run_example(example_name='PcapPrinter', args=args, expected_return_code=1)
		assert 'Error: Input file name was not given' in completed_process.stdout

	def test_print_count_packets(self, tmpdir):
		args = {
			'': path.join('pcap_examples', 'many-protocols.pcap'),
			'-o': path.join(tmpdir, 'output.txt'),
			'-c': '10'
		}
		run_example(example_name='PcapPrinter', args=args)
		assert text_file_contains(file_path=path.join(tmpdir, 'output.txt'), expected_content='Finished. Printed 10 packets')

	def test_filter(self, tmpdir):
		args = {
			'': path.join('pcap_examples', 'many-protocols.pcap'),
			'-o': path.join(tmpdir, 'output.txt'),
			'-i': 'net 10.0.0.1'
		}
		run_example(example_name='PcapPrinter', args=args)
		assert text_file_contains(file_path=path.join(tmpdir, 'output.txt'), expected_content='Finished. Printed 4666 packets')