from os import path
from .test_utils import PcppExampleTest

class PcapPrinterTest(PcppExampleTest):

	def test_sanity(self):
		args = {
			'': path.join('pcap_examples', 'many-protocols.pcap'),
			'-o': path.join(self.temp_dir_name, 'output.txt')
		}
		self.run_example(example_name='PcapPrinter', args=args)
		self.assertFileContentEqual(expected=path.join('expected_output', 'pcapprinter_output.txt'), actual=path.join(self.temp_dir_name, 'output.txt'), shallow=True)
		self.assertTextFileContain(file_path=path.join(self.temp_dir_name, 'output.txt'), expected_content='Finished. Printed 4709 packets')

	def test_input_file_missing(self):
		args = {}
		self.run_example(example_name='PcapPrinter', args=args, expected_return_code=1)
		self.assertStdoutContains('Error: Input file name was not given')

	def test_print_count_packets(self):
		args = {
			'': path.join('pcap_examples', 'many-protocols.pcap'),
			'-o': path.join(self.temp_dir_name, 'output.txt'),
			'-c': '10'
		}
		self.run_example(example_name='PcapPrinter', args=args)
		self.assertTextFileContain(file_path=path.join(self.temp_dir_name, 'output.txt'), expected_content='Finished. Printed 10 packets')

	def test_filter(self):
		args = {
			'': path.join('pcap_examples', 'many-protocols.pcap'),
			'-o': path.join(self.temp_dir_name, 'output.txt'),
			'-i': 'net 10.0.0.1'
		}
		self.run_example(example_name='PcapPrinter', args=args)
		self.assertTextFileContain(file_path=path.join(self.temp_dir_name, 'output.txt'), expected_content='Finished. Printed 4666 packets')
