import os
import subprocess
import tempfile
from .test_file import FileTest

DEFAULT_EXAMPLE_DIR = os.path.abspath('../../Dist/examples/')
CLEANUP_TEMP_DIR = True

class PcppExampleTest(FileTest):
	def setUp(self):
		if CLEANUP_TEMP_DIR:
			self.__temp_dir = tempfile.TemporaryDirectory()
			self.temp_dir_name = self.__temp_dir.name
		else:
			self.temp_dir_name = tempfile.mkdtemp()
		print('created', self.temp_dir_name)

	def run_example(self, example_name, args, timeout=10, expected_return_code=0):
		command_to_run = [os.path.join(DEFAULT_EXAMPLE_DIR, example_name)]
		for flag, val in args.items():
			if flag:
				command_to_run.append(flag)
			if val:
				command_to_run.append(val)
		print('command_to_run', command_to_run)
		self.last_completed_process = subprocess.run(command_to_run, capture_output=True, text=True, timeout=timeout)
		if self.last_completed_process.returncode != expected_return_code:
			raise AssertionError(f'Return code {self.last_completed_process.returncode} is different than expected {expected_return_code}')

	def assertStdoutContain(self, expected_content):
		if not self.last_completed_process:
			raise AssertionError('Command was not run')

		if not self.last_completed_process.stdout:
			raise AssertionError('Command stdout is empty')

		if not expected_content in self.last_completed_process.stdout:
			raise AssertionError('Expected content not found in stdout')

	def assertStderrContain(self, expected_content):
		if not self.last_completed_process:
			raise AssertionError('Command was not run')

		if not self.last_completed_process.stderr:
			raise AssertionError('Command stderr is empty')

		if not expected_content in self.last_completed_process.stderr:
			raise AssertionError('Expected content not found in stderr')

	def tearDown(self):
		if CLEANUP_TEMP_DIR:
			print('deleting', self.temp_dir_name)
			self.__temp_dir.cleanup()
