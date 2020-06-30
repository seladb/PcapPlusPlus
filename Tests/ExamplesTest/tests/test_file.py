import os
import filecmp
from unittest import TestCase

class FileTest(TestCase):
	def assertFileExists(self, path):
		if not os.path.exists(path):
			raise AssertionError('File doesn\'t exist: ' + path)
	
	def assertFileContentEqual(self, expected, actual, shallow=True):
		self.assertFileExists(actual)
		if not filecmp.cmp(actual, expected, shallow=shallow):
			raise AssertionError(f'File content doesn\'t match between \'{actual}\' and \'{expected}\'')

	def assertTextFileContain(self, file_path, expected_content):
		self.assertFileExists(file_path)
		with open(file_path) as f:
			if not expected_content in f.read():
				raise AssertionError('Expected content \'{expected_content}\' not found in \'{file_path}\'')