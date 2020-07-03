import platform
import os
import subprocess
import tempfile

DEFAULT_EXAMPLE_DIR = os.path.abspath('../../Dist/examples/')

def run_example(example_name, args, timeout=10, expected_return_code=0, requires_root=False):
	command_to_run = (['sudo'] if requires_root is True and platform.system() == 'Linux' else []) + [os.path.join(DEFAULT_EXAMPLE_DIR, example_name)]
	for flag, val in args.items():
		if flag:
			command_to_run.append(flag)
		if val:
			command_to_run.append(val)
	print('command_to_run', command_to_run)
	last_completed_process = subprocess.run(command_to_run, capture_output=True, text=True, timeout=timeout)
	assert last_completed_process.returncode == expected_return_code
	return last_completed_process

def text_file_contains(file_path, expected_content):
	if not os.path.exists(file_path):
		return False

	with open(file_path) as f:
		return expected_content in f.read()



