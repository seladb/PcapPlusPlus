from itertools import filterfalse
import os
import platform
import pytest
import subprocess


def run_example(
    example_name,
    args,
    root_path,
    timeout=10,
    expected_return_code=0,
    requires_root=False,
):
    command_to_run = (
        ["sudo"]
        if requires_root
        and (platform.system() == "Linux" or platform.system() == "Darwin")
        else []
    ) + [os.path.join(root_path, example_name)]
    for flag, val in args.items():
        if flag:
            command_to_run.append(flag)
        if val:
            command_to_run.append(val)
    print("command_to_run", command_to_run)
    completed_process = subprocess.run(
        command_to_run, capture_output=True, text=True, timeout=timeout
    )
    print("stdout", completed_process.stdout)
    assert completed_process.returncode == expected_return_code
    return completed_process


def text_file_contains(file_path, expected_content):
    if not os.path.exists(file_path):
        return False

    with open(file_path) as f:
        return expected_content in f.read()


def compare_files_ignore_newline(
    filename1, filename2, examine_lines_predicate=lambda l1, l2: False
):
    with open(filename1, "r") as f1:
        with open(filename2, "r") as f2:
            for line_f1, line_f2 in zip(f1, f2):
                if line_f1 != line_f2 and not examine_lines_predicate(line_f1, line_f2):
                    raise AssertionError(
                        f"lines are different:\n{filename1}:\n{line_f1}\n{filename2}:\n{line_f2}"
                    )
    return True


def compare_stdout_with_file(stdout, file_path, skip_line_predicate):
    assert os.path.exists(file_path)

    with open(file_path, "r") as f:
        for line_f, line_stdout in zip(
            filterfalse(skip_line_predicate, f),
            filterfalse(skip_line_predicate, stdout.splitlines()),
        ):
            assert line_f.rstrip("\n") == line_stdout


class ExampleTest(object):
    @pytest.fixture(autouse=True)
    def _root_path(self, request):
        self.root_path = request.config.getoption("--root-path")

    def run_example(
        self, args, timeout=10, expected_return_code=0, requires_root=False
    ):
        return run_example(
            example_name=self.__class__.__name__[4:],
            args=args,
            root_path=self.root_path,
            timeout=timeout,
            expected_return_code=expected_return_code,
            requires_root=requires_root,
        )
