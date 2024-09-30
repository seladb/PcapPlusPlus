import os
import pytest
from .test_utils import (
    ExampleTest,
    compare_stdout_with_file,
    compare_files_ignore_newline,
)


class TestTLSFingerprinting(ExampleTest):
    pytestmark = [pytest.mark.tlsfingerprinting, pytest.mark.no_network]

    def _get_default_args(self, tmpdir=None):
        args = {
            "-r": os.path.join("pcap_examples", "tls2.pcap"),
        }
        if tmpdir:
            args["-o"] = os.path.join(tmpdir, "temp.dat")
        return args

    def _ignore_console_output_lines(self, line):
        return line.startswith("Start reading") or line.startswith(
            "Output file was written to"
        )

    def _examine_output_file_lines(self, line1, line2, separator):
        line1_elements = line1.split(separator)
        line2_elements = line2.split(separator)
        if len(line1_elements) != 7 or len(line2_elements) != 7:
            return False

        for index, (line1_element, line2_element) in enumerate(
            zip(line1_elements, line2_elements)
        ):
            # ignore comparing IPv6 addresses because their representation might be
            # slightly different on different platforms
            if index in [3, 5] and ":" in line1_element and ":" in line2_element:
                continue

            if line1_element != line2_element:
                return False

        return True

    @pytest.mark.parametrize("tls_type", ["ch", "sh", "ch_sh"])
    def test_sanity(self, tls_type):
        args = self._get_default_args()
        if tls_type != "ch":
            args["-t"] = tls_type

        output_file_name = "tls2.txt"
        expected_output_file_name = f"tls_fp_{tls_type}.txt"
        expected_console_output = f"tls_fp_{tls_type}_console.txt"
        try:
            completed_process = self.run_example(args=args)
            assert compare_files_ignore_newline(
                os.path.join("expected_output", expected_output_file_name),
                output_file_name,
                examine_lines_predicate=lambda l1, l2: self._examine_output_file_lines(
                    l1, l2, "\t"
                ),
            )
            compare_stdout_with_file(
                completed_process.stdout,
                os.path.join("expected_output", expected_console_output),
                self._ignore_console_output_lines,
            )
        finally:
            if os.path.exists(output_file_name):
                os.remove(output_file_name)

    def test_define_output_file(self, tmpdir):
        args = self._get_default_args(tmpdir)
        completed_process = self.run_example(args=args)
        assert compare_files_ignore_newline(
            os.path.join("expected_output", "tls_fp_ch.txt"),
            args["-o"],
            examine_lines_predicate=lambda l1, l2: self._examine_output_file_lines(
                l1, l2, "\t"
            ),
        )
        compare_stdout_with_file(
            completed_process.stdout,
            os.path.join("expected_output", "tls_fp_ch_console.txt"),
            self._ignore_console_output_lines,
        )

    def test_no_input_file(self):
        args = dict()
        completed_process = self.run_example(args=args, expected_return_code=1)
        assert (
            "ERROR: Please provide an interface or an input pcap file"
            in completed_process.stdout
        )

    def test_input_file_doesnt_exist(self):
        args = {"-r": "invalid_file.pcap"}
        completed_process = self.run_example(args=args, expected_return_code=1)
        assert "ERROR: Cannot open pcap/pcapng file" in completed_process.stdout

    def test_invalid_fingerprint_type(self):
        args = self._get_default_args()
        args["-t"] = "invalid"
        completed_process = self.run_example(args=args, expected_return_code=1)
        assert (
            "ERROR: Possible options for TLS fingerprint types are 'ch' (Client Hello), 'sh' (Server Hello) or 'ch_sh' (Client Hello & Server Hello)"
            in completed_process.stdout
        )

    def test_separator(self, tmpdir):
        separator = "#"
        args = self._get_default_args(tmpdir)
        args["-s"] = separator
        completed_process = self.run_example(args=args)
        assert compare_files_ignore_newline(
            os.path.join("expected_output", "tls_fp_ch_hash_separator.txt"),
            args["-o"],
            examine_lines_predicate=lambda l1, l2: self._examine_output_file_lines(
                l1, l2, separator
            ),
        )
        compare_stdout_with_file(
            completed_process.stdout,
            os.path.join("expected_output", "tls_fp_ch_console.txt"),
            self._ignore_console_output_lines,
        )

    @pytest.mark.parametrize("invalid_separator", ["a", "2", ",", "-"])
    def test_invalid_separator(self, invalid_separator):
        args = self._get_default_args()
        args["-s"] = invalid_separator
        completed_process = self.run_example(args=args, expected_return_code=1)
        assert (
            "ERROR: Allowed separators are single characters which are not alphanumeric and not ',', '.', ':', '-'"
            in completed_process.stdout
        )

    def test_filter_packets(self, tmpdir):
        args = self._get_default_args(tmpdir)
        args["-f"] = "net 185.0.0.0 mask 255.0.0.0"
        completed_process = self.run_example(args=args)
        assert compare_files_ignore_newline(
            os.path.join("expected_output", "tls_fp_ch_filter.txt"), args["-o"]
        )
        compare_stdout_with_file(
            completed_process.stdout,
            os.path.join("expected_output", "tls_fp_ch_filter_console.txt"),
            self._ignore_console_output_lines,
        )
