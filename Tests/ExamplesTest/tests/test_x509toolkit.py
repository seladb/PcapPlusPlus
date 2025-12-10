import base64
from datetime import datetime, timezone
import filecmp
import os
import re
import pytest
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from .test_utils import ExampleTest, compare_stdout_with_file


class TestX509Toolkit(ExampleTest):
    pytestmark = [pytest.mark.tlsfingerprinting, pytest.mark.no_network]

    @pytest.mark.parametrize("file_name", ["cert.pem", "cert.der"])
    def test_info(self, file_name):
        args = {
            "": "info",
            "-i": os.path.join("pcap_examples", file_name),
        }
        completed_process = self.run_example(args=args)

        compare_stdout_with_file(
            completed_process.stdout,
            os.path.join("expected_output", "cert_info.txt"),
        )

    @pytest.mark.parametrize("from_format", ["PEM", "DER"])
    @pytest.mark.parametrize("to_format", ["PEM", "DER"])
    def test_convert_to_file(self, tmpdir, from_format, to_format):
        output_file = os.path.join(tmpdir, f"cert.{to_format.lower()}")
        args = {
            "": "convert",
            "-i": os.path.join("pcap_examples", f"cert.{from_format.lower()}"),
            "-f": to_format,
            "-o": output_file,
        }
        completed_process = self.run_example(args=args)

        assert filecmp.cmp(
            output_file,
            os.path.join("pcap_examples", f"cert.{to_format.lower()}"),
            shallow=False,
        )

        assert (
            f"[V] Converted successfully to: {output_file}" in completed_process.stdout
        )

    @pytest.mark.parametrize("from_format", ["PEM", "DER"])
    @pytest.mark.parametrize("to_format", ["PEM", "DER"])
    def test_convert_to_stdout(self, from_format, to_format):
        args = {
            "": "convert",
            "-i": os.path.join("pcap_examples", f"cert.{from_format.lower()}"),
            "-f": to_format,
        }
        completed_process = self.run_example(args=args)

        file_to_compare = (
            os.path.join("pcap_examples", "cert.pem")
            if to_format == "PEM"
            else os.path.join("expected_output", "cert.base64")
        )
        compare_stdout_with_file(completed_process.stdout, file_to_compare)

    def test_convert_format_not_provided(self):
        args = {
            "": "convert",
            "-i": os.path.join("pcap_examples", "cert.pem"),
            "-f": "foo",
        }
        completed_process = self.run_example(args=args, expected_return_code=1)

        assert "ERROR: Unsupported format: foo" in completed_process.stdout

    @pytest.mark.parametrize("to_format", ["PEM", "DER"])
    def test_convert_cannot_open_output_file(self, to_format):
        args = {
            "": "convert",
            "-i": os.path.join("pcap_examples", "cert.pem"),
            "-f": to_format,
            "-o": "/invalid/folder",
        }
        completed_process = self.run_example(args=args, expected_return_code=1)

        assert "ERROR: Failed to open output file" in completed_process.stdout

    def test_json_to_stdout(self):
        args = {
            "": "json",
            "-i": os.path.join("pcap_examples", "cert.pem"),
        }
        completed_process = self.run_example(args=args)

        compare_stdout_with_file(
            completed_process.stdout, os.path.join("expected_output", "cert.json")
        )

    def test_json_to_file(self, tmpdir):
        output_file = os.path.join(tmpdir, "cert.json")
        args = {
            "": "json",
            "-i": os.path.join("pcap_examples", "cert.pem"),
            "-o": output_file,
        }
        self.run_example(args=args)

        with open(os.path.join("expected_output", "cert.json"), "r") as f2:
            print(f2.read())

        assert filecmp.cmp(
            output_file,
            os.path.join("expected_output", "cert.json"),
            shallow=False,
        )

    def test_json_to_file_invalid_path(self, tmpdir):
        output_file = os.path.join("invalid", "cert.json")
        args = {
            "": "json",
            "-i": os.path.join("pcap_examples", "cert.pem"),
            "-o": output_file,
        }
        completed_process = self.run_example(args=args, expected_return_code=1)

        assert "Failed to open output file" in completed_process.stdout

    @pytest.mark.flaky(reruns=2, reruns_delay=2)
    def test_expire_with_valid_cert(self, tmpdir):
        def calc_days_remaining() -> int:
            target_date = datetime.strptime(
                "2037-12-05 07:52:40 UTC", "%Y-%m-%d %H:%M:%S %Z"
            ).replace(tzinfo=timezone.utc)
            now = datetime.now(timezone.utc)
            return (target_date - now).days

        args = {
            "": "expire",
            "-i": os.path.join("pcap_examples", "valid-cert.pem"),
        }
        completed_process = self.run_example(args=args)

        with open(os.path.join("expected_output", "x509_valid_cert.txt"), "r") as f:
            expected_output = f.read()

        expected_output = expected_output.replace("{days}", str(calc_days_remaining()))
        expected_output_file = tmpdir.join("output.txt")
        expected_output_file.write(expected_output)

        compare_stdout_with_file(completed_process.stdout, expected_output_file)

    @pytest.mark.flaky(reruns=2, reruns_delay=2)
    def test_expire_with_expired_cert(self, tmpdir):
        def calc_days_expired() -> int:
            expired_date = datetime.strptime(
                "2024-08-17 08:06:28 UTC", "%Y-%m-%d %H:%M:%S %Z"
            ).replace(tzinfo=timezone.utc)
            now = datetime.now(timezone.utc)
            return (now - expired_date).days

        args = {
            "": "expire",
            "-i": os.path.join("pcap_examples", "expired-cert.pem"),
        }
        completed_process = self.run_example(args=args, expected_return_code=2)

        with open(os.path.join("expected_output", "x509_expired_cert.txt"), "r") as f:
            expected_output = f.read()

        expected_output = expected_output.replace("{days}", str(calc_days_expired()))
        expected_output_file = tmpdir.join("output.txt")
        expected_output_file.write(expected_output)

        compare_stdout_with_file(completed_process.stdout, expected_output_file)

    @pytest.mark.flaky(reruns=2, reruns_delay=2)
    def test_expire_with_future_cert(self, tmpdir):
        def calc_days_start() -> int:
            start_data = datetime.strptime(
                "2037-11-01 00:00:00 UTC", "%Y-%m-%d %H:%M:%S %Z"
            ).replace(tzinfo=timezone.utc)
            now = datetime.now(timezone.utc)
            return (start_data - now).days

        args = {
            "": "expire",
            "-i": os.path.join("pcap_examples", "future-cert.pem"),
        }
        completed_process = self.run_example(args=args, expected_return_code=2)

        with open(os.path.join("expected_output", "x509_future_cert.txt"), "r") as f:
            expected_output = f.read()

        expected_output = expected_output.replace("{days}", str(calc_days_start()))
        expected_output_file = tmpdir.join("output.txt")
        expected_output_file.write(expected_output)

        compare_stdout_with_file(completed_process.stdout, expected_output_file)

    @pytest.mark.parametrize("cert_format", ["PEM", "DER"])
    def test_pcap_extract_to_file(self, tmpdir, cert_format):
        args = {
            "": "pcap-extract",
            "-i": os.path.join("pcap_examples", "tls2.pcap"),
            "-f": cert_format,
            "-o": tmpdir,
            "-s": "",
        }
        completed_process = self.run_example(args=args)
        compare_stdout_with_file(
            completed_process.stdout,
            os.path.join("expected_output", "x509_pcap_extract.txt"),
        )

        cert_file_count = 0
        for cert_file_path in os.listdir(tmpdir):
            with open(os.path.join(tmpdir, cert_file_path), "rb") as cert_file:
                cert_data = cert_file.read()

            if cert_format == "PEM":
                x509.load_pem_x509_certificate(cert_data, default_backend())
            else:
                x509.load_der_x509_certificate(cert_data, default_backend())

            cert_file_count += 1

        assert cert_file_count == 31

    def test_pcap_extract_to_stdout_pem(self):
        args = {
            "": "pcap-extract",
            "-i": os.path.join("pcap_examples", "tls2.pcap"),
            "-f": "PEM",
        }
        completed_process = self.run_example(args=args)

        pem_list = re.findall(
            r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
            completed_process.stdout,
            re.DOTALL,
        )

        assert len(pem_list) == 31

        for pem in pem_list:
            x509.load_pem_x509_certificate(pem.encode(), default_backend())

    def test_pcap_extract_to_stdout_der(self):
        args = {
            "": "pcap-extract",
            "-i": os.path.join("pcap_examples", "tls2.pcap"),
            "-f": "DER",
        }
        completed_process = self.run_example(args=args)

        der_base64_blocks = [
            block.strip()
            for block in completed_process.stdout.split("==============")
            if block.strip()
        ]

        assert len(der_base64_blocks) == 31

        for der_base64 in der_base64_blocks:
            der_bytes = base64.b64decode(der_base64)
            x509.load_der_x509_certificate(der_bytes, backend=default_backend())

    def test_input_file_not_provided(self):
        args = {
            "": "convert",
            "-f": "PEM",
        }
        completed_process = self.run_example(args=args, expected_return_code=1)

        assert "ERROR: Input file name is not specified" in completed_process.stdout

    def test_input_file_does_not_exist(self):
        args = {
            "": "convert",
            "-f": "PEM",
            "-i": os.path.join("pcap_examples", "invalid.pem"),
        }
        completed_process = self.run_example(args=args, expected_return_code=1)

        assert (
            "ERROR: Input file doesn't exist or cannot be opened"
            in completed_process.stdout
        )

    def test_input_file_in_wrong_format(self, tmpdir):
        invalid_file = tmpdir.join("invalid.pem")
        invalid_file.write("invalid")

        args = {"": "convert", "-f": "PEM", "-i": invalid_file}
        completed_process = self.run_example(args=args, expected_return_code=1)

        assert "ERROR: Failed to open input file" in completed_process.stdout
