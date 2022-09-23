import pytest
from .test_utils import ExampleTest


@pytest.mark.dnsresolver
class TestDNSResolver(ExampleTest):
    @pytest.mark.xfail
    def test_sanity(self, use_sudo):
        args = {
            "-s": "www.google.com",
            "-t": "5",
        }
        completed_process = self.run_example(
            args=args, timeout=5, requires_root=use_sudo
        )
        assert "IP address of [www.google.com] is:" in completed_process.stdout

    @pytest.mark.no_network
    def test_hostname_not_provided(self):
        args = {}
        completed_process = self.run_example(args=args, expected_return_code=1)
        assert "ERROR: Hostname not provided" in completed_process.stdout

    def test_hostname_not_exist(self, use_sudo):
        args = {"-s": "www.dlgkdflgkjdfkl.com", "-t": "1"}
        completed_process = self.run_example(args=args, requires_root=use_sudo)
        assert "Could not resolve hostname" in completed_process.stdout

    @pytest.mark.interface_needed
    @pytest.mark.xfail
    def test_use_specific_interface(self, interface_ip_name, use_sudo):
        assert interface_ip_name is not None
        args = {
            "-s": "www.google.com",
            "-i": interface_ip_name,
            "-t": "5",
        }
        completed_process = self.run_example(
            args=args, timeout=5, requires_root=use_sudo
        )
        assert "IP address of [www.google.com] is:" in completed_process.stdout
