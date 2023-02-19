import pytest
from .test_utils import ExampleTest


@pytest.mark.dnsresolver
class TestArping(ExampleTest):
    pytestmark = [pytest.mark.arping]

    @pytest.mark.interface_needed
    @pytest.mark.gateway_ip_needed
    def test_sanity(self, interface_ip_name, gateway_ip, use_sudo):
        args = {"-i": interface_ip_name, "-T": gateway_ip, "-w": "1", "-c": "3"}
        completed_process = self.run_example(args=args, requires_root=use_sudo)
        assert len(completed_process.stdout.splitlines()) == 3
        for line in completed_process.stdout.splitlines():
            assert "Reply from " + gateway_ip in line

    @pytest.mark.xfail
    @pytest.mark.interface_needed
    def test_gateway_not_reachable(self, interface_ip_name, use_sudo):
        args = {"-i": interface_ip_name, "-T": "8.8.8.8", "-w": "1", "-c": "3"}
        completed_process = self.run_example(args=args, requires_root=use_sudo)
        assert len(completed_process.stdout.splitlines()) == 3
        for idx, line in enumerate(completed_process.stdout.splitlines()):
            assert (
                "Arping  index={idx} : ARP request time out".format(idx=idx + 1) == line
            )

    @pytest.mark.no_network
    def test_missing_interface(self):
        args = {}
        completed_process = self.run_example(args=args, expected_return_code=1)
        assert (
            "ERROR: You must provide at least interface name or interface IP (-i switch)"
            in completed_process.stdout
        )

    @pytest.mark.interface_needed
    def test_missing_gateway(self, interface_ip_name):
        args = {"-i": interface_ip_name}
        completed_process = self.run_example(args=args, expected_return_code=1)
        assert (
            "ERROR: You must provide target IP (-T switch)" in completed_process.stdout
        )
