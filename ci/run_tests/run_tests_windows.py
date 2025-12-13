from __future__ import annotations

import os
import argparse
import subprocess
import scapy.arch.windows
from dataclasses import dataclass
from pathlib import Path
from contextlib import contextmanager
from ipaddress import IPv4Address

TCPREPLAY_PATH = "tcpreplay-4.4.1-win"


def find_first_connected_interface() -> tuple[str, IPv4Address] | tuple[None, None]:
    """Find a network interface connected to the internet by checking if it can reach www.google.com."""

    def tcp_replay_list_nics():
        return subprocess.run(
            ["tcpreplay.exe", "--listnics"],
            capture_output=True,
            cwd=TCPREPLAY_PATH,
            check=True,
        )

    def curl_google(ip_address):
        return subprocess.run(
            ["curl", "--interface", str(ip_address), "www.google.com"],
            capture_output=True,
        )

    # Create a set of detected device paths. Possibly unnecessary, but scapy only returns GUID
    tcp_result = tcp_replay_list_nics()
    npf_guids = set()
    for row in tcp_result.stdout.decode("utf-8").split("\n")[2::2]:
        columns = row.split("\t")
        if len(columns) > 1 and columns[1].startswith("\\Device\\NPF"):
            npf_guids.add(columns[1].lstrip("\\Device\\NPF_"))

    all_interfaces = scapy.arch.windows.get_windows_if_list()
    for interface in all_interfaces:
        if_guid: str | None = interface.get("guid", None)
        if if_guid is None:
            continue

        # Not a NPF guid? Can we even get those on a machine with NPcap / WinPcap?
        if if_guid not in npf_guids:
            continue

        ips = interface.get("ips", [])

        if len(ips) <= 0:
            continue

        for ip_raw in ips:
            try:
                ipv4 = IPv4Address(ip_raw)
            except ValueError:
                continue

            # Discards 169.245.x.x
            if ipv4.is_link_local:
                continue

            if curl_google(ipv4).returncode == 0:
                # Construct the full device path again.
                return f"\\Device\\NPF_{if_guid}", ipv4

    return None, None


@contextmanager
def tcp_replay_worker(interface: str, tcpreplay_dir: Path, source_pcap: Path):
    tcpreplay_proc = subprocess.Popen(
        f'tcpreplay.exe -i "{interface}" --mbps=10 -l 0 {source_pcap}',
        cwd=tcpreplay_dir,
    )

    try:
        yield tcpreplay_proc
    finally:
        subprocess.call(["taskkill", "/F", "/T", "/PID", str(tcpreplay_proc.pid)])


@dataclass
class Runner:
    build_dir: Path
    packet_test_path = Path("Tests", "Packet++Test", "Packet++Test")
    pcap_test_path = Path("Tests", "Pcap++Test", "Pcap++Test")

    def run_packet_test(self):
        exe_path = self.build_dir / self.packet_test_path
        work_dir = exe_path.parent

        subprocess.run(str(exe_path.absolute()), cwd=work_dir, check=True)

    def run_packet_coverage(self):
        exe_path = self.build_dir / self.packet_test_path
        work_dir = exe_path.parent

        subprocess.run(
            [
                "OpenCppCoverage.exe",
                "--verbose",
                "--sources",
                "Packet++",
                "--sources",
                "Pcap++",
                "--sources",
                "Common++",
                "--excluded_sources",
                "Tests",
                "--export_type",
                "cobertura:Packet++Coverage.xml",
                "--working_dir",
                str(work_dir.absolute()),
                "--",
                str(exe_path.absolute()),
            ],
            cwd=work_dir,
            check=True,
        )

    def run_pcap_tests(self, include_tests: list[str], skip_tests: list[str]):
        exe_path = self.build_dir / self.pcap_test_path
        work_dir = exe_path.parent

        interface, ip_address = find_first_connected_interface()
        if not interface or not ip_address:
            raise RuntimeError("Cannot find an interface to run tests on!")
        print(f"Interface is {interface} and IP address is {ip_address}")

        source_pcap = work_dir / "PcapExamples" / "example.pcap"

        with tcp_replay_worker(
            interface=interface, tcpreplay_dir=TCPREPLAY_PATH, source_pcap=source_pcap
        ):
            subprocess.run(
                [
                    str(exe_path.absolute()),
                    "-i",
                    str(ip_address),
                    "-x;".join(skip_tests),
                    *include_tests,
                ],
                cwd=work_dir,
                check=True,
            )

    def run_pcap_coverage(self, include_tests: list[str], skip_tests: list[str]):
        exe_path = self.build_dir / self.pcap_test_path
        work_dir = exe_path.parent

        interface, ip_address = find_first_connected_interface()
        if not interface or not ip_address:
            raise RuntimeError("Cannot find an interface to run tests on!")
        print(f"Interface is {interface} and IP address is {ip_address}")

        source_pcap = work_dir / "PcapExamples" / "example.pcap"

        with tcp_replay_worker(
            interface=interface, tcpreplay_dir=TCPREPLAY_PATH, source_pcap=source_pcap
        ):
            subprocess.run(
                [
                    "OpenCppCoverage.exe",
                    "--verbose",
                    "--sources",
                    "Packet++",
                    "--sources",
                    "Pcap++",
                    "--sources",
                    "Common++",
                    "--excluded_sources",
                    "Tests",
                    "--export_type",
                    "cobertura:Pcap++Coverage.xml",
                    "--",
                    str(exe_path.absolute()),
                    "-i",
                    str(ip_address),
                    "-x",
                    ";".join(skip_tests),
                    *include_tests,
                ],
                cwd=work_dir,
                check=True,
            )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--skip-tests",
        "-s",
        type=str,
        nargs="+",
        default=[],
        help="Pcap++ tests to skip",
    )
    parser.add_argument(
        "--include-tests",
        "-t",
        type=str,
        nargs="+",
        default=[],
        help="Pcap++ tests to include",
    )
    parser.add_argument(
        "--coverage",
        "-c",
        action="store_true",
        default=False,
        help="Enable OpenCppCoverage encapsulation to generate coverage report",
    )
    parser.add_argument(
        "--build-dir", type=str, default=os.getcwd(), help="Path to the build directory"
    )
    parser.add_argument(
        "--packet-test-exe",
        type=str,
        help="Custom path to Packet++ test executable. Can be relative to the build directory.",
    )
    parser.add_argument(
        "--pcap-test-exe",
        type=str,
        help="Custom path to Pcap++ test executable. Can be relative to the build directory.",
    )
    args = parser.parse_args()

    runner = Runner(build_dir=Path(args.build_dir))

    # Override default paths if they are provided via the command line.
    if args.packet_test_exe:
        runner.packet_test_path = Path(args.packet_test_exe)
    if args.pcap_test_exe:
        runner.pcap_test_path = Path(args.pcap_test_exe)

    skip_tests = ["TestRemoteCapture"] + args.skip_tests
    include_tests = ["-t", ";".join(args.include_tests)] if args.include_tests else []

    if args.coverage:
        runner.run_packet_coverage()
        runner.run_pcap_coverage(include_tests, skip_tests)
    else:
        runner.run_packet_test()
        runner.run_pcap_tests(include_tests, skip_tests)


if __name__ == "__main__":
    main()
