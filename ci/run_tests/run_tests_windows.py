import os
import argparse
import subprocess
from tkinter import E
import scapy.arch.windows
from dataclasses import dataclass
from pathlib import Path
from contextlib import contextmanager
from ipaddress import IPv4Address, ip_address

TCPREPLAY_PATH = "tcpreplay-4.4.1-win"


def validate_ipv4_address(address):
    try:
        IPv4Address(address)
        return True
    except ValueError:
        return False


def get_ip_by_guid(guid):
    interfaces = scapy.arch.windows.get_windows_if_list()
    for iface in interfaces:
        ips = iface.get("ips", [])
        # Find the first valid IPv4 address inside iface["ips"]. If no address is found, return None
        return next(filter(validate_ipv4_address, ips), None)
    # Return None if no matching interface is found
    return None


def find_interface():
    completed_process = subprocess.run(
        ["tcpreplay.exe", "--listnics"],
        shell=True,
        capture_output=True,
        cwd=TCPREPLAY_PATH,
    )
    if completed_process.returncode != 0:
        print('Error executing "tcpreplay.exe --listnics"!')
        exit(1)

    raw_nics_output = completed_process.stdout.decode("utf-8")
    for row in raw_nics_output.split("\n")[2:]:
        columns = row.split("\t")
        if len(columns) > 1 and columns[1].startswith("\\Device\\NPF_"):
            interface = columns[1]
            try:
                nic_guid = interface.lstrip("\\Device\\NPF_")
                ip_address = get_ip_by_guid(nic_guid)
                if ip_address.startswith("169.254"):
                    continue
                completed_process = subprocess.run(
                    ["curl", "--interface", ip_address, "www.google.com"],
                    capture_output=True,
                    shell=True,
                )
                if completed_process.returncode != 0:
                    continue
                return interface, ip_address
            except Exception:
                pass
    return None, None


@contextmanager
def tcp_replay_worker(interface: str, tcpreplay_dir: Path, source_pcap: Path):
    tcpreplay_proc = subprocess.Popen(f'tcpreplay.exe -i "{interface}" --mbps=10 -l 0 {source_pcap}',
                                      cwd=tcpreplay_dir)
    
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
                "--sources Packet++",
                "--sources Pcap++",
                "--sources Common++",
                "--excluded_sources Tests",
                "--export_type cobertura:Packet++Coverage.xml",
                "--",
                str(exe_path.absolute()),
            ],
            cwd=work_dir,
            check=True
        )

    def run_pcap_tests(self, include_tests: list[str], skip_tests: list[str]):
        exe_path = self.build_dir / self.pcap_test_path
        work_dir = exe_path.parent

        interface, ip_address = find_interface()
        if not interface or not ip_address:
            raise RuntimeError("Cannot find an interface to run tests on!")
        print(f"Interface is {interface} and IP address is {ip_address}")

        source_pcap = work_dir / 'PcapExamples' / 'example.pcap'

        with tcp_replay_worker(interface=interface, tcpreplay_dir=TCPREPLAY_PATH, source_pcap=source_pcap):
            subprocess.run(
                [
                    str(exe_path.absolute()),
                    f"-i {ip_address}",
                    f"-x {';'.join(skip_tests)}",
                    *include_tests,
                ],
                cwd=work_dir,
                check=True,
            )

    def run_pcap_coverage(self, include_tests: list[str], skip_tests: list[str]):
        exe_path = self.build_dir / self.pcap_test_path
        work_dir = exe_path.parent

        interface, ip_address = find_interface()
        if not interface or not ip_address:
            raise RuntimeError("Cannot find an interface to run tests on!")
        print(f"Interface is {interface} and IP address is {ip_address}")

        source_pcap = work_dir / 'PcapExamples' / 'example.pcap'

        with tcp_replay_worker(interface=interface, tcpreplay_dir=TCPREPLAY_PATH, source_pcap=source_pcap):
            subprocess.run(
                [
                    "OpenCppCoverage.exe",
                    "--verbose",
                    "--sources Packet++",
                    "--sources Pcap++",
                    "--sources Common++",
                    "--excluded_sources Tests",
                    "--export_type cobertura:Pcap++Coverage.xml",
                    "--",
                    str(exe_path.absolute()),
                    f"-i {ip_address}",
                    f"-x {';'.join(skip_tests)}",
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
        "--build-dir",
        type=str,
        default=os.getcwd(),
        help="Path to the build directory"
    )
    args = parser.parse_args()

    runner = Runner(build_dir=Path(args.build_dir))

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
