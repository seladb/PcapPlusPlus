from __future__ import annotations

import os
import argparse
import subprocess
from pathlib import Path
from contextlib import contextmanager

import scapy.arch.windows
from ipaddress import IPv4Address

TCPREPLAY_PATH = "tcpreplay-4.4.1-win"
PCAP_FILE_PATH = os.path.abspath(
    os.path.join("Tests", "Pcap++Test", "PcapExamples", "example.pcap")
)


class InterfaceList:
    def __init__(self):
        interfaces = scapy.arch.windows.get_windows_if_list()
        self.interfaces = {
            iface["guid"]: iface for iface in interfaces if "guid" in iface
        }

    def get_ipv4_by_guid(self, guid: str) -> IPv4Address | None:
        interface = self.interfaces.get(guid, None)
        if interface is None:
            return None

        for ip in interface.get("ips", []):
            try:
                return IPv4Address(ip)
            except ValueError:
                pass

        return None


def find_interface() -> tuple[str, IPv4Address] | tuple[None, None]:
    completed_process = subprocess.run(
        ["tcpreplay.exe", "--listnics"],
        shell=True,
        capture_output=True,
        cwd=TCPREPLAY_PATH,
    )
    if completed_process.returncode != 0:
        print('Error executing "tcpreplay.exe --listnics"!')
        exit(1)

    if_list = InterfaceList()

    raw_nics_output = completed_process.stdout.decode("utf-8")
    for row in raw_nics_output.split("\n")[2:]:
        columns = row.split("\t")
        if len(columns) > 1 and columns[1].startswith("\\Device\\NPF_"):
            interface = columns[1]
            try:
                nic_guid = interface.lstrip("\\Device\\NPF_")

                ipv4 = if_list.get_ipv4_by_guid(nic_guid)

                if ipv4 is None:
                    continue

                if ipv4.is_link_local or ipv4.is_loopback:
                    continue

                completed_process = subprocess.run(
                    ["curl", "--interface", str(ipv4), "www.google.com"],
                    capture_output=True,
                    shell=True,
                )
                if completed_process.returncode != 0:
                    continue

                return interface, ipv4
            except Exception:
                pass
    return None, None


@contextmanager
def tcp_replay_worker(interface: str, tcpreplay_dir: Path, source_pcap: Path):
    tcpreplay_proc = subprocess.Popen(
        ["tcpreplay.exe", "-i", interface, "--mbps=10", "-l", "0", str(source_pcap)],
        cwd=tcpreplay_dir,
        shell=True,
    )

    try:
        yield tcpreplay_proc
    finally:
        subprocess.call(["taskkill", "/F", "/T", "/PID", str(tcpreplay_proc.pid)])


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
    args = parser.parse_args()

    tcpreplay_interface, ip_address = find_interface()
    if not tcpreplay_interface or not ip_address:
        print("Cannot find an interface to run tests on!")
        exit(1)
    print(f"Interface is {tcpreplay_interface} and IP address is {ip_address}")

    if args.coverage:
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
                "--",
                os.path.join("Bin", "Packet++Test"),
            ],
            cwd=os.path.join("Tests", "Packet++Test"),
            shell=True,
            check=True,
        )
    else:
        subprocess.run(
            os.path.join("Bin", "Packet++Test"),
            cwd=os.path.join("Tests", "Packet++Test"),
            shell=True,
            check=True,
        )

    skip_tests = ["TestRemoteCapture"] + args.skip_tests
    include_tests = (
        ["-t", ";".join(args.include_tests)] if args.include_tests else []
    )

    with tcp_replay_worker(tcpreplay_interface, Path(TCPREPLAY_PATH), Path(PCAP_FILE_PATH)) as worker:
        tcpreplay_cmd = (
            f'tcpreplay.exe -i "{tcpreplay_interface}" --mbps=10 -l 0 {PCAP_FILE_PATH}'
        )
        tcpreplay_proc = subprocess.Popen(tcpreplay_cmd, shell=True, cwd=TCPREPLAY_PATH)
        if args.coverage:
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
                    os.path.join("Bin", "Pcap++Test"),
                    "-i",
                    str(ip_address),
                    "-x",
                    ";".join(skip_tests),
                    *include_tests,
                ],
                cwd=os.path.join("Tests", "Pcap++Test"),
                shell=True,
                check=True,
            )
        else:
            subprocess.run(
                [
                    os.path.join("Bin", "Pcap++Test"),
                    "-i",
                    str(ip_address),
                    "-x",
                    ";".join(skip_tests),
                    *include_tests,
                ],
                cwd=os.path.join("Tests", "Pcap++Test"),
                shell=True,
                check=True,
            )


if __name__ == "__main__":
    main()
