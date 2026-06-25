from __future__ import annotations

import os
import logging
import argparse
import subprocess
from pathlib import Path
from contextlib import contextmanager
from typing import Iterable, Literal

import scapy.arch.windows
from ipaddress import IPv4Address

TCPREPLAY_PATH = "tcpreplay-4.4.1-win"


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
    parser.add_argument(
        "--build-dir", type=str, default=os.getcwd(), help="Path to the build directory"
    )
    parser.add_argument(
        "--common-test-exe",
        type=str,
        default=os.path.join("Tests", "Common++Test", "Common++Test.exe"),
        help="Custom path to Common++ test executable. Can be relative to the build directory.",
    )
    parser.add_argument(
        "--packet-test-exe",
        type=str,
        default=os.path.join("Tests", "Packet++Test", "Packet++Test.exe"),
        help="Custom path to Packet++ test executable. Can be relative to the build directory.",
    )
    parser.add_argument(
        "--pcap-test-exe",
        type=str,
        default=os.path.join("Tests", "Pcap++Test", "Pcap++Test.exe"),
        help="Custom path to Pcap++ test executable. Can be relative to the build directory.",
    )
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO)

    tcpreplay_interface, ip_address = find_interface()
    if not tcpreplay_interface or not ip_address:
        logging.critical("Cannot find an interface to run tests on!")
        exit(1)

    logging.info(f"Interface is {tcpreplay_interface} and IP address is {ip_address}")

    build_dir = Path(args.build_dir)
    logging.debug("Using build directory: %s", build_dir)

    def run_with_coverage(exec_path: Path, coverage_file: str, args: Iterable[str] = None):
        if args is None:
            args = []

        logging.debug("Running tests with coverage from: %s", exec_path)
        return subprocess.run(
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
                f"cobertura:{coverage_file}",
                "--working_dir",
                str(exec_path.parent),
                "--",
                str(exec_path),
                *args,
            ],
            cwd=exec_path.parent,
            check=True,
        )

    common_exec_path = build_dir / args.common_test_exe
    common_exec_path = common_exec_path.resolve()

    if args.coverage:
        run_with_coverage(common_exec_path, "Common++Coverage.xml")
    else:
        logging.debug("Running Common++ tests from: %s", common_exec_path)
        subprocess.run(
            str(common_exec_path),
            cwd=common_exec_path.parent,
            check=True,
        )

    packet_exec_path = build_dir / args.packet_test_exe
    packet_exec_path = packet_exec_path.resolve()

    if args.coverage:
        logging.debug("Running Packet++ tests with coverage from: %s", packet_exec_path)
        run_with_coverage(packet_exec_path, "Packet++Coverage.xml")
    else:
        logging.debug("Running Packet++ tests from: %s", packet_exec_path)
        subprocess.run(
            str(packet_exec_path),
            cwd=packet_exec_path.parent,
            check=True,
        )

    def make_tests_list_option(
        option: Literal["-t", "-x"], tests: list[str]
    ) -> list[str]:
        if not tests:
            return []
        return [option, ";".join(tests)]

    pcap_exec_path = build_dir / args.pcap_test_exe
    pcap_exec_path = pcap_exec_path.resolve()

    pcap_file_source = pcap_exec_path.parent / "PcapExamples" / "example.pcap"
    logging.debug("Pcap sample file: %s", pcap_file_source)

    with tcp_replay_worker(tcpreplay_interface, Path(TCPREPLAY_PATH), pcap_file_source):
        include_tests_opt = make_tests_list_option("-t", args.include_tests)
        skip_tests_opt = make_tests_list_option(
            "-x", ["TestRemoteCapture"] + args.skip_tests
        )
        pcap_cmd_args = [
            "-i",
            str(ip_address),
            *skip_tests_opt,
            *include_tests_opt,
        ]

        if args.coverage:
            logging.debug("Running Pcap++ tests with coverage from: %s", pcap_exec_path)
            run_with_coverage(pcap_exec_path, "Pcap++Coverage.xml", pcap_cmd_args)
        else:
            logging.debug("Running Pcap++ tests from: %s", pcap_exec_path)
            subprocess.run(
                [
                    str(pcap_exec_path),
                    *pcap_cmd_args,
                ],
                cwd=pcap_exec_path.parent,
                check=True,
            )


if __name__ == "__main__":
    main()
