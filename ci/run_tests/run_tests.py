from __future__ import annotations

import os
import subprocess
import argparse
from pathlib import Path
from dataclasses import dataclass
from contextlib import contextmanager
from scapy.all import get_if_addr

PCAP_FILE_PATH = os.path.join("Tests", "Pcap++Test", "PcapExamples", "example.pcap")


@contextmanager
def tcp_replay_worker(interface: str, tcpreplay_dir: str):
    tcpreplay_proc = subprocess.Popen(
        ["tcpreplay", "-i", interface, "--mbps=10", "-l", "0", PCAP_FILE_PATH],
        cwd=tcpreplay_dir,
    )
    try:
        yield tcpreplay_proc
    finally:
        tcpreplay_proc.kill()


@dataclass
class Runner:
    build_dir: Path
    use_sudo: bool = False
    packet_test_path = Path("Tests", "Packet++Test", "Packet++Test")
    pcap_test_path = Path("Tests", "Pcap++Test", "Pcap++Test")

    def run_packet_tests(self, args: list[str]):
        exe_path = self.build_dir / self.packet_test_path
        work_dir = exe_path.parent

        cmd_line = ["sudo"] if self.use_sudo else []
        cmd_line += [str(exe_path), *args]

        completed_process = subprocess.run(cmd_line, cwd=str(work_dir))

        if completed_process.returncode != 0:
            raise RuntimeError(f"Error while executing Packet++ tests: {completed_process}")


    def run_pcap_tests(self, interface: str, tcpreplay_dir: str, args: list[str]):
        ip_address = get_if_addr(interface)
        print(f"IP address is: {ip_address}")

        exe_path = self.build_dir / self.pcap_test_path
        work_dir = exe_path.parent

        cmd_line = ["sudo"] if self.use_sudo else []
        cmd_line += [str(exe_path), "-i", ip_address, *args]

        with tcp_replay_worker(interface, tcpreplay_dir):
            completed_process = subprocess.run(cmd_line, cwd=str(work_dir))
            if completed_process.returncode != 0:
                raise RuntimeError(
                    f"Error while executing Pcap++ tests: {completed_process}"
                )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--interface", type=str, required=True, help="interface to use")
    parser.add_argument(
        "--use-sudo", action="store_true", help="use sudo when running tests"
    )
    parser.add_argument(
        "--test-suites",
        nargs="+",
        type=str,
        default=["packet", "pcap"],
        choices=["packet", "pcap"],
        help="test suites to use",
    )
    parser.add_argument(
        "--packet-test-args",
        type=str,
        default="",
        help="packet++ test arguments",
    )
    parser.add_argument(
        "--pcap-test-args",
        type=str,
        default="",
        help="pcap++ test arguments",
    )
    parser.add_argument(
        "--tcpreplay-dir",
        type=str,
        default=None,
        help="tcpreplay directory",
    )
    parser.add_argument(
        "build-dir",
        type=str,
        default=os.getcwd(),
        dst="build_dir",
        help="path to the build directory"
    )
    args = parser.parse_args()

    runner = Runner(build_dir=Path(args.build_dir), use_sudo=args.use_sudo)

    if "packet" in args.test_suites:
        runner.run_packet_tests(args.packet_test_args.split())

    if "pcap" in args.test_suites:
        runner.run_pcap_tests(
            args.interface,
            args.tcpreplay_dir,
            args.pcap_test_args.split()
        )


if __name__ == "__main__":
    main()
