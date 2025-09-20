from __future__ import annotations

import os
import subprocess
import argparse
from scapy.all import get_if_addr

from tcp_replay_utils import TcpReplay


def run_packet_tests(args: list[str], use_sudo: bool):
    cmd_line = ["sudo"] if use_sudo else []
    cmd_line += [os.path.join("Bin", "Packet++Test"), *args]

    completed_process = subprocess.run(cmd_line, cwd="Tests/Packet++Test")

    if completed_process.returncode != 0:
        raise RuntimeError(f"Error while executing Packet++ tests: {completed_process}")


def run_pcap_tests(interface: str, tcpreplay: TcpReplay, args: list[str], use_sudo: bool):
    ip_address = get_if_addr(interface)
    print(f"IP address is: {ip_address}")

    with tcpreplay.replay(interface):
        cmd_line = ["sudo"] if use_sudo else []
        cmd_line += [os.path.join("Bin", "Pcap++Test"), "-i", ip_address, *args]

        completed_process = subprocess.run(cmd_line, cwd="Tests/Pcap++Test")
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
    args = parser.parse_args()

    if "packet" in args.test_suites:
        run_packet_tests(args.packet_test_args.split(), args.use_sudo)

    if "pcap" in args.test_suites:
        tcp_replay = TcpReplay(args.tcpreplay_dir)

        run_pcap_tests(
            args.interface,
            tcp_replay,
            args.pcap_test_args.split(),
            args.use_sudo,
        )


if __name__ == "__main__":
    main()
