import os
import argparse
import subprocess
import scapy.arch.windows
from ipaddress import IPv4Address

from tcp_replay_utils import TcpReplay, PCAP_FILE_PATH

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


def find_interface(tcp_replay: TcpReplay):
    nic_devices = tcp_replay.get_nic_list()

    for device in nic_devices:
        nic_guid = device.lstrip("\\Device\\NPF_")
        ip_address = get_ip_by_guid(nic_guid)

        if ip_address and not ip_address.startswith("169.254"):
            completed_process = subprocess.run(
                ["curl", "--interface", ip_address, "www.google.com"],
                capture_output=True,
                shell=True,
            )
            if completed_process.returncode == 0:
                return device, ip_address

    return None, None


def run_packet_tests():
    return subprocess.run(
        os.path.join("Bin", "Packet++Test"),
        cwd=os.path.join("Tests", "Packet++Test"),
        shell=True,
        check=True,  # Raise exception if the worker returns in non-zero status code
    )


def run_packet_coverage():
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
            "cobertura:Packet++Coverage.xml",
            "--",
            os.path.join("Bin", "Packet++Test"),
        ],
        cwd=os.path.join("Tests", "Packet++Test"),
        shell=True,
        check=True,  # Raise exception if the worker returns in non-zero status code
    )


def run_pcap_tests(ip_address: str, skip_tests: list[str]):
    return subprocess.run(
        [
            os.path.join("Bin", "Pcap++Test"),
            "-i",
            ip_address,
            "-x",
            ";".join(skip_tests),
        ],
        cwd=os.path.join("Tests", "Pcap++Test"),
        shell=True,
        check=True,  # Raise exception if the worker returns in non-zero status code
    )


def run_pcap_coverage(ip_address: str, skip_tests: list[str]):
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
            "cobertura:Pcap++Coverage.xml",
            "--",
            os.path.join("Bin", "Pcap++Test"),
            "-i",
            ip_address,
            "-x",
            ";".join(skip_tests),
        ],
        cwd=os.path.join("Tests", "Pcap++Test"),
        shell=True,
        check=True,  # Raise exception if the worker returns in non-zero status code
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
        "--coverage",
        "-c",
        action="store_true",
        default=False,
        help="Enable OpenCppCoverage encapsulation to generate coverage report",
    )
    args = parser.parse_args()

    if args.coverage:
        run_packet_coverage()
    else:
        run_packet_tests()

    tcp_replay = TcpReplay(TCPREPLAY_PATH)

    tcpreplay_interface, ip_address = find_interface(tcp_replay)
    if not tcpreplay_interface or not ip_address:
        print("Cannot find an interface to run tests on!")
        exit(1)

    print(f"Interface is {tcpreplay_interface} and IP address is {ip_address}")

    skip_tests = ["TestRemoteCapture"] + args.skip_tests
    with tcp_replay.replay(tcpreplay_interface, PCAP_FILE_PATH):
        if args.coverage:
            run_pcap_coverage(ip_address, skip_tests)
        else:
            run_pcap_tests(ip_address, skip_tests)


if __name__ == "__main__":
    main()
