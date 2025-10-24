import os
import argparse
import subprocess
import scapy.arch.windows
from ipaddress import IPv4Address

TCPREPLAY_PATH = "tcpreplay-4.4.1-win"
PCAP_FILE_PATH = os.path.abspath(
    os.path.join("Tests", "Pcap++Test", "PcapExamples", "example.pcap")
)


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


def run_common_tests():
    return subprocess.run(
        os.path.join("Bin", "Common++Test"),
        cwd=os.path.join("Tests", "Common++Test"),
        shell=True,
        check=True,  # Raise exception if the worker returns in non-zero status code
    )


def run_common_coverage():
    raise NotImplementedError


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

    tcpreplay_interface, ip_address = find_interface()
    if not tcpreplay_interface or not ip_address:
        print("Cannot find an interface to run tests on!")
        exit(1)
    print(f"Interface is {tcpreplay_interface} and IP address is {ip_address}")

    if args.coverage:
        run_packet_coverage()
    else:
        run_common_tests()
        run_packet_tests()

    try:
        tcpreplay_cmd = (
            f'tcpreplay.exe -i "{tcpreplay_interface}" --mbps=10 -l 0 {PCAP_FILE_PATH}'
        )
        tcpreplay_proc = subprocess.Popen(tcpreplay_cmd, shell=True, cwd=TCPREPLAY_PATH)

        skip_tests = ["TestRemoteCapture"] + args.skip_tests
        if args.coverage:
            run_pcap_coverage(ip_address, skip_tests)
        else:
            run_pcap_tests(ip_address, skip_tests)

    finally:
        subprocess.call(["taskkill", "/F", "/T", "/PID", str(tcpreplay_proc.pid)])


if __name__ == "__main__":
    main()
