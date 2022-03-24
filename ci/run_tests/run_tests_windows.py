import os
import argparse
import subprocess
import netifaces as ni

TCPREPLAY_PATH = "tcpreplay-4.4.1-win"
PCAP_FILE_PATH = os.path.abspath(
    os.path.join("Tests", "Pcap++Test", "PcapExamples", "example.pcap")
)


def find_interface():
    completed_process = subprocess.run(
        ["tcpreplay.exe", "--listnics"],
        shell=True,
        capture_output=True,
        cwd=TCPREPLAY_PATH,
    )
    raw_nics_output = completed_process.stdout.decode("utf-8")
    for row in raw_nics_output.split("\n")[2:]:
        columns = row.split("\t")
        if len(columns) > 1 and columns[1].startswith("\\Device\\NPF_"):
            interface = columns[1]
            try:
                ni_interface = interface.lstrip("\\Device\\NPF_")
                ip_address = ni.ifaddresses(ni_interface)[ni.AF_INET][0]["addr"]
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
            except:
                pass
    return None, None


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
    args = parser.parse_args()

    tcpreplay_interface, ip_address = find_interface()
    if not tcpreplay_interface or not ip_address:
        print("Cannot find an interface to run tests on!")
        exit(1)
    print(f"Interface is {tcpreplay_interface} and IP address is {ip_address}")

    try:
        tcpreplay_cmd = (
            f'tcpreplay.exe -i "{tcpreplay_interface}" --mbps=10 -l 0 {PCAP_FILE_PATH}'
        )
        tcpreplay_proc = subprocess.Popen(tcpreplay_cmd, shell=True, cwd=TCPREPLAY_PATH)

        completed_process = subprocess.run(
            os.path.join("Bin", "Packet++Test"),
            cwd=os.path.join("Tests", "Packet++Test"),
            shell=True,
        )
        if completed_process.returncode != 0:
            exit(completed_process.returncode)

        skip_tests = ["TestRemoteCapture"] + args.skip_tests
        completed_process = subprocess.run(
            [
                os.path.join("Bin", "Pcap++Test"),
                "-i",
                ip_address,
                "-x",
                ";".join(skip_tests),
            ],
            cwd=os.path.join("Tests", "Pcap++Test"),
            shell=True,
        )
        if completed_process.returncode != 0:
            exit(completed_process.returncode)

    finally:
        subprocess.call(["taskkill", "/F", "/T", "/PID", str(tcpreplay_proc.pid)])


if __name__ == "__main__":
    main()
