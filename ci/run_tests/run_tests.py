import os
import subprocess
import argparse
import netifaces as ni

PCAP_FILE_PATH = os.path.join("Tests", "Pcap++Test", "PcapExamples", "example.pcap")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--interface", "-i", type=str, required=True, help="interface to use"
    )
    parser.add_argument(
        "--use-sudo", "-s", action="store_true", help="use sudo when running tests"
    )
    parser.add_argument(
        "--test-args",
        "-t",
        type=str,
        default="",
        help="test arguments",
    )
    parser.add_argument(
        "--tcpreplay-dir",
        "-d",
        type=str,
        default=None,
        help="tcpreplay directory",
    )
    args = parser.parse_args()

    ip_address = ni.ifaddresses(args.interface)[ni.AF_INET][0]["addr"]
    print("IP address is: %s" % ip_address)

    try:
        tcpreplay_proc = subprocess.Popen(
            ["tcpreplay", "-i", args.interface, "--mbps=10", "-l", "0", PCAP_FILE_PATH],
            cwd=args.tcpreplay_dir,
        )

        use_sudo = ["sudo"] if args.use_sudo else []
        completed_process = subprocess.run(
            use_sudo + [os.path.join("Bin", "Packet++Test")] + args.test_args.split(),
            cwd="Tests/Packet++Test",
        )
        if completed_process.returncode != 0:
            exit(completed_process.returncode)

        completed_process = subprocess.run(
            use_sudo
            + [os.path.join("Bin", "Pcap++Test"), "-i", ip_address]
            + args.test_args.split(),
            cwd="Tests/Pcap++Test",
        )
        if completed_process.returncode != 0:
            exit(completed_process.returncode)

    finally:
        tcpreplay_proc.kill()


if __name__ == "__main__":
    main()
