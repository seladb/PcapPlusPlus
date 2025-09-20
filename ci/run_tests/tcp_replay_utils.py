from __future__ import annotations

import subprocess
import sys
from collections.abc import Generator
from dataclasses import dataclass
from contextlib import contextmanager
from pathlib import Path

PCAP_FILE_PATH = Path("Tests", "Pcap++Test", "PcapExamples", "example.pcap").absolute()


@dataclass
class TcpReplayTask:
    """A replay task that holds the tcpreplay instance and the subprocess procedure."""
    replay: TcpReplay
    procedure: subprocess.Popen


class TcpReplay:
    def __init__(self, tcpreplay_dir: str | None = None):
        """
        A wrapper class for managing tcpreplay operations.

        :param tcpreplay_dir: Directory where tcpreplay is located. If None, assumes tcpreplay is in the system PATH.
        """
        if tcpreplay_dir is None:
            self.executable = Path("tcpreplay")
        else:
            self.executable = Path(tcpreplay_dir) / "tcpreplay"

        if sys.platform == "win32":
            self.executable = self.executable.with_suffix(".exe")
        if not self.executable.exists():
            raise FileNotFoundError(f"tcpreplay executable not found at {self.executable}")

    @contextmanager
    def replay(self, interface: str, pcap_file: Path) -> Generator[TcpReplayTask, None, None]:
        """
        Context manager that starts tcpreplay and yields a TcpReplayTask.

        :param interface: Network interface to use for replaying packets.
        :param pcap_file: Path to the pcap file to replay.
        """
        cmd = [self.executable, "-i", interface, "--mbps=10", "-l", "0", str(pcap_file)]
        proc = subprocess.Popen(cmd)
        try:
            yield TcpReplayTask(replay=self, procedure=proc)
        finally:
            self._kill_process(proc)

    def get_nic_list(self):
        """
        Get the list of network interfaces using tcpreplay. Only works on Windows.

        :return: List of network interface names.
        """
        if sys.platform != "win32":
            # We don't use it on non-Windows platforms yet.
            raise RuntimeError("This method is only supported on Windows!")

        completed_process = subprocess.run(
            [self.executable, "--listnics"],
            shell=True,
            capture_output=True,
        )
        if completed_process.returncode != 0:
            raise RuntimeError('Error executing "tcpreplay --listnics"!')

        raw_nics_output = completed_process.stdout.decode("utf-8")
        nics = []
        for row in raw_nics_output.split("\n")[2:]:
            columns = row.split("\t")
            if len(columns) > 1 and columns[1].startswith("\\Device\\NPF_"):
                nics.append(columns[1])
        return nics


    @staticmethod
    def _kill_process(proc: subprocess.Popen) -> None:
        if sys.platform == "win32":
            # Use taskkill to kill the process and its children
            subprocess.call(["taskkill", "/F", "/T", "/PID", str(proc.pid)])
        else:
            proc.kill()
