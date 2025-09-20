from __future__ import annotations

import os
import subprocess
import sys
from collections.abc import Generator
from dataclasses import dataclass
from contextlib import contextmanager
from pathlib import Path

WIN32_TCPREPLAY_PATH = "tcpreplay-4.4.1-win"
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
class TcpReplayTask:
    """A replay task that holds the tcpreplay instance and the subprocess procedure."""
    replay: TcpReplay
    procedure: subprocess.Popen


class TcpReplay:
    def __init__(self, tcpreplay_dir: str):
        """
        A wrapper class for managing tcpreplay operations.

        :param tcpreplay_dir: Directory where tcpreplay is located.
        """
        self.tcpreplay_dir = tcpreplay_dir

    @contextmanager
    def replay(self, interface: str, pcap_file: Path) -> Generator[TcpReplayTask, None, None]:
        """Context manager that starts tcpreplay and yields a TcpReplayTask."""
        cmd = ["tcpreplay", "-i", interface, "--mbps=10", "-l", "0", str(pcap_file)]
        proc = subprocess.Popen(cmd, cwd=self.tcpreplay_dir)
        try:
            yield TcpReplayTask(replay=self, procedure=proc)
        finally:
            self._kill_process(proc)


    @staticmethod
    def _kill_process(proc: subprocess.Popen) -> None:
        if sys.platform == "win32":
            # Use taskkill to kill the process and its children
            subprocess.call(["taskkill", "/F", "/T", "/PID", str(proc.pid)])
        else:
            proc.kill()