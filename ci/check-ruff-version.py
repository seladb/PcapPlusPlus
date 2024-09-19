import subprocess

EXPECTED_RUFF_VERSION = "0.6.5"


def main():
    result = subprocess.run(("ruff", "--version"), capture_output=True)
    result.check_returncode()

    version_str = result.stdout.decode("utf-8").split(" ")[1].strip()
    if version_str != EXPECTED_RUFF_VERSION:
        raise ValueError(
            f"Error: Found ruff version {version_str}, but {EXPECTED_RUFF_VERSION} is required."
        )


if __name__ == "__main__":
    main()
