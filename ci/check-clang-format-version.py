import subprocess

EXPECTED_CLANG_VERSION = "18.1.6"


def main():
    result = subprocess.run("clang-format --version", capture_output=True)
    result.check_returncode()

    version_str = result.stdout.decode("utf-8").split(" ")[2].strip()
    if version_str != EXPECTED_CLANG_VERSION:
        print(
            f"Error: Found clang-format version {version_str}, but {EXPECTED_CLANG_VERSION} is required."
        )
        exit(1)

    print("Clang format version satisfied.")
    exit(0)


if __name__ == "__main__":
    main()
