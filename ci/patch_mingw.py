from os import path
import fileinput

MINGW_PATH = "C:\\MinGW"
ptw32_errno_h_path = path.join(MINGW_PATH, "include", "ptw32_errno.h")


def main():
    with fileinput.FileInput(ptw32_errno_h_path, inplace=True, backup=".bak") as f:
        for line in f:
            if line.startswith("# include <winsock.h>"):
                print("//", line, end="")
            else:
                print(line, end="")
    print("Done patching MinGW")


if __name__ == "__main__":
    main()
