# PcapPlusPlus Development Guide

This file provides guidance for AI coding agents (e.g. OpenAI Codex, Claude, GitHub Copilot
Workspace, etc.) working inside the PcapPlusPlus repository. Read this before writing or
modifying code.

---

## Project Overview

PcapPlusPlus is a **multiplatform C++ library** for capturing, parsing, and crafting network
packets. It wraps popular packet-processing engines (libpcap, Npcap, WinPcap, DPDK, eBPF
AF_XDP, WinDivert, PF_RING) behind a clean, modern C++ API.

The codebase is organized into three libraries:

| Library | Purpose |
|---|---|
| `Common++` | Shared utilities used by both Packet++ and Pcap++ |
| `Packet++` | Protocol parsing, editing, and crafting (standalone; no libpcap required) |
| `Pcap++` | Packet capture/send via libpcap, Npcap, DPDK, etc. |

---

## Repository Layout

```
PcapPlusPlus/
├── Common++/           # Common++ library source & headers
├── Packet++/           # Packet++ library source & headers
├── Pcap++/             # Pcap++ library source & headers
├── Tests/
│   ├── Packet++Test/   # Unit tests for Packet++ (protocol parsing/crafting)
│   ├── Pcap++Test/     # Unit tests for Pcap++ (live capture, file I/O, etc.)
│   └── ExamplesTest/   # Python-based tests (written with pytest) for the example applications
├── Examples/           # Example applications
│   └── Tutorials/      # Tutorial source code
├── cmake/              # CMake helper modules
└── CMakeLists.txt      # Top-level CMake build file
```

---

## Building the Project

PcapPlusPlus uses **CMake** as its build system.

### Linux / macOS

Install the prerequisite (libpcap):
```bash
# Debian/Ubuntu
sudo apt-get install libpcap-dev

# RHEL/Fedora
sudo yum install libpcap-devel

# macOS (Xcode Command Line Tools already include libpcap)
xcode-select --install
```

Configure and build:
```bash
cmake -S . -B build
cmake --build build
```

Build outputs:
- `build/Common++/libCommon++.a`
- `build/Packet++/libPacket++.a`
- `build/Pcap++/libPcap++.a`
- `build/examples_bin/` — example binaries
- `Tests/Packet++Test/Bin/Packet++Test`
- `Tests/Pcap++Test/Bin/Pcap++Test`

### Key CMake Options

| Option                           | Default | Description                                          |
|----------------------------------|---------|------------------------------------------------------|
| `-DPCAPPP_BUILD_EXAMPLES=ON/OFF` | `ON`    | Build example apps                                   |
| `-DPCAPPP_BUILD_TESTS=ON/OFF`    | `ON`    | Build unit tests                                     |
| `-DPCAPPP_BUILD_TUTORIALS=ON/OFF` | `OFF`   | Build tutorial binaries                              |
| `-DBUILD_SHARED_LIBS=ON/OFF`     | `OFF`   | Build shared instead of static libs                  |
| `-DPCAPPP_USE_PCAP=ON/OFF`       | `ON`    | Enable libpcap/WinPcap/Npcap support                 |
| `-DPCAPPP_USE_DPDK=ON/OFF`       | `OFF`   | Enable DPDK support                                  |
| `-DPCAPPP_USE_PF_RING=ON/OFF`    | `OFF`   | Enable PF_RING support                               |
| `-DPCAPPP_USE_XDP=ON/OFF`        | `OFF`   | Enable AF_XDP support                                |
| `-DPCAPPP_USE_WINDIVERT=ON/OFF`  | `OFF`   | Enable WinDivert support                             |
| `-DPCAPPP_BUILD_PCAPPP=ON/OFF`   | `ON`    | Build Pcap++ (turn off for Packet++ & Common++ only) |
| `-DLIGHT_PCAPNG_ZSTD=ON/OFF`     | `OFF`   | Enable Zstd PCAPNG compression                       |

### Windows (Visual Studio 2019/2022)

Download and install Npcap SDK (or WinPcap developer's pack) before configuring:
```powershell
cmake -S . -B build -G "Visual Studio 17 2022" -DPCAP_ROOT=<path_to_npcap_sdk>
cmake --build build --config Release
```

---

## Running Tests

**Always run tests from inside the test directory** — the test binaries rely on relative paths to
fixture files.

### Packet++Test (protocol parsing/crafting — no network required)

```bash
cd Tests/Packet++Test
Bin/Packet++Test
```

Run a subset by tag:
```bash
Bin/Packet++Test -t "eth;ipv4"
```

Run a specific test case:
```bash
Bin/Packet++Test -t ArpPacketCreation
```

Useful flags:

| Flag                         | Description                                                    |
|------------------------------|----------------------------------------------------------------|
| `-t / --include-tags`        | Run only tests matching the given semicolon-separated tag list |
| `-x / --exclude-tags`        | Exclude tests matching the given semicolon-separated tag list  |
| `-m / --mem-verbose`         | Verbose memory allocation output (leak debugging)              |
| `-s / --skip-mem-leak-check` | Skip the per-test memory leak check                            |

### Pcap++Test (live capture, file I/O, DPDK, etc.)

Requires `sudo` on Linux and macOS. Some tests need active network traffic on the specified interface.
```bash
cd Tests/Pcap++Test
sudo Bin/Pcap++Test -i <interface_ip>
```

To skip all tests that require live networking:
```bash
sudo Bin/Pcap++Test -n
```

Run a subset by tag:
```bash
sudo Bin/Pcap++Test -i <interface_ip> -t "dpdk"
```

Run a specific test case:
```bash
sudo Bin/Pcap++Test -i <interface_ip> -t TestSendPacket
```

Useful flags:

| Flag                         | Description                                                            |
|------------------------------|------------------------------------------------------------------------|
| `-i / --use-ip`              | IPv4 address of the interface to use (required for live-traffic tests) |
| `-n / --no-networking`       | Skip tests that require a live network interface                       |
| `-k / --dpdk-port`           | DPDK port number (required when built with DPDK)                       |
| `-t / --include-tags`        | Same tag filter mechanism as Packet++Test                              |
| `-x / --exclude-tags`        | Exclude tests matching the given semicolon-separated tag list          |
| `-d / --debug-mode`          | Set log level to DEBUG for all tests                                   |
| `-s / --skip-mem-leak-check` | Skip per-test memory leak checks                                       |

### Example tests (Python)

There is a Python-based test suite for the example applications under `Tests/ExamplesTests`.

Before running the tests:
- Make sure all examples are built
- Create a virtualenv with the dependencies defined in `ExamplesTest/requirements.txt`

Run the tests:

```bash
cd Tests/ExamplesTest
python3 -m pytest --interface <interface_name> --root-path=../../build/examples_bin
```

---

## Writing Tests

- Tests live in `Tests/Packet++Test/` (Packet++) or `Tests/Pcap++Test/` (Pcap++).
- Each test case is a function decorated with the `PTF_TEST_CASE` macro.
- Register new tests in the `TestDefinition.h` and add `PTF_RUN_TEST(<TEST_NAME>)` in `main.cpp`, assigning meaningful tags.
- Packet example files (`.pcap`, `.pcapng`) used as fixtures go in:
  - `Tests/Packet++Test/PacketExamples/`
  - `Tests/Pcap++Test/PcapExamples/`
- Memory-leak checking via **MemPlumber** runs automatically for every test case. Ensure
  all heap allocations are properly freed.

Example skeleton:
```cpp
PTF_TEST_CASE(MyNewProtocolParseTest)
{
    // Load a pcap file
    pcpp::PcapFileReaderDevice reader("PacketExamples/my_protocol.pcap");
    PTF_ASSERT_TRUE(reader.open());

    pcpp::RawPacket rawPacket;
    PTF_ASSERT_TRUE(reader.getNextPacket(rawPacket));

    pcpp::Packet parsedPacket(&rawPacket);
    auto* layer = parsedPacket.getLayerOfType<pcpp::MyProtocolLayer>();
    PTF_ASSERT_NOT_NULL(layer);

    PTF_ASSERT_EQUAL(layer->getSomeField(), expectedValue);
}  // MyNewProtocolParseTest
```

---

## Coding Conventions

- **Language standard:** C++14 (do not use C++17/20 features).
- **Namespace:** All public API lives under the `pcpp` namespace.
- **Header guards:** Use `#pragma once` (preferred in this codebase) or traditional include guards.
- **Naming:**
  - Classes: `PascalCase` (e.g., `TcpLayer`, `PcapFileReaderDevice`)
  - Methods & functions: `camelCase` (e.g., `getNextPacket`, `parseNextLayer`)
  - Member variables: `m_PascalCase` (e.g., `m_Data`, `m_NextLayer`)
  - Constants / enums: `UPPER_CASE` or `PascalCase` depending on context
- **Formatting:** Use `clang-format` version 19.1.6 (could be installed in Python via virtualenv). A `.clang-format` is present at the repository root. Format new code
  before committing:
  ```bash
  clang-format -i -style=file <your_file.cpp> <your_file.h>
  ```
- **Documentation:** Public API classes, methods, and enums should have Doxygen-style comments using tiple slashes (`///`).
- **No raw `new`/`delete` without ownership clarity:** Prefer RAII. When a class owns heap
  memory, implement or explicitly delete the copy constructor and assignment operator.

---

## Adding a New Protocol Layer

1. Create `Packet++/header/MyProtocolLayer.h` and `Packet++/src/MyProtocolLayer.cpp`.
2. Inherit from `pcpp::Layer` (or a more specific base as needed).
3. Implement at minimum:
   - `parseNextLayer()` — identify and instantiate the next layer
   - `getHeaderLen()` — return the fixed or computed header size
   - `computeCalculateFields()` — recalculate checksums / length fields
   - `toString()` — human-readable summary
4. Register the protocol in `parseNextLayer()` of the previous protocol (that could be `TcpLayer`, `UdpLayer`, `EthLayer`, etc., or sometimes multiple protocols)
   so the packet parser knows when to invoke your layer.
5. Add your files to `Packet++/CMakeLists.txt`.
6. Write test cases in `Tests/Packet++Test/` and add example pcap files to
   `Tests/Packet++Test/PacketExamples/`.

---

## Pull Request Checklist

Before submitting a PR, verify:

- [ ] Code compiles cleanly on Linux (and ideally on macOS/Windows if relevant).
- [ ] All existing tests pass: `Bin/Packet++Test` and `Bin/Pcap++Test -n`.
- [ ] New functionality is covered by new test cases.
- [ ] New public API is documented with Doxygen comments.
- [ ] Code is formatted with `clang-format` using the repository's `.clang-format` config.
- [ ] No memory leaks detected (MemPlumber checks pass).
- [ ] Example pcap/pcapng files added for any new protocol or feature tests.

---

## Useful Links

- **Documentation & website:** https://pcapplusplus.github.io/
- **API reference:** https://pcapplusplus.github.io/docs/api
- **Contribution guide:** https://pcapplusplus.github.io/community#contribute
- **Issue tracker:** https://github.com/seladb/PcapPlusPlus/issues
- **Releases:** https://github.com/seladb/PcapPlusPlus/releases
