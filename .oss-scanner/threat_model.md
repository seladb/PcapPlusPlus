# Threat model

## What this project does and where untrusted input enters
- PcapPlusPlus is a multiplatform C++14 library for capturing, parsing, crafting and editing network packets. It has three libraries: `Common++` (utilities), `Packet++` (protocol parsing/crafting, no libpcap needed) and `Pcap++` (capture/send and file I/O on top of libpcap/Npcap, DPDK, AF_XDP, PF_RING, WinDivert).
- We assume **all packet bytes are untrusted**, whether they come from the wire, from a pcap/pcapng/snoop file, or from a remote capture. A library user may analyze hostile traffic or files, so a crafted packet must never cause memory corruption. Also it is possible that some packets might be corrupted, malformed, truncated or non-standard.
- Main entry points for untrusted input:
  - Raw packet data handed to `pcpp::RawPacket` / `pcpp::Packet` and then parsed layer by layer (`Layer::parseNextLayer()`, constructors and getters of every `*Layer` in `Packet++/src`). This includes length/offset/count fields, TLV and option lists, DNS name compression pointers, HTTP/SIP/SMTP/FTP text parsing, TLS/SSL handshake and X.509/ASN.1 decoding, QUIC, BGP, GTP, LDAP, IPv6 extension headers and all supported protocols fields.
  - Capture files read by `PcapFileReaderDevice`, `PcapNgFileReaderDevice` and `SnoopFileReaderDevice` in `Pcap++/src/PcapFileDevice.cpp`, which use libpcap and the bundled LightPcapNg. File headers, block lengths and options are attacker-controlled.
  - Stateful reassembly over untrusted streams: `TcpReassembly` (`Packet++/src/TcpReassembly.cpp`) and `IPReassembly` / IP fragmentation (`Packet++/src/IPReassembly.cpp`). These keep per-flow state and buffers driven by attacker data.
  - Live capture devices (`PcapLiveDevice`, `PcapRemoteDevice`, `RawSocketDevice`, DPDK, XDP, PF_RING, WinDivert, `MBufRawPacket`) deliver untrusted frames into the parsers.
  - Text/file inputs to helpers: PEM/DER key and certificate decoders (`PemCodec`, `CryptoKeyDecoder`, `X509Decoder`, `Asn1Codec`), BPF filter strings (`PcapFilter`), and IP/MAC address string parsing in `Common++`.
- Not attacker-controlled: command-line arguments of the example applications and the code that a library user writes. Treat those as trusted unless a library API is misused in a way that its documentation does not forbid.

## Components that matter most / least
- **Most important (in scope, highest priority):**
  - `Packet++/src` and `Packet++/header`: all protocol layers, the parser chain in `Packet.cpp`/`Layer.cpp`/`RawPacket.cpp`, the layer editing and crafting code (`extendLayer`, `shortenLayer`, `addOption`, `addResource`, and similar functions that resize or move buffers), `TcpReassembly` and `IPReassembly`.
  - `Pcap++/src/PcapFileDevice.cpp` (pcap/pcapng/snoop file readers and writers), `PcapFilter.cpp`, and the packet-delivery paths of the live devices.
  - `Common++/src`: IP/MAC address parsing, `OUILookup` (parses a JSON dataset), `Serializers`, `GeneralUtils`, `Logger`.
- **In scope but lower priority:** the writer paths (`PcapFileWriterDevice`, `PcapNgFileWriterDevice`), crafting APIs fed by trusted data, the platform-specific device code (DPDK, KNI, XDP, PF_RING, WinDivert, `WinPcapLiveDevice`, `LinuxNicInformationSocket`), and `NetworkUtils`. These matter mostly when they handle captured data.
- **Less important:** the applications in `Examples/` (and `Examples/Tutorials`). Memory-safety bugs there are still reported, particularly in the ones that parse untrusted pcaps or traffic (`PcapPrinter`, `PcapSplitter`, `PcapSearch`, `HttpAnalyzer`, `SSLAnalyzer`, `TcpReassembly`, `X509Toolkit`, `IcmpFileTransfer`). Issues that need a malicious local command line are out of scope.
- **Out of scope (third-party or generated code):**
  - `3rdParty/`: `EndianPortable`, `Getopt-for-Visual-Studio`, `hash-library`, `json` (nlohmann), `MemPlumber`, `OUIDataset`.
  - `3rdParty/LightPcapNg` is vendored third-party code, **but** it parses untrusted pcapng files for us. Report bugs reachable through `PcapNgFileReaderDevice` / `PcapNgFileWriterDevice` and say clearly that the root cause is in the vendored code.
  - `Tests/` (including `PcppTestFramework`, `PcppTestUtilities`), `ci/`, `cmake/`, `build/`, `translation/` and documentation.

## How to exercise it
- Build with CMake: `cmake -S . -B build && cmake --build build`. Add `-DPCAPPP_BUILD_EXAMPLES=ON` for the example binaries (`build/examples_bin/`). To scan only the parsing code use `-DPCAPPP_BUILD_PCAPPP=OFF`, which builds just Common++ and Packet++ and needs no libpcap. Building with ASan/UBSan (for example `-DCMAKE_CXX_FLAGS="-fsanitize=address,undefined -g"`) is recommended. For additional instructions and explanations check `AGENTS.md`
- `Tests/Fuzzers/` has the libFuzzer/oss-fuzz harnesses. `FuzzTarget.cpp` parses pcap, pcapng and snoop input and walks every parsed layer (`ReadParsedPacket.h`). `FuzzWriter.cpp` converts between pcap and pcapng. `Tests/Fuzzers/RegressionTests/` contains regression samples and `run_tests.sh`. New fuzz harnesses for individual layers or for the reassembly classes are welcome.
- `Tests/Packet++Test/` is the unit test suite for parsing/crafting, and needs no network. Fixtures are in `Tests/Packet++Test/PacketExamples/`. Run it from inside that directory: `cd Tests/Packet++Test && Bin/Packet++Test`. Every test is also leak-checked with MemPlumber.
- `Tests/Pcap++Test/` covers file I/O and live capture. Run `sudo Bin/Pcap++Test -n` to skip anything that needs the network. Fixtures are in `Tests/Pcap++Test/PcapExamples/`.
- `Examples/PcapPrinter`, `PcapSplitter`, `PcapSearch`, `TcpReassembly`, `HttpAnalyzer`, `SSLAnalyzer`, `X509Toolkit` and `IPDefragUtil` are small drivers that read a pcap file and exercise the parsers, which makes them good for scanning with crafted files. `Tests/ExamplesTest/` has pytest tests with sample pcaps (`pcap_examples/`).
- Anything that needs a live interface, root privileges, DPDK, PF_RING, XDP or WinDivert hardware is hard to exercise. Prefer reasoning about the code and reproducing with pcap files.
- It is possible to run all tests using `. /src/.venv/bin/activate && python3 /src/ci/run_tests/run_tests.py --interface lo --build-dir /src/build`. But if the provided docker/container has a live interface it should be updated to a live interface name which is exist. If only available interface is loopback some of the `*Live*` named tests might fail this is normal.

## How you rate severity
- Out-of-bounds read or write, use-after-free, double free, uninitialized memory use, or integer overflow leading to any of these, reachable from crafted packet or file bytes through the public API: **high at a minimum**. If the overflow is controlled (attacker picks the size and the content) and could give code execution, rate it **critical**.
- Out-of-bounds **read** that only crashes or leaks a few bytes of adjacent memory: **high**, or medium if it is a small fixed-size over-read that gives the attacker no useful data.
- Denial of service from crafted input is **medium**: infinite loops, unbounded recursion or stack exhaustion (for example DNS compression pointer loops, nested ASN.1/X.509), huge allocations from an attacker-controlled length, and unbounded memory growth in `TcpReassembly` / `IPReassembly` flows. Rate it **low** if it is bounded or needs unusual configuration.
- Parser logic errors with no memory-safety impact (wrong field value, wrong protocol detected, incorrect checksum): **low**, unless they enable a security decision to be bypassed (for example a filter or the reassembly logic being fooled).
- Memory leaks per packet or per file that let an attacker exhaust memory: **medium**. A one-off leak is **low**.
- Findings in `Examples/` are rated one level lower than the equivalent library bug.
- Report only issues reachable from untrusted data, and include a minimal reproducer (a small pcap/pcapng or a byte sequence passed to the layer constructor) plus the sanitizer output if you have it.

## Anything to leave alone
- Everything under `3rdParty/` except the LightPcapNg-via-pcapng-reader case above, plus `Tests/`, `ci/`, `build/`, `cmake/` and `translation/`.
- Misuse of the API that the documentation already prohibits, for example using a `Layer` or `Packet` after its `RawPacket` was freed, passing an `IPAddress` or buffer with a wrong length from trusted code, or calling non-thread-safe methods concurrently. Layers do not validate their own lifetime.
- `Layer`/`Packet` getters that read from a buffer the caller built with a wrong size and flagged as trusted (the caller promises the data is `dataLen` bytes long).
- Command-line argument handling, `getopt`, and path handling in `Examples/` (they are not meant to run with elevated privileges against hostile arguments).
- Requirements for root/CAP_NET_RAW, DPDK/PF_RING/XDP setup, or interface configuration. Needing privileges to open a live device is expected, not a vulnerability.
- Missing hardening that is optional (stack protector, FORTIFY flags) and general code-style or cppcheck/clang-tidy findings already tracked in `cppcheckSuppressions.txt`.
- Issues in the unsupported/deprecated platforms or compilers (for example WinPcap-only code paths).
- Protocol-level weaknesses that are the nature of the protocol (spoofing, ARP/DNS poisoning with `ArpSpoofing`/`DnsSpoofing` examples, which are intentional attack-simulation tools).
- Duplicate findings of issues that oss-fuzz already tracks and that are fixed in `master`.
