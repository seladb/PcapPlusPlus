# IoUringPcapReaderDevice: High-Throughput Linux io_uring PCAP Ingestion for PcapPlusPlus

An experimental offline PCAP file reader for Linux that leverages the asynchronous `io_uring` kernel subsystem (`liburing`) to accelerate ingestion of large packet captures on high-speed NVMe storage.

---

## 1. Motivation & Background

Standard offline PCAP readers in PcapPlusPlus (`pcpp::PcapFileReaderDevice`) rely on synchronous POSIX I/O via `libpcap` or standard streams. When analyzing multi-gigabyte captures on modern NVMe SSDs capable of multi-GB/s read throughput:
- Storage queue depth remains shallow with synchronous requests.
- The CPU can stall waiting for storage blocks rather than actively parsing network headers.
- Repeated synchronous system calls incur kernel transition overhead.

`IoUringPcapReaderDevice` bypasses libpcap for file reading and directly parses the raw binary PCAP format. It maintains a circular asynchronous queue of page-aligned chunk buffers (e.g., three 4MB buffers), overlapping NVMe DMA background pre-fetching with CPU packet header decoding in userspace.

---

## 2. Architecture & Design

### Class Hierarchy
`IoUringPcapReaderDevice` inherits from `pcpp::IFileReaderDevice`, maintaining API compatibility with PcapPlusPlus:
- `open()` / `close()` / `isOpened()`
- `getNextPacket(RawPacket& rawPacket)` (Safe Owning API, compatible with existing code)
- `getNextPacketView(RawPacket& rawPacket)` (Zero-Copy Streaming View API)
- `forEachPacketView(Callback&& callback)` (Inlined functor streaming)
- `getStatistics(PcapStats& stats)`
- `setFilter(string / GeneralFilter)` via BPF filtering engine

### Ring Buffer Pipeline
- **Circular Prefetch Pipeline**: A configurable ring of $N$ buffers (default $N = 3$, chunk size = 4MB) keeps storage queue depth saturated. While the CPU decodes Buffer $k$, the kernel asynchronously fills Buffers $k+1$ and $k+2$.
- **Boundary & Arbitrary Chunk Gathering**: If a packet crosses a chunk boundary (at the 16-byte header or across payload bytes), an internal elastic staging buffer gathers the split record across any number of chunks without truncation or memory corruption.
- **Endianness & Precision**: Automatically detects byte-swapped captures (`0xd4c3b2a1`, `0x4d3cb2a1`) and nanosecond timestamp resolution (`0xa1b23c4d`). Rejects incompatible modified variants (such as Kuznetsov 24-byte records).
- **Strict Lifetime Contracts**:
  - `getNextPacket(rawPacket)`: Allocates an independent owned buffer (`takeOwnership = true`), allowing packets to be retained in vectors, STL containers, or passed across threads.
  - `getNextPacketView(rawPacket)`: Provides zero-copy pointers directly into chunk/staging memory with zero per-packet heap allocations. The view is valid until the next packet read.
- **Teardown & Clean EOF**: Drains in-flight requests before buffer deallocation and strictly validates clean EOF against partial or malformed record boundaries.

---

## 3. Workload & Hardware Dependencies

The performance characteristics of `io_uring` file ingestion depend significantly on workload, file size, and hardware:

- **Storage Media**: The primary advantage comes from keeping high-speed NVMe storage queues deep. On slower storage (rotational disks, network mounts) or single-channel devices, throughput is bound by the underlying medium rather than asynchronous queueing.
- **File Size & Page Cache**: On small files or files already resident in the Linux RAM page cache, standard POSIX `read()` has minimal overhead. In warm-cache scenarios with small captures, ring setup and buffer management overhead may result in performance equivalent to the baseline reader. The asynchronous prefetching model is intended for large captures (hundreds of megabytes to multi-gigabytes).
- **Kernel Version**: Requires Linux with `io_uring` enabled (kernel 5.5+ for `readv`, 5.6+ for `read`).

---

## 4. Benchmark Measurements (Author-Reported on 5.12 GB Test Capture)

> **Disclaimer**: The following performance metrics and system call reductions are author-reported observations obtained on the specific hardware, PCIe NVMe storage, and 5.12 GB dataset described in §3. These figures illustrate throughput potential under high storage queue depth and are not independently verified across different environments, file sizes, or filesystem cache states.

Below are representative metrics measured on a 5,120 MB PCAP capture (7,765,922 Ethernet/IPv4/TCP packets, 64 to 1514 bytes) on an Intel Core i5 test system with PCIe NVMe storage:

### A. Throughput Comparison

| Reader Implementation | Mode | Elapsed Time | Throughput (MB/s) | Packet Rate | Relative Speedup |
|:---|:---|:---:|:---:|:---:|:---:|
| **Baseline (`PcapFileReaderDevice`)** | Raw Ingestion | 1.535 s | 3,259.2 MB/s | 5.06 M pkts/s | 1.00x |
| **`IoUringPcapReaderDevice`** | Standard Owned (`getNextPacket`) | 1.286 s | 3,889.3 MB/s | 6.04 M pkts/s | **1.19x** (+19.3%) |
| **`IoUringPcapReaderDevice`** | Zero-Copy View (`getNextPacketView`) | 1.225 s | **4,081.5 MB/s** | **6.34 M pkts/s** | **1.25x** (+25.2%) |
| **Baseline (`PcapFileReaderDevice`)** | Full Header Parsing (`--parse`) | 4.340 s | 1,152.4 MB/s | 1.79 M pkts/s | 1.00x |
| **`IoUringPcapReaderDevice`** | Full Header Parsing (`--parse`) | 3.572 s | **1,400.2 MB/s** | **2.17 M pkts/s** | **1.22x** (+21.5%) |

### B. System Call Overhead (`strace -c` on 5.12 GB File)

- **Baseline (`PcapFileReaderDevice`)**:
  - `read()` system calls: ~655,000 calls
  - Syscall execution time: ~1.44 seconds

- **`IoUringPcapReaderDevice`**:
  - `io_uring_enter()` system calls: ~1,280 calls
  - Syscall execution time: ~0.35 seconds
  - Significant reduction in kernel transition frequency due to 4MB chunk batching.

---

## 5. Verification & Testing

Verification is implemented across two complementary locations:

1. **Integrated Framework Tests (`Tests/Pcap++Test`)**:
   - Registered under tag `io_uring` in `TestIoUringPcapReaderDevice`.
   - Compares packet count, frame lengths, captured lengths, nanosecond/microsecond timestamps, and byte-for-byte payload matching against `PcapFileReaderDevice`.
   - Tests format variations (nanosecond precision, big-endian byte swapping, SLL/SLL2/RawIP/Null framing).
   - Validates device lifecycle (early close, full EOF reopen, failed open recovery).
   - Tests deterministic chunk boundary straddling and malformed PCAP error handling.

2. **Standalone Test Suite (`Examples/IoUringBenchmark/test_io_uring`)**:
   - Validates chunk sizes from 4KB to 4MB.
   - Tests owning vector persistence and zero-copy view lifetime contracts.
   - Clean under AddressSanitizer and UndefinedBehaviorSanitizer.

---

## 6. How to Build and Run

```bash
# Configure with examples and tests enabled
cmake -B build -S . -DPCAPPP_BUILD_EXAMPLES=ON -DPCAPPP_BUILD_TESTS=ON

# Build library, tests, and benchmark (add -G Ninja during configure if preferred)
cmake --build build -j

# Run integrated tests
./build/Tests/Pcap++Test/Pcap++Test -n -t io_uring

# Generate a 1GB test PCAP file
./build/Examples/IoUringBenchmark/generate_pcap /tmp/test.pcap 1024

# Run standalone test suite
./build/Examples/IoUringBenchmark/test_io_uring /tmp/test.pcap

# Run comparative benchmark
./build/Examples/IoUringBenchmark/benchmark_io_uring /tmp/test.pcap
```
