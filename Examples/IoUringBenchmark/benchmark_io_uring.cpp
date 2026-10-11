#include "PcapFileDevice.h"
#include "IoUringPcapDevice.h"
#include "Packet.h"
#include "IPv4Layer.h"
#include "TcpLayer.h"

#include <iostream>
#include <iomanip>
#include <chrono>
#include <string>
#include <vector>
#include <numeric>
#include <algorithm>
#include <cmath>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/resource.h>

struct RunStats
{
	bool success = false;
	double elapsedSec = 0.0;
	double userCpuSec = 0.0;
	double sysCpuSec = 0.0;
	double cpuUtilPercent = 0.0;
	long maxRssKB = 0;
	uint64_t packetCount = 0;
	uint64_t payloadBytes = 0;
	uint64_t dataChecksum = 0;
};

struct BenchmarkSummary
{
	std::string name;
	std::vector<RunStats> runs;
	double medianElapsedSec = 0.0;
	double meanElapsedSec = 0.0;
	double minElapsedSec = 0.0;
	double maxElapsedSec = 0.0;
	double stdDevElapsedSec = 0.0;
	double medianDiskThroughputMiBs = 0.0;
	double medianDiskThroughputMBs = 0.0;
	double medianPayloadThroughputMiBs = 0.0;
	double medianPacketRateMpkts = 0.0;
	double medianCpuUtil = 0.0;
	uint64_t packetCount = 0;
	uint64_t payloadBytes = 0;
	uint64_t dataChecksum = 0;
};

inline uint64_t hashPacket(uint64_t currentHash, const pcpp::RawPacket& pkt)
{
	constexpr uint64_t FNV_PRIME = 1099511628211ULL;
	uint64_t h = currentHash;
	h = (h ^ static_cast<uint64_t>(pkt.getPacketTimeStamp().tv_sec)) * FNV_PRIME;
	h = (h ^ static_cast<uint64_t>(pkt.getPacketTimeStamp().tv_nsec)) * FNV_PRIME;
	h = (h ^ static_cast<uint64_t>(pkt.getRawDataLen())) * FNV_PRIME;
	const uint8_t* data = pkt.getRawData();
	int len = pkt.getRawDataLen();
	if (data != nullptr && len > 0)
	{
		for (int i = 0; i < len; ++i)
		{
			h = (h ^ data[i]) * FNV_PRIME;
		}
	}
	return h;
}

static void evictPageCache(const std::string& path)
{
	int fd = ::open(path.c_str(), O_RDONLY);
	if (fd >= 0)
	{
		posix_fadvise(fd, 0, 0, POSIX_FADV_DONTNEED);
		::close(fd);
	}
}

static RunStats executeBaseline(const std::string& pcapPath, bool parseHeaders, bool coldCache)
{
	RunStats r;
	if (coldCache)
	{
		evictPageCache(pcapPath);
	}

	struct rusage startUsage{}, endUsage{};
	getrusage(RUSAGE_SELF, &startUsage);
	auto start = std::chrono::steady_clock::now();

	pcpp::PcapFileReaderDevice reader(pcapPath);
	if (!reader.open())
	{
		std::cerr << "\n[ERROR] Failed to open baseline reader for " << pcapPath << "\n";
		r.success = false;
		return r;
	}

	pcpp::RawPacket pkt;
	uint64_t hash = 14695981039346656037ULL;

	while (reader.getNextPacket(pkt))
	{
		r.packetCount++;
		r.payloadBytes += pkt.getRawDataLen();
		hash = hashPacket(hash, pkt);

		if (parseHeaders)
		{
			pcpp::Packet packet(&pkt);
			auto* ip = packet.getLayerOfType<pcpp::IPv4Layer>();
			if (ip != nullptr)
			{
				volatile uint32_t s = ip->getSrcIPv4Address().toInt();
				(void)s;
			}
		}
	}

	reader.close();
	auto end = std::chrono::steady_clock::now();
	getrusage(RUSAGE_SELF, &endUsage);

	r.success = true;
	r.elapsedSec = std::chrono::duration<double>(end - start).count();
	r.userCpuSec = (endUsage.ru_utime.tv_sec - startUsage.ru_utime.tv_sec) +
	               (endUsage.ru_utime.tv_usec - startUsage.ru_utime.tv_usec) / 1e6;
	r.sysCpuSec = (endUsage.ru_stime.tv_sec - startUsage.ru_stime.tv_sec) +
	              (endUsage.ru_stime.tv_usec - startUsage.ru_stime.tv_usec) / 1e6;
	r.cpuUtilPercent = ((r.userCpuSec + r.sysCpuSec) / r.elapsedSec) * 100.0;
	r.maxRssKB = endUsage.ru_maxrss;
	r.dataChecksum = hash;
	return r;
}

static RunStats executeIoUring(const std::string& pcapPath, bool parseHeaders, bool useView, size_t bufferSize,
                               size_t numBuffers, bool coldCache)
{
	RunStats r;
	if (coldCache)
	{
		evictPageCache(pcapPath);
	}

	struct rusage startUsage{}, endUsage{};
	getrusage(RUSAGE_SELF, &startUsage);
	auto start = std::chrono::steady_clock::now();

	pcpp::IoUringReaderOptions opts;
	opts.bufferSize = bufferSize;
	opts.numBuffers = numBuffers;

	pcpp::IoUringPcapReaderDevice reader(pcapPath, opts);
	if (!reader.open())
	{
		std::cerr << "\n[ERROR] Failed to open io_uring reader for " << pcapPath << "\n";
		r.success = false;
		return r;
	}

	pcpp::RawPacket pkt;
	uint64_t hash = 14695981039346656037ULL;

	if (useView)
	{
		while (reader.getNextPacketView(pkt))
		{
			r.packetCount++;
			r.payloadBytes += pkt.getRawDataLen();
			hash = hashPacket(hash, pkt);

			if (parseHeaders)
			{
				pcpp::Packet packet(&pkt);
				auto* ip = packet.getLayerOfType<pcpp::IPv4Layer>();
				if (ip != nullptr)
				{
					volatile uint32_t s = ip->getSrcIPv4Address().toInt();
					(void)s;
				}
			}
		}
	}
	else
	{
		while (reader.getNextPacket(pkt))
		{
			r.packetCount++;
			r.payloadBytes += pkt.getRawDataLen();
			hash = hashPacket(hash, pkt);

			if (parseHeaders)
			{
				pcpp::Packet packet(&pkt);
				auto* ip = packet.getLayerOfType<pcpp::IPv4Layer>();
				if (ip != nullptr)
				{
					volatile uint32_t s = ip->getSrcIPv4Address().toInt();
					(void)s;
				}
			}
		}
	}

	reader.close();
	auto end = std::chrono::steady_clock::now();
	getrusage(RUSAGE_SELF, &endUsage);

	r.success = true;
	r.elapsedSec = std::chrono::duration<double>(end - start).count();
	r.userCpuSec = (endUsage.ru_utime.tv_sec - startUsage.ru_utime.tv_sec) +
	               (endUsage.ru_utime.tv_usec - startUsage.ru_utime.tv_usec) / 1e6;
	r.sysCpuSec = (endUsage.ru_stime.tv_sec - startUsage.ru_stime.tv_sec) +
	              (endUsage.ru_stime.tv_usec - startUsage.ru_stime.tv_usec) / 1e6;
	r.cpuUtilPercent = ((r.userCpuSec + r.sysCpuSec) / r.elapsedSec) * 100.0;
	r.maxRssKB = endUsage.ru_maxrss;
	r.dataChecksum = hash;
	return r;
}

static BenchmarkSummary calculateSummary(const std::string& name, const std::vector<RunStats>& runs,
                                         uint64_t fileSizeBytes)
{
	BenchmarkSummary s;
	s.name = name;
	s.runs = runs;
	if (runs.empty())
		return s;

	s.packetCount = runs[0].packetCount;
	s.payloadBytes = runs[0].payloadBytes;
	s.dataChecksum = runs[0].dataChecksum;

	std::vector<double> times;
	double sum = 0.0;
	for (const auto& r : runs)
	{
		times.push_back(r.elapsedSec);
		sum += r.elapsedSec;
	}
	std::sort(times.begin(), times.end());

	if (times.size() % 2 == 1)
	{
		s.medianElapsedSec = times[times.size() / 2];
	}
	else
	{
		s.medianElapsedSec = (times[times.size() / 2 - 1] + times[times.size() / 2]) / 2.0;
	}
	s.meanElapsedSec = sum / times.size();
	s.minElapsedSec = times.front();
	s.maxElapsedSec = times.back();

	double variance = 0.0;
	for (double t : times)
	{
		variance += (t - s.meanElapsedSec) * (t - s.meanElapsedSec);
	}
	s.stdDevElapsedSec = std::sqrt(variance / times.size());

	double fileMiB = fileSizeBytes / (1024.0 * 1024.0);
	double fileMB = fileSizeBytes / 1e6;
	double payloadMiB = s.payloadBytes / (1024.0 * 1024.0);

	s.medianDiskThroughputMiBs = fileMiB / s.medianElapsedSec;
	s.medianDiskThroughputMBs = fileMB / s.medianElapsedSec;
	s.medianPayloadThroughputMiBs = payloadMiB / s.medianElapsedSec;
	s.medianPacketRateMpkts = (s.packetCount / 1e6) / s.medianElapsedSec;

	std::vector<double> cpus;
	for (const auto& r : runs)
		cpus.push_back(r.cpuUtilPercent);
	std::sort(cpus.begin(), cpus.end());
	s.medianCpuUtil = cpus[cpus.size() / 2];

	return s;
}

static void printSummary(const BenchmarkSummary& s, uint64_t fileSizeBytes)
{
	std::cout << "\n--------------------------------------------------------------------------------\n";
	std::cout << " CONFIGURATION: " << s.name << "\n";
	std::cout << "--------------------------------------------------------------------------------\n";
	std::cout << " Runs (seconds): ";
	for (size_t i = 0; i < s.runs.size(); ++i)
	{
		std::cout << std::fixed << std::setprecision(3) << s.runs[i].elapsedSec << "s"
		          << (i + 1 < s.runs.size() ? ", " : "\n");
	}
	std::cout << " Median Time:            " << std::fixed << std::setprecision(3) << s.medianElapsedSec << " s"
	          << " (Min: " << s.minElapsedSec << "s, Max: " << s.maxElapsedSec << "s, StdDev: " << std::setprecision(4)
	          << s.stdDevElapsedSec << "s)\n";
	std::cout << " Disk Ingestion (MiB/s): " << std::fixed << std::setprecision(1) << s.medianDiskThroughputMiBs
	          << " MiB/s"
	          << " [" << std::fixed << std::setprecision(1) << s.medianDiskThroughputMBs << " MB/s (decimal)]\n";
	std::cout << " Payload Throughput:     " << std::fixed << std::setprecision(1) << s.medianPayloadThroughputMiBs
	          << " MiB/s"
	          << " (" << s.payloadBytes << " payload bytes)\n";
	std::cout << " Ingestion Rate:         " << std::fixed << std::setprecision(2) << s.medianPacketRateMpkts
	          << " M pkts/s"
	          << " (" << s.packetCount << " total packets)\n";
	std::cout << " CPU Core Utilization:   " << std::fixed << std::setprecision(1) << s.medianCpuUtil << " %\n";
	std::cout << " Verification Checksum:  0x" << std::hex << s.dataChecksum << std::dec << "\n";
	std::cout << " Reconciled Check:       " << std::fixed << std::setprecision(2) << s.medianDiskThroughputMiBs
	          << " MiB/s * " << s.medianElapsedSec << " s = " << (s.medianDiskThroughputMiBs * s.medianElapsedSec)
	          << " MiB (File on disk: " << (fileSizeBytes / (1024.0 * 1024.0)) << " MiB)\n";
}

int main(int argc, char* argv[])
{
	if (argc < 2)
	{
		std::cout << "Usage: " << argv[0]
		          << " <pcap_file> [--iterations=N] [--cold-cache] [--parse] [--baseline-only | --uring-only]\n";
		return 1;
	}

	std::string pcapPath = argv[1];
	int iterations = 5;
	bool coldCache = false;
	bool parseHeaders = false;
	bool baselineOnly = false;
	bool uringOnly = false;
	size_t bufferSize = 4 * 1024 * 1024;
	size_t numBuffers = 3;

	for (int i = 2; i < argc; ++i)
	{
		std::string arg = argv[i];
		if (arg.rfind("--iterations=", 0) == 0)
			iterations = std::stoi(arg.substr(13));
		else if (arg == "--iterations" && i + 1 < argc)
			iterations = std::stoi(argv[++i]);
		else if (arg == "--cold-cache")
			coldCache = true;
		else if (arg == "--parse")
			parseHeaders = true;
		else if (arg == "--baseline-only")
			baselineOnly = true;
		else if (arg == "--uring-only")
			uringOnly = true;
	}

	if (iterations <= 0)
	{
		std::cerr << "Error: --iterations must be greater than 0 (got " << iterations << ")\n";
		return 1;
	}

	struct stat st{};
	if (stat(pcapPath.c_str(), &st) != 0)
	{
		std::cerr << "File not found: " << pcapPath << "\n";
		return 1;
	}
	uint64_t fileSizeBytes = static_cast<uint64_t>(st.st_size);
	double fileMiB = fileSizeBytes / (1024.0 * 1024.0);
	double fileMB = fileSizeBytes / 1e6;

	std::cout << "\n================================================================================\n";
	std::cout << " SCIENTIFIC REPRODUCIBLE BENCHMARK: PcapPlusPlus io_uring Optimization\n";
	std::cout << " Target File:     " << pcapPath << "\n";
	std::cout << " File Size:       " << std::fixed << std::setprecision(2) << fileMiB << " MiB (" << std::fixed
	          << std::setprecision(2) << fileMB << " MB decimal, " << fileSizeBytes << " bytes)\n";
	std::cout << " Iterations:      " << iterations << " per configuration (reporting median)\n";
	std::cout << " Cache Mode:      "
	          << (coldCache ? "COLD-ISH (posix_fadvise DONTNEED between runs)" : "WARM (pre-cached in RAM)") << "\n";
	std::cout << " Header Parsing:  " << (parseHeaders ? "YES (Ethernet+IPv4 layer decoding)" : "NO (Raw ingestion)")
	          << "\n";
	std::cout << "================================================================================\n";

	// Warmup pass if not coldCache
	if (!coldCache)
	{
		std::cout << "\nPerforming initial warmup pass to ensure uniform cache residency...\n";
		auto warmup = executeBaseline(pcapPath, false, false);
		if (!warmup.success)
		{
			std::cerr << "\n[FATAL] Warmup pass failed to read " << pcapPath << ". Aborting benchmark.\n";
			return 1;
		}
	}

	std::vector<RunStats> baseRuns;
	std::vector<RunStats> ringOwnedRuns;
	std::vector<RunStats> ringViewRuns;

	if (!uringOnly)
	{
		std::cout << "\n[1/3] Benchmarking Baseline (pcpp::PcapFileReaderDevice) for " << iterations << " runs...\n";
		for (int it = 1; it <= iterations; ++it)
		{
			std::cout << "  Run " << it << "/" << iterations << "... " << std::flush;
			auto r = executeBaseline(pcapPath, parseHeaders, coldCache);
			if (!r.success)
			{
				std::cerr << "\n[FATAL] Baseline run " << it << " failed. Aborting benchmark.\n";
				return 1;
			}
			std::cout << std::fixed << std::setprecision(3) << r.elapsedSec << " s\n";
			baseRuns.push_back(r);
		}
	}

	if (!baselineOnly)
	{
		std::cout << "\n[2/3] Benchmarking io_uring Standard Owned (getNextPacket) for " << iterations << " runs...\n";
		for (int it = 1; it <= iterations; ++it)
		{
			std::cout << "  Run " << it << "/" << iterations << "... " << std::flush;
			auto r = executeIoUring(pcapPath, parseHeaders, false, bufferSize, numBuffers, coldCache);
			if (!r.success)
			{
				std::cerr << "\n[FATAL] io_uring owned run " << it << " failed. Aborting benchmark.\n";
				return 1;
			}
			std::cout << std::fixed << std::setprecision(3) << r.elapsedSec << " s\n";
			ringOwnedRuns.push_back(r);
		}

		std::cout << "\n[3/3] Benchmarking io_uring Zero-Copy View (getNextPacketView) for " << iterations
		          << " runs...\n";
		for (int it = 1; it <= iterations; ++it)
		{
			std::cout << "  Run " << it << "/" << iterations << "... " << std::flush;
			auto r = executeIoUring(pcapPath, parseHeaders, true, bufferSize, numBuffers, coldCache);
			if (!r.success)
			{
				std::cerr << "\n[FATAL] io_uring view run " << it << " failed. Aborting benchmark.\n";
				return 1;
			}
			std::cout << std::fixed << std::setprecision(3) << r.elapsedSec << " s\n";
			ringViewRuns.push_back(r);
		}
	}

	std::cout << "\n================================================================================\n";
	std::cout << " BENCHMARK RESULTS & METRICS SUMMARY\n";
	std::cout << "================================================================================\n";

	BenchmarkSummary sBase, sOwned, sView;
	if (!baseRuns.empty())
	{
		sBase = calculateSummary("Baseline (pcpp::PcapFileReaderDevice)", baseRuns, fileSizeBytes);
		printSummary(sBase, fileSizeBytes);
	}
	if (!ringOwnedRuns.empty())
	{
		sOwned = calculateSummary("io_uring Standard Owned (getNextPacket)", ringOwnedRuns, fileSizeBytes);
		printSummary(sOwned, fileSizeBytes);
	}
	if (!ringViewRuns.empty())
	{
		sView = calculateSummary("io_uring Zero-Copy View (getNextPacketView)", ringViewRuns, fileSizeBytes);
		printSummary(sView, fileSizeBytes);
	}

	if (!baseRuns.empty() && !ringViewRuns.empty())
	{
		std::cout << "\n================================================================================\n";
		std::cout << " COMPARATIVE ANALYSIS & SPEEDUP\n";
		std::cout << "================================================================================\n";
		double speedupOwned = sBase.medianElapsedSec / sOwned.medianElapsedSec;
		double speedupView = sBase.medianElapsedSec / sView.medianElapsedSec;
		bool checksumMatch = (sBase.dataChecksum == sView.dataChecksum);

		std::cout << " Checksum Match:        " << (checksumMatch ? "VERIFIED IDENTICAL (" : "MISMATCH (");
		std::cout << "0x" << std::hex << std::setfill('0') << std::setw(16) << sBase.dataChecksum << std::dec << ")\n";

		std::cout << " Owned API Speedup:     " << std::fixed << std::setprecision(2) << speedupOwned << "x ("
		          << std::fixed << std::setprecision(1) << (speedupOwned - 1.0) * 100.0 << "% faster)\n";
		std::cout << " Zero-Copy View Speedup:" << std::fixed << std::setprecision(2) << speedupView << "x ("
		          << std::fixed << std::setprecision(1) << (speedupView - 1.0) * 100.0 << "% faster)\n";

		double diffMiB = sView.medianDiskThroughputMiBs - sBase.medianDiskThroughputMiBs;
		double diffMB = sView.medianDiskThroughputMBs - sBase.medianDiskThroughputMBs;
		std::cout << " Throughput Advantage:  " << (diffMiB >= 0 ? "+" : "-") << std::fixed << std::setprecision(1)
		          << std::abs(diffMiB) << " MiB/s (" << (diffMB >= 0 ? "+" : "-") << std::abs(diffMB)
		          << " MB/s decimal)\n";

		double diffMpkts = sView.medianPacketRateMpkts - sBase.medianPacketRateMpkts;
		std::cout << " Packet Processing Adv: " << (diffMpkts >= 0 ? "+" : "-") << std::fixed << std::setprecision(2)
		          << std::abs(diffMpkts) << " Million packets/second\n";
		std::cout << "================================================================================\n\n";
	}

	return 0;
}
