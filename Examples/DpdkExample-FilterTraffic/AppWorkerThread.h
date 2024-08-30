#pragma once

#include "Common.h"
#include "PacketMatchingEngine.h"

#include "PacketUtils.h"
#include "DpdkDevice.h"
#include "DpdkDeviceList.h"
#include "PcapFileDevice.h"

/**
 * The worker thread class which does all the work: receive packets from relevant DPDK port(s), matched them with the
 * packet matching engine and send them to TX port and/or save them to a file. In addition it collects packets
 * statistics. Each core is assigned with one such worker thread, and all of them are activated using
 * DpdkDeviceList::startDpdkWorkerThreads (see main.cpp)
 */
class AppWorkerThread : public pcpp::DpdkWorkerThread
{
private:
	AppWorkerConfig& m_WorkerConfig;
	bool m_Stop;
	uint32_t m_CoreId;
	PacketStats m_Stats;
	PacketMatchingEngine& m_PacketMatchingEngine;
	std::unordered_map<uint32_t, bool> m_FlowTable;

public:
	AppWorkerThread(AppWorkerConfig& workerConfig, PacketMatchingEngine& matchingEngine)
	    : m_WorkerConfig(workerConfig), m_Stop(true), m_CoreId(MAX_NUM_OF_CORES + 1),
	      m_PacketMatchingEngine(matchingEngine)
	{}

	virtual ~AppWorkerThread()
	{
		// do nothing
	}

	PacketStats& getStats()
	{
		return m_Stats;
	}

	// implement abstract methods

	bool run(uint32_t coreId)
	{
		m_CoreId = coreId;
		m_Stop = false;
		m_Stats.workerId = coreId;
		pcpp::DpdkDevice* sendPacketsTo = m_WorkerConfig.sendPacketsTo;
		pcpp::PcapFileWriterDevice* pcapWriter = nullptr;

		// if needed, create the pcap file writer which all matched packets will be written into
		if (m_WorkerConfig.writeMatchedPacketsToFile)
		{
			pcapWriter = new pcpp::PcapFileWriterDevice(m_WorkerConfig.pathToWritePackets.c_str());
			if (!pcapWriter->open())
			{
				EXIT_WITH_ERROR("Couldn't open pcap writer device");
			}
		}

		// if no DPDK devices were assigned to this worker/core don't enter the main loop and exit
		if (m_WorkerConfig.inDataCfg.size() == 0)
		{
			return true;
		}

#define MAX_RECEIVE_BURST 64
		pcpp::MBufRawPacket* packetArr[MAX_RECEIVE_BURST] = {};

		// main loop, runs until be told to stop
		// cppcheck-suppress knownConditionTrueFalse
		while (!m_Stop)
		{
			// go over all DPDK devices configured for this worker/core
			for (const auto& iter : m_WorkerConfig.inDataCfg)
			{
				// for each DPDK device go over all RX queues configured for this worker/core
				for (const auto& iter2 : iter.second)
				{
					pcpp::DpdkDevice* dev = iter.first;

					// receive packets from network on the specified DPDK device and RX queue
					uint16_t packetsReceived = dev->receivePackets(packetArr, MAX_RECEIVE_BURST, iter2);

					for (int i = 0; i < packetsReceived; i++)
					{
						// parse packet
						pcpp::Packet parsedPacket(packetArr[i]);

						// collect packet statistics
						m_Stats.collectStats(parsedPacket);

						bool packetMatched;

						// hash the packet by 5-tuple and look in the flow table to see whether this packet belongs to
						// an existing or new flow
						uint32_t hash = pcpp::hash5Tuple(&parsedPacket);
						auto iter3 = m_FlowTable.find(hash);

						// if packet belongs to an already existing flow
						if (iter3 != m_FlowTable.end() && iter3->second)
						{
							packetMatched = true;
						}
						else  // packet belongs to a new flow
						{
							packetMatched = m_PacketMatchingEngine.isMatched(parsedPacket);
							if (packetMatched)
							{
								// put new flow in flow table
								m_FlowTable[hash] = true;

								// collect stats
								if (parsedPacket.isPacketOfType(pcpp::TCP))
								{
									m_Stats.matchedTcpFlows++;
								}
								else if (parsedPacket.isPacketOfType(pcpp::UDP))
								{
									m_Stats.matchedUdpFlows++;
								}
							}
						}

						if (packetMatched)
						{
							// send packet to TX port if needed
							if (sendPacketsTo != nullptr)
							{
								sendPacketsTo->sendPacket(*packetArr[i], 0);
							}

							// save packet to file if needed
							if (pcapWriter != nullptr)
							{
								pcapWriter->writePacket(*packetArr[i]);
							}

							m_Stats.matchedPackets++;
						}
					}
				}
			}
		}

		// free packet array (frees all mbufs as well)
		for (int i = 0; i < MAX_RECEIVE_BURST; i++)
		{
			if (packetArr[i] != nullptr)
				delete packetArr[i];
		}

		// close and delete pcap file writer
		if (pcapWriter != nullptr)
		{
			delete pcapWriter;
		}

		return true;
	}

	void stop()
	{
		// assign the stop flag which will cause the main loop to end
		m_Stop = true;
	}

	uint32_t getCoreId() const
	{
		return m_CoreId;
	}
};
