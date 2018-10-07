#pragma once

#include "Common.h"

#include "PacketUtils.h"
#include "DpdkDevice.h"
#include "DpdkDeviceList.h"
#include "PcapFileDevice.h"

/**
 * The worker thread class which does all the work: receive packets from relevant DPDK port(s), matched them with the packet matching engine and send them to
 * TX port and/or save them to a file. In addition it collects packets statistics.
 * Each core is assigned with one such worker thread, and all of them are activated using DpdkDeviceList::startDpdkWorkerThreads (see main.cpp)
 */
class AppWorkerThread : public pcpp::DpdkWorkerThread
{
private:
	AppWorkerConfig& m_WorkerConfig;
	bool m_Stop;
	uint32_t m_CoreId;

public:
	AppWorkerThread(AppWorkerConfig& workerConfig) :
		m_WorkerConfig(workerConfig), m_Stop(true), m_CoreId(MAX_NUM_OF_CORES+1)
	{
	}

	virtual ~AppWorkerThread()
	{
		// do nothing
	}

	// implement abstract methods

	bool run(uint32_t coreId)
	{
		m_CoreId = coreId;
		m_Stop = false;
		pcpp::DpdkDevice* rxDevice = m_WorkerConfig.RxDevice;
		pcpp::DpdkDevice* txDevice = m_WorkerConfig.TxDevice;

		// if no DPDK devices were assigned to this worker/core don't enter the main loop and exit
		if (!rxDevice || !txDevice)
		{
			return true;
		}

		#define MAX_RECEIVE_BURST 64
		pcpp::MBufRawPacket* packetArr[MAX_RECEIVE_BURST] = {};

		// main loop, runs until be told to stop
		while (!m_Stop)
		{
			// receive packets from network on the specified DPDK device
			uint16_t packetsReceived = rxDevice->receivePackets(packetArr, MAX_RECEIVE_BURST, 0);

			for (int i = 0; i < packetsReceived; i++)
			{
				// send packet to TX port
				txDevice->sendPacket(*packetArr[i], 0);
			}
		}

		// free packet array (frees all mbufs as well)
		for (int i = 0; i < MAX_RECEIVE_BURST; i++)
		{
			if (packetArr[i] != NULL)
				delete packetArr[i];
		}

		return true;
	}

	void stop()
	{
		// assign the stop flag which will cause the main loop to end
		m_Stop = true;
	}

	uint32_t getCoreId()
	{
		return m_CoreId;
	}

};
