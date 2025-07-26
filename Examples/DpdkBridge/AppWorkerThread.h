#pragma once

#include "Common.h"

#include "PacketUtils.h"
#include "DpdkDevice.h"
#include "DpdkDeviceList.h"
#include "PcapFileDevice.h"

/**
 * The worker thread class which does all the work. It's initialized with pointers to the RX and TX devices, then it
 * runs in an endless loop which reads packets from the RX device and sends them to the TX device. The endless loop is
 * interrupted only when the thread is asked to stop (calling its stop() method)
 */
class AppWorkerThread : public pcpp::DpdkWorkerThread
{
private:
	AppWorkerConfig& m_WorkerConfig;
	bool m_Stop{ true };
	uint32_t m_CoreId;

public:
	explicit AppWorkerThread(AppWorkerConfig& workerConfig)
	    : m_WorkerConfig(workerConfig), m_CoreId(MAX_NUM_OF_CORES + 1)
	{}

	~AppWorkerThread() override = default;

	// implement abstract methods

	bool run(uint32_t coreId) override
	{
		m_CoreId = coreId;
		m_Stop = false;
		pcpp::DpdkDevice* rxDevice = m_WorkerConfig.RxDevice;
		pcpp::DpdkDevice* txDevice = m_WorkerConfig.TxDevice;

		// if no DPDK devices were assigned to this worker/core don't enter the main loop and exit
		if ((rxDevice == nullptr) || (txDevice == nullptr))
		{
			return true;
		}

		constexpr auto MAX_RECEIVE_BURST = 64;
		pcpp::MBufRawPacket* packetArr[MAX_RECEIVE_BURST] = {};

		// main loop, runs until be told to stop
		// cppcheck-suppress knownConditionTrueFalse
		while (!m_Stop)
		{
			for (uint16_t i = 0; i < m_WorkerConfig.RxQueues; i++)
			{
				// receive packets from network on the specified DPDK device
				const uint16_t packetsReceived = rxDevice->receivePackets(packetArr, MAX_RECEIVE_BURST, i);

				if (packetsReceived > 0)
				{
					// send packets to TX port
					txDevice->sendPackets(packetArr, packetsReceived, 0);
				}
			}
		}

		// free packet array (frees all mbufs as well)
		for (auto& packet : packetArr)
		{
			delete packet;
		}

		return true;
	}

	void stop() override
	{
		// assign the stop flag which will cause the main loop to end
		m_Stop = true;
	}

	uint32_t getCoreId() const override
	{
		return m_CoreId;
	}
};
