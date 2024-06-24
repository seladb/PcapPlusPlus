#include "WorkerThread.h"

L2FwdWorkerThread::L2FwdWorkerThread(pcpp::DpdkDevice* rxDevice, pcpp::DpdkDevice* txDevice)
    : m_RxDevice(rxDevice), m_TxDevice(txDevice), m_Stop(true), m_CoreId(MAX_NUM_OF_CORES + 1)
{}

bool L2FwdWorkerThread::run(uint32_t coreId)
{
	// Register coreId for this worker
	m_CoreId = coreId;
	m_Stop = false;

	// initialize a mbuf packet array of size 64
	pcpp::MBufRawPacket* mbufArr[64] = {};

	// endless loop, until asking the thread to stop
	// cppcheck-suppress knownConditionTrueFalse
	while (!m_Stop)
	{
		// receive packets from RX device
		uint16_t numOfPackets = m_RxDevice->receivePackets(mbufArr, 64, 0);

		if (numOfPackets > 0)
		{
			// send received packet on the TX device
			m_TxDevice->sendPackets(mbufArr, numOfPackets, 0);
		}
	}

	return true;
}

void L2FwdWorkerThread::stop()
{
	m_Stop = true;
}

uint32_t L2FwdWorkerThread::getCoreId() const
{
	return m_CoreId;
}
