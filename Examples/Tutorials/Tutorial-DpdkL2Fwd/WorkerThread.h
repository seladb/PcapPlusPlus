#pragma once

#include "DpdkDevice.h"
#include "DpdkDeviceList.h"

class L2FwdWorkerThread : public pcpp::DpdkWorkerThread
{
private:
	pcpp::DpdkDevice* m_RxDevice;
	pcpp::DpdkDevice* m_TxDevice;
	bool m_Stop;
	uint32_t m_CoreId;

public:
	// c'tor
	L2FwdWorkerThread(pcpp::DpdkDevice* rxDevice, pcpp::DpdkDevice* txDevice);

	// d'tor (does nothing)
	~L2FwdWorkerThread()
	{}

	// implement abstract method

	// start running the worker thread
	bool run(uint32_t coreId);

	// ask the worker thread to stop
	void stop();

	// get worker thread core ID
	uint32_t getCoreId() const;
};
