#include <Logger.h>

#include "trompeloeil.hpp"
#include "../TestDefinition.h"
#include "../Common/GlobalTestArgs.h"
#include "../Common/TestUtils.h"
#include "WinDivertDevice.h"
#include "PcapFileDevice.h"
#include "Packet.h"
#include "IPLayer.h"
#include "Logger.h"

extern PcapTestArgs PcapTestGlobalArgs;

PTF_TEST_CASE(TestWinDivertReceivePackets)
{
#ifdef USE_WINDIVERT
	// Receive with packet vector
	{
		pcpp::WinDivertDevice device;
		PTF_ASSERT_TRUE(device.open());
		DeviceTeardown devTeardown(&device);

		pcpp::WinDivertDevice::WinDivertRawPacketVector rawPackets;
		uint32_t expectedPacketCount = 10;
		auto result = device.receivePackets(rawPackets, 10000, expectedPacketCount);
		PTF_ASSERT_EQUAL(result.status, pcpp::WinDivertDevice::ReceiveResult::Status::Completed, enumclass);
		PTF_ASSERT_EQUAL(result.error, "");
		PTF_ASSERT_EQUAL(result.errorCode, 0);

		PTF_ASSERT_EQUAL(rawPackets.size(), expectedPacketCount);

		for (const auto& rawPacket : rawPackets)
		{
			PTF_ASSERT_NOT_NULL(device.getNetworkInterface(rawPacket->getInterfaceIndex()));
			pcpp::Packet packet(rawPacket);
			PTF_ASSERT_TRUE(packet.getFirstLayer()->isMemberOfProtocolFamily(pcpp::IP));
		}
	}

	// Receive with callback
	{
		pcpp::WinDivertDevice device;
		PTF_ASSERT_TRUE(device.open());

		DeviceTeardown devTeardown(&device);

		uint32_t expectedPacketCount = 10;
		uint16_t packetCounter = 0;
		bool allPacketsHaveInterface = true;
		bool allPacketsOfTypeIP = true;
		bool isTimestampIncreasing = true;
		uint64_t currentTimestamp = 0;

		auto result = device.receivePackets([&](const pcpp::WinDivertDevice::WinDivertRawPacketVector& packetVec) {
			for (auto& rawPacket : packetVec)
			{
				allPacketsHaveInterface &= device.getNetworkInterface(rawPacket->getInterfaceIndex()) != nullptr;
				pcpp::Packet packet(rawPacket);
				allPacketsOfTypeIP &= packet.getFirstLayer()->isMemberOfProtocolFamily(pcpp::IP);
				isTimestampIncreasing &= (rawPacket->getWinDivertTimestamp() > currentTimestamp);
				currentTimestamp = rawPacket->getWinDivertTimestamp();
			}

			packetCounter += packetVec.size();
			if (packetCounter >= expectedPacketCount)
			{
				device.stopReceive();
			}
		});

		PTF_ASSERT_EQUAL(result.status, pcpp::WinDivertDevice::ReceiveResult::Status::Completed, enumclass);
		PTF_ASSERT_EQUAL(result.error, "");
		PTF_ASSERT_EQUAL(result.errorCode, 0);
		PTF_ASSERT_GREATER_OR_EQUAL_THAN(packetCounter, expectedPacketCount);
		PTF_ASSERT_TRUE(allPacketsHaveInterface);
		PTF_ASSERT_TRUE(allPacketsOfTypeIP);
		PTF_ASSERT_TRUE(isTimestampIncreasing);
	}

	// Receive timeout
	{
		pcpp::WinDivertDevice device;

		auto networkInterfaces = device.getNetworkInterfaces();
		uint32_t invalidInterfaceIndex = 0;
		while (true)
		{
			auto it = std::find_if(networkInterfaces.begin(), networkInterfaces.end(),
			                       [&](const auto& item) { return item.index == invalidInterfaceIndex; });

			if (it == networkInterfaces.end())
			{
				break;
			}

			invalidInterfaceIndex++;
		}

		PTF_ASSERT_TRUE(device.open("ifIdx == " + std::to_string(invalidInterfaceIndex)));

		DeviceTeardown devTeardown(&device);

		pcpp::WinDivertDevice::WinDivertRawPacketVector rawPackets;
		auto result = device.receivePackets(rawPackets, 500);

		PTF_ASSERT_EQUAL(result.status, pcpp::WinDivertDevice::ReceiveResult::Status::Timeout, enumclass);
	}

	// TODO: consider adding stats for number of batches

	// Receive with non-default batch size
	{
		pcpp::WinDivertDevice device;
		PTF_ASSERT_TRUE(device.open());

		DeviceTeardown devTeardown(&device);

		pcpp::WinDivertDevice::WinDivertRawPacketVector rawPackets;
		uint32_t expectedPacketCount = 13;
		auto result = device.receivePackets(rawPackets, 10000, expectedPacketCount, 3);
		PTF_ASSERT_EQUAL(result.status, pcpp::WinDivertDevice::ReceiveResult::Status::Completed, enumclass);

		PTF_ASSERT_EQUAL(rawPackets.size(), expectedPacketCount);
	}

	// Receive with a filter
	{
		pcpp::WinDivertDevice device;
		pcpp::IPAddress ipAddress(PcapTestGlobalArgs.ipToSendReceivePackets);
		std::string filter;
		if (ipAddress.isIPv4())
		{
			filter = "ip.SrcAddr == " + ipAddress.toString();
		}
		else
		{
			filter = "ipv6.SrcAddr == " + ipAddress.toString();
		}
		PTF_ASSERT_TRUE(device.open(filter));

		pcpp::WinDivertDevice::WinDivertRawPacketVector rawPackets;
		auto result = device.receivePackets(rawPackets, 10000, 10);
		PTF_ASSERT_EQUAL(result.status, pcpp::WinDivertDevice::ReceiveResult::Status::Completed, enumclass);

		for (const auto& rawPacket : rawPackets)
		{
			pcpp::Packet packet(rawPacket);
			PTF_ASSERT_EQUAL(packet.getLayerOfType<pcpp::IPLayer>()->getSrcIPAddress(), ipAddress);
		}
	}

	// Receive when device not open
	{
		pcpp::WinDivertDevice device;

		pcpp::WinDivertDevice::WinDivertRawPacketVector rawPackets;
		auto result1 = device.receivePackets(rawPackets);
		auto result2 = device.receivePackets(nullptr);

		for (const auto& result : { result1, result2 })
		{
			PTF_ASSERT_EQUAL(result.status, pcpp::WinDivertDevice::ReceiveResult::Status::Failed, enumclass);
			PTF_ASSERT_EQUAL(result.error, "Device is not open");
			PTF_ASSERT_EQUAL(result.errorCode, 0);
		}
	}

	// Receive when batch size is 0
	{
		pcpp::WinDivertDevice device;
		PTF_ASSERT_TRUE(device.open());

		DeviceTeardown devTeardown(&device);

		pcpp::WinDivertDevice::WinDivertRawPacketVector rawPackets;
		auto result1 = device.receivePackets(rawPackets, 5000, 0, 0);
		auto result2 = device.receivePackets(nullptr, 5000, 0);

		for (const auto& result : { result1, result2 })
		{
			PTF_ASSERT_EQUAL(result.status, pcpp::WinDivertDevice::ReceiveResult::Status::Failed, enumclass);
			PTF_ASSERT_EQUAL(result.error, "Batch size has to be a positive number");
			PTF_ASSERT_EQUAL(result.errorCode, 0);
		}
	}

	// Receive when timeout and maxPackets are 0
	{
		pcpp::WinDivertDevice device;
		PTF_ASSERT_TRUE(device.open());

		DeviceTeardown devTeardown(&device);

		pcpp::WinDivertDevice::WinDivertRawPacketVector rawPackets;
		auto result = device.receivePackets(rawPackets, 0, 0);

		PTF_ASSERT_EQUAL(result.status, pcpp::WinDivertDevice::ReceiveResult::Status::Failed, enumclass);
		PTF_ASSERT_EQUAL(result.error, "At least one of timeout and maxPackets must be a positive number");
		PTF_ASSERT_EQUAL(result.errorCode, 0);
	}

	// Receive when already receiving
	{
		pcpp::WinDivertDevice device;
		PTF_ASSERT_TRUE(device.open());

		DeviceTeardown devTeardown(&device);

		bool failedReceiveWhileReceiving = false;

		device.receivePackets([&](const pcpp::WinDivertDevice::WinDivertRawPacketVector&) {
			auto result1 = device.receivePackets(nullptr);
			pcpp::WinDivertDevice::WinDivertRawPacketVector rawPackets;
			auto result2 = device.receivePackets(rawPackets);

			auto expectedStatus = pcpp::WinDivertDevice::ReceiveResult::Status::Failed;
			auto expectedError = "Already receiving packets, please call stopReceive() first";
			if (result1.status == expectedStatus && result2.status == expectedStatus &&
			    result1.error == expectedError && result2.error == expectedError)
			{
				failedReceiveWhileReceiving = true;
			}

			device.stopReceive();
		});

		PTF_ASSERT_TRUE(failedReceiveWhileReceiving);
	}
#else
	PTF_SKIP_TEST("WinDivert is not configured");
#endif
}  // TestWinDivertReceivePackets

PTF_TEST_CASE(TestWinDivertSendPackets)
{
#ifdef USE_WINDIVERT
	// Send packets
	{
		pcpp::RawPacketVector packetVec;

		pcpp::PcapFileReaderDevice ipv4Reader("PcapExamples/linktype_ipv4.pcap");
		PTF_ASSERT_TRUE(ipv4Reader.open());
		PTF_ASSERT_EQUAL(ipv4Reader.getNextPackets(packetVec, 2), 2);

		pcpp::PcapFileReaderDevice ipv6Reader("PcapExamples/linktype_ipv6.pcap");
		PTF_ASSERT_TRUE(ipv6Reader.open());
		PTF_ASSERT_EQUAL(ipv6Reader.getNextPackets(packetVec, 1), 1);

		pcpp::WinDivertDevice device;
		PTF_ASSERT_TRUE(device.open());

		DeviceTeardown devTeardown(&device);

		auto sendResult = device.sendPackets(packetVec);
		PTF_ASSERT_EQUAL(sendResult.status, pcpp::WinDivertDevice::SendResult::Status::Completed, enumclass);
		PTF_ASSERT_EQUAL(sendResult.error, "");
		PTF_ASSERT_EQUAL(sendResult.packetsSent, 3);
	}

	// Send packets with batch size
	{
		pcpp::RawPacketVector packetVec;

		for (int i = 0; i < 10; i++)
		{
			pcpp::PcapFileReaderDevice ipv4Reader("PcapExamples/linktype_ipv4.pcap");
			PTF_ASSERT_TRUE(ipv4Reader.open());
			PTF_ASSERT_EQUAL(ipv4Reader.getNextPackets(packetVec, 2), 2);
		}

		pcpp::WinDivertDevice device;
		PTF_ASSERT_TRUE(device.open());

		DeviceTeardown devTeardown(&device);

		auto sendResult = device.sendPackets(packetVec, 6);
		PTF_ASSERT_EQUAL(sendResult.status, pcpp::WinDivertDevice::SendResult::Status::Completed, enumclass);
		PTF_ASSERT_EQUAL(sendResult.error, "");
		PTF_ASSERT_EQUAL(sendResult.packetsSent, 20);
	}

	// Send packets with link layer which is not IPv4/6
	{
		pcpp::RawPacketVector packetVec;

		pcpp::PcapFileReaderDevice ethReader("PcapExamples/one_tcp_stream.pcap");
		PTF_ASSERT_TRUE(ethReader.open());
		PTF_ASSERT_EQUAL(ethReader.getNextPackets(packetVec, 2), 2);

		pcpp::WinDivertDevice device;
		PTF_ASSERT_TRUE(device.open());

		DeviceTeardown devTeardown(&device);

		auto sendResult = device.sendPackets(packetVec);
		PTF_ASSERT_EQUAL(sendResult.status, pcpp::WinDivertDevice::SendResult::Status::Failed, enumclass);
		PTF_ASSERT_EQUAL(sendResult.errorCode, 87);
		PTF_ASSERT_EQUAL(sendResult.error, "Sending packets failed: The parameter is incorrect.");
		PTF_ASSERT_EQUAL(sendResult.packetsSent, 0);
	}

	// Send partially succeeds
	{
		pcpp::RawPacketVector packetVec;

		pcpp::PcapFileReaderDevice ipv4Reader("PcapExamples/linktype_ipv4.pcap");
		PTF_ASSERT_TRUE(ipv4Reader.open());
		PTF_ASSERT_EQUAL(ipv4Reader.getNextPackets(packetVec, 2), 2);

		pcpp::PcapFileReaderDevice ethReader("PcapExamples/one_tcp_stream.pcap");
		PTF_ASSERT_TRUE(ethReader.open());
		PTF_ASSERT_EQUAL(ethReader.getNextPackets(packetVec, 2), 2);

		pcpp::WinDivertDevice device;
		PTF_ASSERT_TRUE(device.open());

		DeviceTeardown devTeardown(&device);

		auto sendResult = device.sendPackets(packetVec, 1);
		PTF_ASSERT_EQUAL(sendResult.status, pcpp::WinDivertDevice::SendResult::Status::Failed, enumclass);
		PTF_ASSERT_EQUAL(sendResult.errorCode, 87);
		PTF_ASSERT_EQUAL(sendResult.error, "Sending packets failed: The parameter is incorrect.");
		PTF_ASSERT_EQUAL(sendResult.packetsSent, 2);
	}

	// Send when device not open
	{
		pcpp::RawPacketVector packetVec;

		pcpp::PcapFileReaderDevice ipv4Reader("PcapExamples/linktype_ipv4.pcap");
		PTF_ASSERT_TRUE(ipv4Reader.open());
		PTF_ASSERT_EQUAL(ipv4Reader.getNextPackets(packetVec, 2), 2);

		pcpp::WinDivertDevice device;
		auto sendResult = device.sendPackets(packetVec);

		PTF_ASSERT_EQUAL(sendResult.status, pcpp::WinDivertDevice::SendResult::Status::Failed, enumclass);
		PTF_ASSERT_EQUAL(sendResult.error, "Device is not open");
		PTF_ASSERT_EQUAL(sendResult.errorCode, 0);
		PTF_ASSERT_EQUAL(sendResult.packetsSent, 0);
	}

	// Send when batch size is 0
	{
		pcpp::RawPacketVector packetVec;

		pcpp::PcapFileReaderDevice ipv4Reader("PcapExamples/linktype_ipv4.pcap");
		PTF_ASSERT_TRUE(ipv4Reader.open());
		PTF_ASSERT_EQUAL(ipv4Reader.getNextPackets(packetVec, 2), 2);

		pcpp::WinDivertDevice device;
		PTF_ASSERT_TRUE(device.open());

		DeviceTeardown devTeardown(&device);

		pcpp::WinDivertDevice::WinDivertRawPacketVector rawPackets;
		auto sendResult = device.sendPackets(packetVec, 0);

		PTF_ASSERT_EQUAL(sendResult.status, pcpp::WinDivertDevice::SendResult::Status::Failed, enumclass);
		PTF_ASSERT_EQUAL(sendResult.error, "Batch size has to be a positive number");
		PTF_ASSERT_EQUAL(sendResult.errorCode, 0);
		PTF_ASSERT_EQUAL(sendResult.packetsSent, 0);
	}
#else
	PTF_SKIP_TEST("WinDivert is not configured");
#endif
}  // TestWinDivertSendPackets

PTF_TEST_CASE(TestWinDivertParams)
{
#ifdef USE_WINDIVERT
	{
		pcpp::WinDivertDevice device;
		PTF_ASSERT_TRUE(device.open());

		DeviceTeardown devTeardown(&device);

		PTF_ASSERT_EQUAL(device.getVersion().toString(), "2.2");

		auto queueParams = device.getPacketQueueParams();
		for (const auto& keyValuePair : queueParams)
		{
			PTF_ASSERT_GREATER_THAN(keyValuePair.second, 0);
		}

		pcpp::WinDivertDevice::QueueParams clonedQueueParams(queueParams);
		for (const auto& keyValuePair : clonedQueueParams)
		{
			clonedQueueParams[keyValuePair.first] = keyValuePair.second + 1;
		}
		device.setPacketQueueParams(clonedQueueParams);

		queueParams = device.getPacketQueueParams();
		PTF_ASSERT_TRUE(queueParams == clonedQueueParams);
	}

	// Device is not open
	{
		pcpp::WinDivertDevice device;

		PTF_ASSERT_RAISES(device.getVersion(), std::runtime_error, "Device is not open");
		PTF_ASSERT_RAISES(device.getPacketQueueParams(), std::runtime_error, "Device is not open");
		PTF_ASSERT_RAISES(device.setPacketQueueParams({}), std::runtime_error, "Device is not open");
	}
#else
	PTF_SKIP_TEST("WinDivert is not configured");
#endif
}  // TestWinDivertParams

PTF_TEST_CASE(TestWinDivertNetworkInterfaces)
{
#ifdef USE_WINDIVERT
	pcpp::WinDivertDevice device;

	auto networkInterfaces = device.getNetworkInterfaces();
	bool atLeastOneInterfaceIsUp = false;
	bool atLeastOneLoopbackInterface = false;
	for (const auto& networkInterface : networkInterfaces)
	{
		PTF_ASSERT_GREATER_THAN(networkInterface.index, 0);
		PTF_ASSERT_FALSE(networkInterface.name.empty());
		PTF_ASSERT_FALSE(networkInterface.description.empty());
		atLeastOneInterfaceIsUp |= networkInterface.isUp;
		atLeastOneLoopbackInterface |= networkInterface.isLoopback;
	}

	PTF_ASSERT_TRUE(atLeastOneInterfaceIsUp);
	PTF_ASSERT_TRUE(atLeastOneLoopbackInterface);
#else
	PTF_SKIP_TEST("WinDivert is not configured");
#endif
}  // TestWinDivertNetworkInterfaces

class MockWinDivertHandle : public pcpp::internal::IWinDivertHandle
{
public:
	~MockWinDivertHandle() override = default;
};

class MockWinDivertImplementation : public pcpp::internal::IWinDivertImplementation
{
public:
	MAKE_MOCK4(open, std::unique_ptr<pcpp::internal::IWinDivertHandle>(const std::string&, int, int16_t, uint64_t), override);
	MAKE_MOCK1(close, uint32_t(const pcpp::internal::IWinDivertHandle*), override);
	MAKE_MOCK5(recvEx, uint32_t(const pcpp::internal::IWinDivertHandle*, uint8_t*, uint32_t, size_t, pcpp::internal::IOverlappedWrapper*), override);
	MAKE_MOCK0(recvExComplete, std::vector<pcpp::internal::WinDivertAddress>(), override);
	MAKE_MOCK4(sendEx, uint32_t(const pcpp::internal::IWinDivertHandle*, uint8_t*, uint32_t, size_t), override);
	MAKE_MOCK0(createOverlapped, std::unique_ptr<pcpp::internal::IOverlappedWrapper>(), override);
	MAKE_MOCK3(getParam, bool(const pcpp::internal::IWinDivertHandle*, WinDivertParam, uint64_t&), override);
	MAKE_MOCK3(setParam, bool(const pcpp::internal::IWinDivertHandle*, WinDivertParam, uint64_t), override);
	MAKE_MOCK0(getNetworkInterfaces, std::vector<NetworkInterface>(), const override);
};

class WinDivertDeviceTestFixture
{
public:
	WinDivertDeviceTestFixture()
	{
		m_MockImpl = std::make_unique<MockWinDivertImplementation>();
		mockImplPtr = m_MockImpl.get();
		device.setImplementation(std::move(m_MockImpl));
		mockHandle = std::make_unique<MockWinDivertHandle>();
	}

	pcpp::WinDivertDevice device;
	MockWinDivertImplementation* mockImplPtr;
	std::unique_ptr<MockWinDivertHandle> mockHandle;

private:
	std::unique_ptr<MockWinDivertImplementation> m_MockImpl;
};

PTF_TEST_CASE(TestWinDivertOpen)
{
#ifdef USE_WINDIVERT
	// Happy flow with a default filter
	{
		WinDivertDeviceTestFixture fixture;

		std::vector<pcpp::WinDivertDevice::NetworkInterface> mockInterfaces = {
			{1, L"eth0", L"Ethernet Adapter", false, true},
			{2, L"lo", L"Loopback Adapter", true, true}
		};

		std::vector<pcpp::internal::IWinDivertImplementation::NetworkInterface> mockInternalInterfaces = {
			{1, L"eth0", L"Ethernet Adapter", false, true},
			{2, L"lo", L"Loopback Adapter", true, true}
		};

		ALLOW_CALL(*fixture.mockImplPtr, getNetworkInterfaces())
			.RETURN(mockInternalInterfaces);

		REQUIRE_CALL(*fixture.mockImplPtr, open("inbound or outbound", 0, 0, 0x0001 | 0x0020))
			.LR_RETURN(std::move(fixture.mockHandle));

		PTF_ASSERT_TRUE(fixture.device.open());
		PTF_ASSERT_TRUE(fixture.device.isOpened());
		PTF_ASSERT_VECTORS_EQUAL(fixture.device.getNetworkInterfaces(), mockInterfaces);
	}

	// Happy flow with a custom filter
	{
		WinDivertDeviceTestFixture fixture;

		REQUIRE_CALL(*fixture.mockImplPtr, open("custom filter", 0, 0, 0x0001 | 0x0020))
			.LR_RETURN(std::move(fixture.mockHandle));

		ALLOW_CALL(*fixture.mockImplPtr, getNetworkInterfaces())
			.RETURN(std::vector<pcpp::internal::IWinDivertImplementation::NetworkInterface>{});

		PTF_ASSERT_TRUE(fixture.device.open("custom filter"));
		PTF_ASSERT_TRUE(fixture.device.isOpened());
	}

	// Error opening device
	{
		WinDivertDeviceTestFixture fixture;

		REQUIRE_CALL(*fixture.mockImplPtr, open(trompeloeil::_, trompeloeil::_, trompeloeil::_, trompeloeil::_))
			.LR_RETURN(nullptr);

		ALLOW_CALL(*fixture.mockImplPtr, getNetworkInterfaces())
			.RETURN(std::vector<pcpp::internal::IWinDivertImplementation::NetworkInterface>{});

		PTF_ASSERT_FALSE(fixture.device.open());
		PTF_ASSERT_FALSE(fixture.device.isOpened());
	}

	// Open an already open device
	{
		WinDivertDeviceTestFixture fixture;

		REQUIRE_CALL(*fixture.mockImplPtr, open(trompeloeil::_, trompeloeil::_, trompeloeil::_, trompeloeil::_))
			.TIMES(1)
			.LR_RETURN(std::move(fixture.mockHandle));

		ALLOW_CALL(*fixture.mockImplPtr, getNetworkInterfaces())
			.RETURN(std::vector<pcpp::internal::IWinDivertImplementation::NetworkInterface>{});

		PTF_ASSERT_TRUE(fixture.device.open());
		PTF_ASSERT_TRUE(fixture.device.open());
	}

	// Set network interface throws an exception
	{
		WinDivertDeviceTestFixture fixture;

		REQUIRE_CALL(*fixture.mockImplPtr, getNetworkInterfaces())
			.THROW(std::runtime_error("Failed to get interfaces"));

		pcpp::Logger::getInstance().suppressLogs();
		PTF_ASSERT_FALSE(fixture.device.open());
		pcpp::Logger::getInstance().enableLogs();
		PTF_ASSERT_FALSE(fixture.device.isOpened());
	}
#else
	PTF_SKIP_TEST("WinDivert is not configured");
#endif
}