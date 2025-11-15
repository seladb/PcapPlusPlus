#include "WinDivertDevice.h"
#include "Logger.h"
#include "Packet.h"
#include "windivert.h"
#include "IPv4Layer.h"
#include "IPv6Layer.h"
#include "EndianPortable.h"
#include <iostream>
#include <windows.h>
#include <iphlpapi.h>
#include <winsock2.h>
#include <chrono>

namespace pcpp
{
	namespace internal
	{
		class WinDivertOverlappedWrapper : public IOverlappedWrapper
		{
		public:
			explicit WinDivertOverlappedWrapper(const HANDLE handle)
			{
				m_Handle = handle;
				ZeroMemory(&m_Overlapped, sizeof(m_Overlapped));

				m_Event = CreateEvent(nullptr, TRUE, FALSE, nullptr);
				if (!m_Event)
				{
					throw std::runtime_error("Failed to create event");
				}
				m_Overlapped.hEvent = m_Event;
			}

			// Non-copyable
			WinDivertOverlappedWrapper(const WinDivertOverlappedWrapper&) = delete;
			WinDivertOverlappedWrapper& operator=(const WinDivertOverlappedWrapper&) = delete;

			~WinDivertOverlappedWrapper() override
			{
				CloseHandle(m_Event);
			}

			LPOVERLAPPED get()
			{
				return &m_Overlapped;
			}

			WaitResult wait(uint32_t timeout) override
			{
				auto waitResult = WaitForSingleObject(m_Overlapped.hEvent, timeout);
				if (waitResult == WAIT_OBJECT_0)
				{
					return { WaitResult::Status::Completed, 0 };
				}

				if (waitResult == WAIT_TIMEOUT)
				{
					return { WaitResult::Status::Timeout, 0 };
				}

				return { WaitResult::Status::Failed, static_cast<uint32_t>(GetLastError()) };
			}

			void reset() override
			{
				if (!ResetEvent(m_Event))
				{
					throw std::runtime_error("Failed to reset overlapped event");
				}

				// Zero everything except hEvent
				auto event = m_Overlapped.hEvent;
				ZeroMemory(&m_Overlapped, sizeof(m_Overlapped));
				m_Overlapped.hEvent = event;
			}

			OverlappedResult getOverlappedResult() override
			{
				DWORD packetLen = 0;
				if (GetOverlappedResult(m_Handle, &m_Overlapped, &packetLen, FALSE))
				{
					return { OverlappedResult::Status::Success, static_cast<uint32_t>(packetLen), 0 };
				}

				return { OverlappedResult::Status::Failed, 0, static_cast<uint32_t>(GetLastError()) };
			}

		private:
			HANDLE m_Event;
			HANDLE m_Handle;
			OVERLAPPED m_Overlapped = {};
		};

		class WinDivertHandle : public IWinDivertHandle
		{
		public:
			explicit WinDivertHandle(const HANDLE handle) : m_Handle(handle)
			{}

			uint32_t close() override
			{
				auto result = WinDivertClose(m_Handle);
				if (!result)
				{
					return GetLastError();
				}
				return SuccessResult;
			}

			uint32_t recvEx(uint8_t* buffer, uint32_t bufferLen, size_t addressesSize,
			                IOverlappedWrapper* overlapped) override
			{
				auto winDivertOverlapped = dynamic_cast<WinDivertOverlappedWrapper*>(overlapped);
				if (winDivertOverlapped == nullptr)
				{
					throw std::runtime_error("Failed to get WinDivertOverlapped");
				}

				m_WinDivertAddresses.resize(addressesSize);
				m_WinDivertAddressesSize = sizeof(WINDIVERT_ADDRESS) * addressesSize;

				uint32_t recvLen;
				auto result = WinDivertRecvEx(m_Handle, buffer, bufferLen, &recvLen, 0, m_WinDivertAddresses.data(),
				                              &m_WinDivertAddressesSize, winDivertOverlapped->get());

				if (!result)
				{
					return GetLastError();
				}

				return SuccessResult;
			}

			std::vector<WinDivertAddress> recvExComplete() override
			{
				uint32_t numOfAddressesReceived = m_WinDivertAddressesSize / sizeof(WINDIVERT_ADDRESS);
				std::vector<WinDivertAddress> result(numOfAddressesReceived);

				for (uint32_t i = 0; i < numOfAddressesReceived; i++)
				{
					result[i].isIPv6 = m_WinDivertAddresses[i].IPv6 == 1;
					result[i].interfaceIndex = m_WinDivertAddresses[i].Network.IfIdx;
					result[i].timestamp = m_WinDivertAddresses[i].Timestamp;
				}

				return result;
			}

			uint32_t sendEx(uint8_t* buffer, uint32_t bufferLen, size_t addressesSize) override
			{
				std::vector<WINDIVERT_ADDRESS> winDivertAddresses;
				for (size_t i = 0; i < addressesSize; i++)
				{
					WINDIVERT_ADDRESS addr = {};
					addr.Outbound = 1;
					winDivertAddresses.push_back(addr);
				}

				auto result = WinDivertSendEx(m_Handle, buffer, bufferLen, nullptr, 0, winDivertAddresses.data(),
				                              addressesSize * sizeof(WINDIVERT_ADDRESS), nullptr);
				if (!result)
				{
					return GetLastError();
				}

				return SuccessResult;
			}

			std::unique_ptr<IOverlappedWrapper> createOverlapped() override
			{
				return std::make_unique<WinDivertOverlappedWrapper>(m_Handle);
			}

			bool getParam(WinDivertParam param, uint64_t& value) override
			{
				return WinDivertGetParam(m_Handle, static_cast<WINDIVERT_PARAM>(param), &value);
			}

			bool setParam(WinDivertParam param, uint64_t value) override
			{
				return WinDivertSetParam(m_Handle, static_cast<WINDIVERT_PARAM>(param), value);
			}

		private:
			HANDLE m_Handle;
			std::vector<WINDIVERT_ADDRESS> m_WinDivertAddresses;
			uint32_t m_WinDivertAddressesSize = 0;
		};

		class WinDivertImplementation : public IWinDivertImplementation
		{
		public:
			std::unique_ptr<IWinDivertHandle> open(const std::string& filter, int layer, int16_t priority,
			                                       uint64_t flags) override
			{
				auto handle = WinDivertOpen(filter.c_str(), static_cast<WINDIVERT_LAYER>(layer), priority, flags);
				if (handle == INVALID_HANDLE_VALUE)
				{
					PCPP_LOG_ERROR("Failed to open WinDivertHandle, error was: " << GetLastError());
					return nullptr;
				}
				return std::make_unique<WinDivertHandle>(handle);
			}

			std::vector<NetworkInterface> getNetworkInterfaces() const override
			{
				std::vector<NetworkInterface> networkInterfaces;

				ULONG bufferSize = 15000;
				std::vector<BYTE> buffer(bufferSize);

				auto result = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, nullptr,
				                                   reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data()), &bufferSize);

				if (result == ERROR_BUFFER_OVERFLOW)
				{
					buffer.resize(bufferSize);
					result = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, nullptr,
					                              reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data()), &bufferSize);
				}

				if (result != NO_ERROR)
				{
					throw std::runtime_error("Error while getting network interfaces");
				}

				auto adapter = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data());

				while (adapter)
				{
					NetworkInterface networkInterface;
					networkInterface.index = adapter->IfIndex;
					networkInterface.name = adapter->FriendlyName;
					networkInterface.description = adapter->Description;
					networkInterface.isLoopback = (adapter->IfType == IF_TYPE_SOFTWARE_LOOPBACK);
					networkInterface.isUp = (adapter->OperStatus == IfOperStatusUp);

					networkInterfaces.push_back(networkInterface);
					adapter = adapter->Next;
				}

				return networkInterfaces;
			}
		};

	}  // namespace internal

#define WINDIVERT_BUFFER_LEN 65536

	WinDivertDevice::WinDivertDevice() : m_Impl(std::make_unique<internal::WinDivertImplementation>())
	{}

	bool WinDivertDevice::open()
	{
		return open("true");
	}

	bool WinDivertDevice::open(const std::string& filter)
	{
		m_Handle = m_Impl->open(filter, WINDIVERT_LAYER_NETWORK, 0, WINDIVERT_FLAG_SNIFF | WINDIVERT_FLAG_FRAGMENTS);
		if (!m_Handle)
		{
			return false;
		}

		setNetworkInterfaces();

		m_DeviceOpened = true;
		return true;
	}

	void WinDivertDevice::close()
	{
		auto result = m_Handle->close();
		if (result != internal::IWinDivertHandle::SuccessResult)
		{
			PCPP_LOG_ERROR("Couldn't receive packet, status: " << getErrorString(static_cast<uint16_t>(result)) << "("
			                                                   << static_cast<int>(result) << ")");
		}
	}

	WinDivertDevice::ReceiveResult WinDivertDevice::receivePackets(WinDivertRawPacketVector& packetVec,
	                                                               uint32_t timeout, uint32_t maxPackets,
	                                                               uint8_t batchSize)
	{
		if (!isOpened())
		{
			return { ReceiveResult::Status::Failed, "Device is not open" };
		}

		if (m_IsReceiving)
		{
			return { ReceiveResult::Status::Failed, "Already receiving packets, please call stopReceive() first" };
		}

		if (batchSize == 0)
		{
			return { ReceiveResult::Status::Failed, "Batch size has to be a positive number" };
		}

		if (timeout == 0 && maxPackets == 0)
		{
			return { ReceiveResult::Status::Failed,
				     "At least one of timeout and maxPackets must be a positive number" };
		}

		auto overlapped = m_Handle->createOverlapped();
		uint32_t bufferSize = WINDIVERT_BUFFER_LEN * batchSize;
		std::vector<uint8_t> buffer(bufferSize);

		uint32_t receivedPacketCount = 0;
		while (maxPackets == 0 || receivedPacketCount < maxPackets)
		{
			auto result = receivePacketsInternal(timeout, batchSize, buffer, overlapped.get());

			if (result.status != ReceiveResult::Status::Completed)
			{
				return { result.status, result.error, result.errorCode };
			}

			uint32_t packetCountInCurrentBatch = receivedPacketCount + result.addresses.size() > maxPackets
			                                         ? maxPackets - receivedPacketCount
			                                         : result.addresses.size();
			receivedPacketCount += packetCountInCurrentBatch;

			uint8_t* curPacketPtr = buffer.data();
			size_t remainingBytes = result.capturedDataLength;

			for (uint32_t i = 0; i < packetCountInCurrentBatch; i++)
			{
				auto packetInfo = getPacketInfo(curPacketPtr, remainingBytes, result.addresses[i]);

				auto linkType = std::get<0>(packetInfo);
				if (linkType == LINKTYPE_INVALID)
				{
					continue;
				}

				auto packetLength = std::get<1>(packetInfo);
				auto packetData = std::make_unique<uint8_t[]>(packetLength);
				memcpy(packetData.get(), curPacketPtr, packetLength);
				packetVec.pushBack(new WinDivertRawPacket(
				    packetData.release(), static_cast<int>(packetLength), std::get<2>(packetInfo), true, linkType,
				    result.addresses[i].interfaceIndex, result.addresses[i].timestamp));
				curPacketPtr += packetLength;
				remainingBytes -= packetLength;
			}

			overlapped->reset();
		}

		return { ReceiveResult::Status::Completed };
	}

	WinDivertDevice::ReceiveResult WinDivertDevice::receivePackets(const ReceivePacketCallback& callback,
	                                                               uint32_t timeout, uint8_t batchSize)
	{
		if (!isOpened())
		{
			return { ReceiveResult::Status::Failed, "Device is not open" };
		}

		if (m_IsReceiving)
		{
			return { ReceiveResult::Status::Failed, "Already receiving packets, please call stopReceive() first" };
		}

		if (batchSize == 0)
		{
			return { ReceiveResult::Status::Failed, "Batch size has to be a positive number" };
		}

		auto overlapped = m_Handle->createOverlapped();
		uint32_t bufferSize = WINDIVERT_BUFFER_LEN * batchSize;
		std::vector<uint8_t> buffer(bufferSize);

		m_IsReceiving = true;
		while (m_IsReceiving)
		{
			auto result = receivePacketsInternal(timeout, batchSize, buffer, overlapped.get());

			if (result.status != ReceiveResult::Status::Completed)
			{
				m_IsReceiving = false;
				return { result.status, result.error, result.errorCode };
			}

			uint8_t* curPacketPtr = buffer.data();
			size_t remainingBytes = result.capturedDataLength;

			WinDivertRawPacketVector receivedPackets;
			for (auto& address : result.addresses)
			{
				auto packetInfo = getPacketInfo(curPacketPtr, remainingBytes, address);

				auto linkType = std::get<0>(packetInfo);
				if (linkType == LINKTYPE_INVALID)
				{
					continue;
				}

				auto packetLength = std::get<1>(packetInfo);
				receivedPackets.pushBack(new WinDivertRawPacket(curPacketPtr, static_cast<int>(packetLength),
				                                                std::get<2>(packetInfo), false, linkType,
				                                                address.interfaceIndex, address.timestamp));
				curPacketPtr += packetLength;
				remainingBytes -= packetLength;
			}

			callback(receivedPackets);

			overlapped->reset();
		}

		return { ReceiveResult::Status::Completed };
	}

	void WinDivertDevice::stopReceive()
	{
		m_IsReceiving = false;
	}

	WinDivertDevice::SendResult WinDivertDevice::sendPackets(const RawPacketVector& packetVec, uint8_t batchSize) const
	{
		if (!m_DeviceOpened)
		{
			return { SendResult::Status::Failed, 0, "Device is not open" };
		}

		if (batchSize == 0)
		{
			return { SendResult::Status::Failed, 0, "Batch size has to be a positive number" };
		}

		uint8_t buffer[WINDIVERT_BUFFER_LEN];
		auto curBufferPtr = buffer;

		uint8_t packetsInCurrentBatch = 0;
		size_t packetsSent = 0;
		size_t packetsToSend = packetVec.size();
		for (auto packetIndex = 0; packetIndex < packetVec.size(); packetIndex++)
		{
			memcpy(curBufferPtr, packetVec.at(packetIndex)->getRawData(), packetVec.at(packetIndex)->getRawDataLen());
			curBufferPtr += packetVec.at(packetIndex)->getRawDataLen();
			packetsInCurrentBatch++;

			if (packetsInCurrentBatch >= batchSize || packetIndex >= packetsToSend - 1)
			{
				auto result = m_Handle->sendEx(buffer, WINDIVERT_BUFFER_LEN, packetsInCurrentBatch);
				if (result != internal::IWinDivertHandle::SuccessResult)
				{
					return { SendResult::Status::Failed, packetsSent,
						     "Sending packets failed: " + getErrorString(result), result };
				}
				packetsSent += packetsInCurrentBatch;

				packetsInCurrentBatch = 0;
				memset(buffer, 0, sizeof(buffer));
				curBufferPtr = buffer;
			}
		}

		return { SendResult::Status::Completed, packetsSent };
	}

	WinDivertDevice::QueueParams WinDivertDevice::getPacketQueueParams() const
	{
		if (!m_DeviceOpened)
		{
			throw std::runtime_error("Device is not open");
		}

		uint64_t queueLength, queueTime, queueSize;

		auto getParamResult = true;
		getParamResult |= m_Handle->getParam(internal::IWinDivertHandle::WinDivertParam::QueueLength, queueLength);
		getParamResult |= m_Handle->getParam(internal::IWinDivertHandle::WinDivertParam::QueueTime, queueTime);
		getParamResult |= m_Handle->getParam(internal::IWinDivertHandle::WinDivertParam::QueueSize, queueSize);

		if (!getParamResult)
		{
			throw std::runtime_error("Failed to retrieve queue parameters");
		}

		return {
			{ QueueParam::QueueLength, queueLength },
			{ QueueParam::QueueTime,   queueTime   },
			{ QueueParam::QueueSize,   queueSize   }
		};
	}

	void WinDivertDevice::setPacketQueueParams(const QueueParams& params) const
	{
		if (!m_DeviceOpened)
		{
			throw std::runtime_error("Device is not open");
		}

		for (auto& param : params)
		{
			switch (param.first)
			{
			case QueueParam::QueueLength:
			{
				m_Handle->setParam(internal::IWinDivertHandle::WinDivertParam::QueueLength, param.second);
				break;
			}
			case QueueParam::QueueTime:
			{
				m_Handle->setParam(internal::IWinDivertHandle::WinDivertParam::QueueTime, param.second);
				break;
			}
			case QueueParam::QueueSize:
			{
				m_Handle->setParam(internal::IWinDivertHandle::WinDivertParam::QueueSize, param.second);
				break;
			}
			}
		}
	}

	WinDivertDevice::WinDivertVersion WinDivertDevice::getVersion() const
	{
		if (!m_DeviceOpened)
		{
			throw std::runtime_error("Device is not open");
		}

		uint64_t versionMajor, versionMinor;

		auto getParamResult = true;
		getParamResult |= m_Handle->getParam(internal::IWinDivertHandle::WinDivertParam::VersionMajor, versionMajor);
		getParamResult |= m_Handle->getParam(internal::IWinDivertHandle::WinDivertParam::VersionMajor, versionMinor);

		if (!getParamResult)
		{
			throw std::runtime_error("Failed to retrieve WinDivert version");
		}

		return { versionMajor, versionMinor };
	}

	const WinDivertDevice::NetworkInterface* WinDivertDevice::getNetworkInterface(uint32_t interfaceIndex) const
	{
		auto it = m_NetworkInterfaces.find(interfaceIndex);
		if (it != m_NetworkInterfaces.end())
		{
			return &it->second;
		}

		return nullptr;
	}

	std::vector<WinDivertDevice::NetworkInterface> WinDivertDevice::getNetworkInterfaces() const
	{
		setNetworkInterfaces();

		std::vector<NetworkInterface> interfaces;
		interfaces.reserve(m_NetworkInterfaces.size());

		for (const auto& entry : m_NetworkInterfaces)
		{
			interfaces.push_back(entry.second);
		}

		return interfaces;
	}

	void WinDivertDevice::setImplementation(std::unique_ptr<internal::IWinDivertImplementation> implementation)
	{
		m_Impl = std::move(implementation);
	}

	WinDivertDevice::ReceiveResultInternal WinDivertDevice::receivePacketsInternal(
	    uint32_t timeout, uint8_t batchSize, std::vector<uint8_t>& buffer, internal::IOverlappedWrapper* overlapped)
	{
		auto result = m_Handle->recvEx(buffer.data(), buffer.size(), batchSize, overlapped);
		if (result != internal::IWinDivertHandle::ErrorIoPending)
		{
			return { ReceiveResult::Status::Failed, "Error receiving packets: " + getErrorString(result), result };
		}

		if (timeout == 0)
		{
			timeout = INFINITE;
		}
		auto waitResult = overlapped->wait(timeout);

		switch (waitResult.status)
		{
		case internal::IOverlappedWrapper::WaitResult::Status::Completed:
		{
			auto overlappedResult = overlapped->getOverlappedResult();
			if (overlappedResult.status != internal::IOverlappedWrapper::OverlappedResult::Status::Success)
			{
				return { ReceiveResult::Status::Failed,
					     "Error fetching overlapped result: " + getErrorString(overlappedResult.errorCode),
					     overlappedResult.errorCode };
			}

			return { overlappedResult.packetLen, m_Handle->recvExComplete() };
		}
		case internal::IOverlappedWrapper::WaitResult::Status::Timeout:
		{
			return { ReceiveResult::Status::Timeout };
		}
		default:
		{
			return { ReceiveResult::Status::Failed,
				     "Error while waiting for packets: " + getErrorString(waitResult.errorCode), waitResult.errorCode };
		}
		}
	}

	std::tuple<LinkLayerType, uint16_t, timespec> WinDivertDevice::getPacketInfo(
	    uint8_t* buffer, uint32_t bufferLen, const internal::WinDivertAddress& address)
	{
		uint16_t packetLength = 0;
		LinkLayerType linkType = LINKTYPE_INVALID;
		if (address.isIPv6 && IPv6Layer::isDataValid(buffer, bufferLen))
		{
			packetLength = sizeof(ip6_hdr) + be16toh(reinterpret_cast<ip6_hdr*>(buffer)->payloadLength);
			linkType = LINKTYPE_IPV6;
		}
		else if (IPv4Layer::isDataValid(buffer, bufferLen))
		{
			packetLength = be16toh(reinterpret_cast<iphdr*>(buffer)->totalLength);
			linkType = LINKTYPE_IPV4;
		}
		else
		{
			return { linkType, 0, {} };
		}

		auto now = std::chrono::system_clock::now();
		auto duration = now.time_since_epoch();
		auto nanoSecs = std::chrono::duration_cast<std::chrono::nanoseconds>(duration).count();
		timespec ts = { nanoSecs / 1'000'000'000, nanoSecs % 1'000'000'000 };

		return { linkType, packetLength, ts };
	}

	void WinDivertDevice::setNetworkInterfaces() const
	{
		if (m_NetworkInterfacesInitialized)
		{
			return;
		}

		auto networkInterfaces = m_Impl->getNetworkInterfaces();
		for (const auto& networkInterface : networkInterfaces)
		{
			m_NetworkInterfaces[networkInterface.index] = { networkInterface.index, networkInterface.name,
				                                            networkInterface.description, networkInterface.isLoopback,
				                                            networkInterface.isUp };
		}

		m_NetworkInterfacesInitialized = true;
	}

	std::string WinDivertDevice::getErrorString(uint32_t errorCode)
	{
		LPSTR messageBuffer = nullptr;
		DWORD size = FormatMessageA(
		    FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, nullptr,
		    errorCode, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), reinterpret_cast<LPSTR>(&messageBuffer), 0, nullptr);

		if (size == 0)
		{
			return "Unknown error";
		}

		std::string message(messageBuffer, size);

		// Remove trailing newlines
		while (!message.empty() && (message.back() == '\n' || message.back() == '\r'))
		{
			message.pop_back();
		}

		LocalFree(messageBuffer);

		return message;
	}
}  // namespace pcpp
