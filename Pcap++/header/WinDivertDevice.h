#pragma once

#include <functional>
#include <tuple>
#include <unordered_map>
#include <atomic>
#include "Device.h"

/// @file

namespace pcpp
{
	namespace internal
	{
		class IWinDivertHandle
		{
		public:
			virtual ~IWinDivertHandle() = default;
		};

		class IOverlappedWrapper
		{
		public:
			struct WaitResult
			{
				enum class Status
				{
					Completed,
					Timeout,
					Failed
				};

				Status status;
				uint32_t errorCode = 0;
			};

			struct OverlappedResult
			{
				enum class Status
				{
					Success,
					Failed
				};

				Status status;
				uint32_t packetLen = 0;
				uint32_t errorCode = 0;
			};

			virtual WaitResult wait(uint32_t timeout) = 0;
			virtual void reset() = 0;
			virtual OverlappedResult getOverlappedResult(const IWinDivertHandle* handle) = 0;
			virtual ~IOverlappedWrapper() = default;
		};

		struct WinDivertAddress
		{
			bool isIPv6;
			uint32_t interfaceIndex;
			uint64_t timestamp;
		};

		class IWinDivertImplementation
		{
		public:
			enum class WinDivertParam
			{
				QueueLength = 0,
				QueueTime = 1,
				QueueSize = 2,
				VersionMajor = 3,
				VersionMinor = 4
			};

			struct NetworkInterface
			{
				uint32_t index;
				std::wstring name;
				std::wstring description;
				bool isLoopback;
				bool isUp;
			};

			static constexpr uint32_t SuccessResult = 0;
			static constexpr uint32_t ErrorIoPending = 997;

			virtual ~IWinDivertImplementation() = default;

			virtual std::unique_ptr<IWinDivertHandle> open(const std::string& filter, int layer, int16_t priority,
			                                               uint64_t flags) = 0;
			virtual uint32_t close(const IWinDivertHandle* handle) = 0;
			virtual uint32_t recvEx(const IWinDivertHandle* handle, uint8_t* buffer, uint32_t bufferLen,
			                        size_t addressesSize, IOverlappedWrapper* overlapped) = 0;
			virtual std::vector<WinDivertAddress> recvExComplete() = 0;
			virtual uint32_t sendEx(const IWinDivertHandle* handle, uint8_t* buffer, uint32_t bufferLen,
			                        size_t addressesSize) = 0;
			virtual std::unique_ptr<IOverlappedWrapper> createOverlapped() = 0;
			virtual bool getParam(const IWinDivertHandle* handle, WinDivertParam param, uint64_t& value) = 0;
			virtual bool setParam(const IWinDivertHandle* handle, WinDivertParam param, uint64_t value) = 0;
			virtual std::vector<NetworkInterface> getNetworkInterfaces() const = 0;
		};
	}  // namespace internal

	class WinDivertRawPacket : public RawPacket
	{
	public:
		WinDivertRawPacket(const uint8_t* pRawData, int rawDataLen, timespec timestamp, bool deleteRawDataAtDestructor,
		                   LinkLayerType layerType, uint32_t interfaceIndex, uint64_t winDivertTimestamp)
		    : RawPacket(pRawData, rawDataLen, timestamp, deleteRawDataAtDestructor, layerType),
		      m_InterfaceIndex(interfaceIndex), m_WinDivertTimestamp(winDivertTimestamp)
		{}

		uint32_t getInterfaceIndex() const
		{
			return m_InterfaceIndex;
		}

		uint64_t getWinDivertTimestamp() const
		{
			return m_WinDivertTimestamp;
		}

	private:
		uint32_t m_InterfaceIndex;
		uint64_t m_WinDivertTimestamp;
	};

	class WinDivertDevice : public IDevice
	{
	public:
		struct ReceiveResult
		{
			enum class Status
			{
				Completed,
				Timeout,
				Failed
			};

			Status status;
			std::string error;
			uint32_t errorCode = 0;
		};

		struct SendResult
		{
			enum class Status
			{
				Completed,
				Failed
			};

			Status status;
			size_t packetsSent;
			std::string error;
			uint32_t errorCode = 0;
		};

		struct WinDivertVersion
		{
			uint64_t major;
			uint64_t minor;

			std::string toString() const
			{
				return std::to_string(major) + "." + std::to_string(minor);
			}
		};

		struct NetworkInterface
		{
			uint32_t index;
			std::wstring name;
			std::wstring description;
			bool isLoopback;
			bool isUp;
		};

		enum class QueueParam
		{
			QueueLength,
			QueueTime,
			QueueSize
		};

		using WinDivertRawPacketVector = PointerVector<WinDivertRawPacket>;
		using ReceivePacketCallback = std::function<void(const WinDivertRawPacketVector& packetVec)>;
		using QueueParams = std::unordered_map<QueueParam, uint64_t>;

		WinDivertDevice();

		bool open() override;
		bool open(const std::string& filter);
		void close() override;

		ReceiveResult receivePackets(WinDivertRawPacketVector& packetVec, uint32_t timeout = 5000,
		                             uint32_t maxPackets = 0, uint8_t batchSize = 64);
		ReceiveResult receivePackets(const ReceivePacketCallback& callback, uint32_t timeout = 5000,
		                             uint8_t batchSize = 64);
		void stopReceive();

		SendResult sendPackets(const RawPacketVector& packetVec, uint8_t batchSize = 64) const;

		QueueParams getPacketQueueParams() const;
		void setPacketQueueParams(const QueueParams& params) const;

		WinDivertVersion getVersion() const;

		const NetworkInterface* getNetworkInterface(uint32_t interfaceIndex) const;
		std::vector<NetworkInterface> getNetworkInterfaces() const;

		void setImplementation(std::unique_ptr<internal::IWinDivertImplementation> implementation);

	private:
		std::unique_ptr<internal::IWinDivertImplementation> m_Impl;
		std::unique_ptr<internal::IWinDivertHandle> m_Handle;
		std::atomic<bool> m_IsReceiving{ false };
		mutable std::unordered_map<uint32_t, NetworkInterface> m_NetworkInterfaces;
		mutable bool m_NetworkInterfacesInitialized = false;

		struct ReceiveResultInternal : ReceiveResult
		{
			uint32_t capturedDataLength = 0;
			std::vector<internal::WinDivertAddress> addresses;

			ReceiveResultInternal(Status status, const std::string& error = "", uint32_t errorCode = 0)
			    : ReceiveResult{ status, error, errorCode }
			{}

			ReceiveResultInternal(uint32_t capturedDataLength, const std::vector<internal::WinDivertAddress>& addresses)
			    : ReceiveResult{ Status::Completed, "", 0 }, capturedDataLength(capturedDataLength),
			      addresses(addresses)
			{}
		};

		ReceiveResultInternal receivePacketsInternal(uint32_t timeout, uint8_t batchSize, std::vector<uint8_t>& buffer,
		                                             internal::IOverlappedWrapper* overlapped);
		static std::tuple<LinkLayerType, uint16_t, timespec> getPacketInfo(uint8_t* buffer, uint32_t bufferLen,
		                                                                   const internal::WinDivertAddress& address);
		void setNetworkInterfaces() const;
		static std::string getErrorString(uint32_t errorCode);
	};
}  // namespace pcpp
