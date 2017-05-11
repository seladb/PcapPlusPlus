#ifndef PACKETPP_TCP_REASSEMBLY
#define PACKETPP_TCP_REASSEMBLY

#include <Packet.h>
#include <IpAddress.h>
#include <PointerVector.h>
#include <map>

namespace pcpp
{

struct ConnectionData
{
	IPv4Address srcIP;
	IPv4Address dstIP;
	size_t srcPort;
	size_t dstPort;
	uint32_t flowKey;

	ConnectionData() : srcIP(IPv4Address::Zero), dstIP(IPv4Address::Zero), srcPort(0), dstPort(0), flowKey(0) {}
};

class TcpReassembly;

class TcpStreamData
{
	friend class TcpReassembly;

public:

	TcpStreamData();

	TcpStreamData(uint8_t* tcpData, size_t tcpDataLength, ConnectionData connData);

	~TcpStreamData();

	TcpStreamData(TcpStreamData& other);

	TcpStreamData& operator=(const TcpStreamData& other);

	inline uint8_t* getData() { return m_Data; }

	inline size_t getDataLength() { return m_DataLen; }

	inline ConnectionData getConnectionData() { return m_Connection; }

private:
	uint8_t* m_Data;
	size_t m_DataLen;
	ConnectionData m_Connection;
	bool m_DeleteDataOnDestruction;

	void setDeleteDataOnDestruction(bool flag) { m_DeleteDataOnDestruction = flag; }
	void copyData(const TcpStreamData& other);
};

class TcpReassembly
{
public:

	enum ConnectionEndReason
	{
		TcpReassemblyConnectionClosedByFIN_RST,
		TcpReassemblyConnectionClosedManually
	};

	typedef void (*OnTcpMessageReady)(int side, TcpStreamData tcpData, void* userCookie);

	typedef void (*OnTcpConnectionStart)(ConnectionData connectionData, void* userCookie);

	typedef void (*OnTcpConnectionEnd)(ConnectionData connectionData, ConnectionEndReason reason, void* userCookie);

	TcpReassembly(OnTcpMessageReady onMessageReadyCallback, void* userCookie = NULL, OnTcpConnectionStart onConnectionStartCallback = NULL, OnTcpConnectionEnd onConnectionEndCallback = NULL);

	~TcpReassembly();

	void ReassemblePacket(Packet& tcpData);

	void ReassemblePacket(RawPacket* tcpRawData);

	void closeFlow(uint32_t flowKey);

	void closeAllFlows();

private:
	struct TcpFragment
	{
		uint32_t sequence;
		size_t dataLength;
		uint8_t* data;

		TcpFragment() { sequence = 0; dataLength = 0; data = NULL; }
		~TcpFragment() { if (data != NULL) delete [] data; }
	};

	struct TcpOneSideData
	{
		uint32_t srcIP;
		uint16_t srcPort;
		uint32_t sequence;
		PointerVector<TcpFragment> tcpFragmentList;
		bool gotFinOrRst;

		TcpOneSideData() { srcIP = 0; srcPort = 0; sequence = 0; gotFinOrRst = false; }
	};

	struct TcpReassemblyData
	{
		int numOfSides;
		int prevSide;
		TcpOneSideData twoSides[2];
		ConnectionData connData;

		TcpReassemblyData() { numOfSides = 0; prevSide = -1; }
	};

	OnTcpMessageReady m_OnMessageReadyCallback;
	OnTcpConnectionStart m_OnConnStart;
	OnTcpConnectionEnd m_OnConnEnd;
	void* m_UserCookie;
	std::map<uint32_t, TcpReassemblyData*> m_ConnectionList;
	std::map<uint32_t, bool> m_ClosedConnectionList;

	void checkOutOfOrderFragments(TcpReassemblyData* tcpReassemblyData, int sideIndex, bool cleanWholeFragList);

	std::string prepareMissingDataMessage(uint32_t missingDataLen);

	void handleFinOrRst(TcpReassemblyData* tcpReassemblyData, int sideIndex, uint32_t flowKey);

	void closeFlowInternal(uint32_t flowKey, ConnectionEndReason reason);
};

}

#endif /* PACKETPP_TCP_REASSEMBLY */
