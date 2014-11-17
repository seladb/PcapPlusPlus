#ifndef PCAPPP_FILE_DEVICE
#define PCAPPP_FILE_DEVICE

#include <PcapDevice.h>

class IPcapFileDevice : public IPcapDevice
{
protected:
	char* m_FileName;
public:
	IPcapFileDevice(const char* fileName);
	~IPcapFileDevice();

	//override methods

	virtual void close();
};

class PcapFileReaderDevice : public IPcapFileDevice
{
private:
	uint32_t m_NumOfPacketsRead;
	uint32_t m_NumOfPacketsNotParsed;
public:
	PcapFileReaderDevice(const char* fileName);
	~PcapFileReaderDevice();

	bool getNextPacket(RawPacket& rawPacket);

	//override methods

	virtual bool open();
	virtual void getStatistics(pcap_stat& stats);
};

class PcapFileWriterDevice : public IPcapFileDevice
{
private:
	pcap_dumper_t* m_PcapDumpHandler;
	uint32_t m_NumOfPacketsWritten;
	uint32_t m_NumOfPacketsNotWritten;
public:
	PcapFileWriterDevice(const char* fileName);
	~PcapFileWriterDevice();

	bool writePacket(RawPacket const& packet);

	//override methods

	virtual bool open();
	virtual void close();
	virtual void getStatistics(pcap_stat& stats);
};

#endif
