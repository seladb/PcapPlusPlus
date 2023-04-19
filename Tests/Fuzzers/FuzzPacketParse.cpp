#include <iostream>
#include <IPv4Layer.h>
#include <IPv6Layer.h>
#include <unistd.h>
#include <Packet.h>
#include <PcapFileDevice.h>
#include <RawPacket.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    struct timespec ts;
    timespec_get(&ts, TIME_UTC);

	if (Size < 2)
		return 0;

	// read the first (and only) packet from the file
	pcpp::RawPacket rawPacket(((const uint8_t *)Data + 1), Size - 1, ts, false, pcpp::LinkLayerType(Data[0]));
	// parse the raw packet into a parsed packet
	pcpp::Packet parsedPacket(&rawPacket);
	// Convert the parsed packet to string to trigger all the parsing formats
	parsedPacket.toString();
	return 0;
}