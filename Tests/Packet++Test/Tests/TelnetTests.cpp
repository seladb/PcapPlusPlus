#include "../TestDefinition.h"
#include "../Utils/TestUtils.h"
#include "Logger.h"
#include "EndianPortable.h"
#include "Packet.h"
#include "EthLayer.h"
#include "IPv4Layer.h"
#include "TcpLayer.h"
#include "TelnetLayer.h"
#include "SystemUtils.h"

PTF_TEST_CASE(TelnetControlParsingTests)
{

    timeval time;
    gettimeofday(&time, NULL);

    READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/telnetCommand.dat");

    pcpp::Packet telnetPacket(&rawPacket1);
    pcpp::TelnetLayer *telnetLayer = telnetPacket.getLayerOfType<pcpp::TelnetLayer>();

    PTF_ASSERT_NOT_NULL(telnetLayer);


}

PTF_TEST_CASE(TelnetDataParsingTests)
{

    timeval time;
    gettimeofday(&time, NULL);

    READ_FILE_AND_CREATE_PACKET(1, "PacketExamples/telnetData.dat");

    pcpp::Packet telnetPacket(&rawPacket1);
    pcpp::TelnetLayer *telnetLayer = telnetPacket.getLayerOfType<pcpp::TelnetLayer>();

    PTF_ASSERT_NOT_NULL(telnetLayer);


}