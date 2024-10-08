#include <iostream>
#include <memory>
#include "SystemUtils.h"
#include "Packet.h"
#include "EthLayer.h"
#include "VlanLayer.h"
#include "IPv4Layer.h"
#include "TcpLayer.h"
#include "HttpLayer.h"
#include "UdpLayer.h"
#include "DnsLayer.h"
#include "PcapFileDevice.h"

int main(int argc, char* argv[])
{
	// Packet Editing
	// ~~~~~~~~~~~~~~

	// use the IFileReaderDevice interface to automatically identify file type (pcap/pcap-ng)
	// and create an interface instance that both readers implement
	std::unique_ptr<pcpp::IFileReaderDevice> reader(pcpp::IFileReaderDevice::getReader("1_http_packet.pcap"));

	// verify that a reader interface was indeed created
	if (reader == nullptr)
	{
		std::cerr << "Cannot determine reader for file type" << std::endl;
		return 1;
	}

	// open the reader for reading
	if (!reader->open())
	{
		std::cerr << "Cannot open input.pcap for reading" << std::endl;
		return 1;
	}

	// read the first (and only) packet from the file
	pcpp::RawPacket rawPacket;
	if (!reader->getNextPacket(rawPacket))
	{
		std::cerr << "Couldn't read the first packet in the file" << std::endl;
		return 1;
	}

	// close the file reader, we don't need it anymore
	reader->close();

	// parse the raw packet into a parsed packet
	pcpp::Packet parsedPacket(&rawPacket);

	// now let's get the Ethernet layer
	auto* ethernetLayer = parsedPacket.getLayerOfType<pcpp::EthLayer>();
	// change the source dest MAC address
	ethernetLayer->setDestMac(pcpp::MacAddress("aa:bb:cc:dd:ee:ff"));

	// let's get the IPv4 layer
	auto* ipLayer = parsedPacket.getLayerOfType<pcpp::IPv4Layer>();
	// change source IP address
	ipLayer->setSrcIPv4Address(pcpp::IPv4Address("1.1.1.1"));
	// change IP ID
	ipLayer->getIPv4Header()->ipId = pcpp::hostToNet16(4000);
	// change TTL value
	ipLayer->getIPv4Header()->timeToLive = 12;

	// let's get the TCP layer
	auto* tcpLayer = parsedPacket.getLayerOfType<pcpp::TcpLayer>();
	// change source port
	tcpLayer->getTcpHeader()->portSrc = pcpp::hostToNet16(12345);
	// add URG flag
	tcpLayer->getTcpHeader()->urgFlag = 1;
	// add MSS TCP option
	tcpLayer->insertTcpOptionAfter(pcpp::TcpOptionBuilder(pcpp::TcpOptionEnumType::Mss, (uint16_t)1460));

	// let's get the HTTP layer
	auto* httpRequestLayer = parsedPacket.getLayerOfType<pcpp::HttpRequestLayer>();
	// change the request method from GET to TRACE
	httpRequestLayer->getFirstLine()->setMethod(pcpp::HttpRequestLayer::HttpTRACE);
	// change host to www.google.com
	httpRequestLayer->getFieldByName(PCPP_HTTP_HOST_FIELD)->setFieldValue("www.google.com");
	// change referer value to www.aol.com
	httpRequestLayer->getFieldByName(PCPP_HTTP_REFERER_FIELD)->setFieldValue("www.aol.com");
	// remove cookie field
	httpRequestLayer->removeField(PCPP_HTTP_COOKIE_FIELD);
	// add x-forwarded-for field
	pcpp::HeaderField* xForwardedForField = httpRequestLayer->insertField(
	    httpRequestLayer->getFieldByName(PCPP_HTTP_HOST_FIELD), "X-Forwarded-For", "1.1.1.1");
	// add cache-control field
	httpRequestLayer->insertField(xForwardedForField, "Cache-Control", "max-age=0");

	// create a new vlan layer
	pcpp::VlanLayer newVlanLayer(123, false, 1, PCPP_ETHERTYPE_IP);

	// add the vlan layer to the packet after the existing Ethernet layer
	parsedPacket.insertLayer(ethernetLayer, &newVlanLayer);

	// compute all calculated fields
	parsedPacket.computeCalculateFields();

	// write the modified packet to a pcap file
	pcpp::PcapFileWriterDevice writer("1_modified_packet.pcap");
	if (writer.open())
	{
		writer.writePacket(*(parsedPacket.getRawPacket()));
		writer.close();
	}

	// Packet Creation
	// ~~~~~~~~~~~~~~~

	// create a new Ethernet layer
	pcpp::EthLayer newEthernetLayer(pcpp::MacAddress("00:50:43:11:22:33"), pcpp::MacAddress("aa:bb:cc:dd:ee:ff"));

	// create a new IPv4 layer
	pcpp::IPv4Layer newIPLayer(pcpp::IPv4Address("192.168.1.1"), pcpp::IPv4Address("10.0.0.1"));
	newIPLayer.getIPv4Header()->ipId = pcpp::hostToNet16(2000);
	newIPLayer.getIPv4Header()->timeToLive = 64;

	// create a new UDP layer
	pcpp::UdpLayer newUdpLayer(12345, 53);

	// create a new DNS layer
	pcpp::DnsLayer newDnsLayer;
	newDnsLayer.addQuery("www.ebay.com", pcpp::DNS_TYPE_A, pcpp::DNS_CLASS_IN);

	// create a packet with initial capacity of 100 bytes (will grow automatically if needed)
	pcpp::Packet newPacket(100);

	// add all the layers we created
	newPacket.addLayer(&newEthernetLayer);
	newPacket.addLayer(&newIPLayer);
	newPacket.addLayer(&newUdpLayer);
	newPacket.addLayer(&newDnsLayer);

	// compute all calculated fields
	newPacket.computeCalculateFields();

	// write the new packet to a pcap file
	pcpp::PcapFileWriterDevice writer2("1_new_packet.pcap");
	if (writer2.open())
	{
		writer2.writePacket(*(newPacket.getRawPacket()));
		writer2.close();
	}
}
