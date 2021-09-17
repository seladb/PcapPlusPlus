#include <iostream>
#include "stdlib.h"
#include "SystemUtils.h"
#include "Packet.h"
#include "EthLayer.h"
#include "IPv4Layer.h"
#include "TcpLayer.h"
#include "HttpLayer.h"
#include "PcapFileDevice.h"

std::string getProtocolTypeAsString(pcpp::ProtocolType protocolType)
{
	switch (protocolType)
	{
	case pcpp::Ethernet:
		return "Ethernet";
	case pcpp::IPv4:
		return "IPv4";
	case pcpp::TCP:
		return "TCP";
	case pcpp::HTTPRequest:
	case pcpp::HTTPResponse:
		return "HTTP";
	default:
		return "Unknown";
	}
}

std::string printTcpFlags(pcpp::TcpLayer* tcpLayer)
{
	std::string result = "";
	if (tcpLayer->getTcpHeader()->synFlag == 1)
		result += "SYN ";
	if (tcpLayer->getTcpHeader()->ackFlag == 1)
		result += "ACK ";
	if (tcpLayer->getTcpHeader()->pshFlag == 1)
		result += "PSH ";
	if (tcpLayer->getTcpHeader()->cwrFlag == 1)
		result += "CWR ";
	if (tcpLayer->getTcpHeader()->urgFlag == 1)
		result += "URG ";
	if (tcpLayer->getTcpHeader()->eceFlag == 1)
		result += "ECE ";
	if (tcpLayer->getTcpHeader()->rstFlag == 1)
		result += "RST ";
	if (tcpLayer->getTcpHeader()->finFlag == 1)
		result += "FIN ";

	return result;
}

std::string printTcpOptionType(pcpp::TcpOptionType optionType)
{
	switch (optionType)
	{
	case pcpp::PCPP_TCPOPT_NOP:
		return "NOP";
	case pcpp::PCPP_TCPOPT_TIMESTAMP:
		return "Timestamp";
	default:
		return "Other";
	}
}

std::string printHttpMethod(pcpp::HttpRequestLayer::HttpMethod httpMethod)
{
	switch (httpMethod)
	{
	case pcpp::HttpRequestLayer::HttpGET:
		return "GET";
	case pcpp::HttpRequestLayer::HttpPOST:
		return "POST";
	default:
		return "Other";
	}
}

int main(int argc, char* argv[])
{
	// use the IFileReaderDevice interface to automatically identify file type (pcap/pcap-ng)
	// and create an interface instance that both readers implement
	pcpp::IFileReaderDevice* reader = pcpp::IFileReaderDevice::getReader("1_http_packet.pcap");

	// verify that a reader interface was indeed created
	if (reader == NULL)
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

	// first let's go over the layers one by one and find out its type, its total length, its header length and its payload length
	for (pcpp::Layer* curLayer = parsedPacket.getFirstLayer(); curLayer != NULL; curLayer = curLayer->getNextLayer())
	{
		std::cout
			<< "Layer type: " << getProtocolTypeAsString(curLayer->getProtocol()) << "; " // get layer type
			<< "Total data: " << curLayer->getDataLen() << " [bytes]; " // get total length of the layer
			<< "Layer data: " << curLayer->getHeaderLen() << " [bytes]; " // get the header length of the layer
			<< "Layer payload: " << curLayer->getLayerPayloadSize() << " [bytes]" // get the payload length of the layer (equals total length minus header length)
			<< std::endl;
	}

	// now let's get the Ethernet layer
	pcpp::EthLayer* ethernetLayer = parsedPacket.getLayerOfType<pcpp::EthLayer>();
	if (ethernetLayer == NULL)
	{
		std::cerr << "Something went wrong, couldn't find Ethernet layer" << std::endl;
		return 1;
	}

	// print the source and dest MAC addresses and the Ether type
	std::cout << std::endl
		<< "Source MAC address: " << ethernetLayer->getSourceMac() << std::endl
		<< "Destination MAC address: " << ethernetLayer->getDestMac() << std::endl
		<< "Ether type = 0x" << std::hex << pcpp::netToHost16(ethernetLayer->getEthHeader()->etherType) << std::endl;

	// let's get the IPv4 layer
	pcpp::IPv4Layer* ipLayer = parsedPacket.getLayerOfType<pcpp::IPv4Layer>();
	if (ipLayer == NULL)
	{
		std::cerr << "Something went wrong, couldn't find IPv4 layer" << std::endl;
		return 1;
	}

	// print source and dest IP addresses, IP ID and TTL
	std::cout << std::endl
		<< "Source IP address: " << ipLayer->getSrcIPAddress() << std::endl
		<< "Destination IP address: " << ipLayer->getDstIPAddress() << std::endl
		<< "IP ID: 0x" << std::hex << pcpp::netToHost16(ipLayer->getIPv4Header()->ipId) << std::endl
		<< "TTL: " << std::dec << (int)ipLayer->getIPv4Header()->timeToLive << std::endl;

	// let's get the TCP layer
	pcpp::TcpLayer* tcpLayer = parsedPacket.getLayerOfType<pcpp::TcpLayer>();
	if (tcpLayer == NULL)
	{
		std::cerr << "Something went wrong, couldn't find TCP layer" << std::endl;
		return 1;
	}

	// print TCP source and dest ports, window size, and the TCP flags that are set in this layer
	std::cout << std::endl
		<< "Source TCP port: " << tcpLayer->getSrcPort() << std::endl
		<< "Destination TCP port: " << tcpLayer->getDstPort() << std::endl
		<< "Window size: " << pcpp::netToHost16(tcpLayer->getTcpHeader()->windowSize) << std::endl
		<< "TCP flags: " << printTcpFlags(tcpLayer) << std::endl;

	std::cout << "TCP options: ";
	for (pcpp::TcpOption tcpOption = tcpLayer->getFirstTcpOption(); tcpOption.isNotNull(); tcpOption = tcpLayer->getNextTcpOption(tcpOption))
	{
		std::cout << printTcpOptionType(tcpOption.getTcpOptionType()) << " ";
	}
	std::cout << std::endl;

	// let's get the HTTP request layer
	pcpp::HttpRequestLayer* httpRequestLayer = parsedPacket.getLayerOfType<pcpp::HttpRequestLayer>();
	if (httpRequestLayer == NULL)
	{
		std::cerr << "Something went wrong, couldn't find HTTP request layer" << std::endl;
		return 1;
	}

	// print HTTP method and URI. Both appear in the first line of the HTTP request
	std::cout << std::endl
		<< "HTTP method: " << printHttpMethod(httpRequestLayer->getFirstLine()->getMethod()) << std::endl
		<< "HTTP URI: " << httpRequestLayer->getFirstLine()->getUri() << std::endl;

	// print values of the following HTTP field: Host, User-Agent and Cookie
	std::cout
		<< "HTTP host: " << httpRequestLayer->getFieldByName(PCPP_HTTP_HOST_FIELD)->getFieldValue() << std::endl
		<< "HTTP user-agent: " << httpRequestLayer->getFieldByName(PCPP_HTTP_USER_AGENT_FIELD)->getFieldValue() << std::endl
		<< "HTTP cookie: " << httpRequestLayer->getFieldByName(PCPP_HTTP_COOKIE_FIELD)->getFieldValue() << std::endl;

	// print the full URL of this request
	std::cout << "HTTP full URL: " << httpRequestLayer->getUrl() << std::endl;
}
