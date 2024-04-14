#include <iostream>
#include <memory>
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
	std::string result;
    auto* tcpHeader = tcpLayer->getTcpHeader();
    if (tcpHeader->synFlag) result += "SYN ";
    if (tcpHeader->ackFlag) result += "ACK ";
    if (tcpHeader->pshFlag) result += "PSH ";
    if (tcpHeader->cwrFlag) result += "CWR ";
    if (tcpHeader->urgFlag) result += "URG ";
    if (tcpHeader->eceFlag) result += "ECE ";
    if (tcpHeader->rstFlag) result += "RST ";
    if (tcpHeader->finFlag) result += "FIN ";
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
	std::unique_ptr<pcpp::IFileReaderDevice> reader(pcpp::IFileReaderDevice::getReader("1_http_packet.pcap"));

	// verify that a reader interface was indeed created
	if (reader == nullptr)
	{
		std::cerr << "Cannot determine reader for file type\n";
		return 1;
	}

	// open the reader for reading
	if (!reader->open())
	{
		std::cerr << "Cannot open input.pcap for reading\n";
		return 1;
	}

	// read the first (and only) packet from the file
	pcpp::RawPacket rawPacket;
	if (!reader->getNextPacket(rawPacket))
	{
		std::cerr << "Couldn't read the first packet in the file\n";
		return 1;
	}

	// close the file reader, we don't need it anymore
	reader->close();

	// parse the raw packet into a parsed packet
	pcpp::Packet parsedPacket(&rawPacket);

	// first let's go over the layers one by one and find out its type, its total length, its header length and its payload length
	for (auto* curLayer = parsedPacket.getFirstLayer(); curLayer != nullptr; curLayer = curLayer->getNextLayer())
	{
		std::cout
			<< "Layer type: " << getProtocolTypeAsString(curLayer->getProtocol()) << "; " // get layer type
			<< "Total data: " << curLayer->getDataLen() << " [bytes]; " // get total length of the layer
			<< "Layer data: " << curLayer->getHeaderLen() << " [bytes]; " // get the header length of the layer
			<< "Layer payload: " << curLayer->getLayerPayloadSize() << " [bytes]\n"; // get the payload length of the layer (equals total length minus header length)
	}

	// now let's get the Ethernet layer
	auto* ethernetLayer = parsedPacket.getLayerOfType<pcpp::EthLayer>();
	if (ethernetLayer == nullptr)
	{
		std::cerr << "Something went wrong, couldn't find Ethernet layer\n";
		return 1;
	}

	// print the source and dest MAC addresses and the Ether type
	std::cout << "\nSource MAC address: " << ethernetLayer->getSourceMac() << "\n"
              << "Destination MAC address: " << ethernetLayer->getDestMac() << "\n"
              << "Ether type = 0x" << std::hex << pcpp::netToHost16(ethernetLayer->getEthHeader()->etherType) << std::dec << "\n";

	// let's get the IPv4 layer
	auto* ipLayer = parsedPacket.getLayerOfType<pcpp::IPv4Layer>();
	if (ipLayer == nullptr)
	{
		std::cerr << "Something went wrong, couldn't find IPv4 layer\n";
		return 1;
	}

	// print source and dest IP addresses, IP ID and TTL
	 std::cout << "\nSource IP address: " << ipLayer->getSrcIPAddress() << "\n"
              << "Destination IP address: " << ipLayer->getDstIPAddress() << "\n"
              << "IP ID: 0x" << std::hex << pcpp::netToHost16(ipLayer->getIPv4Header()->ipId) << std::dec << "\n"
              << "TTL: " << static_cast<int>(ipLayer->getIPv4Header()->timeToLive) << "\n";

	// let's get the TCP layer
	auto* tcpLayer = parsedPacket.getLayerOfType<pcpp::TcpLayer>();
	if (tcpLayer == nullptr)
	{
		std::cerr << "Something went wrong, couldn't find TCP layer\n";
		return 1;
	}

	// print TCP source and dest ports, window size, and the TCP flags that are set in this layer
	std::cout << "\nSource TCP port: " << tcpLayer->getSrcPort() << "\n"
              << "Destination TCP port: " << tcpLayer->getDstPort() << "\n"
              << "Window size: " << pcpp::netToHost16(tcpLayer->getTcpHeader()->windowSize) << "\n"
              << "TCP flags: " << printTcpFlags(tcpLayer) << "\n";

	std::cout << "TCP options: ";
	for (pcpp::TcpOption tcpOption = tcpLayer->getFirstTcpOption(); tcpOption.isNotNull(); tcpOption = tcpLayer->getNextTcpOption(tcpOption))
	{
		std::cout << printTcpOptionType(tcpOption.getTcpOptionType()) << " ";
	}
	std::cout << "\n";

	// let's get the HTTP request layer
	auto* httpRequestLayer = parsedPacket.getLayerOfType<pcpp::HttpRequestLayer>();
	if (httpRequestLayer == nullptr)
	{
		std::cerr << "Something went wrong, couldn't find HTTP request layer\n";
		return 1;
	}

	// print HTTP method, URI, Host, User-Agent, Cookie and full URL of this request
	std::cout << "\nHTTP method: " << printHttpMethod(httpRequestLayer->getFirstLine()->getMethod()) << "\n"
              << "HTTP URI: " << httpRequestLayer->getFirstLine()->getUri() << "\n"
              << "HTTP host: " << httpRequestLayer->getFieldByName(PCPP_HTTP_HOST_FIELD)->getFieldValue() << "\n"
              << "HTTP user-agent: " << httpRequestLayer->getFieldByName(PCPP_HTTP_USER_AGENT_FIELD)->getFieldValue() << "\n"
              << "HTTP cookie: " << httpRequestLayer->getFieldByName(PCPP_HTTP_COOKIE_FIELD)->getFieldValue() << "\n"
              << "HTTP full URL: " << httpRequestLayer->getUrl() << std::endl;
}
