#if !defined(WIN32) && !defined(WINx64)
#include <in.h> // this is for using ntohs() and htons() on non-Windows OS's
#endif
#include "stdlib.h"
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

std::string printTcpOptionType(pcpp::TcpOption optionType)
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
		printf("Cannot determine reader for file type\n");
		exit(1);
	}

	// open the reader for reading
	if (!reader->open())
	{
		printf("Cannot open input.pcap for reading\n");
		exit(1);
	}

	// read the first (and only) packet from the file
	pcpp::RawPacket rawPacket;
	if (!reader->getNextPacket(rawPacket))
	{
		printf("Couldn't read the first packet in the file\n");
		return 1;
	}

	// close the file reader, we don't need it anymore
	reader->close();

	// parse the raw packet into a parsed packet
	pcpp::Packet parsedPacket(&rawPacket);

	// first let's go over the layers one by one and find out its type, its total length, its header length and its payload length
	for (pcpp::Layer* curLayer = parsedPacket.getFirstLayer(); curLayer != NULL; curLayer = curLayer->getNextLayer())
	{
		printf("Layer type: %s; Total data: %d [bytes]; Layer data: %d [bytes]; Layer payload: %d [bytes]\n",
				getProtocolTypeAsString(curLayer->getProtocol()).c_str(), // get layer type
				(int)curLayer->getDataLen(),                              // get total length of the layer
				(int)curLayer->getHeaderLen(),                            // get the header length of the layer
				(int)curLayer->getLayerPayloadSize());                    // get the payload length of the layer (equals total length minus header length)
	}

	// now let's get the Ethernet layer
	pcpp::EthLayer* ethernetLayer = parsedPacket.getLayerOfType<pcpp::EthLayer>();
	if (ethernetLayer == NULL)
	{
		printf("Something went wrong, couldn't find Ethernet layer\n");
		exit(1);
	}

	// print the source and dest MAC addresses and the Ether type
	printf("\nSource MAC address: %s\n", ethernetLayer->getSourceMac().toString().c_str());
	printf("Destination MAC address: %s\n", ethernetLayer->getDestMac().toString().c_str());
	printf("Ether type = 0x%X\n", ntohs(ethernetLayer->getEthHeader()->etherType));

	// let's get the IPv4 layer
	pcpp::IPv4Layer* ipLayer = parsedPacket.getLayerOfType<pcpp::IPv4Layer>();
	if (ipLayer == NULL)
	{
		printf("Something went wrong, couldn't find IPv4 layer\n");
		exit(1);
	}

	// print source and dest IP addresses, IP ID and TTL
	printf("\nSource IP address: %s\n", ipLayer->getSrcIpAddress().toString().c_str());
	printf("Destination IP address: %s\n", ipLayer->getDstIpAddress().toString().c_str());
	printf("IP ID: 0x%X\n", ntohs(ipLayer->getIPv4Header()->ipId));
	printf("TTL: %d\n", ipLayer->getIPv4Header()->timeToLive);

	// let's get the TCP layer
	pcpp::TcpLayer* tcpLayer = parsedPacket.getLayerOfType<pcpp::TcpLayer>();
	if (tcpLayer == NULL)
	{
		printf("Something went wrong, couldn't find TCP layer\n");
		exit(1);
	}

	// printf TCP source and dest ports, window size, and the TCP flags that are set in this layer
	printf("\nSource TCP port: %d\n", (int)ntohs(tcpLayer->getTcpHeader()->portSrc));
	printf("Destination TCP port: %d\n", (int)ntohs(tcpLayer->getTcpHeader()->portDst));
	printf("Window size: %d\n", (int)ntohs(tcpLayer->getTcpHeader()->windowSize));
	printf("TCP flags: %s\n", printTcpFlags(tcpLayer).c_str());

	// go over all TCP options in this layer and print its type
	printf("TCP options: ");
	for (pcpp::TcpOptionData* tcpOption = tcpLayer->getFirstTcpOptionData(); tcpOption != NULL; tcpOption = tcpLayer->getNextTcpOptionData(tcpOption))
		printf("%s ", printTcpOptionType(tcpOption->getType()).c_str());
	printf("\n");

	// let's get the HTTP request layer
	pcpp::HttpRequestLayer* httpRequestLayer = parsedPacket.getLayerOfType<pcpp::HttpRequestLayer>();
	if (httpRequestLayer == NULL)
	{
		printf("Something went wrong, couldn't find HTTP request layer\n");
		exit(1);
	}

	// print HTTP method and URI. Both appear in the first line of the HTTP request
	printf("\nHTTP method: %s\n", printHttpMethod(httpRequestLayer->getFirstLine()->getMethod()).c_str());
	printf("HTTP URI: %s\n", httpRequestLayer->getFirstLine()->getUri().c_str());

	// print values of the following HTTP field: Host, User-Agent and Cookie
	printf("HTTP host: %s\n", httpRequestLayer->getFieldByName(PCPP_HTTP_HOST_FIELD)->getFieldValue().c_str());
	printf("HTTP user-agent: %s\n", httpRequestLayer->getFieldByName(PCPP_HTTP_USER_AGENT_FIELD)->getFieldValue().c_str());
	printf("HTTP cookie: %s\n", httpRequestLayer->getFieldByName(PCPP_HTTP_COOKIE_FIELD)->getFieldValue().c_str());

	// print the full URL of this request
	printf("HTTP full URL: %s\n", httpRequestLayer->getUrl().c_str());
}
