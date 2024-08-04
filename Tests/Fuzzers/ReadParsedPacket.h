#pragma once

#include <Packet.h>
#include <IPv4Layer.h>
#include <TelnetLayer.h>
#include <BgpLayer.h>
#include <DhcpLayer.h>
#include <DhcpV6Layer.h>
#include <DnsLayer.h>
#include <IcmpLayer.h>
#include <NtpLayer.h>
#include <SSLLayer.h>
#include <SSLHandshake.h>
#include <TcpLayer.h>
#include <SdpLayer.h>
#include <VrrpLayer.h>
#include <Sll2Layer.h>
#include <FtpLayer.h>
#include <GreLayer.h>
#include <GtpLayer.h>
#include <SomeIpSdLayer.h>

// Call some pcpp::Packet methods that are not invoked from general virtual methods
// as `pcpp::Packet::toString` or `pcpp::Packet::computeCalculateFields` to trigger possible crashes.
// The general rule is the functions do not modify the `parsedPacket`.
// If you made changes to PcapPlusPlus and the code doesn't compile - fix the method call as any other unit test
static void readParsedPacket(pcpp::Packet parsedPacket, pcpp::Layer* layer)
{
	if (parsedPacket.isPacketOfType(pcpp::Telnet))
	{
		if (auto telnetLayer = dynamic_cast<pcpp::TelnetLayer*>(layer))
		{
			telnetLayer->getFirstCommand();
			telnetLayer->getTotalNumberOfCommands();

			pcpp::TelnetLayer::TelnetCommand commandVal;
			do
			{
				commandVal = telnetLayer->getNextCommand();
				std::cout << "Telnet command is '" << telnetLayer->getTelnetCommandAsString(commandVal) << "'"
				          << std::endl;
				pcpp::TelnetLayer::TelnetOption option = telnetLayer->getOption();
				std::cout << "Telnet option is '" << telnetLayer->getTelnetOptionAsString(option) << "'" << std::endl;

				telnetLayer->getDataAsString(true);
				telnetLayer->getNumberOfCommands(commandVal);
				telnetLayer->getOption(commandVal);
				size_t length = 0;
				telnetLayer->getOptionData(length);
				telnetLayer->getOptionData(commandVal, length);
			} while (commandVal != pcpp::TelnetLayer::TelnetCommand::TelnetCommandEndOfPacket);
		}
	}
	if (parsedPacket.isPacketOfType(pcpp::ARP))
	{
		if (auto arpLayer = dynamic_cast<pcpp::ArpLayer*>(layer))
		{
			arpLayer->isReply();
			arpLayer->isRequest();
		}
	}
	if (parsedPacket.isPacketOfType(pcpp::SomeIP))
	{
		if (auto someipLayer = dynamic_cast<pcpp::SomeIpSdLayer*>(layer))
		{
			auto entries = someipLayer->getEntries();
			if (!entries.empty())
			{
				auto opts = someipLayer->getOptionsFromEntry(0);
				for (auto opt : opts)
					delete opt;
			}

			for (auto entry : entries)
			{
				entry->getNumOptions();
				entry->getServiceId();
				entry->getInstanceId();
				entry->getMajorVersion();
				entry->getMinorVersion();
				entry->getCounter();
				entry->getEventgroupId();
				delete entry;
			}

			someipLayer->getFlags();
			auto opts = someipLayer->getOptions();
			for (auto opt : opts)
			{
				opt->getType();
				if (auto v4opt = dynamic_cast<pcpp::SomeIpSdIPv4Option*>(opt))
				{
					v4opt->getIpAddress();
					v4opt->getPort();
					v4opt->getProtocol();
				}
				else if (auto v6opt = dynamic_cast<pcpp::SomeIpSdIPv6Option*>(opt))
				{
					v6opt->getIpAddress();
					v6opt->getPort();
					v6opt->getProtocol();
				}
				delete opt;
			}
		}
	}
	if (parsedPacket.isPacketOfType(pcpp::GTP))
	{
		if (auto gtpLayer = dynamic_cast<pcpp::GtpV1Layer*>(layer))
		{
			uint16_t value16 = 0;
			gtpLayer->getSequenceNumber(value16);
			uint8_t value8;
			gtpLayer->getNpduNumber(value8);
			gtpLayer->getMessageType();
			gtpLayer->getMessageTypeAsString();
			gtpLayer->isGTPUMessage();
			gtpLayer->isGTPCMessage();
			auto ext = gtpLayer->getNextExtension();
			ext.getExtensionType();
			ext.getContent();
			ext.getContentLength();
			ext.getNextExtension();
		}
	}
	if (parsedPacket.isPacketOfType(pcpp::GRE))
	{
		if (auto greLayer = dynamic_cast<pcpp::GreLayer*>(layer))
		{
			uint32_t value32 = 0;
			greLayer->getSequenceNumber(value32);
		}
	}
	if (parsedPacket.isPacketOfType(pcpp::GREv0))
	{
		if (auto greLayer = dynamic_cast<pcpp::GREv0Layer*>(layer))
		{
			uint16_t value16 = 0;
			greLayer->getChecksum(value16);
			greLayer->getOffset(value16);
			uint32_t value32 = 0;
			greLayer->getKey(value32);
		}
	}
	if (parsedPacket.isPacketOfType(pcpp::GREv1))
	{
		if (auto greLayer = dynamic_cast<pcpp::GREv1Layer*>(layer))
		{
			uint32_t value32 = 0;
			greLayer->getAcknowledgmentNum(value32);
		}
	}
	if (parsedPacket.isPacketOfType(pcpp::FTP))
	{
		if (auto ftpLayer = dynamic_cast<pcpp::FtpRequestLayer*>(layer))
		{
			ftpLayer->getCommandOption(false);
			ftpLayer->getCommandOption(true);
		}
		else if (auto ftpLayer = dynamic_cast<pcpp::FtpResponseLayer*>(layer))
		{
			ftpLayer->getStatusCode();
			ftpLayer->getStatusOption(false);
			ftpLayer->getStatusOption(true);
		}
	}
	if (parsedPacket.isPacketOfType(pcpp::SLL2))
	{
		if (auto sllLayer = dynamic_cast<pcpp::Sll2Layer*>(layer))
		{
			sllLayer->getLinkLayerAsMacAddress();
			sllLayer->getProtocolType();
			sllLayer->getInterfaceIndex();
			sllLayer->getArphrdType();
			sllLayer->getPacketType();
		}
	}
	if (parsedPacket.isPacketOfType(pcpp::VRRP))
	{
		if (auto vrrpLayer = dynamic_cast<pcpp::VrrpLayer*>(layer))
		{
			vrrpLayer->getIPAddresses();
			vrrpLayer->isChecksumCorrect();
			vrrpLayer->getChecksum();
			vrrpLayer->getPriorityAsEnum();
			vrrpLayer->getPriority();
			vrrpLayer->getType();
		}
	}
	if (parsedPacket.isPacketOfType(pcpp::VRRPv2))
	{
		if (auto vrrpLayer = dynamic_cast<pcpp::VrrpV2Layer*>(layer))
		{
			vrrpLayer->getAuthTypeAsEnum();
			vrrpLayer->getAdvInt();
		}
	}
	if (parsedPacket.isPacketOfType(pcpp::VRRPv3))
	{
		if (auto vrrpLayer = dynamic_cast<pcpp::VrrpV3Layer*>(layer))
		{
			vrrpLayer->getMaxAdvInt();
		}
	}
	if (parsedPacket.isPacketOfType(pcpp::TCP))
	{
		if (auto tcpLayer = dynamic_cast<pcpp::TcpLayer*>(layer))
		{
			auto tcpLayer2(*tcpLayer);
			tcpLayer2.insertTcpOptionAfter(pcpp::TcpOptionBuilder(pcpp::TcpOptionBuilder::NopEolOptionEnumType::Nop),
			                               pcpp::TcpOptionEnumType::Nop);
		}
	}
	if (parsedPacket.isPacketOfType(pcpp::SDP))
	{
		if (auto sdpLayer = dynamic_cast<pcpp::SdpLayer*>(layer))
		{
			sdpLayer->getOwnerIPv4Address();
			sdpLayer->getMediaPort("audio");
			sdpLayer->getFieldCount();

			auto sdpLayer2 = *sdpLayer;
			std::vector<std::string> audioAttributes;
			audioAttributes.push_back("rtpmap:8 PCMA/8000");
			sdpLayer2.addMediaDescription("audio", 6010, "RTP/AVP", "8 96", audioAttributes);
			sdpLayer2.addField(PCPP_SDP_PROTOCOL_VERSION_FIELD, "0");
			sdpLayer2.removeField(PCPP_SDP_PROTOCOL_VERSION_FIELD);
		}
	}
	if (parsedPacket.isPacketOfType(pcpp::SSL))
	{
		if (auto handshakeLayer = dynamic_cast<pcpp::SSLHandshakeLayer*>(layer))
		{
			if (auto clientHelloMessage = handshakeLayer->getHandshakeMessageOfType<pcpp::SSLClientHelloMessage>())
			{
				clientHelloMessage->getCompressionMethodsValue();
				clientHelloMessage->getSessionID();
				clientHelloMessage->getHandshakeType();
				clientHelloMessage->getHandshakeVersion();

				pcpp::SSLCipherSuite::getCipherSuiteByName("TLS_RSA_WITH_NULL_MD5");
				for (int i = 0; i < clientHelloMessage->getCipherSuiteCount(); i++)
				{
					clientHelloMessage->getCipherSuite(i);
					bool valid;
					clientHelloMessage->getCipherSuiteID(i, valid);
				}
				if (auto ext = clientHelloMessage->getExtensionOfType<pcpp::SSLServerNameIndicationExtension>())
					ext->getHostName();
				if (auto ext = clientHelloMessage->getExtensionOfType<pcpp::SSLSupportedVersionsExtension>())
					ext->getSupportedVersions();

				clientHelloMessage->getExtensionOfType(pcpp::SSL_EXT_SERVER_NAME);
				clientHelloMessage->getExtensionOfType((uint16_t)0);

				auto fingerprint = clientHelloMessage->generateTLSFingerprint();
				fingerprint.toMD5();
			}
			if (auto serverHelloMessage = handshakeLayer->getHandshakeMessageOfType<pcpp::SSLServerHelloMessage>())
			{
				serverHelloMessage->getCompressionMethodsValue();
				serverHelloMessage->getSessionID();
				serverHelloMessage->getCipherSuite();

				serverHelloMessage->getExtensionOfType<pcpp::SSLServerNameIndicationExtension>();
				serverHelloMessage->getExtensionOfType(pcpp::SSL_EXT_SERVER_NAME);
				serverHelloMessage->getExtensionOfType((uint16_t)0);

				serverHelloMessage->getHandshakeVersion();
				auto fingerprint = serverHelloMessage->generateTLSFingerprint();
				fingerprint.toMD5();
			}
			if (auto handshakeMessage = handshakeLayer->getHandshakeMessageOfType<pcpp::SSLHandshakeMessage>())
			{
				handshakeMessage->isMessageComplete();
			}
		}
	}
	if (parsedPacket.isPacketOfType(pcpp::NTP))
	{
		if (auto ntpLayer = dynamic_cast<pcpp::NtpLayer*>(layer))
		{
			ntpLayer->getLeapIndicator();
			ntpLayer->getMode();
			ntpLayer->getModeString();
			ntpLayer->getStratum();
			ntpLayer->getPollInterval();
			ntpLayer->getPrecision();
			ntpLayer->getRootDelay();
			ntpLayer->getRootDispersion();
			ntpLayer->getReferenceIdentifier();
			ntpLayer->getReferenceIdentifierString();
			ntpLayer->getReferenceTimestamp();
			ntpLayer->getOriginTimestamp();
			ntpLayer->getReceiveTimestamp();
			ntpLayer->getTransmitTimestamp();

			ntpLayer->getDigest();
			ntpLayer->getKeyID();

			ntpLayer->getPollIntervalInSecs();
			ntpLayer->getPrecisionInSecs();
			ntpLayer->getRootDelayInSecs();
			ntpLayer->getRootDispersionInSecs();
			ntpLayer->getReferenceTimestampInSecs();
			ntpLayer->getOriginTimestampInSecs();
			ntpLayer->getReceiveTimestampInSecs();
			ntpLayer->getTransmitTimestampInSecs();

			ntpLayer->getReferenceTimestampAsString();
			ntpLayer->getOriginTimestampAsString();
			ntpLayer->getReceiveTimestampAsString();
			ntpLayer->getTransmitTimestampAsString();

			auto ntpLayer2(*ntpLayer);
			ntpLayer2.setRootDelayInSecs(0.1);
			ntpLayer2.setReferenceTimestampInSecs(0.1);
		}
	}
	if (parsedPacket.isPacketOfType(pcpp::ICMP))
	{
		if (auto icmpLayer = dynamic_cast<pcpp::IcmpLayer*>(layer))
		{
			auto icmpLayer2(*icmpLayer);

			if (icmpLayer->isMessageOfType(pcpp::ICMP_TIMESTAMP_REPLY))
			{
				icmpLayer->getTimestampReplyData();
				timeval orig = { 16131, 171000 };
				timeval recv = { 16133, 474000 };
				timeval tran = { 16133, 474000 };
				icmpLayer2.setTimestampReplyData(14640, 0, orig, recv, tran);
			}
			else if (icmpLayer->isMessageOfType(pcpp::ICMP_ADDRESS_MASK_REQUEST))
			{
				icmpLayer->getAddressMaskRequestData();
				icmpLayer2.setAddressMaskRequestData(45068, 1536, pcpp::IPv4Address::Zero);
			}
			else if (icmpLayer->isMessageOfType(pcpp::ICMP_ADDRESS_MASK_REPLY))
			{
				icmpLayer->getAddressMaskReplyData();
				icmpLayer2.setAddressMaskReplyData(45068, 1536, pcpp::IPv4Address::Zero);
			}
			else if (icmpLayer->isMessageOfType(pcpp::ICMP_DEST_UNREACHABLE))
			{
				icmpLayer->getDestUnreachableData();
				icmpLayer2.setDestUnreachableData(pcpp::IcmpHostUnreachable, 0, nullptr, nullptr);
			}
			else if (icmpLayer->isMessageOfType(pcpp::ICMP_INFO_REPLY))
			{
				auto layerData = icmpLayer->getInfoReplyData();
				icmpLayer2.setInfoReplyData(layerData->id, layerData->sequence);
			}
			else if (icmpLayer->isMessageOfType(pcpp::ICMP_INFO_REQUEST))
			{
				auto layerData = icmpLayer->getInfoRequestData();
				icmpLayer2.setInfoRequestData(layerData->id, layerData->sequence);
			}
			else if (icmpLayer->isMessageOfType(pcpp::ICMP_PARAM_PROBLEM))
			{
				auto layerData = icmpLayer->getParamProblemData();
				icmpLayer2.setParamProblemData(layerData->code, layerData->pointer, nullptr, nullptr);
			}
			else if (icmpLayer->isMessageOfType(pcpp::ICMP_TIME_EXCEEDED))
			{
				icmpLayer->getTimeExceededData();
				icmpLayer2.setTimeExceededData(1, nullptr, nullptr);
			}
			else if (icmpLayer->isMessageOfType(pcpp::ICMP_ROUTER_ADV))
			{
				icmpLayer->getRouterAdvertisementData();
				pcpp::icmp_router_address_structure addr1;
				addr1.setRouterAddress(pcpp::IPv4Address("192.168.144.2"), (uint32_t)0x08000000);
				std::vector<pcpp::icmp_router_address_structure> routerAddresses;
				routerAddresses.push_back(addr1);
				icmpLayer2.setRouterAdvertisementData(16, 200, routerAddresses);
			}
		}
	}
	if (parsedPacket.isPacketOfType(pcpp::DHCPv6))
	{
		if (auto dhcpLayer = dynamic_cast<pcpp::DhcpV6Layer*>(layer))
		{
			dhcpLayer->getTransactionID();
			if (dhcpLayer->getOptionCount() > 0)
			{
				pcpp::DhcpV6Option opt = dhcpLayer->getFirstOptionData();
				opt.getType();
				opt.getTotalSize();
				opt.getValueAsHexString();
				for (size_t i = 0; i < dhcpLayer->getOptionCount(); i++)
				{
					opt = dhcpLayer->getNextOptionData(opt);
				}
				dhcpLayer->getOptionData(pcpp::DHCPV6_OPT_CLIENTID);
			}
		}
	}
	if (parsedPacket.isPacketOfType(pcpp::DHCP))
	{
		if (auto dhcpLayer = dynamic_cast<pcpp::DhcpLayer*>(layer))
		{
			dhcpLayer->getOpCode();
			dhcpLayer->getDhcpHeader();
			dhcpLayer->getClientIpAddress();
			dhcpLayer->getYourIpAddress();
			dhcpLayer->getServerIpAddress();
			dhcpLayer->getGatewayIpAddress();
			dhcpLayer->getClientHardwareAddress();
			if (dhcpLayer->getOptionsCount() > 0)
			{
				pcpp::DhcpOption opt = dhcpLayer->getFirstOptionData();
				opt.getValueAsIpAddr();
				opt.getValueAsString();
				for (size_t i = 0; i < dhcpLayer->getOptionsCount(); i++)
				{
					opt = dhcpLayer->getNextOptionData(opt);
				}
			}
			dhcpLayer->getOptionData(pcpp::DHCPOPT_SUBNET_MASK);
		}
	}
	if (parsedPacket.isPacketOfType(pcpp::BGP))
	{
		if (auto bgpLayer = dynamic_cast<pcpp::BgpLayer*>(layer))
		{
			bgpLayer->getMessageTypeAsString();
			if (auto bgpOpenMsgLayer = dynamic_cast<pcpp::BgpOpenMessageLayer*>(bgpLayer))
			{
				std::vector<pcpp::BgpOpenMessageLayer::optional_parameter> optionalParams;
				bgpOpenMsgLayer->getOptionalParameters(optionalParams);
				std::vector<pcpp::BgpOpenMessageLayer::optional_parameter> optionalParams2(optionalParams);
				optionalParams2.push_back(pcpp::BgpOpenMessageLayer::optional_parameter(2, "010400010001"));
				optionalParams2.push_back(pcpp::BgpOpenMessageLayer::optional_parameter(2, "8000"));
				optionalParams2.push_back(pcpp::BgpOpenMessageLayer::optional_parameter(2, "0200"));
				optionalParams2.push_back(pcpp::BgpOpenMessageLayer::optional_parameter(2, "4600"));
				optionalParams2.push_back(pcpp::BgpOpenMessageLayer::optional_parameter(2, "410400000001"));
				bgpOpenMsgLayer->setOptionalParameters(optionalParams2);
				bgpOpenMsgLayer->clearOptionalParameters();
				bgpOpenMsgLayer->setOptionalParameters(optionalParams);
			}
			else if (auto bgpUpdateMsgLayer = dynamic_cast<pcpp::BgpUpdateMessageLayer*>(bgpLayer))
			{
				std::vector<pcpp::BgpUpdateMessageLayer::prefix_and_ip> withdrawnRoutes;
				bgpUpdateMsgLayer->getWithdrawnRoutes(withdrawnRoutes);
				std::vector<pcpp::BgpUpdateMessageLayer::prefix_and_ip> withdrawnRoutes2(withdrawnRoutes);
				withdrawnRoutes2.push_back(pcpp::BgpUpdateMessageLayer::prefix_and_ip(24, "40.1.1.0"));
				withdrawnRoutes2.push_back(pcpp::BgpUpdateMessageLayer::prefix_and_ip(24, "40.40.40.0"));
				withdrawnRoutes2.push_back(pcpp::BgpUpdateMessageLayer::prefix_and_ip(16, "103.103.0.0"));
				withdrawnRoutes2.push_back(pcpp::BgpUpdateMessageLayer::prefix_and_ip(24, "103.103.40.0"));
				bgpUpdateMsgLayer->setWithdrawnRoutes(withdrawnRoutes2);
				bgpUpdateMsgLayer->clearWithdrawnRoutes();
				bgpUpdateMsgLayer->setWithdrawnRoutes(withdrawnRoutes);

				std::vector<pcpp::BgpUpdateMessageLayer::prefix_and_ip> nlriVec;
				bgpUpdateMsgLayer->getNetworkLayerReachabilityInfo(nlriVec);
				std::vector<pcpp::BgpUpdateMessageLayer::prefix_and_ip> nlriVec2(nlriVec);
				nlriVec2.push_back(pcpp::BgpUpdateMessageLayer::prefix_and_ip(24, "40.1.1.0"));
				bgpUpdateMsgLayer->setNetworkLayerReachabilityInfo(nlriVec2);
				bgpUpdateMsgLayer->clearNetworkLayerReachabilityInfo();
				bgpUpdateMsgLayer->setNetworkLayerReachabilityInfo(nlriVec);

				std::vector<pcpp::BgpUpdateMessageLayer::path_attribute> pathAttributes;
				bgpUpdateMsgLayer->getPathAttributes(pathAttributes);
				std::vector<pcpp::BgpUpdateMessageLayer::path_attribute> pathAttributes2(pathAttributes);
				pathAttributes2.push_back(pcpp::BgpUpdateMessageLayer::path_attribute(0x40, 1, "02"));
				pathAttributes2.push_back(
				    pcpp::BgpUpdateMessageLayer::path_attribute(0x40, 2, "02030000000a0000001400000028"));
				pathAttributes2.push_back(pcpp::BgpUpdateMessageLayer::path_attribute(0x40, 3, "1e031e03"));
				bgpUpdateMsgLayer->setPathAttributes(pathAttributes2);
				bgpUpdateMsgLayer->clearPathAttributes();
				bgpUpdateMsgLayer->setPathAttributes(pathAttributes);
			}
			else if (auto bgpNotificationMsgLayer = dynamic_cast<pcpp::BgpNotificationMessageLayer*>(bgpLayer))
			{
				bgpNotificationMsgLayer->getNotificationDataAsHexString();
			}
		}
	}
	if (parsedPacket.isPacketOfType(pcpp::DNS))
	{
		if (auto dnsLayer = dynamic_cast<pcpp::DnsLayer*>(layer))
		{
			dnsLayer->addQuery("mail-attachment.googleusercontent.com", pcpp::DNS_TYPE_A, pcpp::DNS_CLASS_IN);
			dnsLayer->removeQuery("a", true);
			dnsLayer->removeQuery("mail-attachment.googleusercontent.com", false);
			pcpp::IPv4DnsResourceData ipv4DnsData(std::string("151.249.90.217"));
			dnsLayer->addAnswer("assets.pinterest.com.cdngc.net", pcpp::DNS_TYPE_A, pcpp::DNS_CLASS_IN, 3,
			                    &ipv4DnsData);
			dnsLayer->removeAnswer("a", true);
			dnsLayer->removeAnswer("assets.pinterest.com.cdngc.net", false);
			dnsLayer->addAuthority("Yaels-iPhone.local", pcpp::DNS_TYPE_A, pcpp::DNS_CLASS_IN, 120, &ipv4DnsData);
			dnsLayer->removeAuthority("a", true);
			dnsLayer->removeAuthority("Yaels-iPhone.local", false);
			pcpp::GenericDnsResourceData genericData("0004000800df581faa4f3f9d");
			dnsLayer->addAdditionalRecord("abc", pcpp::DNS_TYPE_OPT, 0xa005, 0x1194, &genericData);
			dnsLayer->removeAdditionalRecord("a", true);
			dnsLayer->removeAdditionalRecord("abc", false);

			auto add = dnsLayer->getFirstAdditionalRecord();
			while (add != nullptr)
			{
				add = dnsLayer->getNextAdditionalRecord(add);
			}

			auto answer = dnsLayer->getFirstAnswer();
			while (answer != nullptr)
			{
				answer = dnsLayer->getNextAnswer(answer);
			}

			auto auth = dnsLayer->getFirstAuthority();
			while (auth != nullptr)
			{
				auth = dnsLayer->getNextAuthority(auth);
			}

			pcpp::DnsLayer other(*dnsLayer);
			other = *dnsLayer;
		}
	}
}
