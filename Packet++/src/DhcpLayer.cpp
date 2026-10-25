#define LOG_MODULE PacketLogModuleDhcpLayer

#include "DhcpLayer.h"
#include "Logger.h"
#include "EndianPortable.h"
#include "Serializers.h"
#include "GeneralUtils.h"

namespace pcpp
{

	constexpr uint32_t DhcpMagicNumber = 0x63538263;

	DhcpOption DhcpOptionBuilder::build() const
	{
		size_t recSize = 2 * sizeof(uint8_t) + m_RecValueLen;
		uint8_t recType = static_cast<uint8_t>(m_RecType);

		if ((recType == DHCPOPT_END || recType == DHCPOPT_PAD))
		{
			if (m_RecValueLen != 0)
			{
				PCPP_LOG_ERROR(
				    "Can't set DHCP END option or DHCP PAD option with size different than 0, tried to set size "
				    << (int)m_RecValueLen);
				return DhcpOption(nullptr);
			}

			recSize = sizeof(uint8_t);
		}

		uint8_t* recordBuffer = new uint8_t[recSize];
		memset(recordBuffer, 0, recSize);
		recordBuffer[0] = recType;
		if (recSize > 1)
		{
			recordBuffer[1] = static_cast<uint8_t>(m_RecValueLen);
			if (m_RecValue != nullptr)
				memcpy(recordBuffer + 2, m_RecValue, m_RecValueLen);
			else
				memset(recordBuffer + 2, 0, m_RecValueLen);
		}

		return DhcpOption(recordBuffer);
	}

	DhcpLayer::DhcpLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
	    : Layer(data, dataLen, prevLayer, packet, DHCP)
	{}

	void DhcpLayer::initDhcpLayer(size_t numOfBytesToAllocate)
	{
		allocData(numOfBytesToAllocate);
		m_Protocol = DHCP;
	}

	DhcpLayer::DhcpLayer() : Layer()
	{
		initDhcpLayer(sizeof(dhcp_header));
	}

	DhcpLayer::DhcpLayer(DhcpMessageType msgType, const MacAddress& clientMacAddr) : Layer()
	{
		initDhcpLayer(sizeof(dhcp_header) + 4 * sizeof(uint8_t));

		setClientHardwareAddress(clientMacAddr);

		uint8_t* msgTypeOptionPtr = m_Data + sizeof(dhcp_header);
		msgTypeOptionPtr[0] = (uint8_t)DHCPOPT_DHCP_MESSAGE_TYPE;  // option code
		msgTypeOptionPtr[1] = 1;                                   // option len
		msgTypeOptionPtr[2] = (uint8_t)msgType;                    // option data - message type

		msgTypeOptionPtr[3] = (uint8_t)DHCPOPT_END;
	}

	MacAddress DhcpLayer::getClientHardwareAddress() const
	{
		dhcp_header* hdr = getDhcpHeader();
		if (hdr != nullptr && hdr->hardwareType == 1 && hdr->hardwareAddressLength == 6)
			return MacAddress(hdr->clientHardwareAddress);

		PCPP_LOG_DEBUG("Hardware type isn't Ethernet or hardware addr len != 6, returning MacAddress:Zero");

		return MacAddress::Zero;
	}

	void DhcpLayer::setClientHardwareAddress(const MacAddress& addr)
	{
		dhcp_header* hdr = getDhcpHeader();
		hdr->hardwareType = 1;           // Ethernet
		hdr->hardwareAddressLength = 6;  // MAC address length
		addr.copyTo(hdr->clientHardwareAddress);
	}

	void DhcpLayer::computeCalculateFields()
	{
		dhcp_header* hdr = getDhcpHeader();

		hdr->magicNumber = DhcpMagicNumber;

		DhcpMessageType msgType = getMessageType();
		switch (msgType)
		{
		case DHCP_DISCOVER:
		case DHCP_REQUEST:
		case DHCP_DECLINE:
		case DHCP_RELEASE:
		case DHCP_INFORM:
		case DHCP_UNKNOWN_MSG_TYPE:
			hdr->opCode = DHCP_BOOTREQUEST;
			break;
		case DHCP_OFFER:
		case DHCP_ACK:
		case DHCP_NAK:
			hdr->opCode = DHCP_BOOTREPLY;
			break;
		default:
			break;
		}

		hdr->hardwareType = 1;           // Ethernet
		hdr->hardwareAddressLength = 6;  // MAC address length
	}

	std::string DhcpLayer::toString() const
	{
		std::string msgType = "Unknown";
		switch (getMessageType())
		{
		case DHCP_DISCOVER:
		{
			msgType = "Discover";
			break;
		}
		case DHCP_OFFER:
		{
			msgType = "Offer";
			break;
		}
		case DHCP_REQUEST:
		{
			msgType = "Request";
			break;
		}
		case DHCP_DECLINE:
		{
			msgType = "Decline";
			break;
		}
		case DHCP_ACK:
		{
			msgType = "Acknowledge";
			break;
		}
		case DHCP_NAK:
		{
			msgType = "Negative Acknowledge";
			break;
		}
		case DHCP_RELEASE:
		{
			msgType = "Release";
			break;
		}
		case DHCP_INFORM:
		{
			msgType = "Inform";
			break;
		}
		default:
			break;
		}

		return "DHCP layer (" + msgType + ")";
	}

	DhcpMessageType DhcpLayer::getMessageType() const
	{
		DhcpOption opt = getOptionData(DHCPOPT_DHCP_MESSAGE_TYPE);
		if (opt.isNull())
			return DHCP_UNKNOWN_MSG_TYPE;

		return (DhcpMessageType)opt.getValueAs<uint8_t>();
	}

	bool DhcpLayer::setMessageType(DhcpMessageType msgType)
	{
		if (msgType == DHCP_UNKNOWN_MSG_TYPE)
			return false;

		DhcpOption opt = getOptionData(DHCPOPT_DHCP_MESSAGE_TYPE);
		if (opt.isNull())
		{
			opt = addOptionAfter(DhcpOptionBuilder(DHCPOPT_DHCP_MESSAGE_TYPE, (uint8_t)msgType), DHCPOPT_UNKNOWN);
			if (opt.isNull())
				return false;
		}

		opt.setValue<uint8_t>((uint8_t)msgType);
		return true;
	}

	DhcpOption DhcpLayer::getOptionData(DhcpOptionTypes option) const
	{
		return m_OptionReader.getTLVRecord((uint8_t)option, getOptionsBasePtr(), getHeaderLen() - sizeof(dhcp_header));
	}

	DhcpOption DhcpLayer::getFirstOptionData() const
	{
		return m_OptionReader.getFirstTLVRecord(getOptionsBasePtr(), getHeaderLen() - sizeof(dhcp_header));
	}

	DhcpOption DhcpLayer::getNextOptionData(DhcpOption dhcpOption) const
	{
		return m_OptionReader.getNextTLVRecord(dhcpOption, getOptionsBasePtr(), getHeaderLen() - sizeof(dhcp_header));
	}

	size_t DhcpLayer::getOptionsCount() const
	{
		return m_OptionReader.getTLVRecordCount(getOptionsBasePtr(), getHeaderLen() - sizeof(dhcp_header));
	}

	DhcpOption DhcpLayer::addOptionAt(const DhcpOptionBuilder& optionBuilder, int offset)
	{
		DhcpOption newOpt = optionBuilder.build();

		if (newOpt.isNull())
		{
			PCPP_LOG_ERROR("Cannot build new option of type " << (int)newOpt.getType());
			return DhcpOption(nullptr);
		}

		size_t sizeToExtend = newOpt.getTotalSize();

		if (!extendLayer(offset, sizeToExtend))
		{
			PCPP_LOG_ERROR("Could not extend DhcpLayer in [" << newOpt.getTotalSize() << "] bytes");
			newOpt.purgeRecordData();
			return DhcpOption(nullptr);
		}

		memcpy(m_Data + offset, newOpt.getRecordBasePtr(), newOpt.getTotalSize());

		uint8_t* newOptPtr = m_Data + offset;

		m_OptionReader.changeTLVRecordCount(1);

		newOpt.purgeRecordData();

		return DhcpOption(newOptPtr);
	}

	DhcpOption DhcpLayer::addOption(const DhcpOptionBuilder& optionBuilder)
	{
		int offset = 0;
		DhcpOption endOpt = getOptionData(DHCPOPT_END);
		if (!endOpt.isNull())
			offset = endOpt.getRecordBasePtr() - m_Data;
		else
			offset = getHeaderLen();

		return addOptionAt(optionBuilder, offset);
	}

	DhcpOption DhcpLayer::addOptionAfter(const DhcpOptionBuilder& optionBuilder, DhcpOptionTypes prevOption)
	{
		int offset = 0;

		DhcpOption prevOpt = getOptionData(prevOption);

		if (prevOpt.isNull())
		{
			offset = sizeof(dhcp_header);
		}
		else
		{
			offset = prevOpt.getRecordBasePtr() + prevOpt.getTotalSize() - m_Data;
		}

		return addOptionAt(optionBuilder, offset);
	}

	bool DhcpLayer::removeOption(DhcpOptionTypes optionType)
	{
		DhcpOption optToRemove = getOptionData(optionType);
		if (optToRemove.isNull())
		{
			return false;
		}

		int offset = optToRemove.getRecordBasePtr() - m_Data;

		if (!shortenLayer(offset, optToRemove.getTotalSize()))
		{
			return false;
		}

		m_OptionReader.changeTLVRecordCount(-1);
		return true;
	}

	bool DhcpLayer::removeAllOptions()
	{
		int offset = sizeof(dhcp_header);

		if (!shortenLayer(offset, getHeaderLen() - offset))
			return false;

		m_OptionReader.changeTLVRecordCount(0 - getOptionsCount());
		return true;
	}

	static constexpr const char* dhcpMessageTypeToString(DhcpMessageType msgType)
	{
		switch (msgType)
		{
		case DHCP_DISCOVER:
			return "Discover";
		case DHCP_OFFER:
			return "Offer";
		case DHCP_REQUEST:
			return "Request";
		case DHCP_DECLINE:
			return "Decline";
		case DHCP_ACK:
			return "Acknowledge";
		case DHCP_NAK:
			return "Negative Acknowledge";
		case DHCP_RELEASE:
			return "Release";
		case DHCP_INFORM:
			return "Inform";
		default:
			return "Unknown";
		}
	}

	static constexpr const char* dhcpOptionTypeToString(DhcpOptionTypes optType)
	{
		switch (optType)
		{
		case DHCPOPT_PAD:
			return "Pad";
		case DHCPOPT_SUBNET_MASK:
			return "SubnetMask";
		case DHCPOPT_TIME_OFFSET:
			return "TimeOffset";
		case DHCPOPT_ROUTERS:
			return "Routers";
		case DHCPOPT_TIME_SERVERS:
			return "TimeServers";
		case DHCPOPT_NAME_SERVERS:
			return "NameServers";
		case DHCPOPT_DOMAIN_NAME_SERVERS:
			return "DomainNameServers";
		case DHCPOPT_LOG_SERVERS:
			return "LogServers";
		case DHCPOPT_QUOTES_SERVERS:
			return "QuotesServers";
		case DHCPOPT_LPR_SERVERS:
			return "LprServers";
		case DHCPOPT_IMPRESS_SERVERS:
			return "ImpressServers";
		case DHCPOPT_RESOURCE_LOCATION_SERVERS:
			return "ResourceLocationServers";
		case DHCPOPT_HOST_NAME:
			return "HostName";
		case DHCPOPT_BOOT_SIZE:
			return "BootSize";
		case DHCPOPT_MERIT_DUMP:
			return "MeritDump";
		case DHCPOPT_DOMAIN_NAME:
			return "DomainName";
		case DHCPOPT_SWAP_SERVER:
			return "SwapServer";
		case DHCPOPT_ROOT_PATH:
			return "RootPath";
		case DHCPOPT_EXTENSIONS_PATH:
			return "ExtensionsPath";
		case DHCPOPT_IP_FORWARDING:
			return "IPForwarding";
		case DHCPOPT_NON_LOCAL_SOURCE_ROUTING:
			return "NonLocalSourceRouting";
		case DHCPOPT_POLICY_FILTER:
			return "PolicyFilter";
		case DHCPOPT_MAX_DGRAM_REASSEMBLY:
			return "MaxDatagramReassemblySize";
		case DEFAULT_IP_TTL:
			return "DefaultIPTTL";
		case DHCPOPT_PATH_MTU_AGING_TIMEOUT:
			return "PathMTUAgingTimeout";
		case PATH_MTU_PLATEAU_TABLE:
			return "PathMTUPlateauTable";
		case DHCPOPT_INTERFACE_MTU:
			return "InterfaceMTU";
		case DHCPOPT_ALL_SUBNETS_LOCAL:
			return "AllSubnetsAreLocal";
		case DHCPOPT_BROADCAST_ADDRESS:
			return "BroadcastAddress";
		case DHCPOPT_PERFORM_MASK_DISCOVERY:
			return "PerformMaskDiscovery";
		case DHCPOPT_MASK_SUPPLIER:
			return "MaskSupplier";
		case DHCPOPT_ROUTER_DISCOVERY:
			return "RouterDiscovery";
		case DHCPOPT_ROUTER_SOLICITATION_ADDRESS:
			return "RouterSolicitationAddress";
		case DHCPOPT_STATIC_ROUTES:
			return "StaticRoutes";
		case DHCPOPT_TRAILER_ENCAPSULATION:
			return "TrailerEncapsulation";
		case DHCPOPT_ARP_CACHE_TIMEOUT:
			return "ARPCacheTimeout";
		case DHCPOPT_IEEE802_3_ENCAPSULATION:
			return "IEEE802_3Encapsulation";
		case DHCPOPT_DEFAULT_TCP_TTL:
			return "DefaultTCPTTL";
		case DHCPOPT_TCP_KEEPALIVE_INTERVAL:
			return "TCPKeepaliveInterval";
		case DHCPOPT_TCP_KEEPALIVE_GARBAGE:
			return "TCPKeepaliveGarbage";
		case DHCPOPT_NIS_DOMAIN:
			return "NISDomain";
		case DHCPOPT_NIS_SERVERS:
			return "NISServers";
		case DHCPOPT_NTP_SERVERS:
			return "NTPServers";
		case DHCPOPT_VENDOR_ENCAPSULATED_OPTIONS:
			return "VendorEncapsulatedOptions";
		case DHCPOPT_NETBIOS_NAME_SERVERS:
			return "NetBIOSNameServers";
		case DHCPOPT_NETBIOS_DD_SERVER:
			return "NetBIOSDatagramDistributionServer";
		case DHCPOPT_NETBIOS_NODE_TYPE:
			return "NetBIOSNodeType";
		case DHCPOPT_NETBIOS_SCOPE:
			return "NetBIOSScope";
		case DHCPOPT_FONT_SERVERS:
			return "FontServers";
		case DHCPOPT_X_DISPLAY_MANAGER:
			return "XDisplayManager";
		case DHCPOPT_DHCP_REQUESTED_ADDRESS:
			return "RequestedIPAddress";
		case DHCPOPT_DHCP_LEASE_TIME:
			return "IPAddressLeaseTime";
		case DHCPOPT_DHCP_OPTION_OVERLOAD:
			return "OptionOverload";
		case DHCPOPT_DHCP_MESSAGE_TYPE:
			return "DHCPMessageType";
		case DHCPOPT_DHCP_SERVER_IDENTIFIER:
			return "ServerIdentifier";
		case DHCPOPT_DHCP_PARAMETER_REQUEST_LIST:
			return "ParameterRequestList";
		case DHCPOPT_DHCP_MESSAGE:
			return "DHCPErrorMessage";
		case DHCPOPT_DHCP_MAX_MESSAGE_SIZE:
			return "DHCPMaxMessageSize";
		case DHCPOPT_DHCP_RENEWAL_TIME:
			return "RenewalTime";
		case DHCPOPT_DHCP_REBINDING_TIME:
			return "RebindingTime";
		case DHCPOPT_VENDOR_CLASS_IDENTIFIER:
			return "VendorClassIdentifier";
		case DHCPOPT_DHCP_CLIENT_IDENTIFIER:
			return "ClientIdentifier";
		case DHCPOPT_NWIP_DOMAIN_NAME:
			return "NWIPDomainName";
		case DHCPOPT_NWIP_SUBOPTIONS:
			return "NWIPSubOptions";
		case DHCPOPT_NIS_DOMAIN_NAME:
			return "NISPlusDomainName";
		case DHCPOPT_NIS_SERVER_ADDRESS:
			return "NISPlusServerAddress";
		case DHCPOPT_TFTP_SERVER_NAME:
			return "TFTPServerName";
		case DHCPOPT_BOOTFILE_NAME:
			return "BootfileName";
		case DHCPOPT_HOME_AGENT_ADDRESS:
			return "HomeAgentAddress";
		case DHCPOPT_SMTP_SERVER:
			return "SMTPServer";
		case DHCPOPT_POP3_SERVER:
			return "POP3Server";
		case DHCPOPT_NNTP_SERVER:
			return "NNTPServer";
		case DHCPOPT_WWW_SERVER:
			return "WWWServer";
		case DHCPOPT_FINGER_SERVER:
			return "FingerServer";
		case DHCPOPT_IRC_SERVER:
			return "IRCServer";
		case DHCPOPT_STREETTALK_SERVER:
			return "StreetTalkServer";
		case DHCPOPT_STDA_SERVER:
			return "STDAServer";
		case DHCPOPT_USER_CLASS:
			return "UserClass";
		case DHCPOPT_DIRECTORY_AGENT:
			return "DirectoryAgent";
		case DHCPOPT_SERVICE_SCOPE:
			return "ServiceScope";
		case DHCPOPT_RAPID_COMMIT:
			return "RapidCommit";
		case DHCPOPT_FQDN:
			return "FQDN";
		case DHCPOPT_DHCP_AGENT_OPTIONS:
			return "RelayAgentInformation";
		case DHCPOPT_ISNS:
			return "ISNS";
		case DHCPOPT_NDS_SERVERS:
			return "NDSServers";
		case DHCPOPT_NDS_TREE_NAME:
			return "NDSTreeName";
		case DHCPOPT_NDS_CONTEXT:
			return "NDSContext";
		case DHCPOPT_BCMCS_CONTROLLER_DOMAIN_NAME_LIST:
			return "BCMCSDomainNameList";
		case DHCPOPT_BCMCS_CONTROLLER_IPV4_ADDRESS:
			return "BCMCSIPv4Address";
		case DHCPOPT_AUTHENTICATION:
			return "Authentication";
		case DHCPOPT_CLIENT_LAST_TXN_TIME:
			return "ClientLastTransactionTime";
		case DHCPOPT_ASSOCIATED_IP:
			return "AssociatedIP";
		case DHCPOPT_CLIENT_SYSTEM:
			return "ClientSystem";
		case DHCPOPT_CLIENT_NDI:
			return "ClientNDI";
		case DHCPOPT_LDAP:
			return "LDAP";
		case DHCPOPT_UUID_GUID:
			return "UUID_GUID";
		case DHCPOPT_USER_AUTH:
			return "UserAuthentication";
		case DHCPOPT_GEOCONF_CIVIC:
			return "GeoConfCivic";
		case DHCPOPT_PCODE:
			return "PCode";
		case DHCPOPT_TCODE:
			return "TCode";
		case DHCPOPT_NETINFO_ADDRESS:
			return "NetInfoAddress";
		case DHCPOPT_NETINFO_TAG:
			return "NetInfoTag";
		case DHCPOPT_URL:
			return "URL";
		case DHCPOPT_AUTO_CONFIG:
			return "AutoConfig";
		case DHCPOPT_NAME_SERVICE_SEARCH:
			return "NameServiceSearch";
		case DHCPOPT_SUBNET_SELECTION:
			return "SubnetSelection";
		case DHCPOPT_DOMAIN_SEARCH:
			return "DomainSearch";
		case DHCPOPT_SIP_SERVERS:
			return "SIPServers";
		case DHCPOPT_CLASSLESS_STATIC_ROUTE:
			return "ClasslessStaticRoute";
		case DHCPOPT_CCC:
			return "CableLabsClientConfig";
		case DHCPOPT_GEOCONF:
			return "GeoConf";
		case DHCPOPT_V_I_VENDOR_CLASS:
			return "VendorIdentifyingVendorClass";
		case DHCPOPT_V_I_VENDOR_OPTS:
			return "VendorIdentifyingVendorSpecificInfo";
		case DHCPOPT_OPTION_PANA_AGENT:
			return "PANAAgent";
		case DHCPOPT_OPTION_V4_LOST:
			return "V4Lost";
		case DHCPOPT_OPTION_CAPWAP_AC_V4:
			return "CapwapAcV4";
		case DHCPOPT_OPTION_IPV4_ADDRESS_MOS:
			return "IPv4AddressMOS";
		case DHCPOPT_OPTION_IPV4_FQDN_MOS:
			return "IPv4FqdnMOS";
		case DHCPOPT_SIP_UA_CONFIG:
			return "SIPUAConfig";
		case DHCPOPT_OPTION_IPV4_ADDRESS_ANDSF:
			return "IPv4AddressANDSF";
		case DHCPOPT_GEOLOC:
			return "GeoLoc";
		case DHCPOPT_FORCERENEW_NONCE_CAPABLE:
			return "ForceRenewNonceCapable";
		case DHCPOPT_RDNSS_SELECTION:
			return "RDNSSSelection";
		case DHCPOPT_STATUS_CODE:
			return "StatusCode";
		case DHCPOPT_BASE_TIME:
			return "BaseTime";
		case DHCPOPT_START_TIME_OF_STATE:
			return "StartTimeOfState";
		case DHCPOPT_QUERY_START_TIME:
			return "QueryStartTime";
		case DHCPOPT_QUERY_END_TIME:
			return "QueryEndTime";
		case DHCPOPT_DHCP_STATE:
			return "DHCPState";
		case DHCPOPT_DATA_SOURCE:
			return "DataSource";
		case DHCPOPT_OPTION_V4_PCP_SERVER:
			return "OptionV4PcpServer";
		case DHCPOPT_OPTION_V4_PORTPARAMS:
			return "OptionV4PortParams";
		case DHCPOPT_CAPTIVE_PORTAL:
			return "CaptivePortal";
		case DHCPOPT_OPTION_MUD_URL_V4:
			return "OptionMudUrlV4";
		case DHCPOPT_ETHERBOOT:
			return "Etherboot";
		case DHCPOPT_IP_TELEPHONE:
			return "IPTelephone";
		case DHCPOPT_PXELINUX_MAGIC:
			return "PxeLinuxMagic";
		case DHCPOPT_CONFIGURATION_FILE:
			return "ConfigurationFile";
		case DHCPOPT_PATH_PREFIX:
			return "PathPrefix";
		case DHCPOPT_REBOOT_TIME:
			return "RebootTime";
		case DHCPOPT_OPTION_6RD:
			return "Option6RD";
		case DHCPOPT_OPTION_V4_ACCESS_DOMAIN:
			return "OptionV4AccessDomain";
		case DHCPOPT_SUBNET_ALLOCATION:
			return "SubnetAllocation";
		case DHCPOPT_VIRTUAL_SUBNET_SELECTION:
			return "VirtualSubnetSelection";
		case DHCPOPT_END:
			return "End";
		default:
			return "Unknown";
		}
	}

	const FieldDescriptor DhcpLayer::SerializedFields::OpCode{ Layer::SerializedFields::MaxID + 1, "opCode" };
	const FieldDescriptor DhcpLayer::SerializedFields::HardwareType{ Layer::SerializedFields::MaxID + 2,
		                                                             "hardwareType" };
	const FieldDescriptor DhcpLayer::SerializedFields::HardwareAddressLength{ Layer::SerializedFields::MaxID + 3,
		                                                                      "hardwareAddressLength" };
	const FieldDescriptor DhcpLayer::SerializedFields::Hops{ Layer::SerializedFields::MaxID + 4, "hops" };
	const FieldDescriptor DhcpLayer::SerializedFields::TransactionID{ Layer::SerializedFields::MaxID + 5,
		                                                              "transactionID" };
	const FieldDescriptor DhcpLayer::SerializedFields::SecondsElapsed{ Layer::SerializedFields::MaxID + 6,
		                                                               "secondsElapsed" };
	const FieldDescriptor DhcpLayer::SerializedFields::Flags{ Layer::SerializedFields::MaxID + 7, "flags" };
	const FieldDescriptor DhcpLayer::SerializedFields::ClientIpAddress{ Layer::SerializedFields::MaxID + 8,
		                                                                "clientIpAddress" };
	const FieldDescriptor DhcpLayer::SerializedFields::YourIpAddress{ Layer::SerializedFields::MaxID + 9,
		                                                              "yourIpAddress" };
	const FieldDescriptor DhcpLayer::SerializedFields::ServerIpAddress{ Layer::SerializedFields::MaxID + 10,
		                                                                "serverIpAddress" };
	const FieldDescriptor DhcpLayer::SerializedFields::GatewayIpAddress{ Layer::SerializedFields::MaxID + 11,
		                                                                 "gatewayIpAddress" };
	const FieldDescriptor DhcpLayer::SerializedFields::ClientHardwareAddress{ Layer::SerializedFields::MaxID + 12,
		                                                                      "clientHardwareAddress" };
	const FieldDescriptor DhcpLayer::SerializedFields::MessageType{ Layer::SerializedFields::MaxID + 14,
		                                                            "messageType" };
	const FieldDescriptor DhcpLayer::SerializedFields::Options{ Layer::SerializedFields::MaxID + 15, "options" };
	const FieldDescriptor DhcpLayer::SerializedFields::Option{ 0, "option" };

	void DhcpLayer::serializeLayer(ObjectScope& serializer) const
	{
		const dhcp_header* hdr = getDhcpHeader();
		serializer.writeField(SerializedFields::OpCode, getOpCode() == DHCP_BOOTREQUEST ? "BootRequest"
		                                                : getOpCode() == DHCP_BOOTREPLY ? "BootReply"
		                                                                                : "Unknown");
		serializer.writeField(SerializedFields::HardwareType, hdr->hardwareType);
		serializer.writeField(SerializedFields::HardwareAddressLength, hdr->hardwareAddressLength);
		serializer.writeField(SerializedFields::Hops, hdr->hops);
		serializer.writeHexField(SerializedFields::TransactionID, be32toh(hdr->transactionID));
		serializer.writeField(SerializedFields::SecondsElapsed, be16toh(hdr->secondsElapsed));
		serializer.writeHexField(SerializedFields::Flags, be16toh(hdr->flags));
		serializer.writeField(SerializedFields::ClientIpAddress, getClientIpAddress().toString());
		serializer.writeField(SerializedFields::YourIpAddress, getYourIpAddress().toString());
		serializer.writeField(SerializedFields::ServerIpAddress, getServerIpAddress().toString());
		serializer.writeField(SerializedFields::GatewayIpAddress, getGatewayIpAddress().toString());
		serializer.writeField(SerializedFields::ClientHardwareAddress, getClientHardwareAddress().toString());
		serializer.writeField(SerializedFields::MessageType, dhcpMessageTypeToString(getMessageType()));
		auto options = serializer.writeArray(SerializedFields::Options);
		for (auto opt = getFirstOptionData(); opt.isNotNull(); opt = getNextOptionData(opt))
		{
			options.writeField(SerializedFields::Option,
			                   dhcpOptionTypeToString(static_cast<DhcpOptionTypes>(opt.getType())));
		}
	}

}  // namespace pcpp
